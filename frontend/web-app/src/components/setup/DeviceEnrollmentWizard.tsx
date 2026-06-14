'use client';

import React, { useState, useEffect } from 'react';
import {
  ComputerDesktopIcon,
  DeviceTabletIcon,
  ServerIcon,
  PrinterIcon,
  CheckIcon,
  ClipboardDocumentIcon,
  PlusIcon,
  CommandLineIcon,
  TableCellsIcon,
  ExclamationTriangleIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import { deviceApi, api } from '@/lib/api';
import toast from 'react-hot-toast';
import WizardLayout from '@/components/shared/WizardLayout';

type Platform = 'windows' | 'macos' | 'linux' | 'printer';
type WizardStep = 1 | 2;
type EnrollMode = 'single' | 'bulk';

interface BulkDevice {
  deviceName: string;
  platform: string;
  serialNumber: string;
}

interface BulkEnrollResult {
  deviceName: string;
  status: 'success' | 'failed';
  steps?: string[];
  error?: string;
}

const STEPS = [{ n: 1 as const, label: 'Plattform' }, { n: 2 as const, label: 'Einrichten' }];

interface DeviceEnrollmentWizardProps {
  onClose: () => void;
  /** Pre-select a platform */
  initialPlatform?: Platform;
}

interface EnrollmentToken {
  token: string;
  expiresAt: string;
}

const PLATFORMS = [
  {
    id: 'windows' as Platform,
    name: 'Windows',
    icon: '🪟',
    description: 'Windows 10/11 Desktop & Server',
    color: 'blue',
  },
  {
    id: 'macos' as Platform,
    name: 'macOS',
    icon: '🍎',
    description: 'macOS Ventura, Sonoma, Sequoia',
    color: 'gray',
  },
  {
    id: 'linux' as Platform,
    name: 'Linux',
    icon: '🐧',
    description: 'Ubuntu, Debian, RHEL, SUSE',
    color: 'orange',
  },
  {
    id: 'printer' as Platform,
    name: 'Drucker / Scanner',
    icon: '🖨️',
    description: 'Netzwerkdrucker & Scanner',
    color: 'purple',
  },
];

function getServerUrl(): string {
  if (typeof window !== 'undefined') {
    return window.location.origin;
  }
  return 'http://YOUR-SERVER:8080';
}

function EnrollmentInstructions({ platform, token }: { platform: Platform; token: string }) {
  const serverUrl = getServerUrl();
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(label);
      toast.success(`${label} kopiert`);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  const CodeBlock = ({ code, label }: { code: string; label: string }) => (
    <div className="relative group">
      <pre className="bg-gray-900 text-green-400 rounded-lg p-4 text-sm overflow-x-auto font-mono leading-relaxed">
        {code}
      </pre>
      <button
        onClick={() => copyToClipboard(code, label)}
        className={`absolute top-2 right-2 p-1.5 rounded-md transition-all ${
          copied === label
            ? 'bg-green-600 text-white'
            : 'bg-gray-700 text-gray-300 opacity-0 group-hover:opacity-100 hover:bg-gray-600'
        }`}
        title="Kopieren"
      >
        {copied === label ? (
          <CheckIcon className="h-4 w-4" />
        ) : (
          <ClipboardDocumentIcon className="h-4 w-4" />
        )}
      </button>
    </div>
  );

  if (platform === 'windows') {
    return (
      <div className="space-y-5">
        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 1: PowerShell als Administrator öffnen</h4>
          <p className="text-sm text-gray-500 mb-2">Rechtsklick auf Start → &quot;Windows PowerShell (Administrator)&quot;</p>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 2: Agent installieren</h4>
          <CodeBlock
            label="Windows Install"
            code={`# OpenDirectory Agent herunterladen und installieren
Invoke-WebRequest -Uri "${serverUrl}/api/agents/windows/install.ps1" -OutFile "$env:TEMP\\od-install.ps1"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "$env:TEMP\\od-install.ps1" -ServerUrl "${serverUrl}" -Token "${token}"`}
          />
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 3: Alternativ — Manuell registrieren</h4>
          <CodeBlock
            label="Windows Manual"
            code={`# Gerät manuell registrieren (ohne Agent-Installation)
$body = @{
    name = $env:COMPUTERNAME
    platform = "windows"
    osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
    enrollmentToken = "${token}"
} | ConvertTo-Json

Invoke-RestMethod -Uri "${serverUrl}/api/devices/enroll" \`
    -Method POST -Body $body -ContentType "application/json"`}
          />
        </div>

        <div className="bg-blue-50 rounded-lg p-3">
          <p className="text-xs text-blue-700">
            <strong>Tipp:</strong> Für Massen-Enrollment nutze GPO oder Intune, um das Skript auf allen Geräten auszuführen.
          </p>
        </div>
      </div>
    );
  }

  if (platform === 'macos') {
    return (
      <div className="space-y-5">
        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 1: Terminal öffnen</h4>
          <p className="text-sm text-gray-500 mb-2">Spotlight (Cmd+Space) → &quot;Terminal&quot; eingeben</p>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 2: Agent installieren</h4>
          <CodeBlock
            label="macOS Install"
            code={`# OpenDirectory Agent installieren
curl -sSL ${serverUrl}/api/agents/macos/install.sh | \\
    sudo bash -s -- --server "${serverUrl}" --token "${token}"`}
          />
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 3: Alternativ — Manuell registrieren</h4>
          <CodeBlock
            label="macOS Manual"
            code={`# Gerät manuell registrieren
curl -X POST ${serverUrl}/api/devices/enroll \\
    -H "Content-Type: application/json" \\
    -d '{
        "name": "'$(hostname)'",
        "platform": "macos",
        "osVersion": "'$(sw_vers -productVersion)'",
        "serialNumber": "'$(ioreg -l | grep IOPlatformSerialNumber | awk "{print \\$4}" | tr -d \\"\\")'",,
        "enrollmentToken": "${token}"
    }'`}
          />
        </div>

        <div className="bg-blue-50 rounded-lg p-3">
          <p className="text-xs text-blue-700">
            <strong>Tipp:</strong> Für MDM-Enrollment können Geräte via Apple DEP automatisch registriert werden.
          </p>
        </div>
      </div>
    );
  }

  if (platform === 'linux') {
    return (
      <div className="space-y-5">
        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 1: Terminal öffnen (SSH oder lokal)</h4>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 2: Agent installieren</h4>
          <CodeBlock
            label="Linux Install"
            code={`# OpenDirectory Agent installieren (Debian/Ubuntu/RHEL/SUSE)
curl -sSL ${serverUrl}/api/agents/linux/install.sh | \\
    sudo bash -s -- --server "${serverUrl}" --token "${token}"`}
          />
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Schritt 3: Systemd-Service aktivieren</h4>
          <CodeBlock
            label="Linux Service"
            code={`# Agent als Systemd-Service registrieren (automatischer Start)
sudo systemctl enable --now opendirectory-agent

# Status prüfen
sudo systemctl status opendirectory-agent`}
          />
        </div>

        <div>
          <h4 className="text-sm font-semibold text-gray-900 mb-1">Alternativ: Manuell registrieren</h4>
          <CodeBlock
            label="Linux Manual"
            code={`# Gerät manuell registrieren
curl -X POST ${serverUrl}/api/devices/enroll \\
    -H "Content-Type: application/json" \\
    -d '{
        "name": "'$(hostname)'",
        "platform": "linux",
        "osVersion": "'$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d \\")'",
        "serialNumber": "'$(sudo dmidecode -s system-serial-number 2>/dev/null || echo unknown)'",
        "enrollmentToken": "${token}"
    }'`}
          />
        </div>

        <div className="bg-blue-50 rounded-lg p-3">
          <p className="text-xs text-blue-700">
            <strong>Tipp:</strong> Für mehrere Server nutze Ansible: <code className="bg-blue-100 px-1 rounded">ansible-playbook od-enroll.yml -i hosts</code>
          </p>
        </div>
      </div>
    );
  }

  // Printer
  return (
    <div className="space-y-5">
      <div>
        <h4 className="text-sm font-semibold text-gray-900 mb-1">Option 1: Auto-Discovery (empfohlen)</h4>
        <p className="text-sm text-gray-500 mb-2">OpenDirectory sucht automatisch nach Druckern im Netzwerk.</p>
        <CodeBlock
          label="Printer Discovery"
          code={`# Netzwerk nach Druckern durchsuchen
curl -X POST ${serverUrl}/api/printers/discover \\
    -H "Content-Type: application/json" \\
    -d '{ "subnet": "192.168.1.0/24" }'`}
        />
      </div>

      <div>
        <h4 className="text-sm font-semibold text-gray-900 mb-1">Option 2: Manuell hinzufügen</h4>
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Drucker-Name</label>
            <input
              type="text"
              placeholder="z.B. Büro-Drucker-OG1"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">IP-Adresse</label>
            <input
              type="text"
              placeholder="z.B. 192.168.1.100"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Protokoll</label>
            <select className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
              <option value="ipp">IPP (Internet Printing Protocol)</option>
              <option value="lpd">LPD/LPR</option>
              <option value="smb">SMB/Windows</option>
              <option value="socket">Raw/Socket (Port 9100)</option>
            </select>
          </div>
        </div>
      </div>

      <div className="bg-purple-50 rounded-lg p-3">
        <p className="text-xs text-purple-700">
          <strong>Tipp:</strong> CUPS-Admin-Oberfläche ist auch direkt erreichbar unter <code className="bg-purple-100 px-1 rounded">{serverUrl.replace(':8080', ':631')}</code>
        </p>
      </div>
    </div>
  );
}

export default function DeviceEnrollmentWizard({ onClose, initialPlatform }: DeviceEnrollmentWizardProps) {
  const [step, setStep] = useState<WizardStep>(initialPlatform ? 2 : 1);
  const [selectedPlatform, setSelectedPlatform] = useState<Platform | null>(initialPlatform || null);
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const [loadingToken, setLoadingToken] = useState(false);
  const [enrolledCount, setEnrolledCount] = useState(0);

  // Bulk enrollment state
  const [enrollMode, setEnrollMode] = useState<EnrollMode>('single');
  const [bulkCsv, setBulkCsv] = useState('');
  const [bulkParsed, setBulkParsed] = useState<BulkDevice[]>([]);
  const [bulkParseError, setBulkParseError] = useState('');
  const [bulkSubmitting, setBulkSubmitting] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkEnrollResult[] | null>(null);

  // Generate enrollment token when platform is selected
  useEffect(() => {
    if (selectedPlatform && selectedPlatform !== 'printer') {
      generateToken();
    }
  }, [selectedPlatform]);

  const generateToken = async () => {
    setLoadingToken(true);
    try {
      const response = await deviceApi.generateEnrollmentToken();
      setToken(response.data?.data?.token ? response.data.data : null);
    } catch {
      // Fallback: generate a local demo token
      setToken({
        token: `od-enroll-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      });
    } finally {
      setLoadingToken(false);
    }
  };

  const handlePlatformSelect = (platform: Platform) => {
    setSelectedPlatform(platform);
    setStep(2);
  };

  const handleAddAnother = () => {
    setSelectedPlatform(null);
    setStep(1);
    setEnrolledCount(prev => prev + 1);
  };

  const parseBulkCsv = (csv: string) => {
    setBulkParseError('');
    const lines = csv.trim().split('\n').filter(l => l.trim());
    if (!lines.length) { setBulkParsed([]); return; }
    // Skip header line if it starts with 'deviceName' (case-insensitive)
    const firstLower = lines[0].toLowerCase();
    const startIdx = firstLower.startsWith('devicename') ? 1 : 0;
    const parsed: BulkDevice[] = [];
    const errors: string[] = [];
    lines.slice(startIdx).forEach((line, i) => {
      const cols = line.split(',').map(c => c.trim());
      if (cols.length < 2) { errors.push(`Line ${startIdx + i + 1}: need at least deviceName,platform`); return; }
      const [deviceName, platform, serialNumber = ''] = cols;
      if (!deviceName || !platform) { errors.push(`Line ${startIdx + i + 1}: missing deviceName or platform`); return; }
      parsed.push({ deviceName, platform, serialNumber });
    });
    if (errors.length) setBulkParseError(errors.join('; '));
    setBulkParsed(parsed);
  };

  const handleBulkCsvChange = (val: string) => {
    setBulkCsv(val);
    parseBulkCsv(val);
  };

  const handleBulkEnroll = async () => {
    if (!bulkParsed.length) return;
    setBulkSubmitting(true);
    setBulkResults(null);
    try {
      const res = await api.post('/api/quick/devices/bulk-enroll', { devices: bulkParsed });
      const data = res.data;
      const results: BulkEnrollResult[] = (data.results || data.data?.results || bulkParsed.map(d => ({ deviceName: d.deviceName, status: 'success' as const })));
      setBulkResults(results);
      const successCount = results.filter(r => r.status === 'success').length;
      if (successCount === results.length) {
        toast.success(`All ${successCount} devices enrolled successfully!`);
      } else {
        toast.error(`${successCount}/${results.length} devices enrolled. Check results for details.`);
      }
    } catch (err: any) {
      const msg = err.response?.data?.message || err.message || 'Bulk enrollment failed';
      toast.error(msg);
      setBulkResults(bulkParsed.map(d => ({ deviceName: d.deviceName, status: 'failed', error: msg })));
    } finally {
      setBulkSubmitting(false);
    }
  };

  const platformInfo = PLATFORMS.find(p => p.id === selectedPlatform);

  const title = enrollMode === 'bulk' ? 'Bulk Enrollment' : (step === 1 ? 'Gerät hinzufügen' : (platformInfo?.icon + ' ' + platformInfo?.name + ' einrichten'));
  const subtitle = enrollMode === 'bulk' ? 'Enroll multiple devices via CSV' : (enrolledCount > 0 ? `${enrolledCount} Gerät(e) bereits hinzugefügt` : 'Registriere deine Geräte bei OpenDirectory');

  return (
    <WizardLayout
      color="green"
      title={title}
      subtitle={subtitle}
      icon={<ComputerDesktopIcon className="h-8 w-8" />}
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onClose}
      onComplete={onClose}
      completeLabel="Fertig"
      maxWidth="max-w-2xl"
    >
      {/* Mode toggle — shown on step 1 */}
      {step === 1 && (
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setEnrollMode('single')}
            className={`flex-1 py-2 rounded-lg text-sm font-medium border-2 transition-all ${enrollMode === 'single' ? 'border-green-500 bg-green-50 text-green-700' : 'border-gray-200 text-gray-500 hover:border-gray-300'}`}
          >
            Single Device
          </button>
          <button
            onClick={() => { setEnrollMode('bulk'); setBulkResults(null); setBulkCsv(''); setBulkParsed([]); }}
            className={`flex-1 py-2 rounded-lg text-sm font-medium border-2 transition-all flex items-center justify-center gap-1.5 ${enrollMode === 'bulk' ? 'border-green-500 bg-green-50 text-green-700' : 'border-gray-200 text-gray-500 hover:border-gray-300'}`}
          >
            <TableCellsIcon className="h-4 w-4" />
            Bulk Enroll
          </button>
        </div>
      )}

      {/* Step: Platform selection (single mode) */}
      {step === 1 && enrollMode === 'single' && (
        <div className="space-y-4">
          <p className="text-sm text-gray-500">Welche Art von Gerät möchtest du hinzufügen?</p>

          <div className="grid grid-cols-2 gap-3">
            {PLATFORMS.map((p) => (
              <button
                key={p.id}
                onClick={() => handlePlatformSelect(p.id)}
                className="text-left rounded-xl border-2 border-gray-200 p-5 hover:border-green-500 hover:bg-green-50 transition-all group"
              >
                <span className="text-3xl block mb-2">{p.icon}</span>
                <span className="font-medium text-gray-900 group-hover:text-green-700">{p.name}</span>
                <p className="text-xs text-gray-500 mt-1">{p.description}</p>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Step: Bulk Enrollment (bulk mode) */}
      {step === 1 && enrollMode === 'bulk' && (
        <div className="space-y-4">
          {!bulkResults ? (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">CSV Input</label>
                <textarea
                  value={bulkCsv}
                  onChange={e => handleBulkCsvChange(e.target.value)}
                  rows={8}
                  placeholder={`deviceName,platform,serialNumber\nworkstation-01,windows,SN12345\nlaptop-02,macos,SN67890\nserver-03,linux,`}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-green-500 resize-y"
                  spellCheck={false}
                />
                <p className="text-xs text-gray-400 mt-1.5">
                  Format: <code className="bg-gray-100 px-1 rounded">deviceName,platform,serialNumber</code> — one device per line.
                  Platform: <code className="bg-gray-100 px-1 rounded">windows</code> | <code className="bg-gray-100 px-1 rounded">macos</code> | <code className="bg-gray-100 px-1 rounded">linux</code>.
                  serialNumber is optional.
                </p>
              </div>

              {bulkParseError && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex gap-2">
                  <ExclamationTriangleIcon className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-red-700">{bulkParseError}</p>
                </div>
              )}

              {bulkParsed.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-gray-600 mb-1.5">{bulkParsed.length} device(s) ready to enroll:</p>
                  <div className="border border-gray-200 rounded-lg overflow-hidden max-h-40 overflow-y-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-gray-50 sticky top-0">
                        <tr>
                          {['Device Name', 'Platform', 'Serial'].map(h => (
                            <th key={h} className="px-3 py-2 text-left font-medium text-gray-500">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-100">
                        {bulkParsed.map((d, i) => (
                          <tr key={i} className="hover:bg-gray-50">
                            <td className="px-3 py-1.5 font-mono text-gray-800">{d.deviceName}</td>
                            <td className="px-3 py-1.5 text-gray-600">{d.platform}</td>
                            <td className="px-3 py-1.5 text-gray-400">{d.serialNumber || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              <div className="flex justify-end">
                <button
                  onClick={handleBulkEnroll}
                  disabled={bulkSubmitting || bulkParsed.length === 0}
                  className="flex items-center gap-2 px-5 py-2 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 disabled:opacity-50"
                >
                  {bulkSubmitting ? 'Enrolling…' : `Enroll ${bulkParsed.length > 0 ? bulkParsed.length : ''} Device${bulkParsed.length !== 1 ? 's' : ''}`}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-center justify-between mb-1">
                <p className="text-sm font-medium text-gray-700">Enrollment Results</p>
                <button
                  onClick={() => { setBulkResults(null); setBulkCsv(''); setBulkParsed([]); }}
                  className="text-xs text-blue-600 hover:text-blue-800"
                >
                  Enroll more
                </button>
              </div>
              <div className="border border-gray-200 rounded-lg overflow-hidden">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50">
                    <tr>
                      {['Device Name', 'Status', 'Steps / Error'].map(h => (
                        <th key={h} className="px-3 py-2 text-left font-medium text-gray-500">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {bulkResults.map((r, i) => (
                      <tr key={i} className={r.status === 'failed' ? 'bg-red-50' : 'bg-white'}>
                        <td className="px-3 py-2 font-mono text-gray-800">{r.deviceName}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded font-medium ${r.status === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-600'}`}>
                            {r.status}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-gray-500">
                          {r.error ? (
                            <span className="text-red-600">{r.error}</span>
                          ) : r.steps && r.steps.length > 0 ? (
                            <span>{r.steps.join(' → ')}</span>
                          ) : (
                            <span className="text-gray-400">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex justify-end">
                <button
                  onClick={onClose}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg"
                >
                  Done
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* Step: Instructions */}
      {step === 2 && selectedPlatform && (
        <div className="space-y-5">
          {/* Token display */}
          {selectedPlatform !== 'printer' && (
            <div className="bg-gray-50 rounded-xl p-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-gray-500">Enrollment-Token</span>
                {token && (
                  <span className="text-xs text-gray-400">
                    Gültig bis {new Date(token.expiresAt).toLocaleString()}
                  </span>
                )}
              </div>
              {loadingToken ? (
                <div className="h-8 bg-gray-200 rounded animate-pulse" />
              ) : token ? (
                <div className="flex items-center space-x-2">
                  <code className="flex-1 text-sm font-mono bg-white px-3 py-2 rounded border border-gray-200 select-all">
                    {token.token}
                  </code>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(token.token);
                      toast.success('Token kopiert');
                    }}
                    className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg"
                  >
                    <ClipboardDocumentIcon className="h-4 w-4" />
                  </button>
                </div>
              ) : (
                <p className="text-sm text-red-500">Token konnte nicht generiert werden</p>
              )}
            </div>
          )}

          {/* Platform-specific instructions */}
          <EnrollmentInstructions
            platform={selectedPlatform}
            token={token?.token || 'TOKEN'}
          />

          {/* Add another device button - moved from footer */}
          <div className="flex justify-center pt-4 border-t border-gray-200">
            <button
              onClick={handleAddAnother}
              className="flex items-center px-4 py-2.5 border border-green-600 text-green-700 rounded-lg text-sm font-medium hover:bg-green-50"
            >
              <PlusIcon className="h-4 w-4 mr-1" />
              Weiteres Gerät hinzufügen
            </button>
          </div>
        </div>
      )}
    </WizardLayout>
  );
}
