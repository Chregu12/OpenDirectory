'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  ComputerDesktopIcon,
  CheckIcon,
  ClipboardDocumentIcon,
  PlusIcon,
  TableCellsIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
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
  status: 'success' | 'failed' | 'unconfirmed';
  steps?: string[];
  error?: string;
}

const STEPS = [{ n: 1 as const, label: 'Plattform' }, { n: 2 as const, label: 'Einrichten' }];
const UNCONFIRMED = 'Enrollment could not be confirmed. Check device inventory before retrying.';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseBulkResults(data: unknown, devices: BulkDevice[]): BulkEnrollResult[] {
  if (!isRecord(data) || data.total !== devices.length || !Array.isArray(data.results) || data.results.length !== devices.length) {
    throw new Error(UNCONFIRMED);
  }
  const results = data.results.map((entry: unknown, index: number): BulkEnrollResult => {
    if (!isRecord(entry) || entry.index !== index || entry.deviceName !== devices[index].deviceName || typeof entry.success !== 'boolean') {
      throw new Error(UNCONFIRMED);
    }
    if (entry.result === null) {
      if (entry.success !== false || typeof entry.error !== 'string' || !entry.error.trim()) throw new Error(UNCONFIRMED);
      return { deviceName: entry.deviceName, status: 'failed', error: entry.error };
    }
    const result = entry.result;
    if (!isRecord(result) || result.success !== entry.success || entry.error !== null ||
        typeof result.deviceId !== 'string' || !result.deviceId.trim() || result.platform !== devices[index].platform ||
        !Array.isArray(result.completedSteps) || result.completedSteps.length === 0 ||
        (result.error !== undefined && typeof result.error !== 'string')) {
      throw new Error(UNCONFIRMED);
    }
    const steps = result.completedSteps.map((step: unknown) => {
      if (!isRecord(step) || typeof step.name !== 'string' || !step.name.trim() || typeof step.ok !== 'boolean' ||
          (step.error !== undefined && typeof step.error !== 'string')) throw new Error(UNCONFIRMED);
      return { name: step.name, ok: step.ok, error: step.error };
    });
    if (entry.success !== steps.every(step => step.ok)) throw new Error(UNCONFIRMED);
    return {
      deviceName: entry.deviceName,
      status: entry.success ? 'success' : 'failed',
      steps: steps.map(step => `${step.name}: ${step.ok ? 'ok' : 'failed'}${step.error ? ` (${step.error})` : ''}`),
      error: typeof result.error === 'string' ? result.error : undefined,
    };
  });
  const succeeded = results.filter(result => result.status === 'success').length;
  if (data.succeeded !== succeeded || data.failed !== results.length - succeeded) throw new Error(UNCONFIRMED);
  return results;
}

interface DeviceEnrollmentWizardProps {
  onClose: () => void;
  /** Pre-select a platform */
  initialPlatform?: Platform;
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

function PrinterInstructions() {
  const serverUrl = getServerUrl();
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(label);
      toast.success(`${label} kopiert`);
    }).catch(() => toast.error('Kopieren fehlgeschlagen'));
  };

  useEffect(() => {
    if (!copied) return;
    const timeout = setTimeout(() => setCopied(null), 2000);
    return () => clearTimeout(timeout);
  }, [copied]);

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

  return (
    <div className="space-y-5">
      <div>
        <h4 className="text-sm font-semibold text-gray-900 mb-1">Option 1: Auto-Discovery (empfohlen)</h4>
        <p className="text-sm text-gray-500 mb-2">Der folgende Befehl startet die Druckersuche. Passe das Subnetz an dein Netzwerk an.</p>
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
        <p className="text-sm text-gray-500 mb-2">
          Halte Drucker-Name, IP-Adresse und Protokoll (IPP, LPD, SMB oder Socket) bereit.
          Füge den Drucker in der Druckerverwaltung hinzu; dieser Assistent speichert keine Druckerdaten.
        </p>
        <a href="/printers" className="text-sm text-blue-600 hover:underline">Druckerverwaltung öffnen</a>
      </div>
    </div>
  );
}

export default function DeviceEnrollmentWizard({ onClose, initialPlatform }: DeviceEnrollmentWizardProps) {
  const [step, setStep] = useState<WizardStep>(initialPlatform ? 2 : 1);
  const [selectedPlatform, setSelectedPlatform] = useState<Platform | null>(initialPlatform || null);

  // Bulk enrollment state
  const [enrollMode, setEnrollMode] = useState<EnrollMode>('single');
  const [bulkCsv, setBulkCsv] = useState('');
  const [bulkParsed, setBulkParsed] = useState<BulkDevice[]>([]);
  const [bulkParseError, setBulkParseError] = useState('');
  const [bulkSubmitting, setBulkSubmitting] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkEnrollResult[] | null>(null);
  const bulkRequest = useRef(0);

  useEffect(() => {
    return () => { bulkRequest.current += 1; };
  }, []);

  const handlePlatformSelect = (platform: Platform) => {
    setSelectedPlatform(platform);
    setStep(2);
  };

  const handleAddAnother = () => {
    setSelectedPlatform(null);
    setStep(1);
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
      if (!['windows', 'macos', 'linux'].includes(platform)) { errors.push(`Line ${startIdx + i + 1}: unsupported platform`); return; }
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
    if (!bulkParsed.length || bulkParseError || bulkSubmitting) return;
    const request = ++bulkRequest.current;
    setBulkSubmitting(true);
    setBulkResults(null);
    try {
      const res = await api.post('/api/quick/devices/bulk-enroll', { devices: bulkParsed });
      if (request !== bulkRequest.current) return;
      const results = parseBulkResults(res.data, bulkParsed);
      setBulkResults(results);
      const successCount = results.filter(r => r.status === 'success').length;
      if (successCount === results.length) {
        toast.success(`Backend confirmed all ${successCount} enrollment workflows. Check device inventory for device status.`);
      } else {
        toast.error(`Backend confirmed ${successCount}/${results.length} enrollment workflows. Check results for errors.`);
      }
    } catch (err: unknown) {
      if (request !== bulkRequest.current) return;
      const response = isRecord(err) && isRecord(err.response) ? err.response : null;
      const data = response && isRecord(response.data) ? response.data : null;
      const detail = typeof data?.error === 'string' ? data.error : typeof data?.message === 'string' ? data.message : err instanceof Error ? err.message : '';
      const msg = detail && detail !== UNCONFIRMED ? `${UNCONFIRMED} ${detail}` : UNCONFIRMED;
      toast.error(msg);
      setBulkResults(bulkParsed.map(device => ({ deviceName: device.deviceName, status: 'unconfirmed', error: msg })));
    } finally {
      if (request === bulkRequest.current) setBulkSubmitting(false);
    }
  };

  const platformInfo = PLATFORMS.find(p => p.id === selectedPlatform);

  const title = enrollMode === 'bulk' ? 'Bulk Enrollment' : (step === 1 ? 'Gerät hinzufügen' : (platformInfo?.icon + ' ' + platformInfo?.name + ' einrichten'));
  const subtitle = enrollMode === 'bulk' ? 'Enroll multiple devices via CSV' : 'Einrichtungshinweise für deine Geräte';

  return (
    <WizardLayout
      color="green"
      title={title}
      subtitle={subtitle}
      icon={<ComputerDesktopIcon className="h-8 w-8" />}
      steps={enrollMode === 'bulk' ? [{ n: 1, label: 'Bulk Enrollment' }] : STEPS}
      currentStep={step}
      onStepChange={(nextStep) => { if (nextStep === 1 || selectedPlatform) setStep(nextStep as WizardStep); }}
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
            disabled={bulkSubmitting}
            className={`flex-1 py-2 rounded-lg text-sm font-medium border-2 transition-all ${enrollMode === 'single' ? 'border-green-500 bg-green-50 text-green-700' : 'border-gray-200 text-gray-500 hover:border-gray-300'}`}
          >
            Single Device
          </button>
          <button
            onClick={() => { setEnrollMode('bulk'); setBulkResults(null); setBulkCsv(''); setBulkParsed([]); setBulkParseError(''); }}
            disabled={bulkSubmitting}
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
                <label htmlFor="bulk-device-csv" className="block text-sm font-medium text-gray-700 mb-1">CSV Input</label>
                <textarea
                  id="bulk-device-csv"
                  value={bulkCsv}
                  disabled={bulkSubmitting}
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
                  disabled={bulkSubmitting || bulkParsed.length === 0 || Boolean(bulkParseError)}
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
                      <tr key={i} className={r.status === 'success' ? 'bg-white' : 'bg-red-50'}>
                        <td className="px-3 py-2 font-mono text-gray-800">{r.deviceName}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded font-medium ${r.status === 'success' ? 'bg-green-100 text-green-700' : r.status === 'unconfirmed' ? 'bg-amber-100 text-amber-700' : 'bg-red-100 text-red-600'}`}>
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
              <a href="/devices" className="text-sm text-blue-600 hover:underline">Gerätebestand ansehen</a>
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
      {step === 2 && enrollMode === 'single' && selectedPlatform && (
        <div className="space-y-5">
          {selectedPlatform === 'printer' ? (
            <PrinterInstructions />
          ) : (
            <div role="alert" className="bg-amber-50 rounded-xl p-4 space-y-2">
              <p className="text-sm text-amber-800">Token-basiertes Einzel-Enrollment ist derzeit nicht verfügbar.</p>
              <p className="text-sm text-gray-600">Es wird kein Enrollment-Token ausgegeben und keine Registrierung bestätigt. Prüfe den Gerätebestand oder nutze das Bulk Enrollment mit entsprechender Berechtigung.</p>
              <a href="/devices" className="text-sm text-blue-600 hover:underline">Gerätebestand ansehen</a>
            </div>
          )}

          {/* Add another device button - moved from footer */}
          <div className="flex justify-center pt-4 border-t border-gray-200">
            <button
              onClick={handleAddAnother}
              className="flex items-center px-4 py-2.5 border border-green-600 text-green-700 rounded-lg text-sm font-medium hover:bg-green-50"
            >
              <PlusIcon className="h-4 w-4 mr-1" />
              Andere Plattform auswählen
            </button>
          </div>
        </div>
      )}
    </WizardLayout>
  );
}
