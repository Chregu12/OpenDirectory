'use client';

import React, { useState, useEffect } from 'react';
import {
  ComputerDesktopIcon,
  DeviceTabletIcon,
  ServerIcon,
  PrinterIcon,
  CheckIcon,
  ClipboardDocumentIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  PlusIcon,
  XMarkIcon,
  CommandLineIcon,
} from '@heroicons/react/24/outline';
import { deviceApi } from '@/lib/api';
import toast from 'react-hot-toast';

type Platform = 'windows' | 'macos' | 'linux' | 'printer';
type WizardStep = 'select' | 'instructions' | 'verify';

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
  const [step, setStep] = useState<WizardStep>(initialPlatform ? 'instructions' : 'select');
  const [selectedPlatform, setSelectedPlatform] = useState<Platform | null>(initialPlatform || null);
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const [loadingToken, setLoadingToken] = useState(false);
  const [enrolledCount, setEnrolledCount] = useState(0);

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
    setStep('instructions');
  };

  const handleAddAnother = () => {
    setSelectedPlatform(null);
    setStep('select');
    setEnrolledCount(prev => prev + 1);
  };

  const platformInfo = PLATFORMS.find(p => p.id === selectedPlatform);

  return (
    <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-green-600 to-green-700 px-8 pt-5 pb-6 flex items-center justify-between">
          <div>
            <h2 className="text-white text-xl font-bold">
              {step === 'select' ? 'Gerät hinzufügen' : platformInfo?.icon + ' ' + platformInfo?.name + ' einrichten'}
            </h2>
            <p className="text-green-200 text-sm">
              {enrolledCount > 0 ? `${enrolledCount} Gerät(e) bereits hinzugefügt` : 'Registriere deine Geräte bei OpenDirectory'}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-green-200 hover:text-white p-1 rounded-lg hover:bg-green-500/30 transition-colors"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-8 py-6">

          {/* Step: Platform selection */}
          {step === 'select' && (
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

          {/* Step: Instructions */}
          {step === 'instructions' && selectedPlatform && (
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
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 px-8 py-4 flex items-center justify-between bg-gray-50">
          <div>
            {step === 'instructions' && (
              <button
                onClick={() => { setStep('select'); setSelectedPlatform(null); }}
                className="flex items-center px-4 py-2 text-sm text-gray-600 hover:text-gray-900"
              >
                <ArrowLeftIcon className="h-4 w-4 mr-1" />
                Andere Plattform
              </button>
            )}
          </div>

          <div className="flex items-center space-x-3">
            {step === 'instructions' && (
              <button
                onClick={handleAddAnother}
                className="flex items-center px-4 py-2.5 border border-green-600 text-green-700 rounded-lg text-sm font-medium hover:bg-green-50"
              >
                <PlusIcon className="h-4 w-4 mr-1" />
                Weiteres Gerät
              </button>
            )}
            <button
              onClick={onClose}
              className="flex items-center px-6 py-2.5 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700"
            >
              {step === 'instructions' ? 'Fertig' : 'Schließen'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
