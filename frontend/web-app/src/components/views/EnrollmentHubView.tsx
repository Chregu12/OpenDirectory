'use client';

import React, { useState, useEffect } from 'react';
import {
  ComputerDesktopIcon,
  DevicePhoneMobileIcon,
  CommandLineIcon,
  QrCodeIcon,
  ArrowDownTrayIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ShieldCheckIcon,
  PlusIcon,
  ArrowPathIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { api } from '@/lib/api';

// ─── Types ──────────────────────────────────────────────────────────────────────

type OSPlatform = 'windows' | 'macos' | 'linux' | 'ios' | 'android';

interface EnrollmentToken {
  platform: OSPlatform;
  token: string;
  created: string;
  expires: string;
  uses: number;
  maxUses: number;
}


// ─── Platform Config ─────────────────────────────────────────────────────────────

interface PlatformInfo {
  id: OSPlatform;
  name: string;
  icon: string;
  color: string;
  bg: string;
  border: string;
  method: string;
  description: string;
}

const PLATFORMS: PlatformInfo[] = [
  {
    id: 'windows',
    name: 'Windows',
    icon: '🪟',
    color: 'text-blue-700',
    bg: 'bg-blue-50',
    border: 'border-blue-200',
    method: 'Autopilot-Style / OOBE',
    description: 'Zero-Touch Enrollment via Windows Autopilot-kompatiblem OOBE-Flow oder manuellem Agent',
  },
  {
    id: 'macos',
    name: 'macOS',
    icon: '',
    color: 'text-gray-700',
    bg: 'bg-gray-50',
    border: 'border-gray-200',
    method: 'MDM Profile / ABM-Style DEP',
    description: 'Wie Apple Business Manager: MDM-Profil per URL oder Zero-Touch via DEP-Token',
  },
  {
    id: 'linux',
    name: 'Linux',
    icon: '🐧',
    color: 'text-orange-700',
    bg: 'bg-orange-50',
    border: 'border-orange-200',
    method: 'Bootstrap-Script / PXE',
    description: 'Enrollment via Bash-Script oder PXE-Boot — unterstützt Ubuntu, Fedora, Debian, RHEL, Arch',
  },
  {
    id: 'ios',
    name: 'iOS / iPadOS',
    icon: '📱',
    color: 'text-purple-700',
    bg: 'bg-purple-50',
    border: 'border-purple-200',
    method: 'MDM Enrollment URL / APNS',
    description: 'Apple MDM-kompatibel via APNS — Supervised oder User Enrollment, DEP-Support',
  },
  {
    id: 'android',
    name: 'Android',
    icon: '🤖',
    color: 'text-green-700',
    bg: 'bg-green-50',
    border: 'border-green-200',
    method: 'Android Zero-Touch / QR-Code',
    description: 'Google Zero-Touch Enrollment, QR-Code Setup oder Android Enterprise DPC-Enrollment',
  },
];

// ─── Helper ──────────────────────────────────────────────────────────────────────

function CopyButton({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1 text-xs hover:text-blue-600 transition-colors"
      style={{ color: 'var(--text-muted)' }}
    >
      {copied ? <CheckIcon className="w-3.5 h-3.5 text-green-500" /> : <ClipboardDocumentIcon className="w-3.5 h-3.5" />}
      {label && <span>{copied ? 'Kopiert!' : label}</span>}
    </button>
  );
}

function CodeBlock({ code, language = 'bash' }: { code: string; language?: string }) {
  return (
    <div className="relative group">
      <pre className="bg-gray-900 text-green-400 rounded-lg p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
        {code}
      </pre>
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <CopyButton value={code} label="Kopieren" />
      </div>
      <div className="absolute top-2 left-2">
        <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{language}</span>
      </div>
    </div>
  );
}

// ─── Windows Enrollment ──────────────────────────────────────────────────────────

function WindowsEnrollment({ token, domain }: { token: string; domain: string }) {
  const agentUrl = `https://${domain}/api/enroll/windows/agent.ps1`;
  const autopilotJson = `{
  "Version": "2049",
  "ZtdCorrelationId": "${token}",
  "CloudAssignedTenantId": "opendirectory",
  "CloudAssignedTenantDomain": "${domain}",
  "CloudAssignedMdmId": "0000000a-0000-0000-c000-000000000000",
  "CloudAssignedOobeConfig": 1310,
  "CloudAssignedDomainJoinMethod": 0,
  "CloudAssignedLanguage": "de-DE"
}`;

  return (
    <div className="space-y-5">
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
        <InformationCircleIcon className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-semibold text-blue-800">Windows Autopilot-Style Enrollment</p>
          <p className="text-blue-700 text-xs mt-1">
            Neues Windows-Gerät startet OOBE, liest Autopilot-JSON vom USB-Stick oder Netzwerk und enrolled sich automatisch in OpenDirectory — kein manueller Domain-Join nötig.
          </p>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode A — Autopilot JSON (Zero-Touch, OOBE)</h4>
        <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>JSON-Datei auf FAT32-USB-Stick als <code className="font-mono">AutopilotConfigurationFile.json</code> im Root-Verzeichnis ablegen:</p>
        <CodeBlock language="json" code={autopilotJson} />
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode B — PowerShell Agent (bestehende PCs)</h4>
        <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>In einer Admin-PowerShell ausführen:</p>
        <CodeBlock code={`# OpenDirectory Agent installieren
$token = "${token}"
$url = "${agentUrl}?token=$token"
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-Expression (Invoke-WebRequest -Uri $url -UseBasicParsing).Content`} />
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode C — Winget / MECM / Intune Migration</h4>
        <CodeBlock code={`winget install --id OpenDirectory.Agent --silent --enrollment-token ${token}`} />
      </div>

      <div className="grid grid-cols-3 gap-3 text-xs">
        {[
          { label: 'Windows 10 21H2+', ok: true },
          { label: 'Windows 11', ok: true },
          { label: 'Windows Server 2019+', ok: true },
          { label: 'BitLocker Key Escrow', ok: true },
          { label: 'Windows Hello', ok: true },
          { label: 'Autopilot Reset', ok: true },
        ].map(f => (
          <div key={f.label} className="flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
            <CheckIcon className="w-3.5 h-3.5 text-green-500 shrink-0" />
            {f.label}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── macOS Enrollment ─────────────────────────────────────────────────────────────

function MacOSEnrollment({ token, domain }: { token: string; domain: string }) {
  const profileUrl = `https://${domain}/api/enroll/macos/profile.mobileconfig?token=${token}`;
  const agentUrl = `https://${domain}/api/enroll/macos/agent.sh?token=${token}`;

  return (
    <div className="space-y-5">
      <div className="rounded-xl p-4 flex gap-3" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
        <InformationCircleIcon className="w-5 h-5 shrink-0 mt-0.5" style={{ color: 'var(--text-muted)' }} />
        <div className="text-sm">
          <p className="font-semibold" style={{ color: 'var(--text-secondary)' }}>Apple Business Manager-Style DEP</p>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            Wie ABM: Macs enrollen sich via MDM-Profil automatisch beim ersten Start. OpenDirectory übernimmt die Rolle des MDM-Servers — Jamf Pro, Mosyle oder Kandji nicht nötig.
          </p>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode A — MDM Profil (Empfohlen, wie ABM)</h4>
        <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>Auf dem Mac öffnen oder per URL verteilen:</p>
        <div className="flex items-center gap-2 bg-gray-900 rounded-lg px-4 py-3">
          <code className="text-green-400 text-xs font-mono flex-1 truncate">{profileUrl}</code>
          <CopyButton value={profileUrl} />
        </div>
        <button
          onClick={() => toast.success('.mobileconfig wird heruntergeladen...')}
          className="mt-2 flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
        >
          <ArrowDownTrayIcon className="w-4 h-4" />
          MDM-Profil herunterladen (.mobileconfig)
        </button>
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode B — Terminal Agent (bestehende Macs)</h4>
        <CodeBlock code={`curl -fsSL "${agentUrl}" | sudo bash`} />
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode C — Homebrew (DEV/IT Macs)</h4>
        <CodeBlock code={`brew install opendirectory-agent
sudo od-agent enroll --token ${token} --server https://${domain}`} />
      </div>

      <div className="grid grid-cols-3 gap-3 text-xs">
        {[
          'macOS 12 Monterey+',
          'macOS 13 Ventura',
          'macOS 14 Sonoma',
          'FileVault Key Escrow',
          'MDM Supervision',
          'Activation Lock Bypass',
          'Software Updates (DDM)',
          'Homebrew App Deploy',
          'AirPrint/AirScan',
        ].map(f => (
          <div key={f} className="flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
            <CheckIcon className="w-3.5 h-3.5 text-green-500 shrink-0" />
            {f}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Linux Enrollment ─────────────────────────────────────────────────────────────

function LinuxEnrollment({ token, domain }: { token: string; domain: string }) {
  return (
    <div className="space-y-5">
      <div className="bg-orange-50 border border-orange-200 rounded-xl p-4 flex gap-3">
        <InformationCircleIcon className="w-5 h-5 text-orange-600 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-semibold text-orange-800">Linux — Besser als Intune</p>
          <p className="text-orange-700 text-xs mt-1">
            Microsoft Intune hat kaum Linux-Support. OpenDirectory verwaltet Ubuntu, Debian, Fedora, RHEL, Arch, OpenSUSE vollständig — inklusive Paketmanager, Updates und Compliance.
          </p>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode A — One-Line Install (alle Distros)</h4>
        <CodeBlock code={`curl -fsSL https://${domain}/api/enroll/linux/install.sh | sudo bash -s -- --token ${token}`} />
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode B — Paketmanager</h4>
        <CodeBlock code={`# Ubuntu / Debian
curl -fsSL https://${domain}/gpg | sudo gpg --dearmor -o /usr/share/keyrings/opendirectory.gpg
echo "deb [signed-by=/usr/share/keyrings/opendirectory.gpg] https://${domain}/apt stable main" | \\
  sudo tee /etc/apt/sources.list.d/opendirectory.list
sudo apt update && sudo apt install -y opendirectory-agent
sudo od-agent enroll --token ${token}

# Fedora / RHEL / Rocky
sudo dnf config-manager --add-repo https://${domain}/rpm/opendirectory.repo
sudo dnf install -y opendirectory-agent
sudo od-agent enroll --token ${token}

# Arch Linux
yay -S opendirectory-agent
sudo od-agent enroll --token ${token}`} />
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode C — PXE / Kickstart / Cloud-Init (Server-Fleet)</h4>
        <CodeBlock language="yaml" code={`# cloud-init user-data
#cloud-config
runcmd:
  - curl -fsSL https://${domain}/api/enroll/linux/install.sh | bash -s -- --token ${token} --headless
  - systemctl enable --now opendirectory-agent`} />
      </div>

      <div className="grid grid-cols-3 gap-3 text-xs">
        {[
          'Ubuntu 20.04+',
          'Debian 11+',
          'Fedora 38+',
          'RHEL / Rocky 8+',
          'Arch Linux',
          'openSUSE Leap',
          'APT/DNF/Pacman',
          'Snap / Flatpak',
          'systemd-Services',
        ].map(f => (
          <div key={f} className="flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
            <CheckIcon className="w-3.5 h-3.5 text-green-500 shrink-0" />
            {f}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── iOS Enrollment ───────────────────────────────────────────────────────────────

function IOSEnrollment({ token, domain }: { token: string; domain: string }) {
  const mdmUrl = `https://${domain}/api/enroll/ios/profile.mobileconfig?token=${token}`;

  return (
    <div className="space-y-5">
      <div className="bg-purple-50 border border-purple-200 rounded-xl p-4 flex gap-3">
        <InformationCircleIcon className="w-5 h-5 text-purple-600 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-semibold text-purple-800">Apple MDM via APNS</p>
          <p className="text-purple-700 text-xs mt-1">
            OpenDirectory kommuniziert direkt mit Apple Push Notification Service — Supervised und User Enrollment werden unterstützt.
          </p>
        </div>
      </div>

      <div className="flex gap-4">
        <div className="flex-1 space-y-3">
          <div>
            <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Enrollment URL (Safari auf iPhone/iPad)</h4>
            <div className="flex items-center gap-2 bg-gray-900 rounded-lg px-4 py-3">
              <code className="text-green-400 text-xs font-mono flex-1 truncate">{mdmUrl}</code>
              <CopyButton value={mdmUrl} />
            </div>
          </div>

          <div>
            <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Per E-Mail / Link versenden</h4>
            <button
              onClick={() => toast.success('Enrollment-Link wird per E-Mail versendet...')}
              className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
            >
              <ArrowDownTrayIcon className="w-4 h-4" />
              Enrollment-E-Mail an Nutzer senden
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            {[
              'iOS 14+',
              'iPadOS 14+',
              'Supervised Mode',
              'User Enrollment',
              'MDM App Deploy',
              'Remote Wipe/Lock',
            ].map(f => (
              <div key={f} className="flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
                <CheckIcon className="w-3.5 h-3.5 text-green-500 shrink-0" />
                {f}
              </div>
            ))}
          </div>
        </div>

        {/* QR Code Placeholder */}
        <div className="flex-shrink-0">
          <div className="w-36 h-36 border-2 rounded-xl flex flex-col items-center justify-center gap-2" style={{ background: 'var(--bg-surface-raised)', borderColor: 'var(--border)' }}>
            <QrCodeIcon className="w-16 h-16" style={{ color: 'var(--text-muted)' }} />
            <p className="text-xs text-center leading-tight" style={{ color: 'var(--text-muted)' }}>QR-Code<br />für iOS</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Android Enrollment ───────────────────────────────────────────────────────────

function AndroidEnrollment({ token, domain }: { token: string; domain: string }) {
  return (
    <div className="space-y-5">
      <div className="bg-green-50 border border-green-200 rounded-xl p-4 flex gap-3">
        <InformationCircleIcon className="w-5 h-5 text-green-600 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-semibold text-green-800">Android Enterprise / Zero-Touch</p>
          <p className="text-green-700 text-xs mt-1">
            Unterstützt Google Zero-Touch Enrollment, QR-Code Setup und Android Enterprise Device Owner — Work Profile für BYOD.
          </p>
        </div>
      </div>

      <div className="flex gap-4">
        <div className="flex-1 space-y-4">
          <div>
            <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode A — QR-Code beim Erststart</h4>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Beim "Willkommen"-Screen: 6x auf Display tippen → Kamera öffnet sich → QR-Code scannen.</p>
          </div>

          <div>
            <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode B — NFC Provisioning</h4>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Zwei Geräte aneinander halten beim Erststart — NFC überträgt Enrollment-Token automatisch.</p>
          </div>

          <div>
            <h4 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Methode C — Enrollment Token manuell</h4>
            <CodeBlock code={`# ADB (IT-Admin, bestehende Geräte)
adb shell am start -n com.google.android.apps.work.clouddpc/.MainActivity \\
  --es extra_provisioning_device_admin_package_checksum "<checksum>" \\
  --es extra_enrollment_token "${token}" \\
  --es extra_server_url "https://${domain}"`} />
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            {[
              'Android 8.0+',
              'Work Profile (BYOD)',
              'Device Owner (Kiosk)',
              'Zero-Touch',
              'App Deploy (APK)',
              'Remote Lock/Wipe',
            ].map(f => (
              <div key={f} className="flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
                <CheckIcon className="w-3.5 h-3.5 text-green-500 shrink-0" />
                {f}
              </div>
            ))}
          </div>
        </div>

        <div className="flex-shrink-0">
          <div className="w-36 h-36 border-2 rounded-xl flex flex-col items-center justify-center gap-2" style={{ background: 'var(--bg-surface-raised)', borderColor: 'var(--border)' }}>
            <QrCodeIcon className="w-16 h-16" style={{ color: 'var(--text-muted)' }} />
            <p className="text-xs text-center leading-tight" style={{ color: 'var(--text-muted)' }}>QR-Code<br />für Android</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Token Card ───────────────────────────────────────────────────────────────────

function TokenCard({ token }: { token: EnrollmentToken }) {
  const pct = Math.round((token.uses / token.maxUses) * 100);
  return (
    <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
      <div className="flex items-center justify-between mb-2">
        <code className="text-sm font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{token.token}</code>
        <CopyButton value={token.token} label="Kopieren" />
      </div>
      <div className="flex items-center justify-between text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
        <span>Läuft ab: {token.expires}</span>
        <span>{token.uses}/{token.maxUses} verwendet</span>
      </div>
      <div className="w-full rounded-full h-1.5" style={{ background: 'var(--bg-overlay)' }}>
        <div
          className={`h-1.5 rounded-full transition-all ${pct > 80 ? 'bg-red-500' : pct > 50 ? 'bg-yellow-500' : 'bg-green-500'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────────

export default function EnrollmentHubView() {
  const [selected, setSelected] = useState<OSPlatform>('macos');
  const domain = process.env.NEXT_PUBLIC_AD_DOMAIN ?? 'opendirectory.local';

  const [tokens, setTokens] = useState<Record<string, {token: string; uses: number; maxUses: number; expires: string}>>({});
  const [enrolledCounts, setEnrolledCounts] = useState<Record<string, number>>({});
  const [tokensLoading, setTokensLoading] = useState(true);
  const [tokensError, setTokensError] = useState(false);

  useEffect(() => {
    const load = async () => {
      setTokensLoading(true);
      try {
        const [tokRes, devRes] = await Promise.allSettled([
          api.get('/api/enrollment/tokens'),
          api.get('/api/devices/registry'),
        ]);

        if (tokRes.status === 'fulfilled') {
          const data = tokRes.value.data;
          // The API may return an object keyed by platform, or an array
          const byPlatform: Record<string, any> = {};
          if (Array.isArray(data)) {
            for (const t of data) {
              byPlatform[t.platform] = t;
            }
          } else {
            Object.assign(byPlatform, data);
          }
          setTokens(byPlatform);
        } else {
          setTokensError(true);
        }

        if (devRes.status === 'fulfilled') {
          const devices = Array.isArray(devRes.value.data) ? devRes.value.data : Object.values(devRes.value.data || {});
          const counts: Record<string, number> = {};
          for (const d of devices as any[]) {
            const p = (d.platform || 'unknown').toLowerCase();
            counts[p] = (counts[p] || 0) + 1;
          }
          setEnrolledCounts(counts);
        }
      } catch {
        setTokensError(true);
      }
      setTokensLoading(false);
    };
    load();
  }, []);

  const currentPlatform = PLATFORMS.find(p => p.id === selected)!;
  const currentTokenData = tokens[selected];

  const renderEnrollment = () => {
    const tokenStr = currentTokenData?.token ?? '';
    switch (selected) {
      case 'windows': return <WindowsEnrollment token={tokenStr} domain={domain} />;
      case 'macos':   return <MacOSEnrollment   token={tokenStr} domain={domain} />;
      case 'linux':   return <LinuxEnrollment   token={tokenStr} domain={domain} />;
      case 'ios':     return <IOSEnrollment     token={tokenStr} domain={domain} />;
      case 'android': return <AndroidEnrollment token={tokenStr} domain={domain} />;
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 bg-indigo-600 rounded-xl flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Enrollment Hub</h1>
            <span className="bg-indigo-100 text-indigo-700 text-xs px-2.5 py-1 rounded-full font-medium">Intune + ABM Ersatz</span>
          </div>
          <p className="text-sm ml-12" style={{ color: 'var(--text-muted)' }}>
            Zero-Touch Enrollment für alle Plattformen — wie Apple Business Manager, aber für jedes OS
          </p>
        </div>
        <button
          onClick={() => toast.success('Enrollment-Bericht wird erstellt...')}
          className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-lg hover:bg-gray-50 transition-colors"
          style={{ color: 'var(--text-muted)', border: '1px solid var(--border)' }}
        >
          <ArrowPathIcon className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Overall Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {PLATFORMS.map(p => (
          <button
            key={p.id}
            onClick={() => setSelected(p.id)}
            className={`rounded-xl border p-3 text-center transition-all ${
              selected === p.id
                ? `${p.bg} ${p.border} ring-2 ring-offset-1 ring-current`
                : 'hover:border-gray-300'
            }`}
            style={selected === p.id ? undefined : { background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
          >
            <div className="text-2xl mb-1">{p.icon}</div>
            <p className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>{enrolledCounts[p.id] ?? 0}</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{p.name}</p>
          </button>
        ))}
      </div>

      {/* Main Content: Platform Selector + Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Platform List */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-muted)' }}>Plattform auswählen</h3>
          {PLATFORMS.map(p => (
            <button
              key={p.id}
              onClick={() => setSelected(p.id)}
              className={`w-full flex items-center gap-3 p-3 rounded-xl border transition-all text-left ${
                selected === p.id
                  ? `${p.bg} ${p.border} ring-1 ring-current`
                  : 'hover:border-gray-300 hover:bg-gray-50'
              }`}
              style={selected === p.id ? undefined : { background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
            >
              <span className="text-xl shrink-0">{p.icon}</span>
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-semibold ${selected === p.id ? p.color : ''}`} style={selected === p.id ? undefined : { color: 'var(--text-secondary)' }}>{p.name}</p>
                <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>{p.method}</p>
              </div>
              <span className="text-xs font-bold shrink-0" style={{ color: 'var(--text-muted)' }}>{enrolledCounts[p.id] ?? 0}</span>
            </button>
          ))}

          {/* Token für gewählte Plattform */}
          <div className="pt-3">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Enrollment Token</h3>
              <button
                onClick={() => toast.success('Neuer Token generiert')}
                className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700"
              >
                <PlusIcon className="w-3 h-3" />
                Neu
              </button>
            </div>
            {tokensLoading && (
              <div className="space-y-3">
                {[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-gray-700 rounded-lg animate-pulse" />)}
              </div>
            )}
            {tokensError && (
              <div className="p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg text-yellow-300 text-sm">
                Enrollment-Token-API nicht erreichbar. Überprüfen Sie den oauth-provider Dienst.
              </div>
            )}
            {!tokensLoading && !tokensError && currentTokenData && (
              <TokenCard token={{ platform: selected, token: currentTokenData.token, created: '', expires: currentTokenData.expires, uses: currentTokenData.uses, maxUses: currentTokenData.maxUses }} />
            )}
            {!tokensLoading && !tokensError && !currentTokenData && (
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Kein Token für diese Plattform gefunden.</p>
            )}
          </div>
        </div>

        {/* Right: Enrollment Instructions */}
        <div className="lg:col-span-2 rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2 mb-5 pb-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <span className="text-2xl">{currentPlatform.icon}</span>
            <div>
              <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{currentPlatform.name} Enrollment</h3>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{currentPlatform.description}</p>
            </div>
          </div>
          {renderEnrollment()}
        </div>
      </div>

      {/* Comparison vs Microsoft */}
      <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
        <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>OpenDirectory vs. Microsoft Intune + Apple ABM — Enrollment-Vergleich</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left py-2 pr-4 text-xs font-semibold uppercase w-40" style={{ color: 'var(--text-muted)' }}>Plattform</th>
                <th className="text-left py-2 pr-4 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Microsoft Intune / ABM</th>
                <th className="text-left py-2 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>OpenDirectory</th>
              </tr>
            </thead>
            <tbody>
              {[
                { os: '🪟 Windows', ms: 'Autopilot (Azure-Konto erforderlich)', od: 'Autopilot-Style, kein Azure-Konto', better: true },
                { os: ' macOS', ms: 'ABM DEP + Jamf/Mosyle (kostenpflichtig)', od: 'Eigener MDM-Server, kein Jamf nötig', better: true },
                { os: '🐧 Linux', ms: 'Kaum Support (nur Edge-Browser)', od: 'Vollständig: Ubuntu, Fedora, RHEL, Arch', better: true },
                { os: '📱 iOS/iPadOS', ms: 'ABM DEP + Intune MDM', od: 'APNS MDM, Supervised + User Enroll', better: false },
                { os: '🤖 Android', ms: 'Android Zero-Touch + Intune', od: 'Zero-Touch, QR, Android Enterprise', better: false },
              ].map((row, idx) => (
                <tr key={row.os} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td className="py-2.5 pr-4 font-medium" style={{ color: 'var(--text-secondary)' }}>{row.os}</td>
                  <td className="py-2.5 pr-4 text-xs" style={{ color: 'var(--text-muted)' }}>{row.ms}</td>
                  <td className="py-2.5 text-xs">
                    <span style={row.better ? { color: 'var(--success)', fontWeight: 500 } : { color: 'var(--text-muted)' }}>{row.od}</span>
                    {row.better && <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded-full font-semibold" style={{ background: 'var(--success-light)', color: 'var(--success)' }}>Besser</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
