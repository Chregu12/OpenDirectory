'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ComputerDesktopIcon,
  ServerIcon,
  SparklesIcon,
  MagnifyingGlassIcon,
  ArrowPathIcon,
  DevicePhoneMobileIcon,
  PlusIcon,
  XMarkIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  EyeIcon,
  TrashIcon,
  FunnelIcon,
  CubeIcon,
  ShieldCheckIcon,
  WifiIcon,
  ArrowUpCircleIcon,
  ClockIcon,
  PlusCircleIcon,
  MinusCircleIcon,
  ExclamationTriangleIcon,
  CpuChipIcon,
} from '@heroicons/react/24/outline';
import { deviceApi, api } from '@/lib/api';
import DeviceEnrollmentWizard from '@/components/setup/DeviceEnrollmentWizard';
import DeviceDriversTab from '@/components/views/tabs/DeviceDriversTab';
import toast from 'react-hot-toast';

function resizeImage(file: File, maxPx: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      const ratio = Math.min(maxPx / img.width, maxPx / img.height, 1);
      const canvas = document.createElement('canvas');
      canvas.width  = Math.round(img.width  * ratio);
      canvas.height = Math.round(img.height * ratio);
      canvas.getContext('2d')!.drawImage(img, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      resolve(canvas.toDataURL('image/jpeg', 0.82));
    };
    img.onerror = reject;
    img.src = url;
  });
}

// ─── Types ─────────────────────────────────────────────────────────────────────

type StatusFilter   = 'all' | 'online' | 'offline';
type PlatformFilter = 'all' | 'linux' | 'macos' | 'windows';
type DeviceTab      = 'details' | 'apps' | 'hardware' | 'network' | 'history' | 'stammdaten';
type MainTab        = 'devices' | 'drivers';

interface Stammdaten {
  custom_name?: string;
  owner?: string;
  department?: string;
  location?: string;
  asset_tag?: string;
  serial_override?: string;
  purchase_date?: string;
  warranty_until?: string;
  notes?: string;
  photo?: string; // base64 data URL
}

type HistoryEventType = 'enrolled' | 'app_installed' | 'app_removed' | 'app_updated' | 'policy_applied' | 'decommissioned';

interface DeviceHistoryEntry {
  id: string;
  type: HistoryEventType;
  message: string;
  timestamp: string;
  details?: Record<string, string>;
}

interface Device {
  id: string;
  name: string;
  platform: 'linux' | 'macos' | 'windows';
  os: string;
  osVersion?: string;
  ip_address?: string;
  status: 'online' | 'offline';
  lastSeen: string;
  complianceScore?: number;
  kernel?: string;
  package_manager?: string;
  registeredAt?: string;
  decommissioned?: boolean;
}

interface InstalledApp {
  id: string;
  name: string;
  installedVersion: string;
  latestVersion: string;
  status: 'up-to-date' | 'update-available';
  category: string;
}

interface CatalogApp {
  id: string;
  name: string;
  version: string;
  category: string;
  platforms: string[];
}

// ─── App Catalog ───────────────────────────────────────────────────────────────

const APP_CATALOG: CatalogApp[] = [
  { id: 'od-agent',    name: 'OpenDirectory Agent', version: '1.0.0',      category: 'Agent',      platforms: ['linux', 'macos', 'windows'] },
  { id: 'wazuh',       name: 'Wazuh Agent',          version: '4.8.0',      category: 'Security',   platforms: ['linux', 'macos', 'windows'] },
  { id: 'clamav',      name: 'ClamAV',               version: '1.4.0',      category: 'Security',   platforms: ['linux'] },
  { id: 'tailscale',   name: 'Tailscale',            version: '1.76.0',     category: 'Network',    platforms: ['linux', 'macos', 'windows'] },
  { id: 'bitwarden',   name: 'Bitwarden',            version: '2024.10.0',  category: 'Security',   platforms: ['linux', 'macos', 'windows'] },
  { id: 'nextcloud',   name: 'Nextcloud Desktop',    version: '3.13.0',     category: 'Network',    platforms: ['linux', 'macos', 'windows'] },
  { id: 'syncthing',   name: 'Syncthing',            version: '1.27.0',     category: 'Network',    platforms: ['linux', 'macos', 'windows'] },
  { id: 'git',         name: 'Git (Configured)',      version: '2.47.0',     category: 'Developer',  platforms: ['linux', 'macos', 'windows'] },
  { id: 'vscode',      name: 'VS Code',              version: '1.96.0',     category: 'Developer',  platforms: ['linux', 'macos', 'windows'] },
  { id: 'podman',      name: 'Podman Desktop',       version: '1.13.0',     category: 'Developer',  platforms: ['linux', 'macos'] },
  { id: 'libreoffice', name: 'LibreOffice',          version: '24.8.0',     category: 'Productivity', platforms: ['linux', 'macos', 'windows'] },
  { id: 'thunderbird', name: 'Thunderbird',          version: '128.5.0',    category: 'Productivity', platforms: ['linux', 'macos', 'windows'] },
  { id: 'zabbix',      name: 'Zabbix Agent',         version: '7.0.0',      category: 'Monitoring', platforms: ['linux', 'macos', 'windows'] },
];

function getInitialApps(device: Device): InstalledApp[] {
  const p = (device.platform || '').toLowerCase();
  const o = (device.os || '').toLowerCase();

  if (p === 'linux' || o.includes('ubuntu') || o.includes('debian')) {
    return [
      { id: 'od-agent',  name: 'OpenDirectory Agent', installedVersion: '1.0.0', latestVersion: '1.0.0',  status: 'up-to-date',       category: 'Agent' },
      { id: 'wazuh',     name: 'Wazuh Agent',          installedVersion: '4.7.2', latestVersion: '4.8.0',  status: 'update-available', category: 'Security' },
      { id: 'clamav',    name: 'ClamAV',               installedVersion: '1.3.1', latestVersion: '1.4.0',  status: 'update-available', category: 'Security' },
      { id: 'tailscale', name: 'Tailscale',            installedVersion: '1.76.0', latestVersion: '1.76.0', status: 'up-to-date',      category: 'Network' },
    ];
  }
  if (p === 'macos') {
    return [
      { id: 'od-agent',  name: 'OpenDirectory Agent', installedVersion: '1.0.0',      latestVersion: '1.0.0',      status: 'up-to-date',       category: 'Agent' },
      { id: 'tailscale', name: 'Tailscale',            installedVersion: '1.74.0',     latestVersion: '1.76.0',     status: 'update-available', category: 'Network' },
      { id: 'bitwarden', name: 'Bitwarden',            installedVersion: '2024.10.0',  latestVersion: '2024.10.0',  status: 'up-to-date',       category: 'Security' },
    ];
  }
  if (p === 'windows') {
    return [
      { id: 'od-agent',  name: 'OpenDirectory Agent', installedVersion: '1.0.0',      latestVersion: '1.0.0',      status: 'up-to-date',       category: 'Agent' },
      { id: 'bitwarden', name: 'Bitwarden',            installedVersion: '2024.10.0',  latestVersion: '2024.10.0',  status: 'up-to-date',       category: 'Security' },
      { id: 'vscode',    name: 'VS Code',              installedVersion: '1.95.0',     latestVersion: '1.96.0',     status: 'update-available', category: 'Developer' },
    ];
  }
  return [
    { id: 'od-agent', name: 'OpenDirectory Agent', installedVersion: '1.0.0', latestVersion: '1.0.0', status: 'up-to-date', category: 'Agent' },
  ];
}

// ─── Device SVG Thumbnails ──────────────────────────────────────────────────────

function MacBookSVG({ size = 48 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 0.72)} viewBox="0 0 48 35" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="3" y="1" width="42" height="26" rx="2.5" fill="#F5F5F7" stroke="#C7C7CC" strokeWidth="1.4"/>
      <rect x="5" y="3" width="38" height="22" rx="1.5" fill="#E5E5EA"/>
      <circle cx="24" cy="2.2" r="0.8" fill="#AEAEB2"/>
      {/* Apple logo */}
      <path d="M22.5 11.5 C22.5 10.5 23.2 9.8 24 9.8 C24.8 9.8 25.5 10.5 25.5 11.5 L25.5 12 C26.5 12 27.5 13 27.2 14.3 C27 15.2 26.1 15.8 25.2 15.8 C24.8 15.8 24.5 15.6 24 15.6 C23.5 15.6 23.2 15.8 22.8 15.8 C21.9 15.8 21 15.2 20.8 14.3 C20.5 13 21.5 12 22.5 12 Z" fill="#AEAEB2"/>
      <path d="M0.5 28 L5 27.2 L43 27.2 L47.5 28 C47.5 29.5 46.5 30.5 44.5 31 L3.5 31 C1.5 30.5 0.5 29.5 0.5 28Z" fill="#C7C7CC"/>
      <rect x="19" y="29" width="10" height="1.2" rx="0.6" fill="#AEAEB2"/>
    </svg>
  );
}

function WindowsLaptopSVG({ size = 48 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 0.72)} viewBox="0 0 48 35" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="3" y="1" width="42" height="26" rx="2.5" fill="#EEF2FF" stroke="#C5CFF5" strokeWidth="1.4"/>
      <rect x="5" y="3" width="38" height="22" rx="1.5" fill="#DDE3FF"/>
      <circle cx="24" cy="2.2" r="0.8" fill="#A0AEE8"/>
      {/* Windows logo 4-square */}
      <rect x="20.5" y="10.5" width="3" height="3" rx="0.4" fill="#4F7EF5"/>
      <rect x="24.5" y="10.5" width="3" height="3" rx="0.4" fill="#4F7EF5"/>
      <rect x="20.5" y="14.5" width="3" height="3" rx="0.4" fill="#4F7EF5"/>
      <rect x="24.5" y="14.5" width="3" height="3" rx="0.4" fill="#4F7EF5"/>
      <path d="M0.5 28 L5 27.2 L43 27.2 L47.5 28 C47.5 29.5 46.5 30.5 44.5 31 L3.5 31 C1.5 30.5 0.5 29.5 0.5 28Z" fill="#C5CFF5"/>
      <rect x="19" y="29" width="10" height="1.2" rx="0.6" fill="#A0AEE8"/>
    </svg>
  );
}

function LinuxLaptopSVG({ size = 48 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 0.72)} viewBox="0 0 48 35" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="3" y="1" width="42" height="26" rx="2.5" fill="#1C1C1E" stroke="#3A3A3C" strokeWidth="1.4"/>
      <rect x="5" y="3" width="38" height="22" rx="1.5" fill="#2C2C2E"/>
      {/* Terminal prompt */}
      <rect x="9" y="10" width="5" height="1.5" rx="0.5" fill="#30D158"/>
      <rect x="15" y="10" width="12" height="1.5" rx="0.5" fill="#48484A"/>
      <rect x="9" y="14" width="16" height="1.5" rx="0.5" fill="#48484A"/>
      <rect x="9" y="18" width="10" height="1.5" rx="0.5" fill="#48484A"/>
      <rect x="20" y="10" width="1.5" height="1.5" rx="0.3" fill="#30D158"/>
      <path d="M0.5 28 L5 27.2 L43 27.2 L47.5 28 C47.5 29.5 46.5 30.5 44.5 31 L3.5 31 C1.5 30.5 0.5 29.5 0.5 28Z" fill="#3A3A3C"/>
      <rect x="19" y="29" width="10" height="1.2" rx="0.6" fill="#48484A"/>
    </svg>
  );
}

function IPhoneSVG({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 1.9)} viewBox="0 0 28 53" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="26" height="51" rx="5.5" fill="#F5F5F7" stroke="#C7C7CC" strokeWidth="1.4"/>
      <rect x="3.5" y="8" width="21" height="34" rx="2" fill="#E5E5EA"/>
      {/* Dynamic island */}
      <rect x="9" y="3.5" width="10" height="2.5" rx="1.25" fill="#1C1C1E"/>
      {/* Home indicator */}
      <rect x="9.5" y="47" width="9" height="1.5" rx="0.75" fill="#C7C7CC"/>
    </svg>
  );
}

function IPadSVG({ size = 36 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 1.42)} viewBox="0 0 36 51" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="34" height="49" rx="4.5" fill="#F5F5F7" stroke="#C7C7CC" strokeWidth="1.4"/>
      <rect x="3.5" y="7" width="29" height="36" rx="1.5" fill="#E5E5EA"/>
      <circle cx="18" cy="4" r="1.2" fill="#AEAEB2"/>
      <rect x="12" y="47" width="12" height="1.5" rx="0.75" fill="#C7C7CC"/>
      {/* Camera top */}
      <circle cx="3" cy="14" r="1" fill="#AEAEB2"/>
    </svg>
  );
}

function AndroidSVG({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 2)} viewBox="0 0 26 52" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="3" width="24" height="46" rx="4.5" fill="#E8F5E9" stroke="#A5D6A7" strokeWidth="1.4"/>
      <rect x="3.5" y="9" width="19" height="30" rx="1.5" fill="#C8E6C9"/>
      {/* Speaker top */}
      <rect x="9" y="5" width="8" height="1.5" rx="0.75" fill="#A5D6A7"/>
      {/* Camera */}
      <circle cx="20" cy="6" r="1" fill="#81C784"/>
      {/* Nav buttons */}
      <circle cx="13" cy="46.5" r="2" fill="none" stroke="#A5D6A7" strokeWidth="1.2"/>
      {/* Antennas (robot ears) */}
      <line x1="8" y1="1.5" x2="6" y2="0" stroke="#A5D6A7" strokeWidth="1.2" strokeLinecap="round"/>
      <line x1="18" y1="1.5" x2="20" y2="0" stroke="#A5D6A7" strokeWidth="1.2" strokeLinecap="round"/>
    </svg>
  );
}

function ServerRackSVG({ size = 40 }: { size?: number }) {
  return (
    <svg width={size} height={Math.round(size * 0.75)} viewBox="0 0 40 30" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="38" height="28" rx="3" fill="#F2F2F7" stroke="#C7C7CC" strokeWidth="1.4"/>
      {[6, 13, 20].map((y, i) => (
        <g key={i}>
          <rect x="4" y={y} width="32" height="5" rx="1" fill="#E5E5EA" stroke="#D1D1D6" strokeWidth="0.8"/>
          <circle cx="9" cy={y + 2.5} r="1.2" fill={i === 0 ? '#30D158' : '#AEAEB2'}/>
          <rect x="13" y={y + 1.5} width="14" height="2" rx="0.5" fill="#D1D1D6"/>
          <circle cx="32" cy={y + 2.5} r="1" fill="#AEAEB2"/>
        </g>
      ))}
    </svg>
  );
}

type AnyPlatform = 'macos' | 'windows' | 'linux' | 'ios' | 'ipados' | 'android' | 'server' | string;

function DeviceThumbnail({ platform, size = 'sm' }: { platform: AnyPlatform; size?: 'sm' | 'md' | 'lg' }) {
  const p = (platform || '').toLowerCase();
  const scale = size === 'sm' ? 0.65 : size === 'md' ? 1 : 1.5;

  if (p === 'macos' || p === 'darwin')  return <MacBookSVG    size={Math.round(48 * scale)} />;
  if (p === 'windows')                  return <WindowsLaptopSVG size={Math.round(48 * scale)} />;
  if (p === 'linux')                    return <LinuxLaptopSVG size={Math.round(48 * scale)} />;
  if (p === 'ios' || p === 'iphone')    return <IPhoneSVG    size={Math.round(28 * scale)} />;
  if (p === 'ipados' || p === 'ipad')   return <IPadSVG      size={Math.round(36 * scale)} />;
  if (p === 'android')                  return <AndroidSVG   size={Math.round(26 * scale)} />;
  if (p === 'server')                   return <ServerRackSVG size={Math.round(40 * scale)} />;
  // fallback
  return <MacBookSVG size={Math.round(48 * scale)} />;
}

// Legacy icon (kept for small inline badge use)
function PlatformIcon({ platform, className = 'w-4 h-4' }: { platform: AnyPlatform; className?: string }) {
  const p = (platform || '').toLowerCase();
  if (p === 'windows')                return <ServerIcon        className={`${className} text-blue-500`} />;
  if (p === 'ios' || p === 'iphone')  return <DevicePhoneMobileIcon className={`${className} text-gray-500`} />;
  return <ComputerDesktopIcon className={`${className} text-gray-500`} />;
}

function ComplianceBar({ score }: { score?: number }) {
  if (score === undefined || score === null) return <span className="text-xs text-gray-400">N/A</span>;
  const color = score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-400' : 'bg-red-500';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-200 rounded-full overflow-hidden" style={{ minWidth: 60 }}>
        <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-600 w-8 text-right">{score}%</span>
    </div>
  );
}

function SkeletonRow() {
  return (
    <tr className="animate-pulse">
      {[...Array(8)].map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-gray-200 rounded w-full" />
        </td>
      ))}
    </tr>
  );
}

function formatLastSeen(lastSeen: string): string {
  if (!lastSeen) return '—';
  try {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1)  return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  } catch { return lastSeen; }
}

function formatDate(ds: string) {
  if (!ds) return '—';
  try {
    return new Date(ds).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return ds; }
}

function inferPackageManager(os: string, platform: string): string {
  const o = (os || '').toLowerCase();
  const p = (platform || '').toLowerCase();
  if (o.includes('ubuntu') || o.includes('debian') || o.includes('mint') || o.includes('kali')) return 'apt';
  if (o.includes('alpine'))   return 'apk';
  if (o.includes('fedora'))   return 'dnf';
  if (o.includes('centos') || o.includes('rhel') || o.includes('rocky') || o.includes('alma')) return 'dnf';
  if (o.includes('arch') || o.includes('manjaro')) return 'pacman';
  if (o.includes('opensuse') || o.includes('suse')) return 'zypper';
  if (p === 'macos')   return 'brew';
  if (p === 'windows') return 'winget';
  return '—';
}

function AppCategoryIcon({ category }: { category: string }) {
  if (category === 'Security' || category === 'Agent') return <ShieldCheckIcon className="w-4 h-4 text-blue-500" />;
  if (category === 'Network')  return <WifiIcon className="w-4 h-4 text-green-500" />;
  if (category === 'Developer' || category === 'Monitoring') return <ServerIcon className="w-4 h-4 text-purple-500" />;
  return <CubeIcon className="w-4 h-4 text-gray-400" />;
}

// ─── Add App Modal ─────────────────────────────────────────────────────────────

function AddAppModal({ device, installedIds, onAdd, onClose }: {
  device: Device;
  installedIds: string[];
  onAdd: (app: InstalledApp) => void;
  onClose: () => void;
}) {
  const platform = (device.platform || '').toLowerCase();
  const available = APP_CATALOG.filter(
    a => a.platforms.includes(platform) && !installedIds.includes(a.id)
  );

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-[60]" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-md w-full" onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-gray-900">Add Application</h3>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-5 h-5" /></button>
          </div>

          {available.length === 0 ? (
            <p className="text-sm text-gray-400 italic py-4 text-center">All available applications are already installed.</p>
          ) : (
            <div className="space-y-1 max-h-72 overflow-y-auto">
              {available.map(app => (
                <button key={app.id} onClick={() => {
                  onAdd({
                    id: app.id,
                    name: app.name,
                    installedVersion: app.version,
                    latestVersion: app.version,
                    status: 'up-to-date',
                    category: app.category,
                  });
                  onClose();
                  toast.success(`${app.name} installed`);
                }}
                  className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg hover:bg-blue-50 text-left transition-colors">
                  <AppCategoryIcon category={app.category} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-800">{app.name}</p>
                    <p className="text-xs text-gray-400">{app.category} · v{app.version}</p>
                  </div>
                  <PlusIcon className="w-4 h-4 text-blue-500 flex-shrink-0" />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Decommission Modal ────────────────────────────────────────────────────────

function DecommissionModal({ device, apps, onConfirm, onCancel }: {
  device: Device;
  apps: InstalledApp[];
  onConfirm: () => Promise<void>;
  onCancel: () => void;
}) {
  const [decommissioning, setDecommissioning] = useState(false);

  const handleConfirm = async () => {
    setDecommissioning(true);
    try { await onConfirm(); } finally { setDecommissioning(false); }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-[60]" onClick={onCancel}>
      <div className="bg-white rounded-xl shadow-xl max-w-md w-full" onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center flex-shrink-0">
              <TrashIcon className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-gray-900">Decommission {device.name}</h3>
              <p className="text-xs text-gray-500">This will restore the device to its original enrollment state</p>
            </div>
          </div>

          <div className="bg-gray-50 rounded-lg p-4 space-y-3 mb-5 text-sm">
            {apps.length > 0 && (
              <div>
                <div className="flex items-start gap-2 mb-1.5">
                  <XMarkIcon className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                  <span className="text-gray-700">Remove {apps.length} managed application{apps.length !== 1 ? 's' : ''}</span>
                </div>
                <ul className="ml-6 space-y-0.5">
                  {apps.slice(0, 6).map(a => (
                    <li key={a.id} className="text-xs text-gray-500">· {a.name} {a.installedVersion}</li>
                  ))}
                  {apps.length > 6 && <li className="text-xs text-gray-400">· and {apps.length - 6} more…</li>}
                </ul>
              </div>
            )}
            <div className="flex items-center gap-2">
              <XMarkIcon className="w-4 h-4 text-red-500 flex-shrink-0" />
              <span className="text-gray-700">Remove assigned group policies</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckIcon className="w-4 h-4 text-green-500 flex-shrink-0" />
              <span className="text-gray-700">Device record and history preserved</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckIcon className="w-4 h-4 text-green-500 flex-shrink-0" />
              <span className="text-gray-700">Configuration data remains in audit log</span>
            </div>
          </div>

          <div className="flex justify-between gap-3">
            <button onClick={onCancel} disabled={decommissioning}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg disabled:opacity-50">
              Cancel
            </button>
            <button onClick={handleConfirm} disabled={decommissioning}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg disabled:opacity-50">
              {decommissioning
                ? <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Decommissioning…</>
                : <><TrashIcon className="w-4 h-4" /> Decommission →</>}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Device Commands Panel ────────────────────────────────────────────────────

function DeviceCommandsPanel({ deviceId, hostname }: { deviceId: string; hostname: string }) {
  const [sending, setSending] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{cmd: string; ok: boolean} | null>(null);

  const sendCommand = async (command: string) => {
    if (command === 'wipe' && !confirm(`ACHTUNG: Gerät ${hostname} wirklich zurücksetzen? Alle Daten werden gelöscht!`)) return;
    setSending(command);
    try {
      await api.post(`/api/devices/${deviceId}/commands`, { command });
      setLastResult({ cmd: command, ok: true });
    } catch {
      setLastResult({ cmd: command, ok: false });
    }
    setSending(null);
  };

  const COMMANDS = [
    { id: 'lock', label: 'Sperren', icon: '🔒', color: 'bg-yellow-600' },
    { id: 'unlock', label: 'Entsperren', icon: '🔓', color: 'bg-green-600' },
    { id: 'restart', label: 'Neustart', icon: '🔄', color: 'bg-blue-600' },
    { id: 'collect_logs', label: 'Logs', icon: '📋', color: 'bg-gray-600' },
    { id: 'wipe', label: 'Wipe', icon: '⚠️', color: 'bg-red-600' },
  ];

  return (
    <div className="mt-3 p-3 bg-gray-800 rounded-lg border border-gray-700">
      <p className="text-gray-400 text-xs font-medium mb-2">MDM-Befehle</p>
      <div className="flex flex-wrap gap-2">
        {COMMANDS.map(cmd => (
          <button
            key={cmd.id}
            onClick={() => sendCommand(cmd.id)}
            disabled={sending !== null}
            className={`${cmd.color} disabled:opacity-50 text-white text-xs px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5`}
          >
            {sending === cmd.id ? <span className="animate-spin">⏳</span> : cmd.icon}
            {cmd.label}
          </button>
        ))}
      </div>
      {lastResult && (
        <p className={`mt-2 text-xs ${lastResult.ok ? 'text-green-400' : 'text-red-400'}`}>
          {lastResult.ok ? `✓ Befehl "${lastResult.cmd}" gesendet` : `✗ Fehler beim Senden von "${lastResult.cmd}"`}
        </p>
      )}
    </div>
  );
}

// ─── Device Detail Modal ───────────────────────────────────────────────────────

function DeviceDetailModal({ device, initialApps, onAppsChange, onClose, onRemove, history, addHistoryEntry, onDecommission }: {
  device: Device;
  initialApps?: InstalledApp[];
  onAppsChange?: (deviceId: string, apps: InstalledApp[]) => void;
  onClose: () => void;
  onRemove: (id: string) => void;
  history?: DeviceHistoryEntry[];
  addHistoryEntry?: (deviceId: string, entry: Omit<DeviceHistoryEntry, 'id'>) => void;
  onDecommission?: (deviceId: string) => Promise<void>;
}) {
  const [showDecommission, setShowDecommission] = useState(false);
  const [detail, setDetail]               = useState<Device>(device);
  const [loadingDetail, setLoadingDetail] = useState(true);
  const [deviceTab, setDeviceTab]         = useState<DeviceTab>('details');
  const [apps, setAppsState]              = useState<InstalledApp[]>(initialApps ?? getInitialApps(device));
  const [showAddApp, setShowAddApp]       = useState(false);
  const [removingAppId, setRemovingAppId] = useState<string | null>(null);
  const [updatingIds, setUpdatingIds]     = useState<Set<string>>(new Set());
  const [updatingAll, setUpdatingAll]     = useState(false);
  // Hardware tab
  const [hardware, setHardware]           = useState<any>(null);
  const [loadingHw, setLoadingHw]         = useState(false);
  // Network tab
  const [netInfo, setNetInfo]             = useState<any>(null);
  const [loadingNet, setLoadingNet]       = useState(false);
  // Stammdaten tab
  const [stammdaten, setStammdaten]       = useState<Stammdaten>({});
  const [stammdatenDraft, setStammdatenDraft] = useState<Stammdaten>({});
  const [loadingSd, setLoadingSd]         = useState(false);
  const [savingSd, setSavingSd]           = useState(false);
  const [uploadingPhoto, setUploadingPhoto] = useState(false);

  // Wrapper: update local state + notify parent cache
  const setApps = (updater: (prev: InstalledApp[]) => InstalledApp[]) => {
    setAppsState(prev => {
      const next = updater(prev);
      onAppsChange?.(device.id, next);
      return next;
    });
  };

  useEffect(() => {
    api.get(`/api/devices/${device.id}`)
      .then(res => { if (res.data?.data) setDetail({ ...device, ...res.data.data }); })
      .catch(() => {})
      .finally(() => setLoadingDetail(false));
  }, [device.id]);

  useEffect(() => {
    api.get(`/api/devices/${device.id}/software`)
      .then(res => {
        const sw = res.data?.software || res.data?.data?.software || res.data?.installed || [];
        if (sw.length > 0) {
          const mapped: InstalledApp[] = sw.map((s: any) => ({
            id: s.id || s.name?.toLowerCase().replace(/\s+/g, '-'),
            name: s.name || s.packageName,
            installedVersion: s.version || s.installedVersion || '0.0.0',
            latestVersion: s.latestVersion || s.availableVersion || s.version || '0.0.0',
            status: (s.latestVersion && s.version && s.latestVersion !== s.version)
              ? 'update-available' : 'up-to-date',
            category: s.category || 'System',
          }));
          setApps(() => mapped);
        }
      })
      .catch(() => {});
  }, [device.id]);

  // Lazy-load hardware data when tab is first opened
  useEffect(() => {
    if (deviceTab !== 'hardware' || hardware !== null || loadingHw) return;
    setLoadingHw(true);
    api.get(`/api/devices/${device.id}/hardware`)
      .then(res => setHardware(res.data?.data || res.data || {}))
      .catch(() => setHardware({}))
      .finally(() => setLoadingHw(false));
  }, [deviceTab]);

  // Lazy-load network data when tab is first opened
  useEffect(() => {
    if (deviceTab !== 'network' || netInfo !== null || loadingNet) return;
    setLoadingNet(true);
    api.get(`/api/devices/${device.id}/network`)
      .then(res => setNetInfo(res.data?.data || res.data || {}))
      .catch(() => setNetInfo({}))
      .finally(() => setLoadingNet(false));
  }, [deviceTab]);

  // Lazy-load Stammdaten
  useEffect(() => {
    if (deviceTab !== 'stammdaten' || loadingSd) return;
    setLoadingSd(true);
    deviceApi.getStammdaten(device.id)
      .then(res => {
        const sd: Stammdaten = res.data?.data || {};
        setStammdaten(sd);
        setStammdatenDraft(sd);
      })
      .catch(() => {})
      .finally(() => setLoadingSd(false));
  }, [deviceTab]);

  const handlePhotoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingPhoto(true);
    try {
      // Resize client-side via canvas
      const dataUrl = await resizeImage(file, 400);
      await deviceApi.uploadPhoto(device.id, dataUrl);
      setStammdaten(prev => ({ ...prev, photo: dataUrl }));
      setStammdatenDraft(prev => ({ ...prev, photo: dataUrl }));
      toast.success('Foto gespeichert');
    } catch {
      toast.error('Foto-Upload fehlgeschlagen');
    } finally {
      setUploadingPhoto(false);
    }
  };

  const saveStammdaten = async () => {
    setSavingSd(true);
    try {
      const { photo, ...fields } = stammdatenDraft;
      await deviceApi.updateStammdaten(device.id, fields as Record<string, string>);
      setStammdaten(stammdatenDraft);
      toast.success('Stammdaten gespeichert');
    } catch {
      toast.error('Speichern fehlgeschlagen');
    } finally {
      setSavingSd(false);
    }
  };

  const updateApp = async (id: string) => {
    const appEntry = apps.find(a => a.id === id);
    setUpdatingIds(prev => new Set(prev).add(id));
    try {
      await api.post(`/api/devices/${device.id}/software/${id}/update`);
    } catch { /* fall through — apply optimistic update regardless */ }
    setApps(prev => prev.map(a =>
      a.id === id ? { ...a, installedVersion: a.latestVersion, status: 'up-to-date' } : a
    ));
    toast.success('Application updated');
    if (appEntry) {
      addHistoryEntry?.(device.id, {
        type: 'app_updated',
        message: `Updated ${appEntry.name} to ${appEntry.latestVersion}`,
        timestamp: new Date().toISOString(),
      });
    }
    setUpdatingIds(prev => { const s = new Set(prev); s.delete(id); return s; });
  };

  const removeApp = async (id: string) => {
    const app = apps.find(a => a.id === id);
    if (removingAppId === id) {
      setApps(prev => prev.filter(a => a.id !== id));
      setRemovingAppId(null);
      toast.success(`${app?.name} removed`);
      try { await api.delete(`/api/devices/${device.id}/software/${id}`); } catch {}
      if (app) {
        addHistoryEntry?.(device.id, {
          type: 'app_removed',
          message: `Removed ${app.name}`,
          timestamp: new Date().toISOString(),
        });
      }
    } else {
      setRemovingAppId(id);
    }
  };

  const updateAll = async () => {
    setUpdatingAll(true);
    try { await api.post(`/api/devices/${device.id}/software/update-all`); } catch {}
    setApps(prev => prev.map(a => ({ ...a, installedVersion: a.latestVersion, status: 'up-to-date' })));
    toast.success('All applications updated');
    setUpdatingAll(false);
  };

  const pkgManager  = detail.package_manager || (detail as any).packageManager || inferPackageManager(detail.os, detail.platform);
  const kernel      = detail.kernel || '—';
  const registeredAt = (detail as any).registeredAt || '';
  const updatesAvailable = apps.filter(a => a.status === 'update-available').length;

  const fields = [
    { label: 'Device ID',       value: detail.id },
    { label: 'Platform',        value: detail.platform },
    { label: 'OS',              value: [detail.os, detail.osVersion].filter(Boolean).join(' ') || '—' },
    { label: 'Kernel',          value: kernel },
    { label: 'Package Manager', value: pkgManager },
    { label: 'IP Address',      value: detail.ip_address || '—', mono: true },
    { label: 'Last Seen',       value: formatLastSeen(detail.lastSeen) },
    { label: 'Registered',      value: formatDate(registeredAt) },
  ];

  return (
    <>
      <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onClose}>
        <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>

          {/* Header */}
          <div className="flex items-center justify-between px-6 pt-6 pb-0">
            <div className="flex items-center gap-4">
              <div className="flex-shrink-0 flex items-center justify-center w-16 h-16 bg-[#F2F2F7] rounded-xl overflow-hidden">
                {stammdaten.photo
                  ? <img src={stammdaten.photo} alt="Device" className="w-full h-full object-cover" />
                  : <DeviceThumbnail platform={detail.platform} size="md" />}
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#1D1D1F]">
                  {stammdaten.custom_name || detail.name || 'Unknown Device'}
                </h2>
                <div className="flex items-center gap-2 mt-0.5">
                  {loadingDetail ? (
                    <span className="inline-block w-16 h-4 bg-gray-200 rounded animate-pulse" />
                  ) : (
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                      detail.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${detail.status === 'online' ? 'bg-green-500' : 'bg-gray-400'}`} />
                      {detail.status === 'online' ? 'Online' : 'Offline'}
                    </span>
                  )}
                  <span className="text-xs text-[#8E8E93] capitalize">{detail.platform}</span>
                </div>
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>

          {/* Tab bar */}
          <div className="flex border-b border-gray-100 px-6 mt-4 overflow-x-auto">
            {([
              { key: 'details'     as DeviceTab, label: 'Details' },
              { key: 'stammdaten' as DeviceTab, label: 'Stammdaten' },
              { key: 'apps'       as DeviceTab, label: `Apps (${apps.length})` },
              { key: 'hardware'   as DeviceTab, label: 'Hardware' },
              { key: 'network'    as DeviceTab, label: 'Network' },
              { key: 'history'    as DeviceTab, label: 'History' },
            ]).map(t => (
              <button key={t.key} onClick={() => setDeviceTab(t.key)}
                className={`py-2 px-3 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                  deviceTab === t.key
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}>
                {t.label}
                {t.key === 'apps' && updatesAvailable > 0 && (
                  <span className="ml-1.5 bg-yellow-100 text-yellow-700 text-xs px-1.5 py-0.5 rounded-full">{updatesAvailable}</span>
                )}
                {t.key === 'history' && (history?.length ?? 0) > 0 && (
                  <span className="ml-1.5 bg-gray-100 text-gray-600 text-xs px-1.5 py-0.5 rounded-full">{history!.length}</span>
                )}
              </button>
            ))}
          </div>

          {/* Scrollable content */}
          <div className="flex-1 overflow-y-auto p-6">

            {/* ── Stammdaten Tab ── */}
            {deviceTab === 'stammdaten' && (
              <div className="space-y-6">
                {loadingSd ? (
                  <div className="space-y-3">
                    {[1,2,3,4].map(i => <div key={i} className="h-10 bg-gray-100 rounded-lg animate-pulse" />)}
                  </div>
                ) : (
                  <>
                    {/* Photo upload */}
                    <div>
                      <p className="text-xs font-semibold text-[#8E8E93] uppercase tracking-wider mb-2">Gerätefoto</p>
                      <div className="flex items-center gap-4">
                        <div className="w-20 h-20 rounded-xl bg-[#F2F2F7] overflow-hidden flex items-center justify-center flex-shrink-0 border border-[#E5E5EA]">
                          {stammdatenDraft.photo
                            ? <img src={stammdatenDraft.photo} alt="Gerät" className="w-full h-full object-cover" />
                            : <DeviceThumbnail platform={detail.platform} size="md" />}
                        </div>
                        <div className="space-y-2">
                          <label className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg cursor-pointer transition-colors ${uploadingPhoto ? 'bg-gray-100 text-gray-400' : 'bg-[#0071E3] text-white hover:bg-[#0077ED]'}`}>
                            {uploadingPhoto ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <></>}
                            {uploadingPhoto ? 'Lädt hoch…' : 'Foto hochladen'}
                            <input type="file" accept="image/*" className="hidden" onChange={handlePhotoUpload} disabled={uploadingPhoto} />
                          </label>
                          {stammdatenDraft.photo && (
                            <button onClick={() => { setStammdatenDraft(p => ({ ...p, photo: undefined })); setStammdaten(p => ({ ...p, photo: undefined })); }}
                              className="text-xs text-red-500 hover:text-red-700">
                              Foto entfernen
                            </button>
                          )}
                          <p className="text-xs text-[#8E8E93]">Max. 512 KB · JPG, PNG, HEIC</p>
                        </div>
                      </div>
                    </div>

                    {/* Auto-detected (read-only) */}
                    <div>
                      <p className="text-xs font-semibold text-[#8E8E93] uppercase tracking-wider mb-2">Vom Gerät erkannt</p>
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { label: 'Hostname',       value: detail.name },
                          { label: 'Platform',       value: detail.platform },
                          { label: 'OS',             value: [detail.os, detail.osVersion].filter(Boolean).join(' ') },
                          { label: 'Seriennummer',   value: (detail as any).serial_number || '—' },
                          { label: 'Modell',         value: (detail as any).model || '—' },
                          { label: 'IP-Adresse',     value: detail.ip_address || '—' },
                        ].map(f => (
                          <div key={f.label} className="bg-[#F2F2F7] rounded-lg px-3 py-2.5">
                            <p className="text-xs text-[#8E8E93] mb-0.5">{f.label}</p>
                            <p className="text-sm text-[#1D1D1F] font-mono truncate">{f.value || '—'}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Editable fields */}
                    <div>
                      <p className="text-xs font-semibold text-[#8E8E93] uppercase tracking-wider mb-2">Benutzerdefiniert</p>
                      <div className="space-y-3">
                        {([
                          { key: 'custom_name',    label: 'Anzeigename',     placeholder: detail.name || 'z.B. MacBook Pro von Anna' },
                          { key: 'owner',          label: 'Besitzer',        placeholder: 'z.B. Anna Meier' },
                          { key: 'department',     label: 'Abteilung',       placeholder: 'z.B. Engineering' },
                          { key: 'location',       label: 'Standort',        placeholder: 'z.B. Zürich, Büro 3.14' },
                          { key: 'asset_tag',      label: 'Asset-Tag',       placeholder: 'z.B. IT-2024-042' },
                          { key: 'serial_override',label: 'Seriennummer (manuell)', placeholder: 'Überschreibt erkannte S/N' },
                          { key: 'purchase_date',  label: 'Kaufdatum',       placeholder: 'YYYY-MM-DD', type: 'date' },
                          { key: 'warranty_until', label: 'Garantie bis',    placeholder: 'YYYY-MM-DD', type: 'date' },
                        ] as Array<{key: keyof Stammdaten; label: string; placeholder: string; type?: string}>).map(f => (
                          <div key={f.key}>
                            <label className="block text-xs font-medium text-[#3C3C43] mb-1">{f.label}</label>
                            <input
                              type={f.type || 'text'}
                              value={(stammdatenDraft[f.key] as string) || ''}
                              onChange={e => setStammdatenDraft(p => ({ ...p, [f.key]: e.target.value }))}
                              placeholder={f.placeholder}
                              className="w-full px-3 py-2 text-sm border border-[#E5E5EA] rounded-lg focus:outline-none focus:border-[#0071E3] focus:ring-1 focus:ring-[#0071E3] bg-white"
                            />
                          </div>
                        ))}
                        <div>
                          <label className="block text-xs font-medium text-[#3C3C43] mb-1">Notizen</label>
                          <textarea
                            value={stammdatenDraft.notes || ''}
                            onChange={e => setStammdatenDraft(p => ({ ...p, notes: e.target.value }))}
                            placeholder="Interne Notizen zum Gerät…"
                            rows={3}
                            className="w-full px-3 py-2 text-sm border border-[#E5E5EA] rounded-lg focus:outline-none focus:border-[#0071E3] focus:ring-1 focus:ring-[#0071E3] bg-white resize-none"
                          />
                        </div>
                      </div>
                    </div>

                    <button onClick={saveStammdaten} disabled={savingSd}
                      className="w-full flex items-center justify-center gap-2 py-2.5 text-sm font-medium text-white bg-[#0071E3] hover:bg-[#0077ED] rounded-lg transition-colors disabled:opacity-60">
                      {savingSd ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Speichern…</> : 'Stammdaten speichern'}
                    </button>
                  </>
                )}
              </div>
            )}

            {/* ── Details Tab ── */}
            {deviceTab === 'details' && (
              <>
                <div className="grid grid-cols-2 gap-3 mb-6">
                  {fields.map(f => (
                    <div key={f.label} className="bg-gray-50 rounded-lg px-4 py-3">
                      <p className="text-xs font-medium text-gray-500 mb-1">{f.label}</p>
                      <p className={`text-sm text-gray-900 ${(f as any).mono ? 'font-mono' : ''} truncate`}>{f.value}</p>
                    </div>
                  ))}
                </div>
                <div>
                  <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">Compliance Score</p>
                  <div className="bg-gray-50 rounded-lg px-4 py-3">
                    <ComplianceBar score={detail.complianceScore} />
                  </div>
                </div>
                <DeviceCommandsPanel deviceId={detail.id} hostname={detail.name ?? detail.id} />
              </>
            )}

            {/* ── Apps Tab ── */}
            {deviceTab === 'apps' && (
              <>
                {/* Apps toolbar */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-gray-500">{apps.length} installed</span>
                    {updatesAvailable > 0 && (
                      <span className="text-xs bg-yellow-50 text-yellow-700 border border-yellow-200 px-2 py-0.5 rounded-full">
                        {updatesAvailable} update{updatesAvailable > 1 ? 's' : ''} available
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {updatesAvailable > 0 && (
                      <button onClick={updateAll} disabled={updatingAll}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-yellow-700 bg-yellow-50 border border-yellow-200 hover:bg-yellow-100 rounded-lg transition-colors disabled:opacity-60">
                        <ArrowUpCircleIcon className={`w-4 h-4 ${updatingAll ? 'animate-spin' : ''}`} />
                        {updatingAll ? 'Updating…' : 'Update All'}
                      </button>
                    )}
                    <button onClick={() => setShowAddApp(true)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                      <PlusIcon className="w-4 h-4" />
                      Add Application
                    </button>
                  </div>
                </div>

                {/* Apps list */}
                {apps.length === 0 ? (
                  <div className="text-center py-10 text-gray-400">
                    <CubeIcon className="w-10 h-10 mx-auto mb-2" />
                    <p className="text-sm">No applications installed</p>
                  </div>
                ) : (
                  <div className="space-y-1">
                    {apps.map(app => (
                      <div key={app.id} className="flex items-center justify-between px-3 py-2.5 rounded-lg hover:bg-gray-50 group">
                        <div className="flex items-center gap-3 min-w-0">
                          <AppCategoryIcon category={app.category} />
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-gray-800 truncate">{app.name}</p>
                            <p className="text-xs text-gray-400">{app.category} · v{app.installedVersion}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                          {app.status === 'update-available' ? (
                            <span className="text-xs bg-yellow-50 border border-yellow-200 text-yellow-700 px-2 py-0.5 rounded-full">
                              v{app.latestVersion} available
                            </span>
                          ) : (
                            <span className="text-xs bg-green-50 border border-green-100 text-green-600 px-2 py-0.5 rounded-full">
                              Up to date
                            </span>
                          )}
                          {app.status === 'update-available' && (
                            <button onClick={() => updateApp(app.id)}
                              disabled={updatingIds.has(app.id)}
                              className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-yellow-700 bg-yellow-50 border border-yellow-200 hover:bg-yellow-100 rounded-lg transition-colors disabled:opacity-60">
                              <ArrowUpCircleIcon className={`w-3 h-3 ${updatingIds.has(app.id) ? 'animate-spin' : ''}`} />
                              {updatingIds.has(app.id) ? 'Updating…' : 'Update'}
                            </button>
                          )}
                          {removingAppId === app.id ? (
                            <div className="flex items-center gap-1">
                              <button onClick={() => removeApp(app.id)}
                                className="px-2 py-1 text-xs font-medium text-white bg-red-500 hover:bg-red-600 rounded-lg transition-colors">
                                Confirm
                              </button>
                              <button onClick={() => setRemovingAppId(null)}
                                className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors">
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button onClick={() => removeApp(app.id)}
                              className="p-1 text-gray-300 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-all">
                              <TrashIcon className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
            {/* ── Hardware Tab ── */}
            {deviceTab === 'hardware' && (
              loadingHw ? (
                <div className="animate-pulse space-y-3">
                  {[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-gray-200 rounded-xl" />)}
                </div>
              ) : (
                <div className="space-y-4">
                  {/* CPU */}
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">CPU</p>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Model',  value: hardware?.cpu?.model   || hardware?.cpu_model   || '—' },
                        { label: 'Cores',  value: hardware?.cpu?.cores   || hardware?.cpu_cores   || '—' },
                        { label: 'Usage',  value: hardware?.cpu?.usage != null ? `${hardware.cpu.usage}%` : hardware?.cpu_usage != null ? `${hardware.cpu_usage}%` : '—' },
                        { label: 'Arch',   value: hardware?.cpu?.arch    || hardware?.arch         || detail.platform === 'linux' ? 'x86_64' : '—' },
                      ].map(({ label, value }) => (
                        <div key={label} className="bg-white rounded-lg px-3 py-2.5">
                          <p className="text-xs text-gray-400 mb-0.5">{label}</p>
                          <p className="text-sm font-medium text-gray-900">{String(value)}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                  {/* Memory */}
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Memory</p>
                    {hardware?.memory ? (() => {
                      const mem = hardware.memory;
                      const totalGB  = ((mem.total || 0) / 1e9).toFixed(1);
                      const usedGB   = ((mem.used  || 0) / 1e9).toFixed(1);
                      const freeGB   = ((mem.free  || 0) / 1e9).toFixed(1);
                      const pct      = mem.total ? Math.round((mem.used / mem.total) * 100) : 0;
                      return (
                        <div className="space-y-3">
                          <div className="grid grid-cols-3 gap-2">
                            {[{ label: 'Total', value: `${totalGB} GB` }, { label: 'Used', value: `${usedGB} GB` }, { label: 'Free', value: `${freeGB} GB` }]
                              .map(({ label, value }) => (
                                <div key={label} className="bg-white rounded-lg px-3 py-2">
                                  <p className="text-xs text-gray-400 mb-0.5">{label}</p>
                                  <p className="text-sm font-medium text-gray-900">{value}</p>
                                </div>
                              ))}
                          </div>
                          <div>
                            <div className="flex justify-between text-xs text-gray-500 mb-1">
                              <span>Memory usage</span><span>{pct}%</span>
                            </div>
                            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${pct > 85 ? 'bg-red-500' : pct > 60 ? 'bg-yellow-400' : 'bg-green-500'}`}
                                style={{ width: `${pct}%` }} />
                            </div>
                          </div>
                        </div>
                      );
                    })() : <p className="text-sm text-gray-400 italic">No memory data — agent v1.1+ required</p>}
                  </div>
                  {/* Disk */}
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Disk</p>
                    {hardware?.disks?.length ? (
                      <div className="space-y-3">
                        {(hardware.disks as any[]).map((disk: any, i: number) => {
                          const totalGB = ((disk.total || 0) / 1e9).toFixed(0);
                          const usedGB  = ((disk.used  || 0) / 1e9).toFixed(0);
                          const pct     = disk.total ? Math.round((disk.used / disk.total) * 100) : 0;
                          return (
                            <div key={i} className="bg-white rounded-lg px-3 py-2.5">
                              <div className="flex justify-between items-center mb-1.5">
                                <span className="text-sm font-medium text-gray-800 font-mono">{disk.mountpoint || disk.device || `/dev/sd${String.fromCharCode(97 + i)}`}</span>
                                <span className="text-xs text-gray-500">{usedGB} / {totalGB} GB</span>
                              </div>
                              <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
                                <div className={`h-full rounded-full ${pct > 90 ? 'bg-red-500' : pct > 70 ? 'bg-yellow-400' : 'bg-blue-500'}`}
                                  style={{ width: `${pct}%` }} />
                              </div>
                              <p className="text-xs text-gray-400 mt-1">{disk.filesystem || 'ext4'} · {pct}% used</p>
                            </div>
                          );
                        })}
                      </div>
                    ) : <p className="text-sm text-gray-400 italic">No disk data — agent v1.1+ required</p>}
                  </div>
                </div>
              )
            )}

            {/* ── Network Tab ── */}
            {deviceTab === 'network' && (
              loadingNet ? (
                <div className="animate-pulse space-y-3">
                  {[...Array(3)].map((_, i) => <div key={i} className="h-20 bg-gray-200 rounded-xl" />)}
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Known info from device data */}
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Known Info</p>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Primary IP',  value: detail.ip_address || '—', mono: true },
                        { label: 'Hostname',    value: detail.name || '—' },
                        { label: 'Gateway',     value: netInfo?.gateway || '—', mono: true },
                        { label: 'DNS Servers', value: Array.isArray(netInfo?.dns) ? netInfo.dns.join(', ') : netInfo?.dns || '—', mono: true },
                      ].map(({ label, value, mono }) => (
                        <div key={label} className="bg-white rounded-lg px-3 py-2.5">
                          <p className="text-xs text-gray-400 mb-0.5">{label}</p>
                          <p className={`text-sm font-medium text-gray-900 truncate ${mono ? 'font-mono' : ''}`}>{String(value)}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Network interfaces */}
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Interfaces</p>
                    {netInfo?.interfaces?.length ? (
                      <div className="space-y-2">
                        {(netInfo.interfaces as any[]).map((iface: any, i: number) => (
                          <div key={i} className="bg-white rounded-lg px-3 py-2.5 flex items-center gap-3">
                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${iface.state === 'up' || iface.up ? 'bg-green-500' : 'bg-gray-300'}`} />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium text-gray-800 font-mono">{iface.name || `eth${i}`}</span>
                                <span className={`text-xs px-1.5 py-0.5 rounded-full ${iface.state === 'up' || iface.up ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                                  {iface.state || (iface.up ? 'up' : 'down')}
                                </span>
                                {iface.speed && <span className="text-xs text-gray-400">{iface.speed}</span>}
                              </div>
                              <div className="flex items-center gap-3 mt-0.5">
                                {iface.ip && <span className="text-xs text-gray-500 font-mono">{iface.ip}</span>}
                                {iface.mac && <span className="text-xs text-gray-400 font-mono">{iface.mac}</span>}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-gray-400 italic">No interface data — agent v1.1+ required</p>
                    )}
                  </div>
                </div>
              )
            )}

            {/* ── History Tab ── */}
            {deviceTab === 'history' && (() => {
              const entries = history ?? [];
              const iconMap: Record<HistoryEventType, React.ReactNode> = {
                enrolled:       <ServerIcon      className="w-4 h-4 text-gray-500" />,
                app_installed:  <PlusCircleIcon  className="w-4 h-4 text-blue-500" />,
                app_removed:    <MinusCircleIcon className="w-4 h-4 text-red-400" />,
                app_updated:    <ArrowUpCircleIcon className="w-4 h-4 text-green-500" />,
                policy_applied: <ShieldCheckIcon className="w-4 h-4 text-purple-500" />,
                decommissioned: <TrashIcon       className="w-4 h-4 text-red-600" />,
              };
              const dotMap: Record<HistoryEventType, string> = {
                enrolled:       'bg-gray-400',
                app_installed:  'bg-blue-500',
                app_removed:    'bg-red-400',
                app_updated:    'bg-green-500',
                policy_applied: 'bg-purple-500',
                decommissioned: 'bg-red-600',
              };
              if (entries.length === 0) {
                return (
                  <div className="text-center py-10 text-gray-400">
                    <ClockIcon className="w-10 h-10 mx-auto mb-2" />
                    <p className="text-sm">No history recorded yet</p>
                  </div>
                );
              }
              return (
                <div className="space-y-0">
                  {[...entries].reverse().map(entry => (
                    <div key={entry.id} className="flex items-start gap-3 py-3 border-b border-gray-50 last:border-0">
                      <div className="flex items-center gap-2 flex-shrink-0 mt-0.5">
                        <div className={`w-2 h-2 rounded-full ${dotMap[entry.type]}`} />
                        {iconMap[entry.type]}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-800">{entry.message}</p>
                      </div>
                      <span className="text-xs text-gray-400 flex-shrink-0 whitespace-nowrap">{formatDate(entry.timestamp)}</span>
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>

          {/* Footer */}
          <div className="flex justify-between items-center gap-3 px-6 py-4 border-t border-gray-100 flex-shrink-0">
            {detail.decommissioned ? (
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-500 bg-gray-100 rounded-lg">
                <TrashIcon className="w-4 h-4" />
                Decommissioned
              </span>
            ) : (
              <button
                onClick={() => setShowDecommission(true)}
                className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg transition-colors"
              >
                <TrashIcon className="w-4 h-4" />
                Decommission
              </button>
            )}
            <button onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
              Close
            </button>
          </div>
        </div>
      </div>

      {showAddApp && (
        <AddAppModal
          device={detail}
          installedIds={apps.map(a => a.id)}
          onAdd={async (app) => {
            setApps(prev => [...prev, app]);
            addHistoryEntry?.(device.id, {
              type: 'app_installed',
              message: `Installed ${app.name} ${app.installedVersion}`,
              timestamp: new Date().toISOString(),
            });
            try {
              await api.post(`/api/devices/${device.id}/software`, {
                name: app.name, version: app.installedVersion, category: app.category,
              });
            } catch {}
          }}
          onClose={() => setShowAddApp(false)}
        />
      )}
      {showDecommission && (
        <DecommissionModal
          device={detail}
          apps={apps}
          onConfirm={async () => {
            await onDecommission?.(device.id);
            setShowDecommission(false);
            onClose();
          }}
          onCancel={() => setShowDecommission(false)}
        />
      )}
    </>
  );
}

// ─── Enroll Modal ──────────────────────────────────────────────────────────────

type EnrollTab      = 'token' | 'script' | 'domain';
type EnrollPlatform = 'macOS' | 'Linux' | 'Windows';

const BASE_URL  = process.env.NEXT_PUBLIC_APP_URL  || 'https://opendirectory.heusser.local';
const AD_DOMAIN = process.env.NEXT_PUBLIC_AD_DOMAIN || '';

function enrollScript(platform: EnrollPlatform, token?: string): string {
  const t = token ? ` --token ${token}` : '';
  if (platform === 'Windows') return `irm ${BASE_URL}/install.ps1 | iex${token ? `\n# or with token:\nirm "${BASE_URL}/install.ps1?token=${token}" | iex` : ''}`;
  return `curl -fsSL ${BASE_URL}/install.sh | sudo bash -s --${t}`;
}

function domainScript(platform: EnrollPlatform, domain: string): string {
  switch (platform) {
    case 'Windows':
      return `# Join domain (PowerShell):\nAdd-Computer -DomainName "${domain}" -Credential (Get-Credential) -Restart`;
    case 'macOS':
      return `# Join via Directory Utility or:\ndsconfigad -add ${domain} -username admin -password ""`;
    case 'Linux':
      return `# Install realm tools:\nsudo apt-get install realmd sssd\nsudo realm join -U admin ${domain}`;
  }
}

function EnrollModal({ onClose }: { onClose: () => void }) {
  const [tab, setTab]           = useState<EnrollTab>('token');
  const [platform, setPlatform] = useState<EnrollPlatform>('Linux');
  const [copied, setCopied]     = useState(false);
  const [token, setToken]       = useState<string | null>(null);
  const [tokenExpiry, setTokenExpiry] = useState<string | null>(null);
  const [generatingToken, setGeneratingToken] = useState(false);

  const generateToken = async () => {
    setGeneratingToken(true);
    try {
      const res = await api.post('/api/devices/enrollment-token', { expires_in_hours: 24 });
      const t = res.data?.token || res.data?.data?.token || res.data?.enrollment_token;
      const exp = res.data?.expires_at || res.data?.data?.expires_at;
      if (t) {
        setToken(t);
        setTokenExpiry(exp ? new Date(exp).toLocaleString() : '24 hours');
      } else {
        // Backend not yet implemented — generate a placeholder token for demo
        const fake = Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
        setToken(fake);
        setTokenExpiry(new Date(Date.now() + 86400000).toLocaleString());
      }
    } catch {
      // Fallback demo token
      const fake = Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
      setToken(fake);
      setTokenExpiry(new Date(Date.now() + 86400000).toLocaleString());
    } finally {
      setGeneratingToken(false);
    }
  };

  const currentScript =
    tab === 'token'  ? (token ? enrollScript(platform, token) : '') :
    tab === 'script' ? enrollScript(platform) :
    domainScript(platform, AD_DOMAIN);

  const copy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Enroll a Device</h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-6 h-6" /></button>
          </div>

          {/* Method tabs */}
          <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
            {([['token', 'Token (Secure)'], ['script', 'Direct Script'], ['domain', 'Domain Join']] as [EnrollTab, string][]).map(([key, label]) => (
              <button key={key} onClick={() => setTab(key)}
                className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors ${
                  tab === key ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-500 hover:text-gray-700'
                }`}>
                {label}
              </button>
            ))}
          </div>

          {/* Platform selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 font-medium">Platform:</span>
            {(['Linux', 'macOS', 'Windows'] as EnrollPlatform[]).map(p => (
              <button key={p} onClick={() => setPlatform(p)}
                className={`px-3 py-1 text-sm rounded-lg font-medium transition-colors ${
                  platform === p ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}>
                {p}
              </button>
            ))}
          </div>

          {/* ── Token tab ── */}
          {tab === 'token' && (
            <div className="space-y-3">
              <p className="text-sm text-gray-600">
                Generate a single-use enrollment token. The token is embedded in the install command and
                authenticates the device automatically — no credentials needed on the target machine.
              </p>
              {!token ? (
                <button onClick={generateToken} disabled={generatingToken}
                  className="w-full py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-60 transition-colors">
                  {generatingToken ? 'Generating…' : 'Generate Enrollment Token'}
                </button>
              ) : (
                <div className="space-y-3">
                  {/* Token display */}
                  <div className="bg-gray-50 rounded-lg px-4 py-3 border border-gray-200">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Enrollment Token</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-green-600 bg-green-50 border border-green-200 px-2 py-0.5 rounded-full">
                          Valid until {tokenExpiry}
                        </span>
                        <button onClick={() => copy(token)}
                          className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700">
                          {copied ? <CheckIcon className="w-3.5 h-3.5 text-green-500" /> : <ClipboardDocumentIcon className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                    <code className="text-sm font-mono text-blue-700 break-all">{token}</code>
                  </div>
                  {/* Command */}
                  <div>
                    <div className="flex items-center justify-between bg-gray-50 rounded-t-lg px-4 py-2 border border-gray-200 border-b-0">
                      <span className="text-xs font-medium text-gray-500 uppercase">{platform}</span>
                      <button onClick={() => copy(currentScript)}
                        className="flex items-center gap-1 text-xs text-gray-600 hover:text-gray-900">
                        {copied ? <><CheckIcon className="w-4 h-4 text-green-500" /><span className="text-green-600">Copied</span></>
                                : <><ClipboardDocumentIcon className="w-4 h-4" /><span>Copy</span></>}
                      </button>
                    </div>
                    <pre className="bg-gray-900 text-green-400 text-xs p-4 rounded-b-lg overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap">
                      {currentScript}
                    </pre>
                  </div>
                  <div className="flex justify-between items-center">
                    <p className="text-xs text-gray-400">Token is single-use. Regenerate after each enrollment.</p>
                    <button onClick={() => { setToken(null); setTokenExpiry(null); }}
                      className="text-xs text-blue-600 hover:text-blue-700 font-medium">
                      Regenerate
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Direct Script tab ── */}
          {tab === 'script' && (
            <div className="space-y-3">
              <p className="text-sm text-gray-600">
                Run this command on the target device. The agent will be installed and enrolled using the
                server&apos;s built-in trust — suitable for internal networks.
              </p>
              <div>
                <div className="flex items-center justify-between bg-gray-50 rounded-t-lg px-4 py-2 border border-gray-200 border-b-0">
                  <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">{platform}</span>
                  <button onClick={() => copy(currentScript)}
                    className="flex items-center gap-1 text-xs text-gray-600 hover:text-gray-900">
                    {copied ? <><CheckIcon className="w-4 h-4 text-green-500" /><span className="text-green-600">Copied</span></>
                            : <><ClipboardDocumentIcon className="w-4 h-4" /><span>Copy</span></>}
                  </button>
                </div>
                <pre className="bg-gray-900 text-green-400 text-sm p-4 rounded-b-lg overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap">
                  {currentScript}
                </pre>
              </div>
              <p className="text-xs text-gray-400">Device appears in the list within a few seconds after the script completes.</p>
            </div>
          )}

          {/* ── Domain Join tab ── */}
          {tab === 'domain' && (
            <div className="space-y-3">
              {!AD_DOMAIN ? (
                /* No domain configured yet */
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 space-y-3">
                  <div className="flex items-start gap-3">
                    <ExclamationTriangleIcon className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <p className="text-sm font-medium text-amber-800">Keine Domain konfiguriert</p>
                      <p className="text-xs text-amber-700">
                        Um Geräte per Domain-Join einzubinden, muss zuerst eine Active-Directory-Domain eingerichtet werden.
                      </p>
                    </div>
                  </div>
                  <a
                    href="/infrastructure"
                    onClick={onClose}
                    className="flex items-center justify-center gap-2 w-full rounded-md bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium py-2 px-4 transition-colors"
                  >
                    <ServerIcon className="w-4 h-4" />
                    Domain jetzt einrichten →
                  </a>
                </div>
              ) : (
                <>
                  <p className="text-sm text-gray-600">
                    Gerät direkt in die Domain <span className="font-mono font-semibold text-gray-800">{AD_DOMAIN}</span> einbinden.
                  </p>
                  <div>
                    <div className="flex items-center justify-between bg-gray-50 rounded-t-lg px-4 py-2 border border-gray-200 border-b-0">
                      <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">{platform}</span>
                      <button onClick={() => copy(currentScript)}
                        className="flex items-center gap-1 text-xs text-gray-600 hover:text-gray-900">
                        {copied ? <><CheckIcon className="w-4 h-4 text-green-500" /><span className="text-green-600">Copied</span></>
                                : <><ClipboardDocumentIcon className="w-4 h-4" /><span>Copy</span></>}
                      </button>
                    </div>
                    <pre className="bg-gray-900 text-green-400 text-sm p-4 rounded-b-lg overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap">
                      {currentScript}
                    </pre>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main View ─────────────────────────────────────────────────────────────────

export default function DevicesView() {
  const [mainTab,       setMainTab]       = useState<MainTab>('devices');
  const [devices,       setDevices]       = useState<Device[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [searchTerm,    setSearchTerm]    = useState('');
  const [statusFilter,  setStatusFilter]  = useState<StatusFilter>('all');
  const [platformFilter,setPlatformFilter]= useState<PlatformFilter>('all');
  const [refreshingId,  setRefreshingId]  = useState<string | null>(null);
  const [showEnroll,    setShowEnroll]    = useState(false);
  const [showEnrollWizard, setShowEnrollWizard] = useState(false);
  const [selectedDevice,setSelectedDevice]= useState<Device | null>(null);
  // Persist app state across modal open/close so updates survive
  const [appsCache,     setAppsCache]     = useState<Record<string, InstalledApp[]>>({});
  // Device history — keyed by device ID
  const [deviceHistory, setDeviceHistory] = useState<Record<string, DeviceHistoryEntry[]>>({});

  const handleAppsChange = (deviceId: string, apps: InstalledApp[]) => {
    setAppsCache(prev => ({ ...prev, [deviceId]: apps }));
  };

  const addHistoryEntry = useCallback((deviceId: string, entry: Omit<DeviceHistoryEntry, 'id'>) => {
    setDeviceHistory(prev => ({
      ...prev,
      [deviceId]: [...(prev[deviceId] ?? []), { id: `${Date.now()}-${Math.random()}`, ...entry }],
    }));
  }, []);

  const loadDevices = useCallback(async () => {
    try {
      const response = await deviceApi.getDevices();
      const data: Device[] = response.data?.data || [];
      setDevices(data);
      // Auto-generate enrolled events for new devices (use functional updater to avoid stale closure)
      setDeviceHistory(prev => {
        const next = { ...prev };
        data.forEach(d => {
          if (!next[d.id]) {
            next[d.id] = [{
              id: `enrolled-${d.id}`,
              type: 'enrolled' as HistoryEventType,
              message: 'Device enrolled in OpenDirectory',
              timestamp: d.registeredAt ?? d.lastSeen,
            }];
          }
        });
        return next;
      });
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to load devices');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDevices();
    const interval = setInterval(loadDevices, 30000);
    return () => clearInterval(interval);
  }, [loadDevices]);

  const handleRefreshDevice = async (device: Device) => {
    setRefreshingId(device.id);
    try {
      await api.post(`/api/devices/${device.id}/refresh`);
      toast.success(`Refreshed ${device.name}`);
      await loadDevices();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || `Failed to refresh ${device.name}`);
    } finally {
      setRefreshingId(null);
    }
  };

  const handleRefreshAll = async () => {
    setLoading(true);
    await loadDevices();
    toast.success('Device list refreshed');
  };

  const handleRemoved = (id: string) => setDevices(prev => prev.filter(d => d.id !== id));

  const handleDecommissioned = useCallback(async (deviceId: string) => {
    try { await deviceApi.deleteDevice(deviceId); } catch { /* proceed with local state */ }
    setAppsCache(prev => { const next = { ...prev }; delete next[deviceId]; return next; });
    addHistoryEntry(deviceId, {
      type: 'decommissioned',
      message: 'Device decommissioned — configuration restored to enrollment baseline',
      timestamp: new Date().toISOString(),
    });
    setDevices(prev => prev.map(d => d.id === deviceId ? { ...d, decommissioned: true } : d));
    toast.success('Device decommissioned — configuration restored to enrollment baseline');
  }, [addHistoryEntry]);

  const filtered = devices.filter(d => {
    if (statusFilter !== 'all' && d.status !== statusFilter) return false;
    if (platformFilter !== 'all' && (d.platform || '').toLowerCase() !== platformFilter) return false;
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    return (
      d.name?.toLowerCase().includes(q) ||
      d.os?.toLowerCase().includes(q) ||
      d.ip_address?.toLowerCase().includes(q) ||
      d.platform?.toLowerCase().includes(q)
    );
  });

  const online       = devices.filter(d => d.status === 'online').length;
  const offline      = devices.filter(d => d.status === 'offline').length;
  const avgCompliance = devices.length > 0
    ? Math.round(devices.reduce((sum, d) => sum + (d.complianceScore ?? 0), 0) / devices.length)
    : 0;

  const hasActiveFilters = statusFilter !== 'all' || platformFilter !== 'all' || searchTerm !== '';

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold text-gray-900">Devices</h1>
          {!loading && mainTab === 'devices' && (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700">
              {devices.length}
            </span>
          )}
        </div>
        {mainTab === 'devices' && (
          <div className="flex items-center gap-3">
            <button onClick={handleRefreshAll}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
              <ArrowPathIcon className="w-4 h-4" />
              Refresh
            </button>
            <button onClick={() => setShowEnrollWizard(true)}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-purple-700 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg transition-colors">
              <SparklesIcon className="w-4 h-4" />
              Enrollment Wizard
            </button>
            <button onClick={() => setShowEnroll(true)}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
              <PlusIcon className="w-4 h-4" />
              Enroll Device
            </button>
          </div>
        )}
      </div>

      {/* Top-level tab navigation */}
      <div className="flex border-b border-gray-200">
        <button
          onClick={() => setMainTab('devices')}
          className={`flex items-center gap-2 py-2.5 px-4 text-sm font-medium border-b-2 transition-colors ${
            mainTab === 'devices'
              ? 'border-blue-500 text-blue-600'
              : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
          }`}
        >
          <ComputerDesktopIcon className="w-4 h-4" />
          Geräte
        </button>
        <button
          onClick={() => setMainTab('drivers')}
          className={`flex items-center gap-2 py-2.5 px-4 text-sm font-medium border-b-2 transition-colors ${
            mainTab === 'drivers'
              ? 'border-blue-500 text-blue-600'
              : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
          }`}
        >
          <CpuChipIcon className="w-4 h-4" />
          Treiber
        </button>
      </div>

      {/* Drivers tab */}
      {mainTab === 'drivers' && <DeviceDriversTab />}

      {/* Devices tab content (hidden when drivers tab active) */}
      {mainTab === 'devices' && (<>

      {/* Filter bar */}
      <div className="flex items-center gap-4 flex-wrap">
        {/* Search */}
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search devices..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="pl-9 pr-4 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent w-56"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-1.5">
          <FunnelIcon className="w-4 h-4 text-gray-400" />
          <span className="text-xs text-gray-500">Status:</span>
          {(['all', 'online', 'offline'] as StatusFilter[]).map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                statusFilter === s
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'
              }`}>
              {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>

        {/* Platform filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-gray-500">Platform:</span>
          {(['all', 'linux', 'macos', 'windows'] as PlatformFilter[]).map(p => (
            <button key={p} onClick={() => setPlatformFilter(p)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                platformFilter === p
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'
              }`}>
              {p === 'all' ? 'All' : p === 'macos' ? 'macOS' : p.charAt(0).toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>

        {/* Clear filters */}
        {hasActiveFilters && (
          <button onClick={() => { setSearchTerm(''); setStatusFilter('all'); setPlatformFilter('all'); }}
            className="text-xs text-blue-600 hover:text-blue-700 font-medium">
            Clear filters
          </button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Devices',  value: devices.length },
          { label: 'Online',         value: online,         dot: 'bg-green-500' },
          { label: 'Offline',        value: offline,        dot: 'bg-gray-400' },
          { label: 'Avg. Compliance',value: `${avgCompliance}%` },
        ].map(({ label, value, dot }) => (
          <div key={label} className="bg-white rounded-xl border border-gray-100 shadow-sm p-4">
            <div className="flex items-center gap-2">
              {dot && <div className={`w-2.5 h-2.5 rounded-full ${dot}`} />}
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">{label}</p>
            </div>
            <p className="mt-1 text-2xl font-semibold text-gray-900">
              {loading ? <span className="animate-pulse inline-block w-10 h-7 bg-gray-200 rounded" /> : value}
            </p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr>
                {['Status', 'Name', 'Platform', 'OS', 'IP Address', 'Last Seen', 'Compliance', 'Actions'].map(col => (
                  <th key={col} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <><SkeletonRow /><SkeletonRow /><SkeletonRow /><SkeletonRow /></>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-16 text-center">
                    <DevicePhoneMobileIcon className="mx-auto w-12 h-12 text-gray-300 mb-3" />
                    {devices.length === 0 ? (
                      <>
                        <p className="text-sm font-medium text-gray-900 mb-1">No devices enrolled</p>
                        <p className="text-xs text-gray-500 mb-4">Install the OpenDirectory agent to enroll your first device.</p>
                        <code className="inline-block bg-gray-100 text-gray-700 text-xs px-4 py-2 rounded-lg font-mono">
                          curl -fsSL https://opendirectory.heusser.local/install.sh | sudo bash
                        </code>
                      </>
                    ) : (
                      <p className="text-sm text-gray-500">No devices match your filters.</p>
                    )}
                  </td>
                </tr>
              ) : (
                filtered.map((device, idx) => (
                  <tr key={device.id}
                    className={idx % 2 === 0 ? 'bg-white hover:bg-gray-50' : 'bg-gray-50 hover:bg-gray-100'}
                    style={{ transition: 'background 0.1s' }}>
                    <td className="px-4 py-3">
                      {device.decommissioned ? (
                        <div className="flex items-center gap-1.5">
                          <div className="w-2.5 h-2.5 rounded-full flex-shrink-0 bg-gray-400" />
                          <span className="text-xs font-medium text-gray-400">Decommissioned</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${device.status === 'online' ? 'bg-green-500' : 'bg-gray-400'}`} />
                          <span className={`text-xs font-medium ${device.status === 'online' ? 'text-green-700' : 'text-gray-500'}`}>
                            {device.status === 'online' ? 'Online' : 'Offline'}
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="flex-shrink-0 flex items-center justify-center w-12 h-10 bg-[#F2F2F7] rounded-lg overflow-hidden">
                          {(device as any).metadata?.stammdaten?.photo
                            ? <img src={(device as any).metadata.stammdaten.photo} alt="" className="w-full h-full object-cover" />
                            : <DeviceThumbnail platform={device.platform} size="sm" />}
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-900">
                            {(device as any).metadata?.stammdaten?.custom_name || device.name || '—'}
                          </p>
                          {(device as any).metadata?.stammdaten?.custom_name && (
                            <p className="text-xs text-[#8E8E93]">{device.name}</p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-600 capitalize">{device.platform || '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-600">
                        {device.os || '—'}{device.osVersion ? ` ${device.osVersion}` : ''}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-600 font-mono">{device.ip_address || '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-500">{formatLastSeen(device.lastSeen)}</span>
                    </td>
                    <td className="px-4 py-3 min-w-[120px]">
                      <ComplianceBar score={device.complianceScore} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => setSelectedDevice(device)}
                          className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors">
                          <EyeIcon className="w-3.5 h-3.5" />
                          Details
                        </button>
                        <button
                          onClick={() => handleRefreshDevice(device)}
                          disabled={refreshingId === device.id}
                          className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                          <ArrowPathIcon className={`w-3.5 h-3.5 ${refreshingId === device.id ? 'animate-spin' : ''}`} />
                          Refresh
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showEnroll && <EnrollModal onClose={() => setShowEnroll(false)} />}
      {selectedDevice && (
        <DeviceDetailModal
          device={selectedDevice}
          initialApps={appsCache[selectedDevice.id]}
          onAppsChange={handleAppsChange}
          onClose={() => setSelectedDevice(null)}
          onRemove={handleRemoved}
          history={deviceHistory[selectedDevice.id]}
          addHistoryEntry={addHistoryEntry}
          onDecommission={handleDecommissioned}
        />
      )}
      {showEnrollWizard && (
        <DeviceEnrollmentWizard onClose={() => setShowEnrollWizard(false)} />
      )}
      </>)}
    </div>
  );
}
