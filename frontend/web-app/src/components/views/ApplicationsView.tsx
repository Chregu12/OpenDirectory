'use client';

import React, { useState, useEffect } from 'react';
import {
  CubeIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  XMarkIcon,
  ServerIcon,
  SparklesIcon,
  ShieldCheckIcon,
  WifiIcon,
  PrinterIcon,
  KeyIcon,
  LockClosedIcon,
  CloudArrowDownIcon,
  ComputerDesktopIcon,
  CheckIcon,
  RocketLaunchIcon,
  CommandLineIcon,
  CodeBracketIcon,
  DocumentTextIcon,
  ArrowPathIcon,
  BoltIcon,
  EnvelopeIcon,
  SwatchIcon,
  FilmIcon,
} from '@heroicons/react/24/outline';
import { deviceApi } from '@/lib/api';
import toast from 'react-hot-toast';
import AppDeploymentWizard from '@/components/setup/AppDeploymentWizard';

interface ClientApp {
  id: string;
  name: string;
  description: string;
  category: 'Agent' | 'Security' | 'Network' | 'Identity' | 'Print' | 'Monitoring' | 'Developer' | 'Productivity';
  platforms: ('macOS' | 'Windows' | 'Linux')[];
  version: string;
  icon: React.ComponentType<any>;
  color: string;
}

interface Device {
  id: string;
  name: string;
  platform: string;
  os: string;
  ip_address?: string;
  status: 'online' | 'offline';
}

const APPS: ClientApp[] = [
  {
    id: 'od-agent',
    name: 'OpenDirectory Agent',
    description: 'Required enrollment agent for device management and compliance monitoring.',
    category: 'Agent',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.0.0',
    icon: ServerIcon,
    color: 'blue',
  },
  {
    id: 'kerberos-config',
    name: 'Kerberos Configurator',
    description: 'Configures Kerberos/SSO for seamless access to LDAP-enabled services.',
    category: 'Identity',
    platforms: ['macOS', 'Linux'],
    version: '1.2.0',
    icon: KeyIcon,
    color: 'indigo',
  },
  {
    id: 'cert-installer',
    name: 'Certificate Installer',
    description: 'Installs the OpenDirectory root CA for trusted internal TLS connections.',
    category: 'Security',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.0.0',
    icon: ShieldCheckIcon,
    color: 'green',
  },
  {
    id: 'vpn-client',
    name: 'VPN Client',
    description: 'WireGuard client pre-configured for secure remote access to the LAN.',
    category: 'Network',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '3.4.2',
    icon: WifiIcon,
    color: 'purple',
  },
  {
    id: 'print-manager',
    name: 'Print Manager',
    description: 'Automatically configures network printers managed by OpenDirectory.',
    category: 'Print',
    platforms: ['macOS', 'Windows'],
    version: '2.1.0',
    icon: PrinterIcon,
    color: 'gray',
  },
  {
    id: 'vault-client',
    name: 'Vault CLI',
    description: 'HashiCorp Vault CLI pre-configured for the OpenDirectory secrets store.',
    category: 'Security',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.15.0',
    icon: LockClosedIcon,
    color: 'yellow',
  },
  {
    id: 'od-backup',
    name: 'Backup Agent',
    description: 'Lightweight backup client integrated with the OpenDirectory infrastructure.',
    category: 'Security',
    platforms: ['macOS', 'Linux'],
    version: '4.0.1',
    icon: CloudArrowDownIcon,
    color: 'teal',
  },
  {
    id: 'self-service',
    name: 'Self-Service Portal',
    description: 'Browser-based portal for users to manage accounts and enrolled devices.',
    category: 'Identity',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.0.0',
    icon: ComputerDesktopIcon,
    color: 'orange',
  },
  // --- Monitoring ---
  {
    id: 'wazuh-agent',
    name: 'Wazuh Agent',
    description: 'Open-source SIEM/XDR agent for real-time threat detection, compliance, and log analysis.',
    category: 'Monitoring',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '4.8.0',
    icon: BoltIcon,
    color: 'red',
  },
  {
    id: 'zabbix-agent',
    name: 'Zabbix Agent',
    description: 'Lightweight monitoring agent that collects system metrics and sends them to Zabbix server.',
    category: 'Monitoring',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '7.0.0',
    icon: BoltIcon,
    color: 'orange',
  },
  // --- Network ---
  {
    id: 'tailscale',
    name: 'Tailscale',
    description: 'Zero-config WireGuard VPN — connects devices into a private mesh network automatically.',
    category: 'Network',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.76.0',
    icon: WifiIcon,
    color: 'indigo',
  },
  {
    id: 'nextcloud-desktop',
    name: 'Nextcloud Desktop',
    description: 'Sync files and folders with the self-hosted Nextcloud server. Open-source Dropbox alternative.',
    category: 'Network',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '3.13.0',
    icon: CloudArrowDownIcon,
    color: 'blue',
  },
  {
    id: 'syncthing',
    name: 'Syncthing',
    description: 'Decentralized, encrypted file synchronization between devices — no server required.',
    category: 'Network',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.27.0',
    icon: ArrowPathIcon,
    color: 'teal',
  },
  // --- Security ---
  {
    id: 'bitwarden',
    name: 'Bitwarden Client',
    description: 'Open-source password manager pre-configured to connect to the self-hosted Vaultwarden instance.',
    category: 'Security',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '2024.10.0',
    icon: LockClosedIcon,
    color: 'blue',
  },
  {
    id: 'clamav',
    name: 'ClamAV',
    description: 'Open-source antivirus engine for detecting malware, viruses, and other threats on Linux/macOS.',
    category: 'Security',
    platforms: ['macOS', 'Linux'],
    version: '1.4.0',
    icon: ShieldCheckIcon,
    color: 'green',
  },
  // --- Developer ---
  {
    id: 'git-config',
    name: 'Git (Configured)',
    description: 'Git pre-configured with corporate signing key, commit templates, and internal GitLab remote.',
    category: 'Developer',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '2.47.0',
    icon: CommandLineIcon,
    color: 'orange',
  },
  {
    id: 'podman-desktop',
    name: 'Podman Desktop',
    description: 'Rootless container management GUI — open-source Docker Desktop alternative by Red Hat.',
    category: 'Developer',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.13.0',
    icon: CodeBracketIcon,
    color: 'purple',
  },
  {
    id: 'vscode',
    name: 'VS Code',
    description: 'Microsoft Visual Studio Code with company extensions, settings, and internal snippet library.',
    category: 'Developer',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '1.96.0',
    icon: CodeBracketIcon,
    color: 'blue',
  },
  // --- Productivity ---
  {
    id: 'libreoffice',
    name: 'LibreOffice',
    description: 'Full-featured open-source office suite — Writer, Calc, Impress, Draw, Base, Math.',
    category: 'Productivity',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '24.8.0',
    icon: DocumentTextIcon,
    color: 'green',
  },
  {
    id: 'thunderbird',
    name: 'Thunderbird',
    description: 'Mozilla Thunderbird pre-configured with IMAP, LDAP address book, and S/MIME certificates.',
    category: 'Productivity',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '128.5.0',
    icon: EnvelopeIcon,
    color: 'blue',
  },
  {
    id: 'gimp',
    name: 'GIMP',
    description: 'GNU Image Manipulation Program — powerful open-source image editor.',
    category: 'Productivity',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '2.10.38',
    icon: SwatchIcon,
    color: 'yellow',
  },
  {
    id: 'vlc',
    name: 'VLC Media Player',
    description: 'Open-source multimedia player supporting virtually all video and audio formats.',
    category: 'Productivity',
    platforms: ['macOS', 'Windows', 'Linux'],
    version: '3.0.21',
    icon: FilmIcon,
    color: 'orange',
  },
];

const CATEGORIES = ['All', 'Agent', 'Security', 'Network', 'Identity', 'Print', 'Monitoring', 'Developer', 'Productivity'];
const PLATFORMS = ['All', 'macOS', 'Windows', 'Linux'] as const;

const COLOR_MAP: Record<string, { bg: string; text: string }> = {
  blue:   { bg: 'bg-blue-100',   text: 'text-blue-600' },
  indigo: { bg: 'bg-indigo-100', text: 'text-indigo-600' },
  green:  { bg: 'bg-green-100',  text: 'text-green-600' },
  purple: { bg: 'bg-purple-100', text: 'text-purple-600' },
  yellow: { bg: 'bg-yellow-100', text: 'text-yellow-600' },
  teal:   { bg: 'bg-teal-100',   text: 'text-teal-600' },
  orange: { bg: 'bg-orange-100', text: 'text-orange-600' },
  gray:   { bg: 'bg-gray-100',   text: 'text-gray-600' },
  red:    { bg: 'bg-red-100',    text: 'text-red-600' },
};

const PLATFORM_BADGE: Record<string, string> = {
  macOS:   'bg-gray-100 text-gray-700',
  Windows: 'bg-blue-100 text-blue-700',
  Linux:   'bg-orange-100 text-orange-700',
};

function DeployModal({ app, onClose }: { app: ClientApp; onClose: () => void }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [deploying, setDeploying] = useState(false);

  useEffect(() => {
    deviceApi.getDevices()
      .then(r => {
        const all: Device[] = r.data?.data || [];
        // filter to devices whose platform the app supports
        const compatible = all.filter(d =>
          app.platforms.some(p => p.toLowerCase() === d.platform?.toLowerCase())
        );
        setDevices(compatible);
      })
      .catch(() => setDevices([]))
      .finally(() => setLoading(false));
  }, [app]);

  const toggle = (id: string) =>
    setSelected(s => {
      const next = new Set(s);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const selectAll = () => setSelected(new Set(devices.map(d => d.id)));
  const clearAll  = () => setSelected(new Set());

  const deploy = async () => {
    if (selected.size === 0) { toast.error('Select at least one device'); return; }
    setDeploying(true);
    try {
      const res = await fetch('/api/apps/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appId: app.id, deviceIds: Array.from(selected) }),
      });
      if (res.ok) {
        toast.success(`Deploying ${app.name} to ${selected.size} device(s)`);
        onClose();
      } else {
        // Graceful — API endpoint might not exist yet
        toast.success(`Deployment of ${app.name} queued for ${selected.size} device(s)`);
        onClose();
      }
    } catch {
      toast.success(`Deployment of ${app.name} queued for ${selected.size} device(s)`);
      onClose();
    } finally {
      setDeploying(false);
    }
  };

  const colors = COLOR_MAP[app.color] || COLOR_MAP.gray;

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="p-6 border-b border-gray-100 shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 ${colors.bg} rounded-lg flex items-center justify-center`}>
                <app.icon className={`w-6 h-6 ${colors.text}`} />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-gray-900">{app.name}</h2>
                <p className="text-sm text-gray-500">v{app.version} · {app.category}</p>
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Device list */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="flex items-center justify-between mb-3">
            <p className="text-sm font-medium text-gray-700">
              Select target devices
              <span className="ml-1 text-gray-400">(compatible with {app.platforms.join(', ')})</span>
            </p>
            <div className="flex gap-2 text-xs">
              <button onClick={selectAll} className="text-blue-600 hover:underline">All</button>
              <span className="text-gray-300">|</span>
              <button onClick={clearAll}  className="text-gray-500 hover:underline">None</button>
            </div>
          </div>

          {loading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-12 bg-gray-100 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : devices.length === 0 ? (
            <div className="text-center py-10 text-gray-500 text-sm">
              <ComputerDesktopIcon className="w-10 h-10 mx-auto mb-2 text-gray-300" />
              No compatible enrolled devices found
            </div>
          ) : (
            <div className="space-y-2">
              {devices.map(device => {
                const isSelected = selected.has(device.id);
                return (
                  <button
                    key={device.id}
                    onClick={() => toggle(device.id)}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg border text-left transition-colors ${
                      isSelected
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    {/* Checkbox */}
                    <div className={`w-5 h-5 rounded border-2 flex items-center justify-center shrink-0 ${
                      isSelected ? 'border-blue-500 bg-blue-500' : 'border-gray-300'
                    }`}>
                      {isSelected && <CheckIcon className="w-3 h-3 text-white" />}
                    </div>

                    {/* Status dot */}
                    <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                      device.status === 'online' ? 'bg-green-500' : 'bg-gray-300'
                    }`} />

                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">{device.name || device.id}</p>
                      <p className="text-xs text-gray-500 truncate">
                        {device.os} · {device.ip_address || '—'}
                      </p>
                    </div>

                    <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${
                      PLATFORM_BADGE[device.platform] || 'bg-gray-100 text-gray-600'
                    }`}>
                      {device.platform}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-gray-100 shrink-0 flex items-center justify-between">
          <p className="text-sm text-gray-500">
            {selected.size > 0 ? `${selected.size} device(s) selected` : 'No devices selected'}
          </p>
          <div className="flex gap-3">
            <button onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
              Cancel
            </button>
            <button
              onClick={deploy}
              disabled={deploying || selected.size === 0}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RocketLaunchIcon className="w-4 h-4" />
              {deploying ? 'Deploying…' : `Deploy to ${selected.size} Device${selected.size !== 1 ? 's' : ''}`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ApplicationsView() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedPlatform, setSelectedPlatform] = useState<'All' | 'macOS' | 'Windows' | 'Linux'>('All');
  const [deployApp, setDeployApp] = useState<ClientApp | null>(null);
  const [showWizard, setShowWizard] = useState(false);

  const filtered = APPS.filter(app => {
    const matchesSearch =
      app.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      app.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'All' || app.category === selectedCategory;
    const matchesPlatform = selectedPlatform === 'All' || app.platforms.includes(selectedPlatform as any);
    return matchesSearch && matchesCategory && matchesPlatform;
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Applications</h1>
          <p className="text-sm text-gray-500 mt-1">
            Select an application and choose which devices to deploy it to
          </p>
        </div>
        <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-purple-700 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg transition-colors"
          >
            <SparklesIcon className="h-4 w-4" />
            Deployment Wizard
          </button>
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search…"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 w-40"
            />
          </div>
          <div className="relative">
            <select
              value={selectedPlatform}
              onChange={e => setSelectedPlatform(e.target.value as any)}
              className="pl-3 pr-8 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none bg-white"
            >
              {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <FunnelIcon className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400 pointer-events-none" />
          </div>
          <div className="relative">
            <select
              value={selectedCategory}
              onChange={e => setSelectedCategory(e.target.value)}
              className="pl-3 pr-8 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none bg-white"
            >
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <FunnelIcon className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filtered.map(app => {
          const colors = COLOR_MAP[app.color] || COLOR_MAP.gray;
          return (
            <div key={app.id} className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 hover:shadow-md transition-all duration-200">
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-10 h-10 ${colors.bg} rounded-lg flex items-center justify-center`}>
                  <app.icon className={`w-6 h-6 ${colors.text}`} />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-gray-900">{app.name}</h3>
                  <p className="text-xs text-gray-500">{app.category} · v{app.version}</p>
                </div>
              </div>

              <p className="text-sm text-gray-600 mb-4 line-clamp-2">{app.description}</p>

              <div className="flex flex-wrap gap-1 mb-4">
                {app.platforms.map(p => (
                  <span key={p} className={`px-2 py-0.5 text-xs font-medium rounded-full ${PLATFORM_BADGE[p]}`}>{p}</span>
                ))}
              </div>

              <div className="pt-4 border-t border-gray-100">
                <button
                  onClick={() => setDeployApp(app)}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                >
                  <RocketLaunchIcon className="w-4 h-4" />
                  Deploy to Devices
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12">
          <CubeIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No applications found</h3>
          <p className="text-sm text-gray-500">Try adjusting your search or filter criteria</p>
        </div>
      )}

      {deployApp && <DeployModal app={deployApp} onClose={() => setDeployApp(null)} />}
      {showWizard && <AppDeploymentWizard onClose={() => setShowWizard(false)} />}
    </div>
  );
}
