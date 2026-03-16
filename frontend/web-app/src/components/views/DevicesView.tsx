'use client';

import React, { useState, useEffect } from 'react';
import {
  ComputerDesktopIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  DevicePhoneMobileIcon,
  ServerIcon,
  FunnelIcon,
  PlusIcon,
  EllipsisVerticalIcon,
  ShieldCheckIcon,
  ClockIcon,
  CpuChipIcon,
  SignalIcon
} from '@heroicons/react/24/outline';
import { deviceApi } from '@/lib/api';

// ── Types ──────────────────────────────────────────────────────────────────────

interface Device {
  id: string;
  name: string;
  platform: 'windows' | 'macos' | 'linux' | 'ios' | 'android';
  type: 'workstation' | 'laptop' | 'server' | 'mobile' | 'vm';
  os: string;
  osVersion: string;
  user: string;
  status: 'online' | 'offline' | 'syncing' | 'error';
  compliance: 'compliant' | 'non_compliant' | 'pending' | 'unknown';
  lastSeen: string;
  enrolledAt: string;
  ipAddress: string;
  policies: number;
  pendingUpdates: number;
  encrypted: boolean;
  managed: boolean;
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const mockDevices: Device[] = [
  { id: 'd-1', name: 'WS-001', platform: 'windows', type: 'workstation', os: 'Windows 11', osVersion: '23H2', user: 'j.smith', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T09:00:00Z', enrolledAt: '2025-06-15', ipAddress: '10.0.1.101', policies: 5, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-2', name: 'LAPTOP-23', platform: 'windows', type: 'laptop', os: 'Windows 11', osVersion: '22H2', user: 'k.chen', status: 'online', compliance: 'non_compliant', lastSeen: '2026-03-16T08:45:00Z', enrolledAt: '2025-09-01', ipAddress: '10.0.2.45', policies: 5, pendingUpdates: 3, encrypted: false, managed: true },
  { id: 'd-3', name: 'SRV-DC01', platform: 'windows', type: 'server', os: 'Windows Server 2022', osVersion: '21H2', user: 'admin', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T09:01:00Z', enrolledAt: '2024-01-10', ipAddress: '10.0.0.10', policies: 8, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-4', name: 'SRV-FILE01', platform: 'linux', type: 'server', os: 'Ubuntu Server', osVersion: '24.04 LTS', user: 'admin', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T09:00:00Z', enrolledAt: '2024-03-20', ipAddress: '10.0.0.20', policies: 4, pendingUpdates: 1, encrypted: true, managed: true },
  { id: 'd-5', name: 'MAC-DEV-01', platform: 'macos', type: 'laptop', os: 'macOS', osVersion: 'Sequoia 15.3', user: 's.patel', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T08:55:00Z', enrolledAt: '2025-07-12', ipAddress: '10.0.2.88', policies: 4, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-6', name: 'WS-012', platform: 'windows', type: 'workstation', os: 'Windows 11', osVersion: '22H2', user: 'm.jones', status: 'offline', compliance: 'non_compliant', lastSeen: '2026-03-14T17:30:00Z', enrolledAt: '2025-04-08', ipAddress: '10.0.1.112', policies: 5, pendingUpdates: 5, encrypted: false, managed: true },
  { id: 'd-7', name: 'LINUX-BUILD-01', platform: 'linux', type: 'vm', os: 'Ubuntu', osVersion: '24.04 LTS', user: 'devops', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T09:00:00Z', enrolledAt: '2025-11-20', ipAddress: '10.0.3.50', policies: 3, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-8', name: 'MAC-EXEC-01', platform: 'macos', type: 'laptop', os: 'macOS', osVersion: 'Sequoia 15.3', user: 'c.mueller', status: 'syncing', compliance: 'pending', lastSeen: '2026-03-16T09:02:00Z', enrolledAt: '2026-01-05', ipAddress: '10.0.2.91', policies: 4, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-9', name: 'SRV-WEB02', platform: 'linux', type: 'server', os: 'RHEL', osVersion: '9.3', user: 'admin', status: 'online', compliance: 'non_compliant', lastSeen: '2026-03-16T09:00:00Z', enrolledAt: '2024-08-14', ipAddress: '10.0.0.30', policies: 6, pendingUpdates: 2, encrypted: true, managed: true },
  { id: 'd-10', name: 'WS-007', platform: 'windows', type: 'workstation', os: 'Windows 11', osVersion: '23H2', user: 'helpdesk1', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T08:50:00Z', enrolledAt: '2025-05-22', ipAddress: '10.0.1.107', policies: 5, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-11', name: 'LAPTOP-45', platform: 'windows', type: 'laptop', os: 'Windows 11', osVersion: '23H2', user: 'temp-contractor', status: 'offline', compliance: 'unknown', lastSeen: '2026-03-10T16:00:00Z', enrolledAt: '2026-02-01', ipAddress: '10.0.2.120', policies: 3, pendingUpdates: 0, encrypted: true, managed: true },
  { id: 'd-12', name: 'SRV-DC02', platform: 'windows', type: 'server', os: 'Windows Server 2022', osVersion: '21H2', user: 'admin', status: 'online', compliance: 'compliant', lastSeen: '2026-03-16T09:01:00Z', enrolledAt: '2024-01-10', ipAddress: '10.0.0.11', policies: 8, pendingUpdates: 0, encrypted: true, managed: true },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

const statusBadge = (s: string) =>
  s === 'online' ? 'od-badge-success' :
  s === 'syncing' ? 'od-badge-info' :
  s === 'offline' ? 'bg-gray-100 text-gray-600' :
  'od-badge-danger';

const complianceBadge = (c: string) =>
  c === 'compliant' ? 'od-badge-success' :
  c === 'non_compliant' ? 'od-badge-danger' :
  c === 'pending' ? 'od-badge-warning' :
  'bg-gray-100 text-gray-600';

const platformLabel = (p: string) =>
  p === 'windows' ? 'Windows' : p === 'macos' ? 'macOS' : p === 'linux' ? 'Linux' : p === 'ios' ? 'iOS' : 'Android';

const typeIcon = (t: string) =>
  t === 'server' ? ServerIcon :
  t === 'mobile' ? DevicePhoneMobileIcon :
  t === 'vm' ? CpuChipIcon :
  ComputerDesktopIcon;

// ── Component ──────────────────────────────────────────────────────────────────

export default function DevicesView() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'all' | 'compliant' | 'non_compliant' | 'offline'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  useEffect(() => { loadDevices(); }, []);

  const loadDevices = async () => {
    setLoading(true);
    try {
      const res = await deviceApi.getDevices();
      const apiDevices = (res.data || []).map((d: any) => ({
        id: d.id || d.deviceId,
        name: d.name || d.deviceName || 'Unknown',
        platform: d.platform || 'windows',
        type: d.type || 'workstation',
        os: d.os || 'Unknown',
        osVersion: d.osVersion || '',
        user: d.user || d.assignedUser || '',
        status: d.status || 'offline',
        compliance: d.compliance || d.complianceStatus || 'unknown',
        lastSeen: d.lastSeen || d.lastCheckin || new Date().toISOString(),
        enrolledAt: d.enrolledAt || d.enrollmentDate || '',
        ipAddress: d.ipAddress || d.ip || '',
        policies: d.policies || d.policyCount || 0,
        pendingUpdates: d.pendingUpdates || 0,
        encrypted: d.encrypted ?? false,
        managed: d.managed ?? true,
      }));
      setDevices(apiDevices.length > 0 ? apiDevices : mockDevices);
    } catch {
      setDevices(mockDevices);
    } finally {
      setLoading(false);
    }
  };

  const stats = {
    total: devices.length,
    online: devices.filter(d => d.status === 'online' || d.status === 'syncing').length,
    compliant: devices.filter(d => d.compliance === 'compliant').length,
    nonCompliant: devices.filter(d => d.compliance === 'non_compliant').length,
    encrypted: devices.filter(d => d.encrypted).length,
  };

  const filteredDevices = devices.filter(d => {
    if (searchQuery && !d.name.toLowerCase().includes(searchQuery.toLowerCase()) && !d.user.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    if (activeTab === 'compliant') return d.compliance === 'compliant';
    if (activeTab === 'non_compliant') return d.compliance === 'non_compliant';
    if (activeTab === 'offline') return d.status === 'offline';
    return true;
  });

  const syncDevice = async (deviceId: string) => {
    setDevices(prev => prev.map(d => d.id === deviceId ? { ...d, status: 'syncing' as const } : d));
    await new Promise(r => setTimeout(r, 1500));
    setDevices(prev => prev.map(d => d.id === deviceId ? { ...d, status: 'online' as const } : d));
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            <ComputerDesktopIcon className="w-6 h-6 text-blue-600" /> Device Management
          </h1>
          <p className="text-sm text-gray-500">Manage enrolled devices, compliance, and policies</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
            <input
              className="pl-9 pr-3 py-2 bg-white border border-gray-300 rounded-lg text-sm text-gray-900 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 w-56"
              placeholder="Search devices..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm text-white flex items-center gap-2 shadow-sm">
            <PlusIcon className="w-4 h-4" /> Enroll Device
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="px-6 py-4 grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="od-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-2xl font-bold text-gray-900">{stats.total}</div>
              <div className="text-xs text-gray-500">Total Devices</div>
            </div>
            <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
              <ComputerDesktopIcon className="w-5 h-5 text-blue-600" />
            </div>
          </div>
        </div>
        <div className="od-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-2xl font-bold text-green-600">{stats.online}</div>
              <div className="text-xs text-gray-500">Online</div>
            </div>
            <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
              <SignalIcon className="w-5 h-5 text-green-600" />
            </div>
          </div>
        </div>
        <div className="od-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-2xl font-bold text-green-600">{stats.compliant}</div>
              <div className="text-xs text-gray-500">Compliant</div>
            </div>
            <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
              <CheckCircleIcon className="w-5 h-5 text-green-600" />
            </div>
          </div>
        </div>
        <div className="od-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-2xl font-bold text-red-600">{stats.nonCompliant}</div>
              <div className="text-xs text-gray-500">Non-Compliant</div>
            </div>
            <div className="w-8 h-8 bg-red-100 rounded-lg flex items-center justify-center">
              <XCircleIcon className="w-5 h-5 text-red-600" />
            </div>
          </div>
        </div>
        <div className="od-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-2xl font-bold text-blue-600">{stats.encrypted}</div>
              <div className="text-xs text-gray-500">Encrypted</div>
            </div>
            <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-blue-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-1 border-b border-gray-200 bg-gray-50">
        {([
          ['all', `All Devices (${devices.length})`],
          ['compliant', `Compliant (${stats.compliant})`],
          ['non_compliant', `Non-Compliant (${stats.nonCompliant})`],
          ['offline', `Offline (${devices.filter(d => d.status === 'offline').length})`],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`od-tab ${activeTab === key ? 'od-tab-active' : 'od-tab-inactive'}`}>
            {label}
          </button>
        ))}
      </div>

      {/* Device Table */}
      <div className="flex-1 overflow-auto px-6 py-4">
        <div className="od-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-200 bg-gray-50">
                <th className="px-4 py-3">Device</th>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">OS</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Compliance</th>
                <th className="px-4 py-3">Encryption</th>
                <th className="px-4 py-3">Updates</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.map(d => {
                const TypeIcon = typeIcon(d.type);
                return (
                  <tr key={d.id} className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer" onClick={() => setSelectedDevice(d)}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <TypeIcon className="w-4 h-4 text-gray-400" />
                        <div>
                          <div className="font-medium text-gray-900">{d.name}</div>
                          <div className="text-xs text-gray-400">{d.ipAddress}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-700">{d.user}</td>
                    <td className="px-4 py-3">
                      <div className="text-gray-700">{d.os}</div>
                      <div className="text-xs text-gray-400">{d.osVersion}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${statusBadge(d.status)}`}>
                        {d.status === 'syncing' && <ArrowPathIcon className="w-3 h-3 inline animate-spin mr-1" />}
                        {d.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${complianceBadge(d.compliance)}`}>
                        {d.compliance.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {d.encrypted
                        ? <CheckCircleIcon className="w-4 h-4 text-green-600" />
                        : <XCircleIcon className="w-4 h-4 text-red-500" />}
                    </td>
                    <td className="px-4 py-3">
                      {d.pendingUpdates > 0
                        ? <span className="text-orange-600 font-medium">{d.pendingUpdates} pending</span>
                        : <span className="text-green-600 text-xs">Up to date</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {new Date(d.lastSeen).toLocaleString('de-DE')}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={(e) => { e.stopPropagation(); syncDevice(d.id); }}
                        className="p-1 rounded hover:bg-gray-100 text-gray-400 hover:text-blue-600"
                        title="Sync Device"
                      >
                        <ArrowPathIcon className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Device Detail Slide-over */}
      {selectedDevice && (
        <div className="fixed inset-y-0 right-0 w-96 bg-white border-l border-gray-200 shadow-xl z-50 overflow-y-auto">
          <div className="p-6">
            <div className="flex justify-between items-start mb-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">{selectedDevice.name}</h2>
                <p className="text-sm text-gray-500">{selectedDevice.os} {selectedDevice.osVersion}</p>
              </div>
              <button onClick={() => setSelectedDevice(null)} className="text-gray-400 hover:text-gray-600">
                <XCircleIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-gray-50 rounded-lg">
                  <div className="text-xs text-gray-500">Status</div>
                  <span className={`px-2 py-0.5 rounded text-xs ${statusBadge(selectedDevice.status)}`}>{selectedDevice.status}</span>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <div className="text-xs text-gray-500">Compliance</div>
                  <span className={`px-2 py-0.5 rounded text-xs ${complianceBadge(selectedDevice.compliance)}`}>{selectedDevice.compliance.replace('_', ' ')}</span>
                </div>
              </div>

              <div className="od-card p-4">
                <h3 className="text-sm font-semibold text-gray-600 mb-3">Device Details</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between"><span className="text-gray-500">Platform</span><span className="text-gray-700">{platformLabel(selectedDevice.platform)}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Type</span><span className="text-gray-700 capitalize">{selectedDevice.type}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">User</span><span className="text-gray-700">{selectedDevice.user}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">IP Address</span><span className="text-gray-700 font-mono text-xs">{selectedDevice.ipAddress}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Enrolled</span><span className="text-gray-700">{selectedDevice.enrolledAt}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Last Seen</span><span className="text-gray-700">{new Date(selectedDevice.lastSeen).toLocaleString('de-DE')}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Encryption</span><span className={selectedDevice.encrypted ? 'text-green-600' : 'text-red-600'}>{selectedDevice.encrypted ? 'Enabled' : 'Disabled'}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Policies</span><span className="text-gray-700">{selectedDevice.policies} assigned</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Pending Updates</span><span className={selectedDevice.pendingUpdates > 0 ? 'text-orange-600' : 'text-green-600'}>{selectedDevice.pendingUpdates}</span></div>
                </div>
              </div>

              <div className="flex gap-2">
                <button onClick={() => syncDevice(selectedDevice.id)} className="flex-1 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm flex items-center justify-center gap-2 shadow-sm">
                  <ArrowPathIcon className="w-4 h-4" /> Sync Now
                </button>
                <button className="flex-1 px-3 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm flex items-center justify-center gap-2">
                  <ShieldCheckIcon className="w-4 h-4" /> Check Compliance
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
