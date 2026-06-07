'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  ArrowPathIcon,
  PlayIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  BugAntIcon,
  ComputerDesktopIcon,
  ClockIcon,
  DocumentTextIcon,
  TrashIcon,
  ArrowUturnLeftIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  FunnelIcon,
  ServerIcon,
  SignalIcon,
  ArchiveBoxIcon
} from '@heroicons/react/24/outline';
import { securityApi, deviceApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

// ── Types ──────────────────────────────────────────────────────────────────────

interface DeviceAVStatus {
  deviceId: string;
  deviceName: string;
  platform: 'windows' | 'macos' | 'linux';
  clamavVersion: string;
  signatureVersion: string;
  signatureDate: string;
  lastScan: string;
  lastScanType: string;
  threatsFound: number;
  quarantinedFiles: number;
  realtimeProtection: boolean;
  status: 'protected' | 'at_risk' | 'scanning' | 'outdated' | 'offline';
}

interface ScanJob {
  id: string;
  deviceName: string;
  scanType: 'quick' | 'full' | 'custom' | 'memory';
  status: 'queued' | 'scanning' | 'completed' | 'failed';
  progress: number;
  filesScanned: number;
  threatsFound: number;
  startedAt: string;
  duration: string;
}

interface Threat {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  deviceName: string;
  filePath: string;
  fileHash: string;
  detectedAt: string;
  action: 'quarantined' | 'deleted' | 'allowed' | 'pending';
}

interface QuarantineItem {
  id: string;
  fileName: string;
  originalPath: string;
  threatName: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  deviceName: string;
  quarantinedAt: string;
  fileSize: string;
  sha256: string;
}

interface AVStatistics {
  totalDevices: number;
  protectedDevices: number;
  atRiskDevices: number;
  outdatedSignatures: number;
  totalScansToday: number;
  totalThreatsToday: number;
  totalQuarantined: number;
  signatureVersion: string;
}

const emptyStats: AVStatistics = {
  totalDevices: 0,
  protectedDevices: 0,
  atRiskDevices: 0,
  outdatedSignatures: 0,
  totalScansToday: 0,
  totalThreatsToday: 0,
  totalQuarantined: 0,
  signatureVersion: '—',
};

// ── Helpers ────────────────────────────────────────────────────────────────────

const sevBadge = (s: string) =>
  s === 'critical' ? 'od-badge-critical' :
  s === 'high' ? 'od-badge-high' :
  s === 'medium' ? 'od-badge-medium' :
  'od-badge-low';

const statusColor = (s: string) =>
  s === 'protected' ? 'text-green-600' :
  s === 'scanning' ? 'text-blue-600' :
  s === 'at_risk' ? 'text-red-600' :
  s === 'outdated' ? 'text-yellow-600' :
  'text-gray-500';

const statusBadge = (s: string) =>
  s === 'protected' ? 'bg-green-100 text-green-700 border-green-200' :
  s === 'scanning' ? 'bg-blue-100 text-blue-700 border-blue-200' :
  s === 'at_risk' ? 'bg-red-100 text-red-700 border-red-200' :
  s === 'outdated' ? 'bg-yellow-100 text-yellow-700 border-yellow-200' :
  'bg-gray-100 text-gray-600 border-gray-200';

const platformIcon = (p: string) =>
  p === 'windows' ? 'Win' : p === 'macos' ? 'Mac' : 'Lnx';

// ── Component ──────────────────────────────────────────────────────────────────

interface AntivirusViewProps {
  onOpenWizard?: () => void;
}

export default function AntivirusView({ onOpenWizard }: AntivirusViewProps) {
  const { isSimple } = useUiMode();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'devices' | 'scans' | 'threats' | 'quarantine' | 'signatures'>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [usingDemoData, setUsingDemoData] = useState(false);
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [stats, setStats] = useState<AVStatistics>(emptyStats);
  const [devices, setDevices] = useState<DeviceAVStatus[]>([]);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([]);

  useEffect(() => { loadAntivirusData(); }, []);

  const loadAntivirusData = async () => {
    setLoading(true);
    try {
      const [threatRes, quarantineRes, scansRes, statsRes, devicesRes] = await Promise.allSettled([
        securityApi.getThreats(),
        securityApi.getQuarantine(),
        securityApi.getScans(),
        securityApi.getAvDashboard(),
        securityApi.getAvDevices(),
      ]);

      let apiDataFound = false;

      if (threatRes.status === 'fulfilled') {
        const d = threatRes.value.data;
        const list = Array.isArray(d) ? d : d?.threats ?? [];
        if (list.length > 0) { setThreats(list); apiDataFound = true; }
      }

      if (quarantineRes.status === 'fulfilled') {
        const d = quarantineRes.value.data;
        const list = Array.isArray(d) ? d : d?.quarantine ?? [];
        if (list.length > 0) { setQuarantine(list); apiDataFound = true; }
      }

      if (scansRes.status === 'fulfilled') {
        const d = scansRes.value.data;
        const list = Array.isArray(d) ? d : d?.scans ?? [];
        if (list.length > 0) { setScans(list); apiDataFound = true; }
      }

      if (statsRes.status === 'fulfilled' && statsRes.value.data) {
        const d = statsRes.value.data;
        const s = d.statistics ?? d.stats ?? d;
        if (s?.totalDevices != null || s?.threatsFound != null) {
          setStats({ ...emptyStats, ...s });
          apiDataFound = true;
        }
      }

      if (devicesRes.status === 'fulfilled') {
        const d = devicesRes.value.data;
        const list = Array.isArray(d) ? d : d?.devices ?? [];
        if (list.length > 0) { setDevices(list); apiDataFound = true; }
      }

      setUsingDemoData(!apiDataFound);
    } catch {
      setUsingDemoData(true);
    } finally {
      setLoading(false);
    }
  };

  const startFleetScan = async () => {
    setScanning(true);
    try {
      await securityApi.startScan(undefined, 'quick');
      await loadAntivirusData();
    } catch {
      // scan queued, reload when done
    } finally {
      setScanning(false);
    }
  };

  const filteredThreats = severityFilter === 'all'
    ? threats
    : threats.filter(t => t.severity === severityFilter);

  // ── Simple Mode ──
  if (isSimple) {
    const allProtected = stats.atRiskDevices === 0;
    const activeScans = scans.filter(s => s.status === 'scanning');
    const recentThreats = threats.slice(0, 3);

    return (
      <SimpleViewLayout
        hero={{
          status: stats.atRiskDevices > 0 ? 'critical' : 'ok',
          icon: allProtected
            ? <ShieldCheckIcon className="w-10 h-10 text-green-600" />
            : <ExclamationTriangleIcon className="w-10 h-10 text-red-600" />,
          title: allProtected
            ? 'All Devices Protected'
            : `${stats.atRiskDevices} Device${stats.atRiskDevices > 1 ? 's' : ''} at Risk`,
          subtitle: `${stats.protectedDevices} of ${stats.totalDevices} devices protected`,
        }}
        stats={[
          { value: stats.protectedDevices, label: 'Protected', color: 'text-green-600' },
          { value: stats.totalScansToday, label: 'Scans Today', color: 'text-blue-600' },
          { value: stats.totalThreatsToday, label: 'Threats Today', color: stats.totalThreatsToday > 0 ? 'text-red-600' : 'text-gray-600' },
          { value: stats.totalQuarantined, label: 'Quarantined', color: 'text-amber-600' },
        ]}
        sections={recentThreats.length > 0 ? [{
          title: 'Recent Threats',
          items: recentThreats.map(threat => ({
            key: threat.id,
            icon: <BugAntIcon className={`w-5 h-5 ${threat.severity === 'critical' ? 'text-red-500' : threat.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />,
            title: threat.name,
            subtitle: `${threat.deviceName} · ${threat.type}`,
            trailing: (
              <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                threat.severity === 'critical' ? 'bg-red-100 text-red-700' :
                threat.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                'bg-blue-100 text-blue-700'
              }`}>
                {threat.action}
              </span>
            ),
          })),
        }] : []}
        actions={[
          { label: scanning ? 'Scanning...' : 'Fleet Scan', icon: <PlayIcon className="h-4 w-4" />, onClick: startFleetScan, disabled: scanning },
          ...(onOpenWizard ? [{ label: 'Security Setup', onClick: onOpenWizard, variant: 'secondary' as const }] : []),
        ]}
      >
        {/* Active scans */}
        {activeScans.length > 0 && (
          <div className="bg-blue-50 rounded-xl border border-blue-200 p-5">
            <h3 className="text-sm font-semibold text-blue-800 mb-3">Active Scans</h3>
            {activeScans.map(scan => (
              <div key={scan.id} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ArrowPathIcon className="w-4 h-4 text-blue-600 animate-spin" />
                  <span className="text-sm text-blue-900">{scan.deviceName}</span>
                  <span className="text-xs text-blue-600">{scan.scanType}</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-24 bg-blue-200 rounded-full h-2">
                    <div className="bg-blue-600 h-2 rounded-full" style={{ width: `${scan.progress}%` }} />
                  </div>
                  <span className="text-xs text-blue-700">{scan.progress}%</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </SimpleViewLayout>
    );
  }

  // ── Expert Mode ──
  return (
    <div className="flex flex-col h-full">
      {/* Demo data banner */}
      {usingDemoData && (
        <div className="mx-6 mt-4 p-3 bg-yellow-50 border border-yellow-300 rounded-lg flex items-center gap-2 text-yellow-800 text-sm">
          <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500 shrink-0" />
          <span>Demo-Modus: API nicht erreichbar. Gezeigte Daten sind Beispieldaten.</span>
        </div>
      )}
      {/* Loading skeleton */}
      {loading && (
        <div className="flex-1 p-6 space-y-4 animate-pulse">
          <div className="grid grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-gray-200 rounded-xl" />)}
          </div>
          <div className="h-40 bg-gray-200 rounded-xl" />
          <div className="h-32 bg-gray-200 rounded-xl" />
        </div>
      )}
      {/* Header + Tabs + Content (hidden while loading) */}
      {!loading && <>
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            <ShieldCheckIcon className="w-6 h-6 text-green-600" /> ClamAV Antivirus Protection
          </h1>
          <p className="text-sm text-gray-500">Fleet-wide antivirus management powered by ClamAV</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 bg-gray-100 px-3 py-1.5 rounded-lg border border-gray-200">
            <SignalIcon className="w-3 h-3 inline mr-1" />
            Signatures: {stats.signatureVersion}
          </span>
          {onOpenWizard && (
            <button onClick={onOpenWizard} className="px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 text-sm font-medium transition-colors">
              Security-Assistent
            </button>
          )}
          <button onClick={startFleetScan} disabled={scanning}
            className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 rounded-lg text-sm text-white flex items-center gap-2 shadow-sm">
            {scanning ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />}
            {scanning ? 'Scanning...' : 'Fleet Scan'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-200 bg-gray-50">
        {([
          ['dashboard', 'Dashboard'],
          ['devices', `Devices (${devices.length})`],
          ['scans', `Scans (${scans.length})`],
          ['threats', `Threats (${threats.length})`],
          ['quarantine', `Quarantine (${quarantine.length})`],
          ['signatures', 'Signatures'],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`od-tab ${activeTab === key ? 'od-tab-active' : 'od-tab-inactive'}`}>
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {/* ── Dashboard ──────────────────────────────────────────────────── */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="od-card p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-green-600">{stats.protectedDevices}</div>
                    <div className="text-sm text-gray-500">Protected</div>
                  </div>
                  <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                    <ShieldCheckIcon className="w-6 h-6 text-green-600" />
                  </div>
                </div>
                <div className="mt-2 text-xs text-gray-400">of {stats.totalDevices} devices</div>
              </div>
              <div className="od-card p-4 border-red-200">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-red-600">{stats.atRiskDevices}</div>
                    <div className="text-sm text-gray-500">At Risk</div>
                  </div>
                  <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
                    <ExclamationTriangleIcon className="w-6 h-6 text-red-600" />
                  </div>
                </div>
                <div className="mt-2 text-xs text-gray-400">need attention</div>
              </div>
              <div className="od-card p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-blue-600">{stats.totalScansToday}</div>
                    <div className="text-sm text-gray-500">Scans Today</div>
                  </div>
                  <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                    <ArrowPathIcon className="w-6 h-6 text-blue-600" />
                  </div>
                </div>
              </div>
              <div className="od-card p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-orange-600">{stats.totalThreatsToday}</div>
                    <div className="text-sm text-gray-500">Threats Today</div>
                  </div>
                  <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center">
                    <BugAntIcon className="w-6 h-6 text-orange-600" />
                  </div>
                </div>
              </div>
            </div>

            {/* Threat Trend Chart */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-4">Threats Detected (Last 7 Days)</h3>
              <div className="flex items-end gap-3 h-32">
                {threatTrends.map(t => (
                  <div key={t.date} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs text-gray-600">{t.threats}</span>
                    <div className="w-full rounded-t relative" style={{ height: `${Math.max(t.threats * 15, 4)}px` }}>
                      <div className={`absolute bottom-0 w-full rounded-t ${t.threats > 5 ? 'bg-red-500' : t.threats > 2 ? 'bg-orange-500' : 'bg-green-500'}`}
                        style={{ height: '100%' }} />
                    </div>
                    <span className="text-xs text-gray-500">{new Date(t.date).toLocaleDateString('de-DE', { weekday: 'short' })}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Active Scans */}
            {scans.filter(s => s.status === 'scanning').length > 0 && (
              <div className="od-card p-4 border-blue-200">
                <h3 className="text-sm font-semibold text-blue-700 mb-3">Active Scans</h3>
                {scans.filter(s => s.status === 'scanning').map(scan => (
                  <div key={scan.id} className="flex items-center gap-4">
                    <ArrowPathIcon className="w-5 h-5 text-blue-600 animate-spin" />
                    <div className="flex-1">
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-gray-900">{scan.deviceName} - {scan.scanType} scan</span>
                        <span className="text-gray-500">{scan.filesScanned.toLocaleString()} files</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div className="bg-blue-600 h-2 rounded-full transition-all" style={{ width: `${scan.progress}%` }} />
                      </div>
                    </div>
                    <span className="text-sm text-blue-600 font-medium">{scan.progress}%</span>
                  </div>
                ))}
              </div>
            )}

            {/* Recent Threats */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-3">Recent Threats</h3>
              <div className="space-y-2">
                {threats.length === 0 && (
                  <p className="text-sm text-gray-400 text-center py-4">Keine Bedrohungen gefunden</p>
                )}
                {threats.slice(0, 5).map(t => (
                  <div key={t.id} className="flex items-center gap-3 text-sm p-2 rounded-lg hover:bg-gray-50">
                    <BugAntIcon className={`w-4 h-4 ${t.severity === 'critical' ? 'text-red-500' : t.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />
                    <span className="font-mono text-xs text-gray-700 flex-1 truncate">{t.name}</span>
                    <span className="text-gray-500">{t.deviceName}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${sevBadge(t.severity)}`}>{t.severity}</span>
                    <span className={`text-xs ${t.action === 'quarantined' ? 'text-amber-600' : t.action === 'deleted' ? 'text-red-600' : 'text-gray-500'}`}>{t.action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Devices ────────────────────────────────────────────────────── */}
        {activeTab === 'devices' && (
          <div className="od-card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-200 bg-gray-50">
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">Platform</th>
                  <th className="px-4 py-3">ClamAV</th>
                  <th className="px-4 py-3">Signatures</th>
                  <th className="px-4 py-3">Last Scan</th>
                  <th className="px-4 py-3">Threats</th>
                  <th className="px-4 py-3">Real-time</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.length === 0 && (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-sm text-gray-400">Keine Geräte mit Antivirus-Status gefunden</td></tr>
                )}
                {devices.map(d => (
                  <tr key={d.deviceId} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="px-4 py-3 font-medium text-gray-900 flex items-center gap-2">
                      <ComputerDesktopIcon className="w-4 h-4 text-gray-400" />
                      {d.deviceName}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-gray-100 text-xs text-gray-700">{platformIcon(d.platform)}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-500 font-mono text-xs">{d.clamavVersion}</td>
                    <td className="px-4 py-3">
                      <span className={`font-mono text-xs ${d.signatureVersion === '27180' ? 'text-green-600' : 'text-yellow-600'}`}>
                        {d.signatureVersion}
                      </span>
                      <span className="text-xs text-gray-400 ml-1">({d.signatureDate})</span>
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{new Date(d.lastScan).toLocaleString('de-DE')}</td>
                    <td className="px-4 py-3">
                      {d.threatsFound > 0
                        ? <span className="text-red-600 font-medium">{d.threatsFound}</span>
                        : <span className="text-green-600">0</span>}
                    </td>
                    <td className="px-4 py-3">
                      {d.realtimeProtection
                        ? <CheckCircleIcon className="w-4 h-4 text-green-600" />
                        : <XCircleIcon className="w-4 h-4 text-red-500" />}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs border ${statusBadge(d.status)}`}>
                        {d.status === 'scanning' && <ArrowPathIcon className="w-3 h-3 inline animate-spin mr-1" />}
                        {d.status.replace('_', ' ')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Scans ──────────────────────────────────────────────────────── */}
        {activeTab === 'scans' && (
          <div className="space-y-3">
            {scans.length === 0 && (
              <div className="od-card p-8 text-center text-sm text-gray-400">Keine Scan-Jobs gefunden</div>
            )}
            {scans.map(scan => (
              <div key={scan.id} className={`od-card p-4 ${scan.status === 'scanning' ? 'border-blue-200' : scan.status === 'failed' ? 'border-red-200' : ''}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    {scan.status === 'scanning' ? <ArrowPathIcon className="w-5 h-5 text-blue-600 animate-spin" /> :
                     scan.status === 'completed' ? <CheckCircleIcon className="w-5 h-5 text-green-600" /> :
                     <XCircleIcon className="w-5 h-5 text-red-500" />}
                    <div>
                      <span className="font-medium text-gray-900">{scan.deviceName}</span>
                      <span className="text-gray-500 text-sm ml-2">{scan.scanType} scan</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-sm">
                    <span className="text-gray-500"><ClockIcon className="w-4 h-4 inline mr-1" />{scan.duration}</span>
                    {scan.threatsFound > 0 && <span className="text-red-600"><BugAntIcon className="w-4 h-4 inline mr-1" />{scan.threatsFound} threats</span>}
                    <span className="text-gray-500">{scan.filesScanned.toLocaleString()} files</span>
                  </div>
                </div>
                {scan.status === 'scanning' && (
                  <div className="w-full bg-gray-200 rounded-full h-1.5 mt-2">
                    <div className="bg-blue-600 h-1.5 rounded-full transition-all" style={{ width: `${scan.progress}%` }} />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── Threats ────────────────────────────────────────────────────── */}
        {activeTab === 'threats' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              {['all', 'critical', 'high', 'medium', 'low'].map(s => (
                <button key={s} onClick={() => setSeverityFilter(s)}
                  className={`px-3 py-1 text-xs rounded-lg ${severityFilter === s ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:text-gray-900 hover:bg-gray-200'}`}>
                  {s === 'all' ? `All (${threats.length})` : `${s} (${threats.filter(t => t.severity === s).length})`}
                </button>
              ))}
            </div>
            {filteredThreats.length === 0 && (
              <div className="od-card p-8 text-center text-sm text-gray-400">Keine Bedrohungen gefunden</div>
            )}
            {filteredThreats.map(t => (
              <div key={t.id} className="od-card overflow-hidden">
                <button onClick={() => setExpandedThreat(expandedThreat === t.id ? null : t.id)}
                  className="w-full p-4 flex items-center gap-3 text-left hover:bg-gray-50">
                  <BugAntIcon className={`w-5 h-5 shrink-0 ${t.severity === 'critical' ? 'text-red-500' : t.severity === 'high' ? 'text-orange-500' : t.severity === 'medium' ? 'text-yellow-500' : 'text-blue-500'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-sm text-gray-900 truncate">{t.name}</div>
                    <div className="text-xs text-gray-500">{t.deviceName} - {t.type}</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs ${sevBadge(t.severity)}`}>{t.severity}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${t.action === 'quarantined' ? 'bg-amber-100 text-amber-700' : t.action === 'deleted' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'}`}>{t.action}</span>
                  {expandedThreat === t.id ? <ChevronUpIcon className="w-4 h-4 text-gray-400" /> : <ChevronDownIcon className="w-4 h-4 text-gray-400" />}
                </button>
                {expandedThreat === t.id && (
                  <div className="px-4 pb-4 border-t border-gray-100 pt-3 space-y-2">
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div><span className="text-gray-500">File:</span> <span className="text-gray-700 font-mono text-xs">{t.filePath}</span></div>
                      <div><span className="text-gray-500">SHA256:</span> <span className="text-gray-700 font-mono text-xs">{t.fileHash}</span></div>
                      <div><span className="text-gray-500">Detected:</span> <span className="text-gray-700">{new Date(t.detectedAt).toLocaleString('de-DE')}</span></div>
                      <div><span className="text-gray-500">Device:</span> <span className="text-gray-700">{t.deviceName}</span></div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── Quarantine ─────────────────────────────────────────────────── */}
        {activeTab === 'quarantine' && (
          <div className="space-y-3">
            <p className="text-sm text-gray-500">Quarantined files are isolated and cannot execute. Review and take action.</p>
            {quarantine.length === 0 && (
              <div className="od-card p-8 text-center text-sm text-gray-400">Keine Dateien in Quarantäne</div>
            )}
            {quarantine.map(q => (
              <div key={q.id} className="od-card p-4 flex items-start gap-4">
                <ArchiveBoxIcon className="w-5 h-5 text-amber-500 shrink-0 mt-1" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-medium text-sm text-gray-900">{q.fileName}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${sevBadge(q.severity)}`}>{q.severity}</span>
                  </div>
                  <div className="text-xs text-gray-500 mb-1">{q.threatName}</div>
                  <div className="text-xs text-gray-400 font-mono truncate">{q.originalPath}</div>
                  <div className="flex gap-4 text-xs text-gray-500 mt-1">
                    <span>{q.deviceName}</span>
                    <span>{q.fileSize}</span>
                    <span>{new Date(q.quarantinedAt).toLocaleString('de-DE')}</span>
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button className="p-1.5 rounded bg-gray-100 hover:bg-yellow-100 text-yellow-600 border border-gray-200" title="Restore">
                    <ArrowUturnLeftIcon className="w-4 h-4" />
                  </button>
                  <button className="p-1.5 rounded bg-gray-100 hover:bg-red-100 text-red-600 border border-gray-200" title="Delete permanently">
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Signatures ─────────────────────────────────────────────────── */}
        {activeTab === 'signatures' && (
          <div className="space-y-4">
            {/* Current version */}
            <div className="od-card p-5 border-green-200">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-gray-900 flex items-center gap-2">
                    <ServerIcon className="w-5 h-5 text-green-600" />
                    Current Signature Database
                  </h3>
                  <div className="mt-2 grid grid-cols-3 gap-6 text-sm">
                    <div>
                      <span className="text-gray-500">Version:</span>
                      <span className="ml-2 font-mono text-green-600">27180</span>
                    </div>
                    <div>
                      <span className="text-gray-500">ClamAV:</span>
                      <span className="ml-2 font-mono text-gray-700">0.104.3</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Last Updated:</span>
                      <span className="ml-2 text-gray-700">2026-03-15 06:00 UTC</span>
                    </div>
                  </div>
                  <div className="mt-2 text-sm">
                    <span className="text-gray-500">Total Signatures:</span>
                    <span className="ml-2 text-gray-700">8,654,320</span>
                  </div>
                </div>
                <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-sm text-white flex items-center gap-2 shadow-sm">
                  <ArrowPathIcon className="w-4 h-4" /> Update Now
                </button>
              </div>
            </div>

            {/* Fleet signature status */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-3">Fleet Signature Status</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 bg-gray-50 rounded-lg text-center">
                  <div className="text-2xl font-bold text-green-600">{stats.totalDevices - stats.outdatedSignatures}</div>
                  <div className="text-xs text-gray-500">Up to Date</div>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg text-center">
                  <div className="text-2xl font-bold text-yellow-600">{stats.outdatedSignatures}</div>
                  <div className="text-xs text-gray-500">Outdated</div>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg text-center">
                  <div className="text-2xl font-bold text-gray-600">4h</div>
                  <div className="text-xs text-gray-500">Update Interval</div>
                </div>
              </div>
            </div>

            {/* Update schedule */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-3">freshclam Update Schedule</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Server freshclam interval</span>
                  <span className="text-gray-700">Every 4 hours</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Client push update</span>
                  <span className="text-gray-700">Within 30 minutes of server update</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Mirror source</span>
                  <span className="text-gray-700 font-mono text-xs">database.clamav.net</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Custom signatures</span>
                  <span className="text-gray-700">12 custom rules active</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      </>}
    </div>
  );
}
