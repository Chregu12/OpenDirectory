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

// ── Mock Data ──────────────────────────────────────────────────────────────────

const mockStats: AVStatistics = {
  totalDevices: 245,
  protectedDevices: 228,
  atRiskDevices: 8,
  outdatedSignatures: 9,
  totalScansToday: 1420,
  totalThreatsToday: 7,
  totalQuarantined: 34,
  signatureVersion: 'ClamAV 0.104.3 / 27180 / 2026-03-15',
};

const mockDevices: DeviceAVStatus[] = [
  { deviceId: 'd-1', deviceName: 'WS-001', platform: 'windows', clamavVersion: '0.104.3', signatureVersion: '27180', signatureDate: '2026-03-15', lastScan: '2026-03-15T08:00:00Z', lastScanType: 'quick', threatsFound: 0, quarantinedFiles: 0, realtimeProtection: true, status: 'protected' },
  { deviceId: 'd-2', deviceName: 'LAPTOP-23', platform: 'windows', clamavVersion: '0.104.3', signatureVersion: '27180', signatureDate: '2026-03-15', lastScan: '2026-03-15T07:30:00Z', lastScanType: 'full', threatsFound: 2, quarantinedFiles: 2, realtimeProtection: true, status: 'at_risk' },
  { deviceId: 'd-3', deviceName: 'SRV-DC01', platform: 'windows', clamavVersion: '0.104.3', signatureVersion: '27180', signatureDate: '2026-03-15', lastScan: '2026-03-15T02:00:00Z', lastScanType: 'full', threatsFound: 0, quarantinedFiles: 0, realtimeProtection: true, status: 'protected' },
  { deviceId: 'd-4', deviceName: 'MAC-DEV-01', platform: 'macos', clamavVersion: '0.104.3', signatureVersion: '27178', signatureDate: '2026-03-13', lastScan: '2026-03-14T18:00:00Z', lastScanType: 'quick', threatsFound: 0, quarantinedFiles: 0, realtimeProtection: true, status: 'outdated' },
  { deviceId: 'd-5', deviceName: 'SRV-FILE01', platform: 'linux', clamavVersion: '0.104.3', signatureVersion: '27180', signatureDate: '2026-03-15', lastScan: '2026-03-15T06:00:00Z', lastScanType: 'full', threatsFound: 1, quarantinedFiles: 1, realtimeProtection: true, status: 'protected' },
  { deviceId: 'd-6', deviceName: 'WS-012', platform: 'windows', clamavVersion: '0.104.2', signatureVersion: '27165', signatureDate: '2026-03-01', lastScan: '2026-03-10T08:00:00Z', lastScanType: 'quick', threatsFound: 0, quarantinedFiles: 0, realtimeProtection: false, status: 'at_risk' },
  { deviceId: 'd-7', deviceName: 'LINUX-BUILD-01', platform: 'linux', clamavVersion: '0.104.3', signatureVersion: '27180', signatureDate: '2026-03-15', lastScan: '2026-03-15T04:00:00Z', lastScanType: 'full', threatsFound: 0, quarantinedFiles: 0, realtimeProtection: true, status: 'protected' },
  { deviceId: 'd-8', deviceName: 'MAC-EXEC-01', platform: 'macos', clamavVersion: '0.104.3', signatureVersion: '27180', signatureDate: '2026-03-15', lastScan: '2026-03-15T09:00:00Z', lastScanType: 'quick', threatsFound: 0, quarantinedFiles: 0, realtimeProtection: true, status: 'scanning' },
];

const mockScans: ScanJob[] = [
  { id: 'scan-1', deviceName: 'MAC-EXEC-01', scanType: 'quick', status: 'scanning', progress: 67, filesScanned: 34200, threatsFound: 0, startedAt: '2026-03-15T09:00:00Z', duration: '3m 24s' },
  { id: 'scan-2', deviceName: 'LAPTOP-23', scanType: 'full', status: 'completed', progress: 100, filesScanned: 892341, threatsFound: 2, startedAt: '2026-03-15T07:30:00Z', duration: '47m 12s' },
  { id: 'scan-3', deviceName: 'SRV-FILE01', scanType: 'full', status: 'completed', progress: 100, filesScanned: 1245000, threatsFound: 1, startedAt: '2026-03-15T06:00:00Z', duration: '1h 23m' },
  { id: 'scan-4', deviceName: 'WS-001', scanType: 'quick', status: 'completed', progress: 100, filesScanned: 45200, threatsFound: 0, startedAt: '2026-03-15T08:00:00Z', duration: '5m 8s' },
  { id: 'scan-5', deviceName: 'SRV-DC01', scanType: 'full', status: 'completed', progress: 100, filesScanned: 567000, threatsFound: 0, startedAt: '2026-03-15T02:00:00Z', duration: '58m 44s' },
];

const mockThreats: Threat[] = [
  { id: 't-1', name: 'Win.Trojan.Agent-798234', severity: 'critical', type: 'Trojan', deviceName: 'LAPTOP-23', filePath: 'C:\\Users\\k.chen\\Downloads\\setup_crack.exe', fileHash: 'a1b2c3d4e5f6...', detectedAt: '2026-03-15T07:45:00Z', action: 'quarantined' },
  { id: 't-2', name: 'Win.Malware.CoinMiner-9823', severity: 'high', type: 'Cryptominer', deviceName: 'LAPTOP-23', filePath: 'C:\\Users\\k.chen\\AppData\\Local\\Temp\\svchost.exe', fileHash: 'f6e5d4c3b2a1...', detectedAt: '2026-03-15T07:46:00Z', action: 'quarantined' },
  { id: 't-3', name: 'Unix.Trojan.Mirai-234', severity: 'high', type: 'Trojan', deviceName: 'SRV-FILE01', filePath: '/tmp/.hidden/payload.bin', fileHash: '1a2b3c4d5e6f...', detectedAt: '2026-03-15T06:22:00Z', action: 'quarantined' },
  { id: 't-4', name: 'Win.Adware.BrowserHelper-12', severity: 'low', type: 'Adware', deviceName: 'WS-007', filePath: 'C:\\Users\\s.patel\\AppData\\Local\\BrowserHelper.dll', fileHash: '9f8e7d6c5b4a...', detectedAt: '2026-03-14T14:30:00Z', action: 'quarantined' },
  { id: 't-5', name: 'Doc.Exploit.CVE-2024-1234', severity: 'critical', type: 'Exploit', deviceName: 'WS-019', filePath: 'C:\\Users\\m.jones\\Documents\\Invoice_Q1.docx', fileHash: '2b3c4d5e6f7a...', detectedAt: '2026-03-14T10:15:00Z', action: 'quarantined' },
  { id: 't-6', name: 'Win.PUA.CrackTool-45', severity: 'medium', type: 'PUA', deviceName: 'WS-003', filePath: 'C:\\Users\\temp\\Desktop\\keygen.exe', fileHash: '3c4d5e6f7a8b...', detectedAt: '2026-03-13T16:00:00Z', action: 'deleted' },
  { id: 't-7', name: 'Phishing.Email.FakeLogin-87', severity: 'medium', type: 'Phishing', deviceName: 'MAC-DEV-01', filePath: '/Users/dev/Mail/Attachments/login_verify.html', fileHash: '4d5e6f7a8b9c...', detectedAt: '2026-03-13T09:20:00Z', action: 'quarantined' },
];

const mockQuarantine: QuarantineItem[] = [
  { id: 'q-1', fileName: 'setup_crack.exe', originalPath: 'C:\\Users\\k.chen\\Downloads\\setup_crack.exe', threatName: 'Win.Trojan.Agent-798234', severity: 'critical', deviceName: 'LAPTOP-23', quarantinedAt: '2026-03-15T07:45:00Z', fileSize: '2.4 MB', sha256: 'a1b2c3d4e5f67890...' },
  { id: 'q-2', fileName: 'svchost.exe', originalPath: 'C:\\Users\\k.chen\\AppData\\Local\\Temp\\svchost.exe', threatName: 'Win.Malware.CoinMiner-9823', severity: 'high', deviceName: 'LAPTOP-23', quarantinedAt: '2026-03-15T07:46:00Z', fileSize: '856 KB', sha256: 'f6e5d4c3b2a19876...' },
  { id: 'q-3', fileName: 'payload.bin', originalPath: '/tmp/.hidden/payload.bin', threatName: 'Unix.Trojan.Mirai-234', severity: 'high', deviceName: 'SRV-FILE01', quarantinedAt: '2026-03-15T06:22:00Z', fileSize: '124 KB', sha256: '1a2b3c4d5e6f7890...' },
  { id: 'q-4', fileName: 'BrowserHelper.dll', originalPath: 'C:\\Users\\s.patel\\AppData\\Local\\BrowserHelper.dll', threatName: 'Win.Adware.BrowserHelper-12', severity: 'low', deviceName: 'WS-007', quarantinedAt: '2026-03-14T14:30:00Z', fileSize: '340 KB', sha256: '9f8e7d6c5b4a3210...' },
  { id: 'q-5', fileName: 'Invoice_Q1.docx', originalPath: 'C:\\Users\\m.jones\\Documents\\Invoice_Q1.docx', threatName: 'Doc.Exploit.CVE-2024-1234', severity: 'critical', deviceName: 'WS-019', quarantinedAt: '2026-03-14T10:15:00Z', fileSize: '78 KB', sha256: '2b3c4d5e6f7a8b90...' },
  { id: 'q-6', fileName: 'login_verify.html', originalPath: '/Users/dev/Mail/Attachments/login_verify.html', threatName: 'Phishing.Email.FakeLogin-87', severity: 'medium', deviceName: 'MAC-DEV-01', quarantinedAt: '2026-03-13T09:20:00Z', fileSize: '12 KB', sha256: '4d5e6f7a8b9c0123...' },
];

const threatTrends = [
  { date: '2026-03-09', threats: 3 },
  { date: '2026-03-10', threats: 1 },
  { date: '2026-03-11', threats: 5 },
  { date: '2026-03-12', threats: 2 },
  { date: '2026-03-13', threats: 4 },
  { date: '2026-03-14', threats: 3 },
  { date: '2026-03-15', threats: 7 },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

const sevColor = (s: string) =>
  s === 'critical' ? 'bg-red-900/40 text-red-300' :
  s === 'high' ? 'bg-orange-900/40 text-orange-300' :
  s === 'medium' ? 'bg-yellow-900/40 text-yellow-300' :
  'bg-blue-900/40 text-blue-300';

const statusColor = (s: string) =>
  s === 'protected' ? 'text-green-400' :
  s === 'scanning' ? 'text-blue-400' :
  s === 'at_risk' ? 'text-red-400' :
  s === 'outdated' ? 'text-yellow-400' :
  'text-gray-500';

const statusBadge = (s: string) =>
  s === 'protected' ? 'bg-green-900/30 text-green-400 border-green-800' :
  s === 'scanning' ? 'bg-blue-900/30 text-blue-400 border-blue-800' :
  s === 'at_risk' ? 'bg-red-900/30 text-red-400 border-red-800' :
  s === 'outdated' ? 'bg-yellow-900/30 text-yellow-400 border-yellow-800' :
  'bg-gray-900/30 text-gray-400 border-gray-800';

const platformIcon = (p: string) =>
  p === 'windows' ? 'Win' : p === 'macos' ? 'Mac' : 'Lnx';

// ── Component ──────────────────────────────────────────────────────────────────

export default function AntivirusView() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'devices' | 'scans' | 'threats' | 'quarantine' | 'signatures'>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');

  const startFleetScan = async () => {
    setScanning(true);
    await new Promise(r => setTimeout(r, 2000));
    setScanning(false);
  };

  const filteredThreats = severityFilter === 'all'
    ? mockThreats
    : mockThreats.filter(t => t.severity === severityFilter);

  return (
    <div className="flex flex-col h-full bg-gray-950 text-gray-100">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <ShieldCheckIcon className="w-6 h-6 text-green-400" /> ClamAV Antivirus Protection
          </h1>
          <p className="text-sm text-gray-500">Fleet-wide antivirus management powered by ClamAV</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 bg-gray-900 px-3 py-1.5 rounded-lg">
            <SignalIcon className="w-3 h-3 inline mr-1" />
            Signatures: {mockStats.signatureVersion}
          </span>
          <button onClick={startFleetScan} disabled={scanning}
            className="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:opacity-50 rounded-lg text-sm flex items-center gap-2">
            {scanning ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />}
            {scanning ? 'Scanning...' : 'Fleet Scan'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-800">
        {([
          ['dashboard', 'Dashboard'],
          ['devices', `Devices (${mockDevices.length})`],
          ['scans', `Scans (${mockScans.length})`],
          ['threats', `Threats (${mockThreats.length})`],
          ['quarantine', `Quarantine (${mockQuarantine.length})`],
          ['signatures', 'Signatures'],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`px-4 py-2 text-sm rounded-t-lg transition-colors ${activeTab === key ? 'bg-gray-800 text-white border-t border-x border-gray-700' : 'text-gray-500 hover:text-gray-300'}`}>
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
              <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-green-400">{mockStats.protectedDevices}</div>
                    <div className="text-sm text-gray-500">Protected</div>
                  </div>
                  <ShieldCheckIcon className="w-8 h-8 text-green-600/30" />
                </div>
                <div className="mt-2 text-xs text-gray-600">of {mockStats.totalDevices} devices</div>
              </div>
              <div className="p-4 rounded-lg bg-gray-900 border border-red-900/30">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-red-400">{mockStats.atRiskDevices}</div>
                    <div className="text-sm text-gray-500">At Risk</div>
                  </div>
                  <ExclamationTriangleIcon className="w-8 h-8 text-red-600/30" />
                </div>
                <div className="mt-2 text-xs text-gray-600">need attention</div>
              </div>
              <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-blue-400">{mockStats.totalScansToday}</div>
                    <div className="text-sm text-gray-500">Scans Today</div>
                  </div>
                  <ArrowPathIcon className="w-8 h-8 text-blue-600/30" />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-3xl font-bold text-orange-400">{mockStats.totalThreatsToday}</div>
                    <div className="text-sm text-gray-500">Threats Today</div>
                  </div>
                  <BugAntIcon className="w-8 h-8 text-orange-600/30" />
                </div>
              </div>
            </div>

            {/* Threat Trend Chart */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <h3 className="text-sm font-semibold text-gray-400 mb-4">Threats Detected (Last 7 Days)</h3>
              <div className="flex items-end gap-3 h-32">
                {threatTrends.map(t => (
                  <div key={t.date} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs text-gray-400">{t.threats}</span>
                    <div className="w-full rounded-t relative" style={{ height: `${Math.max(t.threats * 15, 4)}px` }}>
                      <div className={`absolute bottom-0 w-full rounded-t ${t.threats > 5 ? 'bg-red-600' : t.threats > 2 ? 'bg-orange-600' : 'bg-green-600'}`}
                        style={{ height: '100%' }} />
                    </div>
                    <span className="text-xs text-gray-600">{new Date(t.date).toLocaleDateString('de-DE', { weekday: 'short' })}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Active Scans */}
            {mockScans.filter(s => s.status === 'scanning').length > 0 && (
              <div className="p-4 rounded-lg bg-gray-900 border border-blue-900/30">
                <h3 className="text-sm font-semibold text-blue-400 mb-3">Active Scans</h3>
                {mockScans.filter(s => s.status === 'scanning').map(scan => (
                  <div key={scan.id} className="flex items-center gap-4">
                    <ArrowPathIcon className="w-5 h-5 text-blue-400 animate-spin" />
                    <div className="flex-1">
                      <div className="flex justify-between text-sm mb-1">
                        <span>{scan.deviceName} - {scan.scanType} scan</span>
                        <span className="text-gray-500">{scan.filesScanned.toLocaleString()} files</span>
                      </div>
                      <div className="w-full bg-gray-800 rounded-full h-2">
                        <div className="bg-blue-500 h-2 rounded-full transition-all" style={{ width: `${scan.progress}%` }} />
                      </div>
                    </div>
                    <span className="text-sm text-blue-400">{scan.progress}%</span>
                  </div>
                ))}
              </div>
            )}

            {/* Recent Threats */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Recent Threats</h3>
              <div className="space-y-2">
                {mockThreats.slice(0, 5).map(t => (
                  <div key={t.id} className="flex items-center gap-3 text-sm">
                    <BugAntIcon className={`w-4 h-4 ${t.severity === 'critical' ? 'text-red-500' : t.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />
                    <span className="font-mono text-xs text-gray-300 flex-1 truncate">{t.name}</span>
                    <span className="text-gray-500">{t.deviceName}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${sevColor(t.severity)}`}>{t.severity}</span>
                    <span className={`text-xs ${t.action === 'quarantined' ? 'text-amber-400' : t.action === 'deleted' ? 'text-red-400' : 'text-gray-500'}`}>{t.action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Devices ────────────────────────────────────────────────────── */}
        {activeTab === 'devices' && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-2 pr-4">Device</th>
                  <th className="pb-2 pr-4">Platform</th>
                  <th className="pb-2 pr-4">ClamAV</th>
                  <th className="pb-2 pr-4">Signatures</th>
                  <th className="pb-2 pr-4">Last Scan</th>
                  <th className="pb-2 pr-4">Threats</th>
                  <th className="pb-2 pr-4">Real-time</th>
                  <th className="pb-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {mockDevices.map(d => (
                  <tr key={d.deviceId} className="border-b border-gray-900 hover:bg-gray-900/50">
                    <td className="py-3 pr-4 font-medium flex items-center gap-2">
                      <ComputerDesktopIcon className="w-4 h-4 text-gray-500" />
                      {d.deviceName}
                    </td>
                    <td className="py-3 pr-4">
                      <span className="px-2 py-0.5 rounded bg-gray-800 text-xs text-gray-300">{platformIcon(d.platform)}</span>
                    </td>
                    <td className="py-3 pr-4 text-gray-400 font-mono text-xs">{d.clamavVersion}</td>
                    <td className="py-3 pr-4">
                      <span className={`font-mono text-xs ${d.signatureVersion === '27180' ? 'text-green-400' : 'text-yellow-400'}`}>
                        {d.signatureVersion}
                      </span>
                      <span className="text-xs text-gray-600 ml-1">({d.signatureDate})</span>
                    </td>
                    <td className="py-3 pr-4 text-gray-500 text-xs">{new Date(d.lastScan).toLocaleString('de-DE')}</td>
                    <td className="py-3 pr-4">
                      {d.threatsFound > 0
                        ? <span className="text-red-400 font-medium">{d.threatsFound}</span>
                        : <span className="text-green-400">0</span>}
                    </td>
                    <td className="py-3 pr-4">
                      {d.realtimeProtection
                        ? <CheckCircleIcon className="w-4 h-4 text-green-400" />
                        : <XCircleIcon className="w-4 h-4 text-red-400" />}
                    </td>
                    <td className="py-3">
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
            {mockScans.map(scan => (
              <div key={scan.id} className={`p-4 rounded-lg bg-gray-900 border ${scan.status === 'scanning' ? 'border-blue-800' : scan.status === 'failed' ? 'border-red-800' : 'border-gray-800'}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    {scan.status === 'scanning' ? <ArrowPathIcon className="w-5 h-5 text-blue-400 animate-spin" /> :
                     scan.status === 'completed' ? <CheckCircleIcon className="w-5 h-5 text-green-400" /> :
                     <XCircleIcon className="w-5 h-5 text-red-400" />}
                    <div>
                      <span className="font-medium">{scan.deviceName}</span>
                      <span className="text-gray-500 text-sm ml-2">{scan.scanType} scan</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-sm">
                    <span className="text-gray-500"><ClockIcon className="w-4 h-4 inline mr-1" />{scan.duration}</span>
                    {scan.threatsFound > 0 && <span className="text-red-400"><BugAntIcon className="w-4 h-4 inline mr-1" />{scan.threatsFound} threats</span>}
                    <span className="text-gray-500">{scan.filesScanned.toLocaleString()} files</span>
                  </div>
                </div>
                {scan.status === 'scanning' && (
                  <div className="w-full bg-gray-800 rounded-full h-1.5 mt-2">
                    <div className="bg-blue-500 h-1.5 rounded-full transition-all" style={{ width: `${scan.progress}%` }} />
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
                  className={`px-3 py-1 text-xs rounded-lg ${severityFilter === s ? 'bg-gray-700 text-white' : 'bg-gray-900 text-gray-500 hover:text-gray-300'}`}>
                  {s === 'all' ? `All (${mockThreats.length})` : `${s} (${mockThreats.filter(t => t.severity === s).length})`}
                </button>
              ))}
            </div>
            {filteredThreats.map(t => (
              <div key={t.id} className="rounded-lg bg-gray-900 border border-gray-800 overflow-hidden">
                <button onClick={() => setExpandedThreat(expandedThreat === t.id ? null : t.id)}
                  className="w-full p-4 flex items-center gap-3 text-left hover:bg-gray-800/50">
                  <BugAntIcon className={`w-5 h-5 shrink-0 ${t.severity === 'critical' ? 'text-red-500' : t.severity === 'high' ? 'text-orange-500' : t.severity === 'medium' ? 'text-yellow-500' : 'text-blue-500'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-sm truncate">{t.name}</div>
                    <div className="text-xs text-gray-500">{t.deviceName} - {t.type}</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs ${sevColor(t.severity)}`}>{t.severity}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${t.action === 'quarantined' ? 'bg-amber-900/30 text-amber-400' : t.action === 'deleted' ? 'bg-red-900/30 text-red-400' : 'bg-gray-800 text-gray-400'}`}>{t.action}</span>
                  {expandedThreat === t.id ? <ChevronUpIcon className="w-4 h-4 text-gray-500" /> : <ChevronDownIcon className="w-4 h-4 text-gray-500" />}
                </button>
                {expandedThreat === t.id && (
                  <div className="px-4 pb-4 border-t border-gray-800 pt-3 space-y-2">
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div><span className="text-gray-500">File:</span> <span className="text-gray-300 font-mono text-xs">{t.filePath}</span></div>
                      <div><span className="text-gray-500">SHA256:</span> <span className="text-gray-300 font-mono text-xs">{t.fileHash}</span></div>
                      <div><span className="text-gray-500">Detected:</span> <span className="text-gray-300">{new Date(t.detectedAt).toLocaleString('de-DE')}</span></div>
                      <div><span className="text-gray-500">Device:</span> <span className="text-gray-300">{t.deviceName}</span></div>
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
            {mockQuarantine.map(q => (
              <div key={q.id} className="p-4 rounded-lg bg-gray-900 border border-gray-800 flex items-start gap-4">
                <ArchiveBoxIcon className="w-5 h-5 text-amber-400 shrink-0 mt-1" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-medium text-sm">{q.fileName}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${sevColor(q.severity)}`}>{q.severity}</span>
                  </div>
                  <div className="text-xs text-gray-500 mb-1">{q.threatName}</div>
                  <div className="text-xs text-gray-600 font-mono truncate">{q.originalPath}</div>
                  <div className="flex gap-4 text-xs text-gray-500 mt-1">
                    <span>{q.deviceName}</span>
                    <span>{q.fileSize}</span>
                    <span>{new Date(q.quarantinedAt).toLocaleString('de-DE')}</span>
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button className="p-1.5 rounded bg-gray-800 hover:bg-gray-700 text-yellow-400" title="Restore">
                    <ArrowUturnLeftIcon className="w-4 h-4" />
                  </button>
                  <button className="p-1.5 rounded bg-gray-800 hover:bg-red-900 text-red-400" title="Delete permanently">
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
            <div className="p-5 rounded-lg bg-gray-900 border border-green-900/30">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold flex items-center gap-2">
                    <ServerIcon className="w-5 h-5 text-green-400" />
                    Current Signature Database
                  </h3>
                  <div className="mt-2 grid grid-cols-3 gap-6 text-sm">
                    <div>
                      <span className="text-gray-500">Version:</span>
                      <span className="ml-2 font-mono text-green-400">27180</span>
                    </div>
                    <div>
                      <span className="text-gray-500">ClamAV:</span>
                      <span className="ml-2 font-mono text-gray-300">0.104.3</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Last Updated:</span>
                      <span className="ml-2 text-gray-300">2026-03-15 06:00 UTC</span>
                    </div>
                  </div>
                  <div className="mt-2 text-sm">
                    <span className="text-gray-500">Total Signatures:</span>
                    <span className="ml-2 text-gray-300">8,654,320</span>
                  </div>
                </div>
                <button className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded-lg text-sm flex items-center gap-2">
                  <ArrowPathIcon className="w-4 h-4" /> Update Now
                </button>
              </div>
            </div>

            {/* Fleet signature status */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Fleet Signature Status</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 bg-gray-950 rounded text-center">
                  <div className="text-2xl font-bold text-green-400">{mockStats.totalDevices - mockStats.outdatedSignatures}</div>
                  <div className="text-xs text-gray-500">Up to Date</div>
                </div>
                <div className="p-3 bg-gray-950 rounded text-center">
                  <div className="text-2xl font-bold text-yellow-400">{mockStats.outdatedSignatures}</div>
                  <div className="text-xs text-gray-500">Outdated</div>
                </div>
                <div className="p-3 bg-gray-950 rounded text-center">
                  <div className="text-2xl font-bold text-gray-400">4h</div>
                  <div className="text-xs text-gray-500">Update Interval</div>
                </div>
              </div>
            </div>

            {/* Update schedule */}
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">freshclam Update Schedule</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Server freshclam interval</span>
                  <span className="text-gray-300">Every 4 hours</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Client push update</span>
                  <span className="text-gray-300">Within 30 minutes of server update</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Mirror source</span>
                  <span className="text-gray-300 font-mono text-xs">database.clamav.net</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Custom signatures</span>
                  <span className="text-gray-300">12 custom rules active</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
