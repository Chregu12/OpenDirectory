'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  BeakerIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ChevronRightIcon,
  PlayIcon,
  ArrowUturnLeftIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';
import { securityApi, deviceApi } from '@/lib/api';

// ── Types ──────────────────────────────────────────────────────────────────────

interface SimulationResult {
  id: string;
  policyName: string;
  change: string;
  timestamp: string;
  impact: {
    devicesAffected: number;
    usersAffected: number;
    complianceChange: { before: number; after: number };
    osUpgradeTriggered: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low';
  };
  affectedGroups: string[];
  warnings: string[];
}

interface DriftItem {
  deviceId: string;
  deviceName: string;
  policyName: string;
  expectedState: string;
  actualState: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detectedAt: string;
}

interface TimelineEvent {
  timestamp: string;
  event: string;
  type: 'enrolled' | 'policy_applied' | 'update_installed' | 'compliance_gained' | 'compliance_lost' | 'remediated';
  details: string;
}

interface PolicyConflict {
  policies: string[];
  conflictType: string;
  description: string;
  resolution: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const mockSimulations: SimulationResult[] = [
  {
    id: 'sim-1', policyName: 'Update Ring A', change: 'Change deferral from 14 to 0 days',
    timestamp: '2026-03-15T10:30:00Z',
    impact: { devicesAffected: 340, usersAffected: 280, complianceChange: { before: 87, after: 72 }, osUpgradeTriggered: 220, riskLevel: 'high' },
    affectedGroups: ['IT-Staff', 'Developers', 'Early-Adopters'],
    warnings: ['220 devices will receive OS upgrade immediately', 'Potential driver compatibility issues on 15 devices', '3 line-of-business apps not tested on target version'],
  },
  {
    id: 'sim-2', policyName: 'BitLocker Policy', change: 'Enforce XTS-AES-256 encryption',
    timestamp: '2026-03-15T09:15:00Z',
    impact: { devicesAffected: 45, usersAffected: 45, complianceChange: { before: 87, after: 91 }, osUpgradeTriggered: 0, riskLevel: 'medium' },
    affectedGroups: ['All-Users'],
    warnings: ['45 devices currently unencrypted will require restart', 'Estimated 2-4 hours for full encryption per device'],
  },
];

const mockDrift: DriftItem[] = [
  { deviceId: 'LAPTOP-23', deviceName: 'LAPTOP-23', policyName: 'Security Baseline', expectedState: 'Firewall: Enabled', actualState: 'Firewall: Disabled', severity: 'critical', detectedAt: '2026-03-15T08:00:00Z' },
  { deviceId: 'WS-007', deviceName: 'WS-007', policyName: 'BitLocker Policy', expectedState: 'Encryption: XTS-AES-256', actualState: 'Encryption: None', severity: 'critical', detectedAt: '2026-03-15T07:30:00Z' },
  { deviceId: 'WS-012', deviceName: 'WS-012', policyName: 'Update Ring B', expectedState: 'Windows 11 23H2', actualState: 'Windows 11 22H2', severity: 'high', detectedAt: '2026-03-14T22:00:00Z' },
  { deviceId: 'MAC-05', deviceName: 'MAC-05', policyName: 'Endpoint Protection', expectedState: 'EDR: Active', actualState: 'EDR: Stopped', severity: 'high', detectedAt: '2026-03-15T06:45:00Z' },
  { deviceId: 'SRV-WEB02', deviceName: 'SRV-WEB02', policyName: 'Patch Policy', expectedState: 'KB5031234: Installed', actualState: 'KB5031234: Missing', severity: 'medium', detectedAt: '2026-03-14T18:00:00Z' },
];

const mockTimeline: TimelineEvent[] = [
  { timestamp: '2026-01-10', event: 'Device Enrolled', type: 'enrolled', details: 'LAPTOP-23 enrolled via Autopilot' },
  { timestamp: '2026-01-10', event: 'Security Baseline Applied', type: 'policy_applied', details: 'Applied Security Baseline v2.1' },
  { timestamp: '2026-01-11', event: 'BitLocker Enabled', type: 'policy_applied', details: 'XTS-AES-256 encryption completed' },
  { timestamp: '2026-01-15', event: 'Compliance Gained', type: 'compliance_gained', details: 'Device fully compliant with all policies' },
  { timestamp: '2026-02-12', event: 'Update Installed', type: 'update_installed', details: 'KB5030219 installed successfully' },
  { timestamp: '2026-03-01', event: 'EDR Agent Stopped', type: 'compliance_lost', details: 'Defender for Endpoint service stopped unexpectedly' },
  { timestamp: '2026-03-02', event: 'Auto Remediation', type: 'remediated', details: 'EDR service restarted via remediation script' },
  { timestamp: '2026-03-10', event: 'Compliance Lost', type: 'compliance_lost', details: 'Firewall disabled by local admin. 3 updates missing.' },
];

const mockConflicts: PolicyConflict[] = [
  { policies: ['Update Ring A', 'Update Ring B'], conflictType: 'Overlapping scope', description: 'Both rings target the "Developers" group with different deferral settings.', resolution: 'Remove "Developers" from Ring B or adjust deferral to match.' },
  { policies: ['Security Baseline', 'Legacy App Policy'], conflictType: 'Contradicting settings', description: 'Security Baseline requires TLS 1.2+, Legacy App Policy allows TLS 1.0.', resolution: 'Migrate legacy app or create exception group.' },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

const sevBadge = (s: string) =>
  s === 'critical' ? 'od-badge-critical' :
  s === 'high' ? 'od-badge-high' :
  s === 'medium' ? 'od-badge-medium' :
  'od-badge-low';

const severityBorder = (s: string) =>
  s === 'critical' ? 'border-red-200' :
  s === 'high' ? 'border-orange-200' :
  s === 'medium' ? 'border-yellow-200' :
  'border-blue-200';

const riskBadge = (s: string) =>
  s === 'critical' ? 'bg-red-100 text-red-700' :
  s === 'high' ? 'bg-orange-100 text-orange-700' :
  s === 'medium' ? 'bg-yellow-100 text-yellow-700' :
  'bg-blue-100 text-blue-700';

const timelineColor = (type: string) =>
  type === 'enrolled' ? 'bg-blue-500' :
  type === 'policy_applied' ? 'bg-purple-500' :
  type === 'update_installed' ? 'bg-cyan-500' :
  type === 'compliance_gained' ? 'bg-green-500' :
  type === 'compliance_lost' ? 'bg-red-500' :
  'bg-amber-500';

const timelineBadge = (type: string) =>
  type === 'compliance_lost' ? 'bg-red-100 text-red-700' :
  type === 'compliance_gained' ? 'bg-green-100 text-green-700' :
  type === 'remediated' ? 'bg-amber-100 text-amber-700' :
  'bg-gray-100 text-gray-600';

// ── Component ──────────────────────────────────────────────────────────────────

export default function PolicySimulatorView() {
  const [activeTab, setActiveTab] = useState<'simulate' | 'drift' | 'timeline' | 'conflicts'>('simulate');
  const [simulating, setSimulating] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState('Update Ring A');
  const [changeDescription, setChangeDescription] = useState('Change deferral from 14 to 0 days');
  const [results, setResults] = useState<SimulationResult[]>(mockSimulations);
  const [drift, setDrift] = useState<DriftItem[]>(mockDrift);
  const [timeline, setTimeline] = useState<TimelineEvent[]>(mockTimeline);
  const [conflicts, setConflicts] = useState<PolicyConflict[]>(mockConflicts);
  const [timelineDevice, setTimelineDevice] = useState('LAPTOP-23');

  useEffect(() => { loadSimulatorData(); }, []);

  const loadSimulatorData = async () => {
    try {
      const [complianceRes, devicesRes] = await Promise.allSettled([
        securityApi.getComplianceStatus(),
        deviceApi.getDevices(),
      ]);

      if (complianceRes.status === 'fulfilled' && complianceRes.value.data) {
        const data = complianceRes.value.data;
        if (data.drift?.length > 0) setDrift(data.drift);
        if (data.conflicts?.length > 0) setConflicts(data.conflicts);
        if (data.timeline?.length > 0) setTimeline(data.timeline);
      }
    } catch {
      // Keep mock data as fallback
    }
  };

  const runSimulation = useCallback(async () => {
    setSimulating(true);
    try {
      const res = await securityApi.getComplianceStatus();
      if (res.data?.simulation) {
        setResults(prev => [res.data.simulation, ...prev]);
      }
    } catch {
      // Fallback: keep existing mock results
    } finally {
      await new Promise(r => setTimeout(r, 500));
      setSimulating(false);
    }
  }, []);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2"><BeakerIcon className="w-6 h-6 text-purple-600" /> Policy Simulator</h1>
        <p className="text-sm text-gray-500">What-if analysis, drift detection, compliance timeline</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-200 bg-gray-50">
        {([
          ['simulate', 'What-If Simulator'],
          ['drift', `Drift Detection (${drift.length})`],
          ['timeline', 'Compliance Timeline'],
          ['conflicts', `Policy Conflicts (${conflicts.length})`],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`od-tab ${activeTab === key ? 'od-tab-active' : 'od-tab-inactive'}`}>
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {/* ── Simulator ──────────────────────────────────────────────────── */}
        {activeTab === 'simulate' && (
          <div className="space-y-6">
            {/* Input form */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-3">Run Simulation</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs text-gray-500">Policy</label>
                  <select value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)}
                    className="w-full mt-1 bg-white border border-gray-300 rounded-lg px-3 py-2 text-sm text-gray-900 focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
                    <option>Update Ring A</option>
                    <option>Update Ring B</option>
                    <option>Security Baseline</option>
                    <option>BitLocker Policy</option>
                    <option>Firewall Rules</option>
                    <option>Endpoint Protection</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-500">Change Description</label>
                  <input value={changeDescription} onChange={e => setChangeDescription(e.target.value)}
                    className="w-full mt-1 bg-white border border-gray-300 rounded-lg px-3 py-2 text-sm text-gray-900 focus:ring-1 focus:ring-blue-500 focus:border-blue-500" />
                </div>
                <div className="flex items-end">
                  <button onClick={runSimulation} disabled={simulating}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 rounded-lg text-sm text-white flex items-center gap-2 shadow-sm">
                    {simulating ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />}
                    {simulating ? 'Simulating...' : 'Run Simulation'}
                  </button>
                </div>
              </div>
            </div>

            {/* Results */}
            {results.map(sim => (
              <div key={sim.id} className={`od-card p-4 ${severityBorder(sim.impact.riskLevel)}`}>
                <div className="flex justify-between items-start mb-3">
                  <div>
                    <h3 className="font-semibold text-gray-900 flex items-center gap-2">
                      <DocumentTextIcon className="w-5 h-5 text-gray-400" />
                      {sim.policyName}: {sim.change}
                    </h3>
                    <span className="text-xs text-gray-500">{new Date(sim.timestamp).toLocaleString()}</span>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${riskBadge(sim.impact.riskLevel)}`}>
                    {sim.impact.riskLevel.toUpperCase()} RISK
                  </span>
                </div>

                {/* Impact metrics */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                  <div className="p-3 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{sim.impact.devicesAffected}</div>
                    <div className="text-xs text-gray-500">Devices Affected</div>
                  </div>
                  <div className="p-3 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-600">{sim.impact.usersAffected}</div>
                    <div className="text-xs text-gray-500">Users Impacted</div>
                  </div>
                  <div className="p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-baseline gap-1">
                      <span className="text-2xl font-bold text-green-600">{sim.impact.complianceChange.before}%</span>
                      <ChevronRightIcon className="w-3 h-3 text-gray-400" />
                      <span className={`text-2xl font-bold ${sim.impact.complianceChange.after < sim.impact.complianceChange.before ? 'text-red-600' : 'text-green-600'}`}>
                        {sim.impact.complianceChange.after}%
                      </span>
                    </div>
                    <div className="text-xs text-gray-500">Compliance Change</div>
                  </div>
                  <div className="p-3 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-cyan-600">{sim.impact.osUpgradeTriggered}</div>
                    <div className="text-xs text-gray-500">OS Upgrades Triggered</div>
                  </div>
                </div>

                {/* Warnings */}
                {sim.warnings.length > 0 && (
                  <div className="space-y-1">
                    {sim.warnings.map((w, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm text-yellow-700">
                        <ExclamationTriangleIcon className="w-4 h-4 mt-0.5 shrink-0" />
                        {w}
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex gap-2 mt-3">
                  <span className="text-xs text-gray-500">Affected groups:</span>
                  {sim.affectedGroups.map(g => (
                    <span key={g} className="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded">{g}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Drift Detection ────────────────────────────────────────────── */}
        {activeTab === 'drift' && (
          <div className="space-y-3">
            <p className="text-sm text-gray-500 mb-4">Devices where actual configuration differs from expected policy state.</p>
            <div className="od-card overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-200 bg-gray-50">
                    <th className="px-4 py-3">Device</th>
                    <th className="px-4 py-3">Policy</th>
                    <th className="px-4 py-3">Expected</th>
                    <th className="px-4 py-3">Actual</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {drift.map(d => (
                    <tr key={`${d.deviceId}-${d.policyName}`} className="border-b border-gray-100 hover:bg-gray-50">
                      <td className="px-4 py-3 font-medium text-gray-900 flex items-center gap-2">
                        <ComputerDesktopIcon className="w-4 h-4 text-gray-400" />
                        {d.deviceName}
                      </td>
                      <td className="px-4 py-3 text-gray-600">{d.policyName}</td>
                      <td className="px-4 py-3 text-green-700">{d.expectedState}</td>
                      <td className="px-4 py-3 text-red-600">{d.actualState}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs ${sevBadge(d.severity)}`}>
                          {d.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-500">{new Date(d.detectedAt).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Compliance Timeline ─────────────────────────────────────────── */}
        {activeTab === 'timeline' && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <label className="text-sm text-gray-500">Device:</label>
              <select value={timelineDevice} onChange={e => setTimelineDevice(e.target.value)}
                className="bg-white border border-gray-300 rounded-lg px-3 py-1.5 text-sm text-gray-900 focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
                <option>LAPTOP-23</option>
                <option>WS-001</option>
                <option>SRV-DC01</option>
                <option>MAC-DEV-01</option>
              </select>
            </div>
            <div className="relative pl-8">
              {timeline.map((evt, i) => (
                <div key={i} className="relative mb-6 last:mb-0">
                  {/* Vertical line */}
                  {i < timeline.length - 1 && (
                    <div className="absolute left-[-20px] top-6 w-0.5 h-full bg-gray-200" />
                  )}
                  {/* Dot */}
                  <div className={`absolute left-[-24px] top-1.5 w-3 h-3 rounded-full ${timelineColor(evt.type)} ring-2 ring-white`} />
                  {/* Content */}
                  <div className="od-card p-3">
                    <div className="flex justify-between items-start">
                      <h4 className="font-medium text-sm text-gray-900">{evt.event}</h4>
                      <span className="text-xs text-gray-500">{evt.timestamp}</span>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{evt.details}</p>
                    <span className={`inline-block mt-1 text-xs px-2 py-0.5 rounded ${timelineBadge(evt.type)}`}>
                      {evt.type.replace('_', ' ')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Policy Conflicts ───────────────────────────────────────────── */}
        {activeTab === 'conflicts' && (
          <div className="space-y-4">
            <p className="text-sm text-gray-500">Conflicting or overlapping policy assignments.</p>
            {conflicts.map((c, i) => (
              <div key={i} className="od-card p-4 border-yellow-200">
                <div className="flex items-start gap-2 mb-2">
                  <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500 shrink-0" />
                  <div>
                    <h3 className="font-semibold text-sm text-gray-900">{c.conflictType}</h3>
                    <div className="flex gap-2 mt-1">
                      {c.policies.map(p => (
                        <span key={p} className="text-xs px-2 py-0.5 bg-gray-100 rounded text-gray-700">{p}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <p className="text-sm text-gray-600 mb-2">{c.description}</p>
                <div className="flex items-start gap-2 text-sm text-green-700">
                  <CheckCircleIcon className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>{c.resolution}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
