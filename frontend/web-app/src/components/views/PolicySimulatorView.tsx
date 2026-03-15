'use client';

import React, { useState, useCallback } from 'react';
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

const severityColor = (s: string) =>
  s === 'critical' ? 'text-red-400 bg-red-900/30 border-red-800' :
  s === 'high' ? 'text-orange-400 bg-orange-900/30 border-orange-800' :
  s === 'medium' ? 'text-yellow-400 bg-yellow-900/30 border-yellow-800' :
  'text-blue-400 bg-blue-900/30 border-blue-800';

const timelineColor = (type: string) =>
  type === 'enrolled' ? 'bg-blue-500' :
  type === 'policy_applied' ? 'bg-purple-500' :
  type === 'update_installed' ? 'bg-cyan-500' :
  type === 'compliance_gained' ? 'bg-green-500' :
  type === 'compliance_lost' ? 'bg-red-500' :
  'bg-amber-500';

// ── Component ──────────────────────────────────────────────────────────────────

export default function PolicySimulatorView() {
  const [activeTab, setActiveTab] = useState<'simulate' | 'drift' | 'timeline' | 'conflicts'>('simulate');
  const [simulating, setSimulating] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState('Update Ring A');
  const [changeDescription, setChangeDescription] = useState('Change deferral from 14 to 0 days');
  const [results, setResults] = useState<SimulationResult[]>(mockSimulations);
  const [timelineDevice, setTimelineDevice] = useState('LAPTOP-23');

  const runSimulation = useCallback(async () => {
    setSimulating(true);
    // Simulate processing time
    await new Promise(r => setTimeout(r, 1500));
    setSimulating(false);
  }, []);

  return (
    <div className="flex flex-col h-full bg-gray-950 text-gray-100">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-800">
        <h1 className="text-xl font-bold flex items-center gap-2"><BeakerIcon className="w-6 h-6 text-purple-400" /> Policy Simulator</h1>
        <p className="text-sm text-gray-500">What-if analysis, drift detection, compliance timeline</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-800">
        {([
          ['simulate', 'What-If Simulator'],
          ['drift', `Drift Detection (${mockDrift.length})`],
          ['timeline', 'Compliance Timeline'],
          ['conflicts', `Policy Conflicts (${mockConflicts.length})`],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`px-4 py-2 text-sm rounded-t-lg transition-colors ${activeTab === key ? 'bg-gray-800 text-white border-t border-x border-gray-700' : 'text-gray-500 hover:text-gray-300'}`}>
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
            <div className="p-4 rounded-lg bg-gray-900 border border-gray-800">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Run Simulation</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs text-gray-500">Policy</label>
                  <select value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)}
                    className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm">
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
                    className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm" />
                </div>
                <div className="flex items-end">
                  <button onClick={runSimulation} disabled={simulating}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 rounded-lg text-sm flex items-center gap-2">
                    {simulating ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <PlayIcon className="w-4 h-4" />}
                    {simulating ? 'Simulating…' : 'Run Simulation'}
                  </button>
                </div>
              </div>
            </div>

            {/* Results */}
            {results.map(sim => (
              <div key={sim.id} className={`p-4 rounded-lg border ${severityColor(sim.impact.riskLevel)}`}>
                <div className="flex justify-between items-start mb-3">
                  <div>
                    <h3 className="font-semibold flex items-center gap-2">
                      <DocumentTextIcon className="w-5 h-5" />
                      {sim.policyName}: {sim.change}
                    </h3>
                    <span className="text-xs text-gray-500">{new Date(sim.timestamp).toLocaleString()}</span>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${sim.impact.riskLevel === 'high' ? 'bg-orange-900 text-orange-300' : 'bg-yellow-900 text-yellow-300'}`}>
                    {sim.impact.riskLevel.toUpperCase()} RISK
                  </span>
                </div>

                {/* Impact metrics */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                  <div className="p-3 bg-gray-950/50 rounded">
                    <div className="text-2xl font-bold text-blue-400">{sim.impact.devicesAffected}</div>
                    <div className="text-xs text-gray-500">Devices Affected</div>
                  </div>
                  <div className="p-3 bg-gray-950/50 rounded">
                    <div className="text-2xl font-bold text-purple-400">{sim.impact.usersAffected}</div>
                    <div className="text-xs text-gray-500">Users Impacted</div>
                  </div>
                  <div className="p-3 bg-gray-950/50 rounded">
                    <div className="flex items-baseline gap-1">
                      <span className="text-2xl font-bold text-green-400">{sim.impact.complianceChange.before}%</span>
                      <ChevronRightIcon className="w-3 h-3 text-gray-500" />
                      <span className={`text-2xl font-bold ${sim.impact.complianceChange.after < sim.impact.complianceChange.before ? 'text-red-400' : 'text-green-400'}`}>
                        {sim.impact.complianceChange.after}%
                      </span>
                    </div>
                    <div className="text-xs text-gray-500">Compliance Change</div>
                  </div>
                  <div className="p-3 bg-gray-950/50 rounded">
                    <div className="text-2xl font-bold text-cyan-400">{sim.impact.osUpgradeTriggered}</div>
                    <div className="text-xs text-gray-500">OS Upgrades Triggered</div>
                  </div>
                </div>

                {/* Warnings */}
                {sim.warnings.length > 0 && (
                  <div className="space-y-1">
                    {sim.warnings.map((w, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm text-yellow-400">
                        <ExclamationTriangleIcon className="w-4 h-4 mt-0.5 shrink-0" />
                        {w}
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex gap-2 mt-3">
                  <span className="text-xs text-gray-500">Affected groups:</span>
                  {sim.affectedGroups.map(g => (
                    <span key={g} className="text-xs px-2 py-0.5 bg-purple-900/30 text-purple-300 rounded">{g}</span>
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
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-2 pr-4">Device</th>
                    <th className="pb-2 pr-4">Policy</th>
                    <th className="pb-2 pr-4">Expected</th>
                    <th className="pb-2 pr-4">Actual</th>
                    <th className="pb-2 pr-4">Severity</th>
                    <th className="pb-2">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {mockDrift.map(d => (
                    <tr key={`${d.deviceId}-${d.policyName}`} className="border-b border-gray-900 hover:bg-gray-900/50">
                      <td className="py-3 pr-4 font-medium flex items-center gap-2">
                        <ComputerDesktopIcon className="w-4 h-4 text-gray-500" />
                        {d.deviceName}
                      </td>
                      <td className="py-3 pr-4 text-gray-400">{d.policyName}</td>
                      <td className="py-3 pr-4 text-green-400">{d.expectedState}</td>
                      <td className="py-3 pr-4 text-red-400">{d.actualState}</td>
                      <td className="py-3 pr-4">
                        <span className={`px-2 py-0.5 rounded text-xs ${d.severity === 'critical' ? 'bg-red-900/40 text-red-300' : d.severity === 'high' ? 'bg-orange-900/40 text-orange-300' : 'bg-yellow-900/40 text-yellow-300'}`}>
                          {d.severity}
                        </span>
                      </td>
                      <td className="py-3 text-gray-500">{new Date(d.detectedAt).toLocaleDateString()}</td>
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
                className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm">
                <option>LAPTOP-23</option>
                <option>WS-001</option>
                <option>SRV-DC01</option>
                <option>MAC-DEV-01</option>
              </select>
            </div>
            <div className="relative pl-8">
              {mockTimeline.map((evt, i) => (
                <div key={i} className="relative mb-6 last:mb-0">
                  {/* Vertical line */}
                  {i < mockTimeline.length - 1 && (
                    <div className="absolute left-[-20px] top-6 w-0.5 h-full bg-gray-800" />
                  )}
                  {/* Dot */}
                  <div className={`absolute left-[-24px] top-1.5 w-3 h-3 rounded-full ${timelineColor(evt.type)} ring-2 ring-gray-950`} />
                  {/* Content */}
                  <div className="p-3 rounded-lg bg-gray-900 border border-gray-800">
                    <div className="flex justify-between items-start">
                      <h4 className="font-medium text-sm">{evt.event}</h4>
                      <span className="text-xs text-gray-500">{evt.timestamp}</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">{evt.details}</p>
                    <span className={`inline-block mt-1 text-xs px-2 py-0.5 rounded ${
                      evt.type === 'compliance_lost' ? 'bg-red-900/30 text-red-400' :
                      evt.type === 'compliance_gained' ? 'bg-green-900/30 text-green-400' :
                      evt.type === 'remediated' ? 'bg-amber-900/30 text-amber-400' :
                      'bg-gray-800 text-gray-400'
                    }`}>
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
            {mockConflicts.map((c, i) => (
              <div key={i} className="p-4 rounded-lg bg-gray-900 border border-yellow-800/50">
                <div className="flex items-start gap-2 mb-2">
                  <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500 shrink-0" />
                  <div>
                    <h3 className="font-semibold text-sm">{c.conflictType}</h3>
                    <div className="flex gap-2 mt-1">
                      {c.policies.map(p => (
                        <span key={p} className="text-xs px-2 py-0.5 bg-gray-800 rounded text-gray-300">{p}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <p className="text-sm text-gray-400 mb-2">{c.description}</p>
                <div className="flex items-start gap-2 text-sm text-green-400">
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
