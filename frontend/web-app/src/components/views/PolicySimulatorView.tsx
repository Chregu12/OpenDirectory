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
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

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

const severityBorderStyle = (s: string): React.CSSProperties => ({
  borderColor: s === 'critical' ? 'var(--danger)' :
               s === 'high' ? '#f97316' :
               s === 'medium' ? 'var(--warning)' :
               'var(--accent)',
});

const riskBadgeStyle = (s: string): React.CSSProperties => ({
  color: s === 'critical' ? 'var(--danger)' :
         s === 'high' ? '#f97316' :
         s === 'medium' ? 'var(--warning)' :
         'var(--accent)',
  background: s === 'critical' ? 'var(--danger-light)' :
              s === 'high' ? 'rgba(249,115,22,0.15)' :
              s === 'medium' ? 'var(--warning-light)' :
              'var(--accent-light)',
});

const timelineDotColor = (type: string): string =>
  type === 'enrolled' ? '#006FFF' :
  type === 'policy_applied' ? '#a855f7' :
  type === 'update_installed' ? '#06b6d4' :
  type === 'compliance_gained' ? '#3fb950' :
  type === 'compliance_lost' ? '#f85149' :
  '#d29922';

const timelineBadgeStyle = (type: string): React.CSSProperties => ({
  color: type === 'compliance_lost' ? 'var(--danger)' :
         type === 'compliance_gained' ? 'var(--success)' :
         type === 'remediated' ? 'var(--warning)' :
         'var(--text-secondary)',
  background: type === 'compliance_lost' ? 'var(--danger-light)' :
              type === 'compliance_gained' ? 'var(--success-light)' :
              type === 'remediated' ? 'var(--warning-light)' :
              'var(--bg-overlay)',
});

// ── Component ──────────────────────────────────────────────────────────────────

export default function PolicySimulatorView() {
  const { isSimple } = useUiMode();
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

  const inputStyle: React.CSSProperties = {
    width: '100%',
    marginTop: 4,
    background: 'var(--bg-overlay)',
    border: '1px solid var(--border-strong)',
    borderRadius: 8,
    padding: '8px 12px',
    fontSize: 14,
    color: 'var(--text-primary)',
    outline: 'none',
    boxSizing: 'border-box',
  };

  // ── Simple Mode ──
  if (isSimple) {
    const criticalDrift = drift.filter(d => d.severity === 'critical');

    return (
      <SimpleViewLayout
        hero={{
          status: criticalDrift.length === 0 && conflicts.length === 0 ? 'ok' : 'warning',
          title: criticalDrift.length === 0 && conflicts.length === 0 ? 'Policies Consistent' : `${drift.length} Drift Issue${drift.length > 1 ? 's' : ''} Detected`,
          subtitle: `${drift.length} drift items · ${conflicts.length} conflicts · ${results.length} simulations`,
        }}
        stats={[
          { value: drift.length, label: 'Drift Items', color: drift.length > 0 ? 'text-red-600' : 'text-green-600' },
          { value: criticalDrift.length, label: 'Critical Drift', color: criticalDrift.length > 0 ? 'text-red-600' : 'text-gray-600' },
          { value: conflicts.length, label: 'Conflicts', color: conflicts.length > 0 ? 'text-yellow-600' : 'text-gray-600' },
          { value: results.length, label: 'Simulations', color: 'text-purple-600' },
        ]}
        sections={[
          {
            title: 'Configuration Drift',
            items: drift.map(d => ({
              key: `${d.deviceId}-${d.policyName}`,
              icon: <ComputerDesktopIcon className={`w-5 h-5 ${d.severity === 'critical' ? 'text-red-500' : d.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />,
              title: d.deviceName,
              subtitle: `${d.policyName}: ${d.actualState}`,
              trailing: <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${sevBadge(d.severity)}`}>{d.severity}</span>,
            })),
          },
          {
            title: 'Policy Conflicts',
            items: conflicts.map((c, i) => ({
              key: `conflict-${i}`,
              icon: <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />,
              title: c.conflictType,
              subtitle: c.policies.join(' vs '),
            })),
          },
        ]}
        actions={[{
          label: simulating ? 'Simulating...' : 'Run Simulation',
          icon: simulating ? <ArrowPathIcon className="h-4 w-4 animate-spin" /> : <PlayIcon className="h-4 w-4" />,
          onClick: runSimulation,
          disabled: simulating,
        }]}
      />
    );
  }

  // ── Expert Mode ──
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border)', background: 'var(--bg-surface)', flexShrink: 0 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
          <BeakerIcon style={{ width: 24, height: 24, color: '#a855f7' }} /> Policy Simulator
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>What-if analysis, drift detection, compliance timeline</p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, padding: '12px 24px 0', borderBottom: '1px solid var(--border)', background: 'var(--bg-surface-raised)', flexShrink: 0 }}>
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
      <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
        {/* ── Simulator ──────────────────────────────────────────────────── */}
        {activeTab === 'simulate' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {/* Input form */}
            <div className="od-card" style={{ padding: 16 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 12 }}>Run Simulation</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Policy</label>
                  <select value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)} style={inputStyle}>
                    <option>Update Ring A</option>
                    <option>Update Ring B</option>
                    <option>Security Baseline</option>
                    <option>BitLocker Policy</option>
                    <option>Firewall Rules</option>
                    <option>Endpoint Protection</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Change Description</label>
                  <input value={changeDescription} onChange={e => setChangeDescription(e.target.value)} style={inputStyle} />
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button onClick={runSimulation} disabled={simulating}
                    style={{
                      padding: '8px 16px', background: '#a855f7', color: '#fff', border: 'none', borderRadius: 8,
                      fontSize: 14, display: 'flex', alignItems: 'center', gap: 8, cursor: simulating ? 'not-allowed' : 'pointer',
                      opacity: simulating ? 0.5 : 1, boxShadow: 'var(--card-shadow)',
                    }}>
                    {simulating ? <ArrowPathIcon style={{ width: 16, height: 16 }} /> : <PlayIcon style={{ width: 16, height: 16 }} />}
                    {simulating ? 'Simulating...' : 'Run Simulation'}
                  </button>
                </div>
              </div>
            </div>

            {/* Results */}
            {results.map(sim => (
              <div key={sim.id} className="od-card" style={{ padding: 16, ...severityBorderStyle(sim.impact.riskLevel) }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                  <div>
                    <h3 style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <DocumentTextIcon style={{ width: 20, height: 20, color: 'var(--text-muted)' }} />
                      {sim.policyName}: {sim.change}
                    </h3>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{new Date(sim.timestamp).toLocaleString()}</span>
                  </div>
                  <span style={{ padding: '4px 8px', borderRadius: 4, fontSize: 12, fontWeight: 500, ...riskBadgeStyle(sim.impact.riskLevel) }}>
                    {sim.impact.riskLevel.toUpperCase()} RISK
                  </span>
                </div>

                {/* Impact metrics */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
                  <div style={{ padding: 12, background: 'var(--bg-surface-raised)', borderRadius: 8 }}>
                    <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent)' }}>{sim.impact.devicesAffected}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Devices Affected</div>
                  </div>
                  <div style={{ padding: 12, background: 'var(--bg-surface-raised)', borderRadius: 8 }}>
                    <div style={{ fontSize: 24, fontWeight: 700, color: '#a855f7' }}>{sim.impact.usersAffected}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Users Impacted</div>
                  </div>
                  <div style={{ padding: 12, background: 'var(--bg-surface-raised)', borderRadius: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                      <span style={{ fontSize: 24, fontWeight: 700, color: 'var(--success)' }}>{sim.impact.complianceChange.before}%</span>
                      <ChevronRightIcon style={{ width: 12, height: 12, color: 'var(--text-muted)' }} />
                      <span style={{ fontSize: 24, fontWeight: 700, color: sim.impact.complianceChange.after < sim.impact.complianceChange.before ? 'var(--danger)' : 'var(--success)' }}>
                        {sim.impact.complianceChange.after}%
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Compliance Change</div>
                  </div>
                  <div style={{ padding: 12, background: 'var(--bg-surface-raised)', borderRadius: 8 }}>
                    <div style={{ fontSize: 24, fontWeight: 700, color: '#06b6d4' }}>{sim.impact.osUpgradeTriggered}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>OS Upgrades Triggered</div>
                  </div>
                </div>

                {/* Warnings */}
                {sim.warnings.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {sim.warnings.map((w, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 14, color: 'var(--warning)' }}>
                        <ExclamationTriangleIcon style={{ width: 16, height: 16, marginTop: 2, flexShrink: 0 }} />
                        {w}
                      </div>
                    ))}
                  </div>
                )}

                <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'center' }}>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Affected groups:</span>
                  {sim.affectedGroups.map(g => (
                    <span key={g} style={{ fontSize: 12, padding: '2px 8px', background: 'rgba(168,85,247,0.15)', color: '#a855f7', borderRadius: 4 }}>{g}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Drift Detection ────────────────────────────────────────────── */}
        {activeTab === 'drift' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <p style={{ fontSize: 14, color: 'var(--text-muted)', marginBottom: 16 }}>Devices where actual configuration differs from expected policy state.</p>
            <div className="od-card" style={{ overflow: 'hidden' }}>
              <table style={{ width: '100%', fontSize: 14, borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}>
                    <th style={{ padding: '12px 16px' }}>Device</th>
                    <th style={{ padding: '12px 16px' }}>Policy</th>
                    <th style={{ padding: '12px 16px' }}>Expected</th>
                    <th style={{ padding: '12px 16px' }}>Actual</th>
                    <th style={{ padding: '12px 16px' }}>Severity</th>
                    <th style={{ padding: '12px 16px' }}>Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {drift.map(d => (
                    <tr key={`${d.deviceId}-${d.policyName}`} style={{ borderBottom: '1px solid var(--border)' }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                      onMouseLeave={e => (e.currentTarget.style.background = '')}>
                      <td style={{ padding: '12px 16px', fontWeight: 500, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <ComputerDesktopIcon style={{ width: 16, height: 16, color: 'var(--text-muted)' }} />
                        {d.deviceName}
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>{d.policyName}</td>
                      <td style={{ padding: '12px 16px', color: 'var(--success)' }}>{d.expectedState}</td>
                      <td style={{ padding: '12px 16px', color: 'var(--danger)' }}>{d.actualState}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`px-2 py-0.5 rounded text-xs ${sevBadge(d.severity)}`}>
                          {d.severity}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>{new Date(d.detectedAt).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Compliance Timeline ─────────────────────────────────────────── */}
        {activeTab === 'timeline' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <label style={{ fontSize: 14, color: 'var(--text-muted)' }}>Device:</label>
              <select value={timelineDevice} onChange={e => setTimelineDevice(e.target.value)}
                style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: '6px 12px', fontSize: 14, color: 'var(--text-primary)', outline: 'none' }}>
                <option>LAPTOP-23</option>
                <option>WS-001</option>
                <option>SRV-DC01</option>
                <option>MAC-DEV-01</option>
              </select>
            </div>
            <div style={{ position: 'relative', paddingLeft: 32 }}>
              {timeline.map((evt, i) => (
                <div key={i} style={{ position: 'relative', marginBottom: i < timeline.length - 1 ? 24 : 0 }}>
                  {i < timeline.length - 1 && (
                    <div style={{ position: 'absolute', left: -20, top: 24, width: 2, height: '100%', background: 'var(--border)' }} />
                  )}
                  <div style={{ position: 'absolute', left: -24, top: 6, width: 12, height: 12, borderRadius: '50%', background: timelineDotColor(evt.type), boxShadow: '0 0 0 2px var(--bg-surface)' }} />
                  <div className="od-card" style={{ padding: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <h4 style={{ fontWeight: 500, fontSize: 14, color: 'var(--text-primary)' }}>{evt.event}</h4>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{evt.timestamp}</span>
                    </div>
                    <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{evt.details}</p>
                    <span style={{ display: 'inline-block', marginTop: 4, fontSize: 12, padding: '2px 8px', borderRadius: 4, ...timelineBadgeStyle(evt.type) }}>
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>Conflicting or overlapping policy assignments.</p>
            {conflicts.map((c, i) => (
              <div key={i} className="od-card" style={{ padding: 16, borderColor: 'var(--warning)' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 8 }}>
                  <ExclamationTriangleIcon style={{ width: 20, height: 20, color: 'var(--warning)', flexShrink: 0 }} />
                  <div>
                    <h3 style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{c.conflictType}</h3>
                    <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                      {c.policies.map(p => (
                        <span key={p} style={{ fontSize: 12, padding: '2px 8px', background: 'var(--bg-overlay)', borderRadius: 4, color: 'var(--text-secondary)' }}>{p}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 8 }}>{c.description}</p>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 14, color: 'var(--success)' }}>
                  <CheckCircleIcon style={{ width: 16, height: 16, marginTop: 2, flexShrink: 0 }} />
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
