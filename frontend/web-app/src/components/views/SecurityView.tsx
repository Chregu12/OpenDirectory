'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  SparklesIcon,
  ExclamationTriangleIcon,
  BugAntIcon,
  ServerIcon,
  CheckCircleIcon,
  XCircleIcon,
  ComputerDesktopIcon,
  MagnifyingGlassIcon,
  LinkIcon,
} from '@heroicons/react/24/outline';
import { securityApi, deviceApi } from '@/lib/api';
import SecuritySetupWizard from '@/components/setup/SecuritySetupWizard';

// ─── Types ──────────────────────────────────────────────────────────────────────

type Severity  = 'critical' | 'high' | 'medium' | 'low' | 'info';
type AlertTab  = 'overview' | 'alerts' | 'agents' | 'compliance';

interface Alert {
  id: string;
  severity: Severity;
  rule: string;
  description: string;
  device: string;
  timestamp: string;
  resolved: boolean;
  ruleId: number;
  category: string;
}

interface Agent {
  id: string;
  name: string;
  platform: string;
  version: string;
  status: 'active' | 'disconnected';
  lastKeepAlive: string;
  ip: string;
}

interface Compliance {
  id: string;
  name: string;
  passed: number;
  total: number;
}

// ─── Normalizers ────────────────────────────────────────────────────────────────

function normalizeAlert(a: any): Alert {
  return {
    id: a.id || a._id || String(Math.random()),
    severity: a.severity || a.level || 'info',
    rule: a.rule?.description || a.rule || a.name || 'Unknown Rule',
    description: a.description || a.full_log || a.data?.message || '',
    device: a.agent?.name || a.device || a.hostname || 'Unknown',
    timestamp: a.timestamp || a.createdAt || new Date().toISOString(),
    resolved: a.resolved || false,
    ruleId: a.rule?.id || a.ruleId || 0,
    category: a.rule?.groups?.[0] || a.category || 'General',
  };
}

function normalizeCompliance(c: any): Compliance {
  return {
    id: c.id || c.framework,
    name: c.name || c.framework,
    passed: c.passed || c.pass_count || 0,
    total: c.total || c.total_count || 1,
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  });
}

const SEVERITY_STYLES: Record<Severity, { badge: React.CSSProperties; dot: string; label: string }> = {
  critical: { badge: { background: 'var(--danger-light)', color: 'var(--danger)', border: '1px solid rgba(248,81,73,0.3)' },         dot: 'bg-red-500',    label: 'Critical' },
  high:     { badge: { background: 'rgba(234,88,12,0.15)', color: '#f97316', border: '1px solid rgba(234,88,12,0.3)' },               dot: 'bg-orange-500', label: 'High' },
  medium:   { badge: { background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid rgba(210,153,34,0.3)' },       dot: 'bg-yellow-500', label: 'Medium' },
  low:      { badge: { background: 'var(--accent-light)', color: 'var(--accent)', border: '1px solid rgba(0,111,255,0.3)' },          dot: 'bg-blue-400',   label: 'Low' },
  info:     { badge: { background: 'var(--bg-surface-raised)', color: 'var(--text-muted)', border: '1px solid var(--border)' },       dot: 'bg-gray-400',   label: 'Info' },
};

function SeverityBadge({ sev }: { sev: Severity }) {
  const s = SEVERITY_STYLES[sev] ?? SEVERITY_STYLES['info'];
  return (
    <span style={{ ...s.badge, display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 9999, fontSize: 12, fontWeight: 500 }}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

function ComplianceBar({ passed, total }: { passed: number; total: number }) {
  const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
  const color = pct >= 90 ? 'bg-green-500' : pct >= 70 ? 'bg-yellow-400' : 'bg-red-400';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-surface-raised)' }}>
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-medium w-10 text-right" style={{ color: 'var(--text-secondary)' }}>{pct}%</span>
    </div>
  );
}

// ─── Loading Skeleton ────────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-10 rounded-xl" style={{ background: 'var(--bg-surface-raised)' }} />
      <div className="h-10 rounded-xl" style={{ background: 'var(--bg-surface-raised)' }} />
      <div className="h-10 rounded-xl" style={{ background: 'var(--bg-surface-raised)' }} />
    </div>
  );
}

// ─── Tabs ──────────────────────────────────────────────────────────────────────

function OverviewTab({
  alerts,
  agents,
  compliance,
}: {
  alerts: Alert[];
  agents: Agent[];
  compliance: Compliance[];
}) {
  const active   = alerts.filter(a => !a.resolved);
  const critical = active.filter(a => a.severity === 'critical').length;
  const high     = active.filter(a => a.severity === 'high').length;
  const medium   = active.filter(a => a.severity === 'medium').length;
  const agentsUp = agents.filter(a => a.status === 'active').length;

  const avgCompliance =
    compliance.length > 0
      ? Math.round(
          (compliance.reduce((s, c) => s + (c.total > 0 ? c.passed / c.total : 0), 0) /
            compliance.length) *
            100,
        )
      : 0;

  const kpis = [
    { label: 'Active Alerts',  value: active.length,                      style: { color: 'var(--text-primary)',   background: 'var(--bg-surface-raised)' },  icon: ShieldExclamationIcon },
    { label: 'Critical',       value: critical,                            style: { color: 'var(--danger)',          background: 'var(--danger-light)' },        icon: ExclamationTriangleIcon },
    { label: 'High',           value: high,                                style: { color: '#f97316',               background: 'rgba(234,88,12,0.15)' },       icon: ShieldExclamationIcon },
    { label: 'Medium',         value: medium,                              style: { color: 'var(--warning)',         background: 'var(--warning-light)' },       icon: BugAntIcon },
    { label: 'Agents Online',  value: `${agentsUp}/${agents.length}`,      style: { color: 'var(--success)',         background: 'var(--success-light)' },       icon: ServerIcon },
    { label: 'Avg Compliance', value: `${avgCompliance}%`,                 style: { color: 'var(--accent)',          background: 'var(--accent-light)' },        icon: ShieldCheckIcon },
  ];

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpis.map(k => (
          <div key={k.label} style={{ background: k.style.background, borderRadius: 12, padding: 16 }}>
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs font-medium" style={{ color: k.style.color }}>{k.label}</p>
              <k.icon style={{ width: 16, height: 16, color: k.style.color }} />
            </div>
            <p className="text-2xl font-bold" style={{ color: k.style.color }}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* Recent alerts */}
      <div className="rounded-xl" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}>
        <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Recent Active Alerts</h3>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{active.length} open</span>
        </div>
        <div>
          {active.slice(0, 6).map(alert => (
            <div key={alert.id} className="flex items-start gap-3 px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="mt-0.5 flex-shrink-0">
                <SeverityBadge sev={alert.severity} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{alert.rule}</p>
                <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>{alert.description}</p>
              </div>
              <div className="flex-shrink-0 text-right">
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{alert.device}</p>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{fmtTime(alert.timestamp)}</p>
              </div>
            </div>
          ))}
          {active.length === 0 && (
            <div className="flex items-center gap-2 px-5 py-6" style={{ color: 'var(--success)' }}>
              <CheckCircleIcon className="w-5 h-5" />
              <span className="text-sm font-medium">No active alerts — system is clean</span>
            </div>
          )}
        </div>
      </div>

      {/* Compliance summary */}
      <div className="rounded-xl" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}>
        <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Compliance Overview</h3>
        </div>
        {compliance.length === 0 ? (
          <div className="px-5 py-6 text-sm" style={{ color: 'var(--text-muted)' }}>No compliance data</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-5">
            {compliance.map(c => (
              <div key={c.id} className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>{c.name}</span>
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{c.passed}/{c.total} checks</span>
                </div>
                <ComplianceBar passed={c.passed} total={c.total} />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AlertsTab({ initialAlerts }: { initialAlerts: Alert[] }) {
  const [alerts, setAlerts]           = useState<Alert[]>(initialAlerts);
  const [search, setSearch]           = useState('');
  const [sevFilter, setSevFilter]     = useState<Severity | 'all'>('all');
  const [showResolved, setShowResolved] = useState(false);

  // Keep local state in sync if parent re-fetches
  useEffect(() => {
    setAlerts(initialAlerts);
  }, [initialAlerts]);

  const resolve = (id: string) =>
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, resolved: true } : a));

  const filtered = alerts.filter(a => {
    if (!showResolved && a.resolved) return false;
    if (sevFilter !== 'all' && a.severity !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.rule.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.device.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <MagnifyingGlassIcon className="absolute left-3 inset-y-0 my-auto h-4 w-4" style={{ color: 'var(--text-muted)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search alerts…"
            className="w-full pl-9 pr-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
            style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
          />
        </div>
        <div className="flex items-center gap-1.5">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(s => (
            <button
              key={s}
              onClick={() => setSevFilter(s)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg capitalize transition-colors ${
                sevFilter === s ? 'bg-blue-600 text-white' : ''
              }`}
              style={sevFilter === s ? {} : { background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
            >
              {s}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-sm cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
          <input
            type="checkbox"
            checked={showResolved}
            onChange={e => setShowResolved(e.target.checked)}
            className="w-4 h-4 rounded text-blue-600"
          />
          Show resolved
        </label>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}>
        {alerts.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No alerts detected</div>
        ) : (
          <table className="min-w-full">
            <thead style={{ background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }}>
              <tr>
                {['Severity', 'Rule', 'Description', 'Device', 'Category', 'Time', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(alert => (
                <tr key={alert.id} className={`transition-colors ${alert.resolved ? 'opacity-50' : ''}`} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td className="px-4 py-3 whitespace-nowrap"><SeverityBadge sev={alert.severity} /></td>
                  <td className="px-4 py-3">
                    <p className="text-sm font-medium whitespace-nowrap" style={{ color: 'var(--text-primary)' }}>{alert.rule}</p>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Rule {alert.ruleId}</p>
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <p className="text-sm truncate" style={{ color: 'var(--text-secondary)' }}>{alert.description}</p>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm" style={{ color: 'var(--text-secondary)' }}>{alert.device}</td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }}>{alert.category}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs" style={{ color: 'var(--text-muted)' }}>{fmtTime(alert.timestamp)}</td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {!alert.resolved ? (
                      <button
                        onClick={() => resolve(alert.id)}
                        className="px-2.5 py-1 text-xs font-medium rounded-lg transition-colors"
                        style={{ color: 'var(--success)', background: 'var(--success-light)', border: '1px solid rgba(63,185,80,0.3)' }}
                      >
                        Resolve
                      </button>
                    ) : (
                      <span className="text-xs flex items-center gap-1" style={{ color: 'var(--text-muted)' }}>
                        <CheckCircleIcon className="w-3.5 h-3.5 text-green-500" /> Resolved
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                    No alerts match the current filter
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function AgentsTab({ agents }: { agents: Agent[] }) {
  const activeCount = agents.filter(a => a.status === 'active').length;

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}>
      <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Wazuh Agents</h3>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {activeCount}/{agents.length} active
        </span>
      </div>
      {agents.length === 0 ? (
        <div className="px-5 py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No agents enrolled</div>
      ) : (
        <table className="min-w-full">
          <thead style={{ background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }}>
            <tr>
              {['Agent', 'Platform', 'Version', 'IP Address', 'Status', 'Last Active'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {agents.map(agent => (
              <tr key={agent.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <ComputerDesktopIcon className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
                    <div>
                      <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{agent.name}</p>
                      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>ID: {agent.id}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{agent.platform}</td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }}>v{agent.version}</span>
                </td>
                <td className="px-4 py-3 text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{agent.ip}</td>
                <td className="px-4 py-3">
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    padding: '2px 8px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
                    background: agent.status === 'active' ? 'var(--success-light)' : 'var(--bg-surface-raised)',
                    color: agent.status === 'active' ? 'var(--success)' : 'var(--text-muted)',
                  }}>
                    <span className={`w-1.5 h-1.5 rounded-full ${agent.status === 'active' ? 'bg-green-500' : 'bg-gray-400'}`} />
                    {agent.status === 'active' ? 'Active' : 'Disconnected'}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{fmtTime(agent.lastKeepAlive)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ComplianceTab({ compliance }: { compliance: Compliance[] }) {
  return (
    <div className="space-y-4">
      {compliance.length === 0 ? (
        <div className="rounded-xl px-5 py-10 text-center text-sm" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
          No compliance data
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {compliance.map(c => {
            const pct   = c.total > 0 ? Math.round((c.passed / c.total) * 100) : 0;
            const colorStyle =
              pct >= 90 ? { color: 'var(--success)', background: 'var(--success-light)', border: '1px solid rgba(63,185,80,0.3)' } :
              pct >= 70 ? { color: 'var(--warning)', background: 'var(--warning-light)', border: '1px solid rgba(210,153,34,0.3)' } :
                          { color: 'var(--danger)',  background: 'var(--danger-light)',  border: '1px solid rgba(248,81,73,0.3)' };
            const label = pct >= 90 ? 'Compliant' : pct >= 70 ? 'Partial' : 'Non-Compliant';
            const Icon  = pct >= 90 ? CheckCircleIcon : pct >= 70 ? ExclamationTriangleIcon : XCircleIcon;

            return (
              <div key={c.id} style={{ borderRadius: 12, padding: 20, background: colorStyle.background, border: colorStyle.border }}>
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-base font-semibold" style={{ color: colorStyle.color }}>{c.name}</h3>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{c.passed} / {c.total} checks passed</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xl font-bold" style={{ color: colorStyle.color }}>{pct}%</span>
                    <Icon style={{ width: 20, height: 20, color: colorStyle.color }} />
                  </div>
                </div>
                <ComplianceBar passed={c.passed} total={c.total} />
                <div className="mt-3 flex items-center justify-between">
                  <span style={{
                    fontSize: 12, fontWeight: 500, padding: '2px 8px', borderRadius: 9999,
                    ...colorStyle,
                  }}>{label}</span>
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{c.total - c.passed} checks failing</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────────

export default function SecurityView() {
  const [activeTab, setActiveTab]   = useState<AlertTab>('overview');
  const [alerts, setAlerts]         = useState<Alert[]>([]);
  const [agents, setAgents]         = useState<Agent[]>([]);
  const [compliance, setCompliance] = useState<Compliance[]>([]);
  const [loading, setLoading]       = useState(true);
  const [showWizard, setShowWizard] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function fetchAll() {
      setLoading(true);
      try {
        const [alertsRes, devicesRes, complianceRes] = await Promise.allSettled([
          securityApi.getSecurityAlerts(),
          deviceApi.getDevices(),
          securityApi.getComplianceStatus(),
        ]);

        if (cancelled) return;

        // Alerts
        if (alertsRes.status === 'fulfilled') {
          const raw = alertsRes.value.data;
          const list: any[] = raw.alerts ?? raw.data ?? (Array.isArray(raw) ? raw : []);
          setAlerts(list.map(normalizeAlert));
        }

        // Agents — mapped from enrolled devices
        if (devicesRes.status === 'fulfilled') {
          const raw = devicesRes.value.data;
          const list: any[] = raw.data ?? raw.devices ?? (Array.isArray(raw) ? raw : []);
          const mapped: Agent[] = list.map((d: any) => ({
            id: d.id || d._id || String(Math.random()),
            name: d.name || d.hostname || 'Unknown',
            platform: d.os || d.platform || 'Unknown',
            version: d.wazuhVersion || 'Unknown',
            status: d.status === 'online' ? 'active' : 'disconnected',
            lastKeepAlive: d.lastSeen || d.last_seen || new Date().toISOString(),
            ip: d.ip_address || d.ip || '—',
          }));
          setAgents(mapped);
        }

        // Compliance
        if (complianceRes.status === 'fulfilled') {
          const raw = complianceRes.value.data;
          const list: any[] =
            raw.frameworks ?? raw.compliance ?? (Array.isArray(raw) ? raw : []);
          setCompliance(list.map(normalizeCompliance));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchAll();
    return () => { cancelled = true; };
  }, []);

  const activeAlerts = alerts.filter(a => !a.resolved).length;
  const critAlerts   = alerts.filter(a => !a.resolved && a.severity === 'critical').length;

  const tabs: { key: AlertTab; label: string; badge?: number }[] = [
    { key: 'overview',   label: 'Overview' },
    { key: 'alerts',     label: 'Alerts',     badge: activeAlerts },
    { key: 'agents',     label: 'Agents' },
    { key: 'compliance', label: 'Compliance' },
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: 'var(--danger-light)', border: '1px solid rgba(248,81,73,0.3)' }}>
            <ShieldExclamationIcon className="w-5 h-5" style={{ color: 'var(--danger)' }} />
          </div>
          <div>
            <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>Security Suite</h1>
            <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Powered by Wazuh · {activeAlerts} active alert{activeAlerts !== 1 ? 's' : ''}
              {critAlerts > 0 && (
                <span className="ml-1.5 font-medium" style={{ color: 'var(--danger)' }}>· {critAlerts} critical</span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors"
            style={{ color: '#a855f7', background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)' }}
          >
            <SparklesIcon className="w-4 h-4" />
            Security Wizard
          </button>
          <a
            href="https://siem.heusser.local"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}
          >
            <LinkIcon className="w-4 h-4" />
            Open Wazuh
          </a>
        </div>
      </div>

      {/* Tabs */}
      <div className="rounded-xl" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}>
        <nav className="flex px-5" style={{ borderBottom: '1px solid var(--border)' }}>
          {tabs.map(t => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`py-3 px-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                activeTab === t.key
                  ? 'border-blue-500'
                  : 'border-transparent'
              }`}
              style={{ color: activeTab === t.key ? 'var(--accent)' : 'var(--text-muted)' }}
            >
              {t.label}
              {t.badge !== undefined && t.badge > 0 && (
                <span style={{ background: 'var(--danger-light)', color: 'var(--danger)', fontSize: 12, fontWeight: 500, padding: '2px 6px', borderRadius: 9999 }}>
                  {t.badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div className="p-5">
          {loading ? (
            <LoadingSkeleton />
          ) : (
            <>
              {activeTab === 'overview'   && <OverviewTab alerts={alerts} agents={agents} compliance={compliance} />}
              {activeTab === 'alerts'     && <AlertsTab initialAlerts={alerts} />}
              {activeTab === 'agents'     && <AgentsTab agents={agents} />}
              {activeTab === 'compliance' && <ComplianceTab compliance={compliance} />}
            </>
          )}
        </div>
      </div>
      {showWizard && <SecuritySetupWizard onClose={() => setShowWizard(false)} />}
    </div>
  );
}
