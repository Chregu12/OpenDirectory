'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
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

const SEVERITY_STYLES: Record<Severity, { badge: string; dot: string; label: string }> = {
  critical: { badge: 'bg-red-100 text-red-800 border-red-200',         dot: 'bg-red-500',    label: 'Critical' },
  high:     { badge: 'bg-orange-100 text-orange-800 border-orange-200', dot: 'bg-orange-500', label: 'High' },
  medium:   { badge: 'bg-yellow-100 text-yellow-800 border-yellow-200', dot: 'bg-yellow-500', label: 'Medium' },
  low:      { badge: 'bg-blue-100 text-blue-800 border-blue-200',       dot: 'bg-blue-400',   label: 'Low' },
  info:     { badge: 'bg-gray-100 text-gray-700 border-gray-200',       dot: 'bg-gray-400',   label: 'Info' },
};

function SeverityBadge({ sev }: { sev: Severity }) {
  const s = SEVERITY_STYLES[sev] ?? SEVERITY_STYLES['info'];
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${s.badge}`}>
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
      <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-medium text-gray-600 w-10 text-right">{pct}%</span>
    </div>
  );
}

// ─── Loading Skeleton ────────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-10 bg-gray-200 rounded-xl" />
      <div className="h-10 bg-gray-200 rounded-xl" />
      <div className="h-10 bg-gray-200 rounded-xl" />
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
    { label: 'Active Alerts',  value: active.length,                      color: 'text-gray-900',   bg: 'bg-gray-50',    icon: ShieldExclamationIcon },
    { label: 'Critical',       value: critical,                            color: 'text-red-700',    bg: 'bg-red-50',     icon: ExclamationTriangleIcon },
    { label: 'High',           value: high,                                color: 'text-orange-700', bg: 'bg-orange-50',  icon: ShieldExclamationIcon },
    { label: 'Medium',         value: medium,                              color: 'text-yellow-700', bg: 'bg-yellow-50',  icon: BugAntIcon },
    { label: 'Agents Online',  value: `${agentsUp}/${agents.length}`,      color: 'text-green-700',  bg: 'bg-green-50',   icon: ServerIcon },
    { label: 'Avg Compliance', value: `${avgCompliance}%`,                 color: 'text-blue-700',   bg: 'bg-blue-50',    icon: ShieldCheckIcon },
  ];

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpis.map(k => (
          <div key={k.label} className={`${k.bg} rounded-xl p-4`}>
            <div className="flex items-center justify-between mb-1">
              <p className={`text-xs font-medium ${k.color}`}>{k.label}</p>
              <k.icon className={`h-4 w-4 ${k.color}`} />
            </div>
            <p className={`text-2xl font-bold ${k.color}`}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* Recent alerts */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-700">Recent Active Alerts</h3>
          <span className="text-xs text-gray-400">{active.length} open</span>
        </div>
        <div className="divide-y divide-gray-50">
          {active.slice(0, 6).map(alert => (
            <div key={alert.id} className="flex items-start gap-3 px-5 py-3 hover:bg-gray-50">
              <div className="mt-0.5 flex-shrink-0">
                <SeverityBadge sev={alert.severity} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-gray-800">{alert.rule}</p>
                <p className="text-xs text-gray-500 truncate">{alert.description}</p>
              </div>
              <div className="flex-shrink-0 text-right">
                <p className="text-xs text-gray-500">{alert.device}</p>
                <p className="text-xs text-gray-400">{fmtTime(alert.timestamp)}</p>
              </div>
            </div>
          ))}
          {active.length === 0 && (
            <div className="flex items-center gap-2 px-5 py-6 text-green-600">
              <CheckCircleIcon className="w-5 h-5" />
              <span className="text-sm font-medium">No active alerts — system is clean</span>
            </div>
          )}
        </div>
      </div>

      {/* Compliance summary */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        <div className="px-5 py-4 border-b border-gray-100">
          <h3 className="text-sm font-semibold text-gray-700">Compliance Overview</h3>
        </div>
        {compliance.length === 0 ? (
          <div className="px-5 py-6 text-sm text-gray-400">No compliance data</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-5">
            {compliance.map(c => (
              <div key={c.id} className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-700">{c.name}</span>
                  <span className="text-xs text-gray-500">{c.passed}/{c.total} checks</span>
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
          <MagnifyingGlassIcon className="absolute left-3 inset-y-0 my-auto h-4 w-4 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search alerts…"
            className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div className="flex items-center gap-1.5">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(s => (
            <button
              key={s}
              onClick={() => setSevFilter(s)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg capitalize transition-colors ${
                sevFilter === s ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-sm text-gray-600 cursor-pointer">
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
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        {alerts.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-gray-400">No alerts detected</div>
        ) : (
          <table className="min-w-full">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr>
                {['Severity', 'Rule', 'Description', 'Device', 'Category', 'Time', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {filtered.map(alert => (
                <tr key={alert.id} className={`hover:bg-gray-50 transition-colors ${alert.resolved ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3 whitespace-nowrap"><SeverityBadge sev={alert.severity} /></td>
                  <td className="px-4 py-3">
                    <p className="text-sm font-medium text-gray-800 whitespace-nowrap">{alert.rule}</p>
                    <p className="text-xs text-gray-400">Rule {alert.ruleId}</p>
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <p className="text-sm text-gray-600 truncate">{alert.description}</p>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-600">{alert.device}</td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">{alert.category}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-gray-400">{fmtTime(alert.timestamp)}</td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {!alert.resolved ? (
                      <button
                        onClick={() => resolve(alert.id)}
                        className="px-2.5 py-1 text-xs font-medium text-green-700 bg-green-50 hover:bg-green-100 rounded-lg border border-green-200 transition-colors"
                      >
                        Resolve
                      </button>
                    ) : (
                      <span className="text-xs text-gray-400 flex items-center gap-1">
                        <CheckCircleIcon className="w-3.5 h-3.5 text-green-500" /> Resolved
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-sm text-gray-400">
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
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-700">Wazuh Agents</h3>
        <span className="text-xs text-gray-400">
          {activeCount}/{agents.length} active
        </span>
      </div>
      {agents.length === 0 ? (
        <div className="px-5 py-10 text-center text-sm text-gray-400">No agents enrolled</div>
      ) : (
        <table className="min-w-full">
          <thead className="bg-gray-50 border-b border-gray-100">
            <tr>
              {['Agent', 'Platform', 'Version', 'IP Address', 'Status', 'Last Active'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {agents.map(agent => (
              <tr key={agent.id} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <ComputerDesktopIcon className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-gray-800">{agent.name}</p>
                      <p className="text-xs text-gray-400">ID: {agent.id}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 text-sm text-gray-600">{agent.platform}</td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono bg-gray-100 px-2 py-0.5 rounded">v{agent.version}</span>
                </td>
                <td className="px-4 py-3 text-sm font-mono text-gray-600">{agent.ip}</td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                    agent.status === 'active'
                      ? 'bg-green-100 text-green-700'
                      : 'bg-gray-100 text-gray-500'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${agent.status === 'active' ? 'bg-green-500' : 'bg-gray-400'}`} />
                    {agent.status === 'active' ? 'Active' : 'Disconnected'}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-400">{fmtTime(agent.lastKeepAlive)}</td>
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
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 px-5 py-10 text-center text-sm text-gray-400">
          No compliance data
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {compliance.map(c => {
            const pct   = c.total > 0 ? Math.round((c.passed / c.total) * 100) : 0;
            const color = pct >= 90 ? 'text-green-700' : pct >= 70 ? 'text-yellow-700' : 'text-red-700';
            const bg    = pct >= 90 ? 'bg-green-50 border-green-100' : pct >= 70 ? 'bg-yellow-50 border-yellow-100' : 'bg-red-50 border-red-100';
            const label = pct >= 90 ? 'Compliant' : pct >= 70 ? 'Partial' : 'Non-Compliant';
            const Icon  = pct >= 90 ? CheckCircleIcon : pct >= 70 ? ExclamationTriangleIcon : XCircleIcon;

            return (
              <div key={c.id} className={`rounded-xl border p-5 ${bg}`}>
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className={`text-base font-semibold ${color}`}>{c.name}</h3>
                    <p className="text-xs text-gray-500 mt-0.5">{c.passed} / {c.total} checks passed</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xl font-bold ${color}`}>{pct}%</span>
                    <Icon className={`w-5 h-5 ${color}`} />
                  </div>
                </div>
                <ComplianceBar passed={c.passed} total={c.total} />
                <div className="mt-3 flex items-center justify-between">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${
                    pct >= 90 ? 'bg-green-100 text-green-700 border-green-200' :
                    pct >= 70 ? 'bg-yellow-100 text-yellow-700 border-yellow-200' :
                                'bg-red-100 text-red-700 border-red-200'
                  }`}>{label}</span>
                  <span className="text-xs text-gray-400">{c.total - c.passed} checks failing</span>
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
          <div className="w-9 h-9 bg-red-50 border border-red-100 rounded-lg flex items-center justify-center">
            <ShieldExclamationIcon className="w-5 h-5 text-red-600" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">Security Suite</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Powered by Wazuh · {activeAlerts} active alert{activeAlerts !== 1 ? 's' : ''}
              {critAlerts > 0 && (
                <span className="ml-1.5 text-red-600 font-medium">· {critAlerts} critical</span>
              )}
            </p>
          </div>
        </div>
        <a
          href="https://siem.heusser.local"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 hover:bg-gray-50 rounded-lg transition-colors"
        >
          <LinkIcon className="w-4 h-4" />
          Open Wazuh
        </a>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        <nav className="flex border-b border-gray-100 px-5">
          {tabs.map(t => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`py-3 px-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                activeTab === t.key
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {t.label}
              {t.badge !== undefined && t.badge > 0 && (
                <span className="bg-red-100 text-red-700 text-xs font-medium px-1.5 py-0.5 rounded-full">
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
    </div>
  );
}
