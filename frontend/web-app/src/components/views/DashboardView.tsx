'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  UsersIcon,
  ComputerDesktopIcon,
  SparklesIcon,
  ServerIcon,
  ShieldCheckIcon,
  ChartBarIcon,
  BellAlertIcon,
  CpuChipIcon,
  CloudIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  SignalIcon,
  Cog6ToothIcon,
  DocumentTextIcon,
  LockClosedIcon,
} from '@heroicons/react/24/outline';
import {
  api,
  lldapApi,
  deviceApi,
  securityApi,
  prometheusApi,
  healthApi,
  gatewayApi,
  configApi,
  policyApi,
} from '@/lib/api';
import PIMGroupsPanel from './PIMGroupsPanel';
import BackupRecoveryWizard from '@/components/setup/BackupRecoveryWizard';
import toast from 'react-hot-toast';
import { PageHeader } from '@/components/ui/PageHeader';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface KpiData {
  // Row 1
  totalUsers: number | null;
  totalGroups: number | null;
  onlineDevices: number | null;
  totalDevices: number | null;
  healthyServices: number | null;
  totalServices: number | null;
  openAlerts: number | null;
  // Row 2
  activePolicies: number | null;
  totalPolicies: number | null;
  uptime: string | null;
  memoryPercent: number | null;
  enabledModules: number | null;
  totalModules: number | null;
}

type ServiceStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

interface ServiceCard {
  id: string;
  label: string;
  status: ServiceStatus;
  responseTime?: number;
  checkedAt: Date;
}

interface ActivityEvent {
  id: string;
  message: string;
  user?: string;
  timestamp: string;
  type: 'info' | 'warning' | 'error' | 'success';
}

interface ResourceMetric {
  label: string;
  value: number | null;
  hasData: boolean;
}

interface DeviceCompliance {
  compliant: number;
  atRisk: number;
  nonCompliant: number;
  noData: number;
  total: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function safeNum(val: unknown): number | null {
  if (val === null || val === undefined || val === '') return null;
  const n = Number(val);
  return isNaN(n) ? null : n;
}

function formatUptime(seconds: number): string {
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    return `${m}m`;
  }
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${m}m`;
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return `${d}d ${h}h`;
}

function parsePrometheusValue(data: unknown): number | null {
  try {
    const result = (data as any)?.data?.data?.result;
    if (Array.isArray(result) && result.length > 0) {
      const v = parseFloat(result[0]?.value?.[1]);
      return isNaN(v) ? null : Math.round(v * 10) / 10;
    }
    // Some proxies unwrap the result differently
    const altResult = (data as any)?.data?.result;
    if (Array.isArray(altResult) && altResult.length > 0) {
      const v = parseFloat(altResult[0]?.value?.[1]);
      return isNaN(v) ? null : Math.round(v * 10) / 10;
    }
  } catch {
    // ignore
  }
  return null;
}

function resolveServiceStatus(res: PromiseSettledResult<any>): ServiceStatus {
  if (res.status === 'rejected') return 'unknown';
  const d = res.value?.data;
  if (!d) return 'unknown';
  const s = (d.status ?? d.state ?? '').toLowerCase();
  if (s === 'healthy' || s === 'ok' || s === 'up') return 'healthy';
  if (s === 'unhealthy' || s === 'down' || s === 'error') return 'unhealthy';
  if (s === 'degraded' || s === 'warning') return 'degraded';
  return 'unknown';
}

function resolveResponseTime(res: PromiseSettledResult<any>): number | undefined {
  if (res.status === 'rejected') return undefined;
  const d = res.value?.data;
  return safeNum(d?.responseTime ?? d?.response_time ?? d?.latency) ?? undefined;
}

// Derive a service's status from /health/detailed response (handles multiple shapes)
function extractServiceStatus(detailedData: any, serviceKey: string): ServiceStatus {
  if (!detailedData) return 'unknown';
  // Shape A: { services: { lldap: { status: "healthy" } } }
  // Shape B: { lldap: { status: "healthy" } }
  const svc = detailedData?.services?.[serviceKey] ?? detailedData?.[serviceKey];
  if (!svc) return 'unknown';
  const s = (svc.status ?? svc.state ?? svc.health ?? '').toLowerCase();
  if (s === 'healthy' || s === 'ok' || s === 'up' || s === 'running') return 'healthy';
  if (s === 'unhealthy' || s === 'down' || s === 'error' || s === 'failed') return 'unhealthy';
  if (s === 'degraded' || s === 'warning' || s === 'slow') return 'degraded';
  return 'unknown';
}

function metricBarColor(pct: number): string {
  if (pct >= 85) return 'bg-red-500';
  if (pct >= 60) return 'bg-yellow-400';
  return 'bg-green-500';
}

function metricTextColor(pct: number): string {
  if (pct >= 85) return 'text-red-600';
  if (pct >= 60) return 'text-yellow-600';
  return 'text-green-600';
}

function statusDotClass(status: ServiceStatus): string {
  switch (status) {
    case 'healthy': return 'bg-green-500';
    case 'degraded': return 'bg-yellow-400';
    case 'unhealthy': return 'bg-red-500';
    default: return 'bg-gray-400';
  }
}

function statusLabel(status: ServiceStatus): string {
  switch (status) {
    case 'healthy': return 'Healthy';
    case 'degraded': return 'Degraded';
    case 'unhealthy': return 'Unhealthy';
    default: return 'Unknown';
  }
}

function statusLabelColor(status: ServiceStatus): React.CSSProperties {
  switch (status) {
    case 'healthy': return { color: 'var(--success)', background: 'var(--success-light)' };
    case 'degraded': return { color: 'var(--warning)', background: 'var(--warning-light)' };
    case 'unhealthy': return { color: 'var(--danger)', background: 'var(--danger-light)' };
    default: return { color: 'var(--text-muted)', background: 'var(--bg-surface-raised)' };
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SkeletonCard() {
  return (
    <div className="rounded-xl p-4 animate-pulse" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
      <div className="flex items-center gap-4">
        <div className="w-9 h-9 rounded-lg" style={{ background: 'var(--bg-surface-raised)' }} />
        <div className="flex-1 space-y-2">
          <div className="h-3 rounded w-1/2" style={{ background: 'var(--bg-surface-raised)' }} />
          <div className="h-7 rounded w-1/3" style={{ background: 'var(--bg-surface-raised)' }} />
        </div>
      </div>
      <div className="mt-4 h-2 rounded" style={{ background: 'var(--bg-surface-raised)' }} />
    </div>
  );
}

function SkeletonPanel({ tall = false }: { tall?: boolean }) {
  return (
    <div className={`rounded-xl p-4 animate-pulse ${tall ? 'h-80' : 'h-56'}`} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
      <div className="h-4 rounded w-1/3 mb-4" style={{ background: 'var(--bg-surface-raised)' }} />
      <div className="space-y-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-3 rounded" style={{ background: 'var(--bg-surface-raised)' }} />
        ))}
      </div>
    </div>
  );
}

interface KpiCardProps {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  subtitle?: React.ReactNode;
  footer?: React.ReactNode;
  alert?: boolean;
}

function KpiCard({ icon, label, value, subtitle, footer, alert }: KpiCardProps) {
  return (
    <div
      className={`od-dashboard-kpi rounded-xl p-4 ${alert ? 'border-red-200' : ''}`}
      style={alert
        ? { background: 'var(--bg-surface)', border: '1px solid #f85149', boxShadow: 'var(--card-shadow)' }
        : { background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }
      }
    >
      <div className="flex items-start gap-4">
        <div className="od-dashboard-kpi-icon">
          {icon}
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: 'var(--text-muted)' }}>{label}</p>
          <div className="text-2xl font-semibold mt-0.5 leading-tight" style={{ color: 'var(--text-primary)' }}>{value}</div>
          {subtitle && <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{subtitle}</div>}
        </div>
      </div>
      {footer && <div className="mt-4">{footer}</div>}
    </div>
  );
}

interface ProgressBarProps {
  value: number;
  colorClass: string;
  height?: string;
}

function ProgressBar({ value, colorClass, height = 'h-2' }: ProgressBarProps) {
  const clamped = Math.min(100, Math.max(0, value));
  return (
    <div className={`w-full rounded-full ${height} overflow-hidden`} style={{ background: 'var(--bg-surface-raised)' }}>
      <div
        className={`${height} rounded-full transition-all duration-500 ${colorClass}`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function DashboardView() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [showBackupWizard, setShowBackupWizard] = useState(false);

  const [kpi, setKpi] = useState<KpiData>({
    totalUsers: null,
    totalGroups: null,
    onlineDevices: null,
    totalDevices: null,
    healthyServices: null,
    totalServices: null,
    openAlerts: null,
    activePolicies: null,
    totalPolicies: null,
    uptime: null,
    memoryPercent: null,
    enabledModules: null,
    totalModules: null,
  });

  const [serviceCards, setServiceCards] = useState<ServiceCard[]>([]);
  const [activityEvents, setActivityEvents] = useState<ActivityEvent[] | null>(null);
  const [activityError, setActivityError] = useState(false);

  const [resources, setResources] = useState<ResourceMetric[]>([
    { label: 'CPU', value: null, hasData: false },
    { label: 'Memory', value: null, hasData: false },
    { label: 'Disk', value: null, hasData: false },
  ]);

  const [deviceCompliance, setDeviceCompliance] = useState<DeviceCompliance | null>(null);
  const [platformBreakdown, setPlatformBreakdown] = useState<{label:string;count:number;color:string}[]>([]);

  const loadData = useCallback(async () => {
    const configured: string[] | null = await api.get('/api/platform/capabilities').then(response => response.data.configuredServices ?? null).catch(() => null);
    const now = new Date();

    // -----------------------------------------------------------------------
    // Fire ALL top-level fetches in parallel
    // -----------------------------------------------------------------------
    const [
      lldapUsersRes,
      lldapGroupsRes,
      devicesRes,
      gatewayServicesRes,
      securityAlertsRes,
      policiesRes,
      detailedHealthRes,
      memQueryRes,
      modulesRes,
      // Prometheus resource queries
      cpuRes,
      memRes,
      diskRes,
      // Activity feed
      auditRes,
    ] = await Promise.allSettled([
      lldapApi.getUsers(),
      lldapApi.getGroups(),
      deviceApi.getDevices(),
      gatewayApi.getServices(),
      configured !== null && !configured.includes('security-scanner') ? Promise.reject(new Error('Security scanner not configured')) : securityApi.getSecurityAlerts(),
      policyApi.getPolicies(),
      healthApi.getDetailedHealth(),
      prometheusApi.query('100 * (1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes))'),
      configApi.getModules(),
      // Prometheus resources
      prometheusApi.query('100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
      prometheusApi.query('100 * (1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes))'),
      prometheusApi.query('100 - (sum(node_filesystem_free_bytes{fstype=~"ext4|xfs|btrfs|vfat"}) / sum(node_filesystem_size_bytes{fstype=~"ext4|xfs|btrfs|vfat"}) * 100)'),
      // Activity feed (may 404)
      api.get('/api/auth/audit/login-history?limit=8').then(response => { if (!Array.isArray(response.data?.history)) throw new Error('Unconfirmed login history'); return response.data.history; }),
    ]);

    // -----------------------------------------------------------------------
    // KPI Row 1: Users
    // -----------------------------------------------------------------------
    let totalUsers: number | null = null;
    let totalGroups: number | null = null;
    if (lldapUsersRes.status === 'fulfilled') {
      const d = lldapUsersRes.value?.data;
      const arr: any[] = Array.isArray(d) ? d : (d?.users ?? d?.data ?? []);
      totalUsers = arr.length > 0 ? arr.length : 0;
    }
    if (lldapGroupsRes.status === 'fulfilled') {
      const d = lldapGroupsRes.value?.data;
      const arr: any[] = Array.isArray(d) ? d : (d?.groups ?? d?.data ?? []);
      totalGroups = arr.length;
    }

    // -----------------------------------------------------------------------
    // KPI Row 1: Devices
    // -----------------------------------------------------------------------
    let onlineDevices: number | null = null;
    let totalDevices: number | null = null;
    let rawDevices: any[] = [];
    if (devicesRes.status === 'fulfilled') {
      rawDevices = Array.isArray(devicesRes.value?.data)
        ? devicesRes.value.data
        : devicesRes.value?.data?.devices ?? [];
      totalDevices = rawDevices.length;
      onlineDevices = rawDevices.filter(
        (d: any) => (d.status ?? d.online_status ?? '').toLowerCase() === 'online'
      ).length;
    }

    // -----------------------------------------------------------------------
    // KPI Row 1: Dienstzustand
    // -----------------------------------------------------------------------
    let healthyServices: number | null = null;
    let totalServices: number | null = null;
    if (gatewayServicesRes.status === 'fulfilled') {
      const services: any[] = (Array.isArray(gatewayServicesRes.value?.data)
        ? gatewayServicesRes.value.data
        : gatewayServicesRes.value?.data?.services ?? []).filter((service: any) => service.status !== 'disabled');
      totalServices = services.length;
      healthyServices = services.filter(
        (s: any) => (s.status ?? '').toLowerCase() === 'healthy'
      ).length;
    }

    // -----------------------------------------------------------------------
    // KPI Row 1: Security Alerts
    // -----------------------------------------------------------------------
    let openAlerts: number | null = null;
    if (securityAlertsRes.status === 'fulfilled') {
      const alerts: any[] = Array.isArray(securityAlertsRes.value?.data)
        ? securityAlertsRes.value.data
        : securityAlertsRes.value?.data?.alerts ?? [];
      openAlerts = alerts.filter(
        (a: any) => (a.status ?? a.state ?? 'open').toLowerCase() === 'open'
      ).length;
    }

    // -----------------------------------------------------------------------
    // KPI Row 2: Policies
    // -----------------------------------------------------------------------
    let activePolicies: number | null = null;
    let totalPolicies: number | null = null;
    if (policiesRes.status === 'fulfilled') {
      const policies: any[] = Array.isArray(policiesRes.value?.data)
        ? policiesRes.value.data
        : policiesRes.value?.data?.policies ?? [];
      totalPolicies = policies.length;
      activePolicies = policies.filter(
        (p: any) => p.enabled === true || p.status === 'active'
      ).length;
    }

    // -----------------------------------------------------------------------
    // KPI Row 2: Uptime
    // -----------------------------------------------------------------------
    let uptime: string | null = null;
    if (detailedHealthRes.status === 'fulfilled') {
      const d = detailedHealthRes.value?.data;
      const rawUptime =
        d?.gateway?.uptime ??
        d?.uptime ??
        d?.system?.uptime ??
        null;
      if (rawUptime !== null) {
        const secs = safeNum(rawUptime);
        if (secs !== null) uptime = formatUptime(secs);
      }
    }

    // -----------------------------------------------------------------------
    // KPI Row 2: Memory (from quick prometheus query)
    // -----------------------------------------------------------------------
    let memoryPercent: number | null = null;
    if (memQueryRes.status === 'fulfilled') {
      memoryPercent = parsePrometheusValue(memQueryRes.value);
    }

    // -----------------------------------------------------------------------
    // KPI Row 2: Modules
    // -----------------------------------------------------------------------
    let enabledModules: number | null = null;
    let totalModules: number | null = null;
    if (modulesRes.status === 'fulfilled') {
      const mods = modulesRes.value?.data ?? {};
      const entries = Array.isArray(mods) ? mods : Object.values(mods);
      totalModules = entries.length;
      enabledModules = entries.filter((m: any) => m?.enabled === true).length;
    }

    setKpi({
      totalUsers,
      totalGroups,
      onlineDevices,
      totalDevices,
      healthyServices,
      totalServices,
      openAlerts,
      activePolicies,
      totalPolicies,
      uptime,
      memoryPercent,
      enabledModules,
      totalModules,
    });

    // -----------------------------------------------------------------------
    // Service Cards — built from /api/services (real health checks) +
    //                 gateway overall status from /health/detailed
    // -----------------------------------------------------------------------
    const detailedData = detailedHealthRes.status === 'fulfilled' ? detailedHealthRes.value?.data : null;

    // /api/services returns an array: [{ id, name, status, port, responseTime, lastCheck }]
    const apiServices: any[] = gatewayServicesRes.status === 'fulfilled'
      ? (Array.isArray(gatewayServicesRes.value?.data)
          ? gatewayServicesRes.value.data
          : gatewayServicesRes.value?.data?.services ?? [])
      : [];

    // Index by id for fast lookup
    const svcById: Record<string, any> = {};
    for (const s of apiServices) {
      if (s.id) svcById[s.id] = s;
    }

    // Gateway overall status from health endpoint
    const gatewayStatus: ServiceStatus =
      detailedData?.status === 'healthy' ? 'healthy' :
      detailedData?.status === 'degraded' ? 'degraded' :
      detailedData?.status === 'unhealthy' ? 'unhealthy' : 'unknown';

    const SERVICE_DEFS = [
      { id: 'gateway',                label: 'OpenDirectory Gateway' },
      { id: 'lldap',                  label: 'LLDAP Directory' },
      { id: 'grafana',                label: 'Grafana' },
      { id: 'prometheus',             label: 'Prometheus' },
      { id: 'vault',                  label: 'HashiCorp Vault' },
      { id: 'network-infrastructure', label: 'Network Infrastructure' },
      { id: 'wazuh',                  label: 'Wazuh Security' },
    ];

    const cards: ServiceCard[] = SERVICE_DEFS.filter(({ id }) => svcById[id]?.status !== 'disabled').map(({ id, label }) => {
      if (id === 'gateway') {
        return { id, label, status: gatewayStatus, checkedAt: now };
      }
      const svc = svcById[id];
      if (!svc) return { id, label, status: 'unknown' as ServiceStatus, checkedAt: now };
      const s = (svc.status ?? '').toLowerCase();
      const status: ServiceStatus =
        s === 'healthy' ? 'healthy' :
        s === 'unhealthy' ? 'unhealthy' :
        s === 'degraded' ? 'degraded' : 'unknown';
      return {
        id,
        label,
        status,
        responseTime: svc.responseTime ?? undefined,
        checkedAt: svc.lastCheck ? new Date(svc.lastCheck) : now,
      };
    });

    setServiceCards(cards);

    // -----------------------------------------------------------------------
    // Activity Feed
    // -----------------------------------------------------------------------
    if (auditRes.status === 'fulfilled') {
      const events: any[] = auditRes.value;
      if (events.length === 0) {
        setActivityError(false);
        setActivityEvents([]);
      } else {
        const mapped: ActivityEvent[] = events.slice(0, 8).map((e: any, i: number) => ({
          id: e.id ?? String(i),
          message: e.message ?? e.action ?? e.description ?? 'Event recorded',
          user: e.user ?? e.username ?? e.actor,
          timestamp: e.timestamp ?? e.created_at ?? e.time ?? new Date().toISOString(),
          type: (e.severity === 'error' || e.type === 'error')
            ? 'error'
            : (e.severity === 'warning' || e.type === 'warning')
            ? 'warning'
            : (e.type === 'success')
            ? 'success'
            : 'info',
        }));
        setActivityEvents(mapped);
        setActivityError(false);
      }
    } else {
      // Try /api/monitoring/alerts as a fallback
      setActivityError(true);
      setActivityEvents(null);
    }

    // -----------------------------------------------------------------------
    // System Resources
    // -----------------------------------------------------------------------
    const cpuVal = cpuRes.status === 'fulfilled' ? parsePrometheusValue(cpuRes.value) : null;
    const memVal = memRes.status === 'fulfilled' ? parsePrometheusValue(memRes.value) : null;
    const diskVal = diskRes.status === 'fulfilled' ? parsePrometheusValue(diskRes.value) : null;

    setResources([
      { label: 'CPU', value: cpuVal, hasData: cpuVal !== null },
      { label: 'Memory', value: memVal, hasData: memVal !== null },
      { label: 'Disk', value: diskVal, hasData: diskVal !== null },
    ]);

    // -----------------------------------------------------------------------
    // Device Compliance
    // -----------------------------------------------------------------------
    if (rawDevices.length > 0) {
      let compliant = 0, atRisk = 0, nonCompliant = 0, noData = 0;
      for (const d of rawDevices) {
        const score = safeNum(d.complianceScore ?? d.compliance_score ?? d.compliance);
        if (score === null) { noData++; }
        else if (score >= 80) { compliant++; }
        else if (score >= 50) { atRisk++; }
        else { nonCompliant++; }
      }
      setDeviceCompliance({ compliant, atRisk, nonCompliant, noData, total: rawDevices.length });

      // Platform breakdown from real device data
      const PLATFORM_COLORS: Record<string, string> = { windows: 'bg-blue-500', macos: 'bg-gray-700', linux: 'bg-orange-500', ios: 'bg-purple-500', android: 'bg-green-500' };
      const counts: Record<string, number> = {};
      for (const d of rawDevices) {
        const p = (d.platform ?? d.os ?? 'unknown').toLowerCase();
        counts[p] = (counts[p] ?? 0) + 1;
      }
      setPlatformBreakdown(
        Object.entries(counts)
          .sort((a, b) => b[1] - a[1])
          .map(([p, count]) => ({ label: p.charAt(0).toUpperCase() + p.slice(1), count, color: PLATFORM_COLORS[p] ?? 'bg-teal-500' }))
      );
    } else {
      setDeviceCompliance(null);
      setPlatformBreakdown([]);
    }

    setLastRefresh(now);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  // ---------------------------------------------------------------------------
  // Render: Loading skeleton
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="od-dashboard space-y-4">
        {/* Header skeleton */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-7 w-56 rounded animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />
            <div className="h-4 w-80 rounded animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />
          </div>
          <div className="h-5 w-28 rounded animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />
        </div>
        <PIMGroupsPanel key="pim-groups" />
        {/* KPI rows */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
        {/* Row 3 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2"><SkeletonPanel tall /></div>
          <div><SkeletonPanel tall /></div>
        </div>
        {/* Row 4 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SkeletonPanel />
          <SkeletonPanel />
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Render: Full dashboard
  // ---------------------------------------------------------------------------

  const modulePct =
    kpi.totalModules && kpi.totalModules > 0 && kpi.enabledModules !== null
      ? Math.round((kpi.enabledModules / kpi.totalModules) * 100)
      : 0;

  const serviceHealthPct =
    kpi.totalServices && kpi.totalServices > 0 && kpi.healthyServices !== null
      ? Math.round((kpi.healthyServices / kpi.totalServices) * 100)
      : 0;

  return (
    <div className="od-dashboard space-y-4">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                              */}
      {/* ------------------------------------------------------------------ */}
      <PageHeader title="Übersicht" subtitle="Status deiner OpenDirectory-Infrastruktur" icon={ChartBarIcon} actions={<>
        <button className="fluent-btn-secondary" onClick={() => setShowBackupWizard(true)}><SparklesIcon className="h-4 w-4" />Backup-Assistent</button>
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aktualisierung alle 30 Sekunden · zuletzt {lastRefresh.toLocaleTimeString('de-CH')}</p>
      </>} />

      <PIMGroupsPanel key="pim-groups" />

      {/* ------------------------------------------------------------------ */}
      {/* Quick Actions                                                        */}
      {/* ------------------------------------------------------------------ */}
      <div className="od-dashboard-actions">
        {[
          { label: 'Gerät erfassen', target: '/devices?create=1', icon: ComputerDesktopIcon },
          { label: 'Nutzer hinzufügen', target: '/users?create=1', icon: UsersIcon },
          { label: 'App verbinden', target: '/identity', icon: SparklesIcon },
          { label: 'Richtlinien verwalten', target: '/policies', icon: DocumentTextIcon },
        ].map(action => (
          <button key={action.label} onClick={() => router.push(action.target)} className="fluent-btn-secondary">
            <action.icon className="w-5 h-5" />
            {action.label}
          </button>
        ))}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 1 KPIs                                                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. Users */}
        <KpiCard
          icon={<UsersIcon className="w-6 h-6 text-blue-600" />}
          label="Benutzer"
          value={kpi.totalUsers !== null ? kpi.totalUsers.toLocaleString() : '—'}
          subtitle={
            kpi.totalGroups !== null
              ? `${kpi.totalGroups} group${kpi.totalGroups !== 1 ? 's' : ''}`
              : 'Groups unavailable'
          }
          footer={
            <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
              <UsersIcon className="w-3.5 h-3.5" />
              <span>Directory accounts</span>
            </div>
          }
        />

        {/* 2. Devices */}
        <KpiCard
          icon={<ComputerDesktopIcon className="w-6 h-6 text-indigo-600" />}
          label="Geräte"
          value={kpi.totalDevices !== null ? kpi.totalDevices.toLocaleString() : '—'}
          subtitle={
            kpi.onlineDevices !== null && kpi.totalDevices !== null
              ? `${kpi.onlineDevices} online`
              : 'Status unavailable'
          }
          footer={
            kpi.onlineDevices !== null && kpi.totalDevices !== null ? (
              <div className="flex items-center gap-2 text-xs">
                <span className="inline-block w-2 h-2 rounded-full bg-green-500" />
                <span className="text-green-600 font-medium">
                  {kpi.onlineDevices} online
                </span>
                {kpi.totalDevices - kpi.onlineDevices > 0 && (
                  <>
                    <span className="inline-block w-2 h-2 rounded-full bg-gray-300" />
                    <span style={{ color: 'var(--text-muted)' }}>
                      {kpi.totalDevices - kpi.onlineDevices} offline
                    </span>
                  </>
                )}
              </div>
            ) : (
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>No device data</div>
            )
          }
        />

        {/* 3. Dienstzustand */}
        <KpiCard
          icon={<ServerIcon className="w-6 h-6 text-emerald-600" />}
          label="Dienstzustand"
          value={
            kpi.healthyServices !== null && kpi.totalServices !== null
              ? `${kpi.healthyServices} / ${kpi.totalServices}`
              : '—'
          }
          subtitle={
            kpi.totalServices !== null
              ? `${serviceHealthPct}% operational`
              : 'Unavailable'
          }
          footer={
            kpi.totalServices !== null ? (
              <ProgressBar
                value={serviceHealthPct}
                colorClass={serviceHealthPct === 100 ? 'bg-emerald-500' : serviceHealthPct >= 75 ? 'bg-yellow-400' : 'bg-red-500'}
              />
            ) : (
              <ProgressBar value={0} colorClass="bg-gray-200" />
            )
          }
        />

        {/* 4. Security Alerts */}
        <KpiCard
          alert={kpi.openAlerts !== null && kpi.openAlerts > 0}
          icon={<BellAlertIcon className={`w-6 h-6 ${kpi.openAlerts ? 'text-red-600' : 'text-orange-500'}`} />}
          label="Sicherheitsmeldungen"
          value={
            <span className={kpi.openAlerts ? 'text-red-600' : ''} style={kpi.openAlerts ? {} : { color: 'var(--text-primary)' }}>
              {kpi.openAlerts !== null ? kpi.openAlerts : '—'}
            </span>
          }
          subtitle="Open alerts"
          footer={
            kpi.openAlerts !== null ? (
              kpi.openAlerts === 0 ? (
                <div className="flex items-center gap-1.5 text-xs text-green-600">
                  <CheckCircleIcon className="w-3.5 h-3.5" />
                  <span>No active alerts</span>
                </div>
              ) : (
                <div className="flex items-center gap-1.5 text-xs text-red-600">
                  <ExclamationTriangleIcon className="w-3.5 h-3.5" />
                  <span>{kpi.openAlerts} alert{kpi.openAlerts !== 1 ? 's' : ''} require attention</span>
                </div>
              )
            ) : (
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>Data unavailable</div>
            )
          }
        />
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 2 KPIs                                                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 5. Active Policies */}
        <KpiCard
          icon={<DocumentTextIcon className="w-6 h-6 text-violet-600" />}
          label="Aktive Richtlinien"
          value={kpi.activePolicies !== null ? kpi.activePolicies : '—'}
          subtitle={
            kpi.totalPolicies !== null
              ? `of ${kpi.totalPolicies} total`
              : 'Unavailable'
          }
          footer={
            kpi.totalPolicies !== null && kpi.totalPolicies > 0 ? (
              <ProgressBar
                value={Math.round(((kpi.activePolicies ?? 0) / kpi.totalPolicies) * 100)}
                colorClass="bg-violet-500"
              />
            ) : (
              <ProgressBar value={0} colorClass="bg-gray-200" />
            )
          }
        />

        {/* 6. Gateway-Laufzeit */}
        <KpiCard
          icon={<ClockIcon className="w-6 h-6 text-sky-600" />}
          label="Gateway-Laufzeit"
          value={kpi.uptime ?? '—'}
          subtitle="Quelle: API-Gateway"
          footer={
            <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
              <span>{kpi.uptime ? 'Laufzeit vom Gateway bestätigt' : 'Laufzeit nicht bestätigt'}</span>
            </div>
          }
        />

        {/* 7. Memory */}
        <KpiCard
          icon={<ChartBarIcon className="w-6 h-6 text-fuchsia-600" />}
          label="Speicherauslastung"
          value={
            kpi.memoryPercent !== null
              ? <span className={metricTextColor(kpi.memoryPercent)}>{kpi.memoryPercent.toFixed(1)}%</span>
              : '—'
          }
          subtitle="Prometheus · erfasste Knoten"
          footer={
            kpi.memoryPercent !== null ? (
              <ProgressBar
                value={kpi.memoryPercent}
                colorClass={metricBarColor(kpi.memoryPercent)}
              />
            ) : (
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>Prometheus unavailable</div>
            )
          }
        />

        {/* 8. Active Modules */}
        <KpiCard
          icon={<Cog6ToothIcon className="w-6 h-6 text-amber-600" />}
          label="Aktive Module"
          value={
            kpi.enabledModules !== null && kpi.totalModules !== null
              ? `${kpi.enabledModules} / ${kpi.totalModules}`
              : '—'
          }
          subtitle={`${modulePct}% enabled`}
          footer={
            <ProgressBar value={modulePct} colorClass="bg-amber-500" />
          }
        />
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 3: Dienstzustand Grid + Activity Feed                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Dienstzustand Grid (2/3) */}
        <div className="lg:col-span-2 rounded-xl" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
            <div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Dienstzustand</h2>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Quelle: angebundene Integrationen</p>
            </div>
            <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
              <SignalIcon className="w-4 h-4" />
              <span>
                Checked at{' '}
                {lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          </div>
          <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {serviceCards.map((svc) => (
              <div
                key={svc.id}
                className="flex items-center gap-3 p-4 rounded-lg transition-colors"
                style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}
              >
                {/* Status dot */}
                <div className="relative shrink-0">
                  <span className={`block w-3 h-3 rounded-full ${statusDotClass(svc.status)}`} />
                  {svc.status === 'healthy' && (
                    <span className="absolute inset-0 rounded-full bg-green-500 animate-ping opacity-30" />
                  )}
                </div>
                {/* Info */}
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>{svc.label}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs font-medium px-1.5 py-0.5 rounded" style={statusLabelColor(svc.status)}>
                      {statusLabel(svc.status)}
                    </span>
                    {svc.responseTime !== undefined && (
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{svc.responseTime}ms</span>
                    )}
                    {svc.responseTime === undefined && svc.status === 'healthy' && (
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>N/A</span>
                    )}
                  </div>
                </div>
                {/* Last checked */}
                <div className="text-xs shrink-0 text-right" style={{ color: 'var(--text-muted)' }}>
                  <ClockIcon className="w-3.5 h-3.5 inline-block mr-0.5 -mt-0.5" />
                  {svc.checkedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Letzte Anmeldungen Feed (1/3) */}
        <div className="rounded-xl flex flex-col" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Letzte Anmeldungen</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Quelle: eigene Anmeldehistorie</p>
          </div>
          <div className="flex-1 p-4 overflow-y-auto">
            {activityError || activityEvents === null ? (
              /* Empty state */
              <div className="flex flex-col items-center justify-center h-full min-h-[160px] text-center px-4">
                <div className="w-12 h-12 rounded-full flex items-center justify-center mb-3" style={{ background: 'var(--bg-surface-raised)' }}>
                  <DocumentTextIcon className="w-6 h-6" style={{ color: 'var(--text-muted)' }} />
                </div>
                <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>{activityError ? 'Anmeldehistorie nicht erreichbar' : 'Anmeldehistorie wird geprüft …'}</p>
                <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  Diese Abfrage betrifft die eigene Anmeldehistorie. Daraus wird kein Gesamtzustand aller Dienste abgeleitet.
                </p>
              </div>
            ) : (
              <ol className="space-y-3">
                {activityEvents.map((evt) => {
                  const iconEl =
                    evt.type === 'error' ? (
                      <XCircleIcon className="w-4 h-4 text-red-500" />
                    ) : evt.type === 'warning' ? (
                      <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500" />
                    ) : evt.type === 'success' ? (
                      <CheckCircleIcon className="w-4 h-4 text-green-500" />
                    ) : (
                      <SignalIcon className="w-4 h-4 text-blue-400" />
                    );
                  return (
                    <li key={evt.id} className="flex items-start gap-2.5">
                      <div className="mt-0.5 shrink-0">{iconEl}</div>
                      <div className="min-w-0">
                        <p className="text-xs leading-snug" style={{ color: 'var(--text-secondary)' }}>{evt.message}</p>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          {evt.user && (
                            <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>{evt.user}</span>
                          )}
                          {evt.user && <span style={{ color: 'var(--text-muted)' }}>·</span>}
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {new Date(evt.timestamp).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </span>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 4: System Resources + Device Compliance                         */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* System Resources */}
        <div className="rounded-xl" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
            <div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Systemressourcen</h2>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Aktuelle Messwerte über Prometheus</p>
            </div>
            <CpuChipIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
          </div>
          <div className="p-4 space-y-5">
            {resources.map((metric) => {
              const displayVal = metric.hasData && metric.value !== null
                ? metric.value
                : 0;
              const colorBar = metric.hasData && metric.value !== null
                ? metricBarColor(metric.value)
                : 'bg-gray-200';
              const colorText = metric.hasData && metric.value !== null
                ? metricTextColor(metric.value)
                : '';
              return (
                <div key={metric.label}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>{metric.label}</span>
                    <span
                      className={`text-sm font-semibold ${colorText}`}
                      style={metric.hasData && metric.value !== null ? {} : { color: 'var(--text-muted)' }}
                    >
                      {metric.hasData && metric.value !== null
                        ? `${metric.value.toFixed(1)}%`
                        : 'No data'}
                    </span>
                  </div>
                  <ProgressBar value={displayVal} colorClass={colorBar} height="h-3" />
                  <div className="flex justify-between mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <span>0%</span>
                    <span className="text-yellow-400">60%</span>
                    <span className="text-red-400">85%</span>
                    <span style={{ color: 'var(--text-muted)' }}>100%</span>
                  </div>
                </div>
              );
            })}
          </div>
          {/* Legend */}
          <div className="px-6 pb-4 flex items-center gap-4 text-xs" style={{ color: 'var(--text-muted)' }}>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-2.5 rounded-sm bg-green-500" /> Normal (&lt;60%)
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-2.5 rounded-sm bg-yellow-400" /> Warning (60–85%)
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-2.5 rounded-sm bg-red-500" /> Critical (&gt;85%)
            </span>
          </div>
        </div>

        {/* Device Compliance */}
        <div className="rounded-xl" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
            <div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Device Compliance</h2>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Based on compliance score</p>
            </div>
            <ShieldCheckIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
          </div>
          <div className="p-4">
            {deviceCompliance === null ? (
              <div className="flex flex-col items-center justify-center h-40 text-center">
                <ComputerDesktopIcon className="w-10 h-10 mb-3" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm font-medium" style={{ color: 'var(--text-muted)' }}>No device data</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Enroll devices to see compliance status</p>
              </div>
            ) : (
              <>
                {/* Stacked bar */}
                <div className="mb-5">
                  <div className="flex rounded-full overflow-hidden h-5 gap-0.5">
                    {deviceCompliance.compliant > 0 && (
                      <div
                        className="bg-green-500 transition-all duration-500"
                        style={{ width: `${(deviceCompliance.compliant / deviceCompliance.total) * 100}%` }}
                        title={`Compliant: ${deviceCompliance.compliant}`}
                      />
                    )}
                    {deviceCompliance.atRisk > 0 && (
                      <div
                        className="bg-yellow-400 transition-all duration-500"
                        style={{ width: `${(deviceCompliance.atRisk / deviceCompliance.total) * 100}%` }}
                        title={`At Risk: ${deviceCompliance.atRisk}`}
                      />
                    )}
                    {deviceCompliance.nonCompliant > 0 && (
                      <div
                        className="bg-red-500 transition-all duration-500"
                        style={{ width: `${(deviceCompliance.nonCompliant / deviceCompliance.total) * 100}%` }}
                        title={`Non-Compliant: ${deviceCompliance.nonCompliant}`}
                      />
                    )}
                    {deviceCompliance.noData > 0 && (
                      <div
                        className="bg-gray-200 transition-all duration-500"
                        style={{ width: `${(deviceCompliance.noData / deviceCompliance.total) * 100}%` }}
                        title={`No Data: ${deviceCompliance.noData}`}
                      />
                    )}
                    {deviceCompliance.total === 0 && (
                      <div className="bg-gray-200 w-full" />
                    )}
                  </div>
                </div>
                {/* Legend rows */}
                <div className="space-y-2.5">
                  {[
                    {
                      label: 'Compliant',
                      count: deviceCompliance.compliant,
                      color: 'bg-green-500',
                      text: 'text-green-700',
                      desc: 'Score ≥ 80',
                    },
                    {
                      label: 'At Risk',
                      count: deviceCompliance.atRisk,
                      color: 'bg-yellow-400',
                      text: 'text-yellow-700',
                      desc: 'Score 50–79',
                    },
                    {
                      label: 'Non-Compliant',
                      count: deviceCompliance.nonCompliant,
                      color: 'bg-red-500',
                      text: 'text-red-700',
                      desc: 'Score < 50',
                    },
                    {
                      label: 'No Data',
                      count: deviceCompliance.noData,
                      color: 'bg-gray-300',
                      text: '',
                      desc: 'Score unavailable',
                    },
                  ].map((row) => (
                    <div key={row.label} className="flex items-center gap-2.5">
                      <span className={`w-3 h-3 rounded-sm shrink-0 ${row.color}`} />
                      <span className="text-sm flex-1" style={{ color: 'var(--text-secondary)' }}>{row.label}</span>
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{row.desc}</span>
                      <span className={`text-sm font-semibold ml-2 min-w-[2rem] text-right ${row.text}`} style={row.text ? {} : { color: 'var(--text-muted)' }}>
                        {row.count}
                      </span>
                    </div>
                  ))}
                  <div className="pt-2 flex items-center justify-between" style={{ borderTop: '1px solid var(--border)' }}>
                    <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Total devices</span>
                    <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{deviceCompliance.total}</span>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
      <details className="od-advanced-section"><summary>Geräte nach Plattform</summary>
        {platformBreakdown.length ? <table className="fluent-table w-full"><thead><tr><th>Plattform</th><th>Geräte</th></tr></thead><tbody>{platformBreakdown.map(platform => <tr key={platform.label}><td>{platform.label}</td><td>{platform.count}</td></tr>)}</tbody></table> : <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Keine Gerätedaten vorhanden.</p>}
      </details>
      {showBackupWizard && <BackupRecoveryWizard onClose={() => setShowBackupWizard(false)} />}
    </div>
  );
}
