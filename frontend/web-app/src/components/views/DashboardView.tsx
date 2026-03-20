'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  UsersIcon,
  ComputerDesktopIcon,
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
  lldapApi,
  deviceApi,
  securityApi,
  prometheusApi,
  healthApi,
  gatewayApi,
  configApi,
  policyApi,
} from '@/lib/api';

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

function statusLabelColor(status: ServiceStatus): string {
  switch (status) {
    case 'healthy': return 'text-green-700 bg-green-50';
    case 'degraded': return 'text-yellow-700 bg-yellow-50';
    case 'unhealthy': return 'text-red-700 bg-red-50';
    default: return 'text-gray-600 bg-gray-100';
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SkeletonCard() {
  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-6 animate-pulse">
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-gray-200" />
        <div className="flex-1 space-y-2">
          <div className="h-3 bg-gray-200 rounded w-1/2" />
          <div className="h-7 bg-gray-200 rounded w-1/3" />
        </div>
      </div>
      <div className="mt-4 h-2 bg-gray-200 rounded" />
    </div>
  );
}

function SkeletonPanel({ tall = false }: { tall?: boolean }) {
  return (
    <div className={`bg-white rounded-xl border border-gray-100 shadow-sm p-6 animate-pulse ${tall ? 'h-80' : 'h-56'}`}>
      <div className="h-4 bg-gray-200 rounded w-1/3 mb-4" />
      <div className="space-y-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-3 bg-gray-200 rounded" />
        ))}
      </div>
    </div>
  );
}

interface KpiCardProps {
  icon: React.ReactNode;
  iconBg: string;
  label: string;
  value: React.ReactNode;
  subtitle?: React.ReactNode;
  footer?: React.ReactNode;
  alert?: boolean;
}

function KpiCard({ icon, iconBg, label, value, subtitle, footer, alert }: KpiCardProps) {
  return (
    <div className={`bg-white rounded-xl border shadow-sm p-6 transition-shadow hover:shadow-md ${alert ? 'border-red-200' : 'border-gray-100'}`}>
      <div className="flex items-start gap-4">
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${iconBg}`}>
          {icon}
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-gray-500 truncate">{label}</p>
          <div className="text-2xl font-semibold text-gray-900 mt-0.5 leading-tight">{value}</div>
          {subtitle && <div className="text-xs text-gray-400 mt-0.5">{subtitle}</div>}
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
    <div className={`w-full bg-gray-100 rounded-full ${height} overflow-hidden`}>
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
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

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

  const loadData = useCallback(async () => {
    const now = new Date();

    // -----------------------------------------------------------------------
    // Fire ALL top-level fetches in parallel
    // -----------------------------------------------------------------------
    const [
      lldapUsersRes,
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
      deviceApi.getDevices(),
      gatewayApi.getServices(),
      securityApi.getSecurityAlerts(),
      policyApi.getPolicies(),
      healthApi.getDetailedHealth(),
      prometheusApi.query('100 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100)'),
      configApi.getModules(),
      // Prometheus resources
      prometheusApi.query('100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
      prometheusApi.query('100 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100)'),
      prometheusApi.query('100 - (node_filesystem_free_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} * 100)'),
      // Activity feed (may 404)
      fetch('/api/audit/events').then(r => { if (!r.ok) throw new Error('no audit'); return r.json(); }),
    ]);

    // -----------------------------------------------------------------------
    // KPI Row 1: Users
    // -----------------------------------------------------------------------
    let totalUsers: number | null = null;
    let totalGroups: number | null = null;
    if (lldapUsersRes.status === 'fulfilled') {
      const d = lldapUsersRes.value?.data;
      // getUsers() returns an array or { users: [...] }
      const arr: any[] = Array.isArray(d) ? d : (d?.users ?? d?.data ?? []);
      totalUsers = arr.length > 0 ? arr.length : null;
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
    // KPI Row 1: Service Health
    // -----------------------------------------------------------------------
    let healthyServices: number | null = null;
    let totalServices: number | null = null;
    if (gatewayServicesRes.status === 'fulfilled') {
      const services: any[] = Array.isArray(gatewayServicesRes.value?.data)
        ? gatewayServicesRes.value.data
        : gatewayServicesRes.value?.data?.services ?? [];
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
    // Service Cards — derived from /health/detailed (one call, no individual endpoint needed)
    // -----------------------------------------------------------------------
    const detailedData = detailedHealthRes.status === 'fulfilled' ? detailedHealthRes.value?.data : null;
    const cards: ServiceCard[] = [
      { id: 'gateway',                label: 'OpenDirectory Gateway' },
      { id: 'lldap',                  label: 'LLDAP Directory' },
      { id: 'grafana',                label: 'Grafana' },
      { id: 'prometheus',             label: 'Prometheus' },
      { id: 'vault',                  label: 'HashiCorp Vault' },
      { id: 'network-infrastructure', label: 'Network Infrastructure' },
      { id: 'wazuh',                  label: 'Wazuh Security' },
    ].map(({ id, label }) => ({
      id,
      label,
      status: extractServiceStatus(detailedData, id),
      checkedAt: now,
    }));

    setServiceCards(cards);

    // -----------------------------------------------------------------------
    // Activity Feed
    // -----------------------------------------------------------------------
    if (auditRes.status === 'fulfilled') {
      const raw = auditRes.value;
      const events: any[] = Array.isArray(raw) ? raw : raw?.events ?? raw?.data ?? [];
      if (events.length === 0) {
        setActivityError(true);
        setActivityEvents(null);
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
    } else {
      setDeviceCompliance(null);
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
      <div className="p-6 space-y-6">
        {/* Header skeleton */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-7 w-56 bg-gray-200 rounded animate-pulse" />
            <div className="h-4 w-80 bg-gray-200 rounded animate-pulse" />
          </div>
          <div className="h-5 w-28 bg-gray-200 rounded animate-pulse" />
        </div>
        {/* KPI rows */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
        {/* Row 3 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2"><SkeletonPanel tall /></div>
          <div><SkeletonPanel tall /></div>
        </div>
        {/* Row 4 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
    <div className="p-6 space-y-6">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                              */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">System Overview</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Real-time status of your OpenDirectory infrastructure
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm text-gray-500 shrink-0">
          <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span>Auto-refresh every 30s</span>
          <span className="text-gray-300 mx-1">|</span>
          <span>
            Last updated{' '}
            {lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Row 1 KPIs                                                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. Users */}
        <KpiCard
          icon={<UsersIcon className="w-6 h-6 text-blue-600" />}
          iconBg="bg-blue-50"
          label="Users"
          value={kpi.totalUsers !== null ? kpi.totalUsers.toLocaleString() : '—'}
          subtitle={
            kpi.totalGroups !== null
              ? `${kpi.totalGroups} group${kpi.totalGroups !== 1 ? 's' : ''}`
              : 'Groups unavailable'
          }
          footer={
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <UsersIcon className="w-3.5 h-3.5" />
              <span>Directory accounts</span>
            </div>
          }
        />

        {/* 2. Devices */}
        <KpiCard
          icon={<ComputerDesktopIcon className="w-6 h-6 text-indigo-600" />}
          iconBg="bg-indigo-50"
          label="Devices"
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
                    <span className="text-gray-400">
                      {kpi.totalDevices - kpi.onlineDevices} offline
                    </span>
                  </>
                )}
              </div>
            ) : (
              <div className="text-xs text-gray-400">No device data</div>
            )
          }
        />

        {/* 3. Service Health */}
        <KpiCard
          icon={<ServerIcon className="w-6 h-6 text-emerald-600" />}
          iconBg="bg-emerald-50"
          label="Service Health"
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
          iconBg={kpi.openAlerts ? 'bg-red-50' : 'bg-orange-50'}
          label="Security Alerts"
          value={
            <span className={kpi.openAlerts ? 'text-red-600' : 'text-gray-900'}>
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
              <div className="text-xs text-gray-400">Data unavailable</div>
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
          iconBg="bg-violet-50"
          label="Active Policies"
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

        {/* 6. System Uptime */}
        <KpiCard
          icon={<ClockIcon className="w-6 h-6 text-sky-600" />}
          iconBg="bg-sky-50"
          label="System Uptime"
          value={kpi.uptime ?? '—'}
          subtitle="Gateway runtime"
          footer={
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <span className="inline-block w-2 h-2 rounded-full bg-green-500" />
              <span>Running stable</span>
            </div>
          }
        />

        {/* 7. Memory */}
        <KpiCard
          icon={<ChartBarIcon className="w-6 h-6 text-fuchsia-600" />}
          iconBg="bg-fuchsia-50"
          label="Memory Usage"
          value={
            kpi.memoryPercent !== null
              ? <span className={metricTextColor(kpi.memoryPercent)}>{kpi.memoryPercent.toFixed(1)}%</span>
              : '—'
          }
          subtitle="System memory"
          footer={
            kpi.memoryPercent !== null ? (
              <ProgressBar
                value={kpi.memoryPercent}
                colorClass={metricBarColor(kpi.memoryPercent)}
              />
            ) : (
              <div className="text-xs text-gray-400">Prometheus unavailable</div>
            )
          }
        />

        {/* 8. Active Modules */}
        <KpiCard
          icon={<Cog6ToothIcon className="w-6 h-6 text-amber-600" />}
          iconBg="bg-amber-50"
          label="Active Modules"
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
      {/* Row 3: Service Health Grid + Activity Feed                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Service Health Grid (2/3) */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-gray-100 shadow-sm">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-gray-900">Service Health</h2>
              <p className="text-xs text-gray-400 mt-0.5">All infrastructure services</p>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <SignalIcon className="w-4 h-4" />
              <span>
                Checked at{' '}
                {lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          </div>
          <div className="p-6 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {serviceCards.map((svc) => (
              <div
                key={svc.id}
                className="flex items-center gap-3 p-4 rounded-lg border border-gray-100 bg-gray-50 hover:bg-white hover:border-gray-200 transition-colors"
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
                  <p className="text-sm font-medium text-gray-900 truncate">{svc.label}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${statusLabelColor(svc.status)}`}>
                      {statusLabel(svc.status)}
                    </span>
                    {svc.responseTime !== undefined && (
                      <span className="text-xs text-gray-400">{svc.responseTime}ms</span>
                    )}
                    {svc.responseTime === undefined && svc.status === 'healthy' && (
                      <span className="text-xs text-gray-400">N/A</span>
                    )}
                  </div>
                </div>
                {/* Last checked */}
                <div className="text-xs text-gray-400 shrink-0 text-right">
                  <ClockIcon className="w-3.5 h-3.5 inline-block mr-0.5 -mt-0.5" />
                  {svc.checkedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity Feed (1/3) */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm flex flex-col">
          <div className="px-6 py-4 border-b border-gray-100">
            <h2 className="text-base font-semibold text-gray-900">Recent Activity</h2>
            <p className="text-xs text-gray-400 mt-0.5">Audit log & alerts</p>
          </div>
          <div className="flex-1 p-6 overflow-y-auto">
            {activityError || activityEvents === null ? (
              /* Empty state */
              <div className="flex flex-col items-center justify-center h-full min-h-[160px] text-center px-4">
                <div className="w-12 h-12 rounded-full bg-gray-100 flex items-center justify-center mb-3">
                  <DocumentTextIcon className="w-6 h-6 text-gray-400" />
                </div>
                <p className="text-sm font-medium text-gray-600">No activity yet</p>
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                  Audit log integration coming soon. Events will appear here automatically.
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
                        <p className="text-xs text-gray-700 leading-snug">{evt.message}</p>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          {evt.user && (
                            <span className="text-xs text-gray-400 font-medium">{evt.user}</span>
                          )}
                          {evt.user && <span className="text-gray-300">·</span>}
                          <span className="text-xs text-gray-400">
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Resources */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-gray-900">System Resources</h2>
              <p className="text-xs text-gray-400 mt-0.5">Live metrics via Prometheus</p>
            </div>
            <CpuChipIcon className="w-5 h-5 text-gray-300" />
          </div>
          <div className="p-6 space-y-5">
            {resources.map((metric) => {
              const displayVal = metric.hasData && metric.value !== null
                ? metric.value
                : 0;
              const colorBar = metric.hasData && metric.value !== null
                ? metricBarColor(metric.value)
                : 'bg-gray-200';
              const colorText = metric.hasData && metric.value !== null
                ? metricTextColor(metric.value)
                : 'text-gray-400';
              return (
                <div key={metric.label}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">{metric.label}</span>
                    <span className={`text-sm font-semibold ${colorText}`}>
                      {metric.hasData && metric.value !== null
                        ? `${metric.value.toFixed(1)}%`
                        : 'No data'}
                    </span>
                  </div>
                  <ProgressBar value={displayVal} colorClass={colorBar} height="h-3" />
                  <div className="flex justify-between mt-1 text-xs text-gray-300">
                    <span>0%</span>
                    <span className="text-yellow-400">60%</span>
                    <span className="text-red-400">85%</span>
                    <span>100%</span>
                  </div>
                </div>
              );
            })}
          </div>
          {/* Legend */}
          <div className="px-6 pb-4 flex items-center gap-4 text-xs text-gray-400">
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
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-gray-900">Device Compliance</h2>
              <p className="text-xs text-gray-400 mt-0.5">Based on compliance score</p>
            </div>
            <ShieldCheckIcon className="w-5 h-5 text-gray-300" />
          </div>
          <div className="p-6">
            {deviceCompliance === null ? (
              <div className="flex flex-col items-center justify-center h-40 text-center">
                <ComputerDesktopIcon className="w-10 h-10 text-gray-200 mb-3" />
                <p className="text-sm text-gray-500 font-medium">No device data</p>
                <p className="text-xs text-gray-400 mt-1">Enroll devices to see compliance status</p>
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
                      text: 'text-gray-500',
                      desc: 'Score unavailable',
                    },
                  ].map((row) => (
                    <div key={row.label} className="flex items-center gap-2.5">
                      <span className={`w-3 h-3 rounded-sm shrink-0 ${row.color}`} />
                      <span className="text-sm text-gray-700 flex-1">{row.label}</span>
                      <span className="text-xs text-gray-400">{row.desc}</span>
                      <span className={`text-sm font-semibold ml-2 min-w-[2rem] text-right ${row.text}`}>
                        {row.count}
                      </span>
                    </div>
                  ))}
                  <div className="pt-2 border-t border-gray-100 flex items-center justify-between">
                    <span className="text-xs text-gray-400 font-medium">Total devices</span>
                    <span className="text-sm font-semibold text-gray-900">{deviceCompliance.total}</span>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
