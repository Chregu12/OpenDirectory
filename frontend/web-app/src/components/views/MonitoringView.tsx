'use client';

import React, { useState, useEffect } from 'react';
import {
  ChartBarIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  BellAlertIcon,
  CpuChipIcon,
  ServerIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  SignalIcon,
  EyeIcon,
  BoltIcon
} from '@heroicons/react/24/outline';
import { monitoringApi, prometheusApi, healthApi, gatewayApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';

// ── Types ──────────────────────────────────────────────────────────────────────

interface SystemMetric {
  name: string;
  value: number;
  unit: string;
  trend: 'up' | 'down' | 'stable';
  trendValue: string;
  status: 'healthy' | 'warning' | 'critical';
}

interface Alert {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  source: string;
  timestamp: string;
  acknowledged: boolean;
}

interface ServiceMetric {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  responseTime: number;
  uptime: string;
  requests: number;
  errors: number;
  lastCheck: string;
}

interface TimeseriesPoint {
  time: string;
  value: number;
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const mockMetrics: SystemMetric[] = [
  { name: 'CPU Usage', value: 34, unit: '%', trend: 'down', trendValue: '-2.1%', status: 'healthy' },
  { name: 'Memory Usage', value: 67, unit: '%', trend: 'up', trendValue: '+1.8%', status: 'healthy' },
  { name: 'Disk I/O', value: 12, unit: 'MB/s', trend: 'stable', trendValue: '0%', status: 'healthy' },
  { name: 'Network Throughput', value: 245, unit: 'Mbps', trend: 'up', trendValue: '+15%', status: 'healthy' },
  { name: 'Active Connections', value: 1842, unit: '', trend: 'up', trendValue: '+124', status: 'healthy' },
  { name: 'API Latency (p95)', value: 42, unit: 'ms', trend: 'down', trendValue: '-8ms', status: 'healthy' },
];

const mockAlerts: Alert[] = [
  { id: 'a-1', severity: 'critical', title: 'High memory usage on SRV-WEB02', description: 'Memory usage exceeded 90% threshold for more than 5 minutes.', source: 'Prometheus', timestamp: '2026-03-16T08:45:00Z', acknowledged: false },
  { id: 'a-2', severity: 'warning', title: 'Certificate expiring in 14 days', description: 'TLS certificate for api.corp.local expires on 2026-03-30.', source: 'Certificate Monitor', timestamp: '2026-03-16T06:00:00Z', acknowledged: false },
  { id: 'a-3', severity: 'warning', title: 'Disk space below 20% on SRV-FILE01', description: 'Volume /data has 18% free space remaining (52 GB of 280 GB).', source: 'Prometheus', timestamp: '2026-03-16T04:30:00Z', acknowledged: true },
  { id: 'a-4', severity: 'info', title: 'Backup completed successfully', description: 'Full system backup completed in 2h 14m. 1.2 TB backed up.', source: 'Backup System', timestamp: '2026-03-16T03:00:00Z', acknowledged: true },
  { id: 'a-5', severity: 'warning', title: 'LLDAP service restarted', description: 'LLDAP service was automatically restarted after health check failure.', source: 'Service Monitor', timestamp: '2026-03-15T22:15:00Z', acknowledged: true },
  { id: 'a-6', severity: 'info', title: 'Signature database updated', description: 'ClamAV signatures updated to version 27180.', source: 'Antivirus', timestamp: '2026-03-15T18:00:00Z', acknowledged: true },
];

const mockServices: ServiceMetric[] = [
  { name: 'API Gateway', status: 'healthy', responseTime: 12, uptime: '99.99%', requests: 45230, errors: 3, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'LLDAP (User Directory)', status: 'healthy', responseTime: 8, uptime: '99.95%', requests: 12400, errors: 0, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'Device Service', status: 'healthy', responseTime: 15, uptime: '99.98%', requests: 8900, errors: 2, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'Network Infrastructure', status: 'healthy', responseTime: 22, uptime: '99.97%', requests: 3200, errors: 0, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'Prometheus', status: 'healthy', responseTime: 5, uptime: '100%', requests: 89000, errors: 0, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'Grafana', status: 'healthy', responseTime: 35, uptime: '99.90%', requests: 1200, errors: 1, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'Vault', status: 'healthy', responseTime: 18, uptime: '100%', requests: 560, errors: 0, lastCheck: '2026-03-16T09:00:00Z' },
  { name: 'Printer Service', status: 'unknown', responseTime: 0, uptime: 'N/A', requests: 0, errors: 0, lastCheck: '2026-03-16T09:00:00Z' },
];

const generateTimeseries = (): TimeseriesPoint[] => {
  const points: TimeseriesPoint[] = [];
  const now = Date.now();
  for (let i = 23; i >= 0; i--) {
    points.push({
      time: new Date(now - i * 3600000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }),
      value: 25 + Math.random() * 30 + (i < 8 ? 15 : 0),
    });
  }
  return points;
};

const cpuTimeseries = generateTimeseries();

// ── Component ──────────────────────────────────────────────────────────────────

interface MonitoringViewProps {
  onOpenWizard?: () => void;
}

export default function MonitoringView({ onOpenWizard }: MonitoringViewProps) {
  const { isSimple } = useUiMode();
  const [activeTab, setActiveTab] = useState<'overview' | 'alerts' | 'services' | 'metrics'>('overview');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<SystemMetric[]>([]);
  const [services, setServices] = useState<ServiceMetric[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { loadMonitoringData(); }, []);

  const loadMonitoringData = async () => {
    setLoading(true);
    try {
      const [alertsRes, statusRes, servicesRes] = await Promise.allSettled([
        monitoringApi.getAlerts(),
        monitoringApi.getSystemStatus(),
        gatewayApi.getServices(),
      ]);

      // Alerts
      if (alertsRes.status === 'fulfilled' && alertsRes.value.data?.length > 0) {
        setAlerts(alertsRes.value.data.map((a: any) => ({
          id: a.id,
          severity: a.severity || 'info',
          title: a.title || a.message || 'Alert',
          description: a.description || '',
          source: a.source || 'System',
          timestamp: a.timestamp || new Date().toISOString(),
          acknowledged: a.acknowledged ?? false,
        })));
      } else {
        setAlerts(mockAlerts);
      }

      // Metrics from system status
      if (statusRes.status === 'fulfilled' && statusRes.value.data) {
        const s = statusRes.value.data;
        if (s.cpu !== undefined || s.memory !== undefined) {
          setMetrics([
            { name: 'CPU Usage', value: s.cpu ?? 0, unit: '%', trend: 'stable', trendValue: '0%', status: (s.cpu ?? 0) > 80 ? 'critical' : 'healthy' },
            { name: 'Memory Usage', value: s.memory ?? 0, unit: '%', trend: 'stable', trendValue: '0%', status: (s.memory ?? 0) > 80 ? 'warning' : 'healthy' },
            ...mockMetrics.slice(2),
          ]);
        } else {
          setMetrics(mockMetrics);
        }
      } else {
        setMetrics(mockMetrics);
      }

      // Services
      if (servicesRes.status === 'fulfilled' && servicesRes.value.data?.length > 0) {
        setServices(servicesRes.value.data.map((s: any) => ({
          name: s.name || 'Unknown',
          status: s.status || 'unknown',
          responseTime: s.responseTime || 0,
          uptime: s.uptime || 'N/A',
          requests: s.requests || 0,
          errors: s.errors || 0,
          lastCheck: s.lastCheck || new Date().toISOString(),
        })));
      } else {
        setServices(mockServices);
      }
    } catch {
      setAlerts(mockAlerts);
      setMetrics(mockMetrics);
      setServices(mockServices);
    } finally {
      setLoading(false);
    }
  };

  const unacknowledgedAlerts = alerts.filter(a => !a.acknowledged).length;

  const acknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, acknowledged: true } : a));
  };

  const alertSeverityBadge = (s: string) =>
    s === 'critical' ? 'od-badge-critical' :
    s === 'warning' ? 'od-badge-medium' :
    'od-badge-info';

  const alertSeverityIcon = (s: string) =>
    s === 'critical' ? <XCircleIcon className="w-5 h-5 text-red-500" /> :
    s === 'warning' ? <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" /> :
    <CheckCircleIcon className="w-5 h-5 text-blue-500" />;

  if (isSimple) {
    const healthyCount = services.filter(s => s.status === 'healthy').length;
    const unhealthyCount = services.filter(s => s.status === 'unhealthy').length;
    const hasCriticalAlerts = alerts.some(a => a.severity === 'critical' && !a.acknowledged);

    return (
      <SimpleViewLayout
        hero={{
          status: hasCriticalAlerts || unhealthyCount > 0 ? 'critical' : unacknowledgedAlerts > 0 ? 'warning' : 'ok',
          icon: <ChartBarIcon className="w-10 h-10 text-purple-600" />,
          title: hasCriticalAlerts
            ? `${unacknowledgedAlerts} Active Alert${unacknowledgedAlerts > 1 ? 's' : ''}`
            : unacknowledgedAlerts > 0
            ? `${unacknowledgedAlerts} Warning${unacknowledgedAlerts > 1 ? 's' : ''}`
            : 'All Systems Healthy',
          subtitle: `${healthyCount} of ${services.length} services running`,
        }}
        stats={[
          { value: healthyCount, label: 'Healthy', color: 'text-green-600' },
          { value: unhealthyCount, label: 'Unhealthy', color: 'text-red-600' },
          { value: unacknowledgedAlerts, label: 'Alerts', color: unacknowledgedAlerts > 0 ? 'text-red-600' : 'text-gray-600' },
          { value: `${Math.round(services.reduce((acc, s) => acc + s.responseTime, 0) / (services.filter(s => s.responseTime > 0).length || 1))}ms`, label: 'Avg Response', color: 'text-blue-600' },
        ]}
        sections={alerts.length > 0 ? [{
          title: 'Recent Alerts',
          maxItems: 4,
          items: alerts.slice(0, 4).map(a => ({
            key: a.id,
            icon: alertSeverityIcon(a.severity),
            title: a.title,
            subtitle: `${a.source} - ${new Date(a.timestamp).toLocaleString('de-DE')}`,
            trailing: (
              <span className={`px-2 py-0.5 rounded text-xs ${alertSeverityBadge(a.severity)}`}>{a.severity}</span>
            ),
          })),
        }] : []}
      >
        {/* CPU Timeline Chart */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <h3 className="text-sm font-semibold text-gray-600 mb-4">CPU Usage (Last 24h)</h3>
          <div className="flex items-end gap-1 h-32">
            {cpuTimeseries.map((p, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1">
                <div className="w-full relative" style={{ height: `${p.value * 1.2}px` }}>
                  <div className={`absolute bottom-0 w-full rounded-t ${p.value > 60 ? 'bg-orange-500' : p.value > 40 ? 'bg-blue-500' : 'bg-green-500'}`}
                    style={{ height: '100%' }} />
                </div>
              </div>
            ))}
          </div>
          <div className="flex justify-between mt-2 text-xs text-gray-400">
            <span>{cpuTimeseries[0]?.time}</span>
            <span>{cpuTimeseries[Math.floor(cpuTimeseries.length / 2)]?.time}</span>
            <span>{cpuTimeseries[cpuTimeseries.length - 1]?.time}</span>
          </div>
        </div>
      </SimpleViewLayout>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            <ChartBarIcon className="w-6 h-6 text-purple-600" /> Insights & Analytics
          </h1>
          <p className="text-sm text-gray-500">System monitoring, alerts, and performance metrics</p>
        </div>
        <div className="flex items-center gap-3">
          {unacknowledgedAlerts > 0 && (
            <span className="px-3 py-1 bg-red-100 text-red-700 rounded-lg text-sm flex items-center gap-1">
              <BellAlertIcon className="w-4 h-4" /> {unacknowledgedAlerts} active alerts
            </span>
          )}
          {onOpenWizard && (
            <button onClick={onOpenWizard} className="px-3 py-1.5 rounded-lg bg-cyan-50 hover:bg-cyan-100 text-cyan-700 text-sm font-medium transition-colors">
              Setup-Assistent
            </button>
          )}
          <button className="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 text-gray-600" title="Refresh">
            <ArrowPathIcon className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-3 border-b border-gray-200 bg-gray-50">
        {([
          ['overview', 'Overview'],
          ['alerts', `Alerts (${unacknowledgedAlerts})`],
          ['services', `Services (${services.length})`],
          ['metrics', 'Metrics'],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`od-tab ${activeTab === key ? 'od-tab-active' : 'od-tab-inactive'}`}>
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {/* ── Overview ───────────────────────────────────────────────────── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* System Metrics Cards */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              {metrics.map(m => (
                <div key={m.name} className="od-card p-4">
                  <div className="text-xs text-gray-500 mb-1">{m.name}</div>
                  <div className="text-2xl font-bold text-gray-900">
                    {m.value}<span className="text-sm text-gray-400 ml-1">{m.unit}</span>
                  </div>
                  <div className="flex items-center text-xs mt-1">
                    {m.trend === 'up' ? <ArrowTrendingUpIcon className="w-3 h-3 text-green-500 mr-1" /> :
                     m.trend === 'down' ? <ArrowTrendingDownIcon className="w-3 h-3 text-green-500 mr-1" /> :
                     <span className="w-3 h-3 mr-1">-</span>}
                    <span className="text-gray-500">{m.trendValue}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* CPU Timeline Chart */}
            <div className="od-card p-4">
              <h3 className="text-sm font-semibold text-gray-600 mb-4">CPU Usage (Last 24h)</h3>
              <div className="flex items-end gap-1 h-32">
                {cpuTimeseries.map((p, i) => (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1">
                    <div className="w-full relative" style={{ height: `${p.value * 1.2}px` }}>
                      <div className={`absolute bottom-0 w-full rounded-t ${p.value > 60 ? 'bg-orange-500' : p.value > 40 ? 'bg-blue-500' : 'bg-green-500'}`}
                        style={{ height: '100%' }} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex justify-between mt-2 text-xs text-gray-400">
                <span>{cpuTimeseries[0]?.time}</span>
                <span>{cpuTimeseries[Math.floor(cpuTimeseries.length / 2)]?.time}</span>
                <span>{cpuTimeseries[cpuTimeseries.length - 1]?.time}</span>
              </div>
            </div>

            {/* Recent Alerts */}
            <div className="od-card p-4">
              <div className="flex justify-between items-center mb-3">
                <h3 className="text-sm font-semibold text-gray-600">Recent Alerts</h3>
                <button onClick={() => setActiveTab('alerts')} className="text-xs text-blue-600 hover:text-blue-700">View all</button>
              </div>
              <div className="space-y-2">
                {alerts.slice(0, 4).map(a => (
                  <div key={a.id} className={`flex items-start gap-3 p-3 rounded-lg ${a.acknowledged ? 'bg-gray-50' : 'bg-white border border-gray-200'}`}>
                    {alertSeverityIcon(a.severity)}
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-gray-900">{a.title}</div>
                      <div className="text-xs text-gray-500">{a.source} - {new Date(a.timestamp).toLocaleString('de-DE')}</div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs ${alertSeverityBadge(a.severity)}`}>{a.severity}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Service Status Summary */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="od-card p-4 text-center">
                <div className="text-3xl font-bold text-green-600">{services.filter(s => s.status === 'healthy').length}</div>
                <div className="text-xs text-gray-500">Healthy Services</div>
              </div>
              <div className="od-card p-4 text-center">
                <div className="text-3xl font-bold text-red-600">{services.filter(s => s.status === 'unhealthy').length}</div>
                <div className="text-xs text-gray-500">Unhealthy</div>
              </div>
              <div className="od-card p-4 text-center">
                <div className="text-3xl font-bold text-yellow-600">{services.filter(s => s.status === 'unknown').length}</div>
                <div className="text-xs text-gray-500">Unknown</div>
              </div>
              <div className="od-card p-4 text-center">
                <div className="text-3xl font-bold text-blue-600">
                  {Math.round(services.reduce((acc, s) => acc + s.responseTime, 0) / (services.filter(s => s.responseTime > 0).length || 1))}ms
                </div>
                <div className="text-xs text-gray-500">Avg Response</div>
              </div>
            </div>
          </div>
        )}

        {/* ── Alerts ─────────────────────────────────────────────────────── */}
        {activeTab === 'alerts' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-500">{unacknowledgedAlerts} unacknowledged alerts</p>
              {unacknowledgedAlerts > 0 && (
                <button onClick={() => setAlerts(prev => prev.map(a => ({ ...a, acknowledged: true })))}
                  className="text-xs px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg">
                  Acknowledge All
                </button>
              )}
            </div>
            {alerts.map(a => (
              <div key={a.id} className={`od-card p-4 ${!a.acknowledged ? (a.severity === 'critical' ? 'border-red-200' : a.severity === 'warning' ? 'border-yellow-200' : '') : ''}`}>
                <div className="flex items-start gap-3">
                  {alertSeverityIcon(a.severity)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{a.title}</div>
                        <p className="text-sm text-gray-500 mt-1">{a.description}</p>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-xs shrink-0 ml-3 ${alertSeverityBadge(a.severity)}`}>{a.severity}</span>
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-400">
                      <span>{a.source}</span>
                      <span>{new Date(a.timestamp).toLocaleString('de-DE')}</span>
                      {!a.acknowledged && (
                        <button onClick={() => acknowledgeAlert(a.id)}
                          className="text-blue-600 hover:text-blue-700 font-medium">
                          Acknowledge
                        </button>
                      )}
                      {a.acknowledged && <span className="text-green-600">Acknowledged</span>}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Services ───────────────────────────────────────────────────── */}
        {activeTab === 'services' && (
          <div className="od-card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-200 bg-gray-50">
                  <th className="px-4 py-3">Service</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Response Time</th>
                  <th className="px-4 py-3">Uptime</th>
                  <th className="px-4 py-3">Requests (24h)</th>
                  <th className="px-4 py-3">Errors</th>
                  <th className="px-4 py-3">Last Check</th>
                </tr>
              </thead>
              <tbody>
                {services.map(s => (
                  <tr key={s.name} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <ServerIcon className="w-4 h-4 text-gray-400" />
                        <span className="font-medium text-gray-900">{s.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs ${
                        s.status === 'healthy' ? 'od-badge-success' :
                        s.status === 'unhealthy' ? 'od-badge-danger' :
                        'bg-gray-100 text-gray-600'
                      }`}>
                        {s.status === 'healthy' ? <CheckCircleIcon className="w-3 h-3" /> :
                         s.status === 'unhealthy' ? <XCircleIcon className="w-3 h-3" /> :
                         <ExclamationTriangleIcon className="w-3 h-3" />}
                        {s.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-mono text-xs ${s.responseTime < 20 ? 'text-green-600' : s.responseTime < 50 ? 'text-yellow-600' : 'text-red-600'}`}>
                        {s.responseTime > 0 ? `${s.responseTime}ms` : '-'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-700">{s.uptime}</td>
                    <td className="px-4 py-3 text-gray-700">{s.requests.toLocaleString()}</td>
                    <td className="px-4 py-3">
                      {s.errors > 0
                        ? <span className="text-red-600 font-medium">{s.errors}</span>
                        : <span className="text-green-600">0</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{new Date(s.lastCheck).toLocaleTimeString('de-DE')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Metrics ────────────────────────────────────────────────────── */}
        {activeTab === 'metrics' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {metrics.map(m => (
                <div key={m.name} className="od-card p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold text-gray-600">{m.name}</h3>
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      m.status === 'healthy' ? 'od-badge-success' :
                      m.status === 'warning' ? 'od-badge-warning' :
                      'od-badge-danger'
                    }`}>{m.status}</span>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-bold text-gray-900">{m.value}</span>
                    <span className="text-gray-500">{m.unit}</span>
                  </div>
                  <div className="mt-3">
                    <div className="w-full bg-gray-100 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${m.value > 80 ? 'bg-red-500' : m.value > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                        style={{ width: `${Math.min(m.value, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div className="flex items-center text-xs mt-2">
                    {m.trend === 'up' ? <ArrowTrendingUpIcon className="w-3 h-3 text-green-500 mr-1" /> :
                     m.trend === 'down' ? <ArrowTrendingDownIcon className="w-3 h-3 text-green-500 mr-1" /> :
                     null}
                    <span className="text-gray-500">{m.trendValue} vs last hour</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
