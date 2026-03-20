'use client';

import React, { useState, useEffect } from 'react';
import {
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ServerIcon,
  CpuChipIcon,
  ChartBarIcon,
  CircleStackIcon,
  ComputerDesktopIcon,
} from '@heroicons/react/24/outline';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';
import { healthApi, prometheusApi, grafanaApi, deviceApi } from '@/lib/api';
import toast from 'react-hot-toast';

interface ServiceHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  lastCheck: string;
  responseTime?: number;
}

interface KPI {
  label: string;
  value: string;
  icon: React.ComponentType<any>;
  color: string;
  bg: string;
}

interface MetricPoint {
  time: string;
  value: number;
}

type MetricKey = 'cpu_usage' | 'memory_usage' | 'request_rate' | 'error_rate';

const METRIC_OPTIONS: { key: MetricKey; label: string; color: string; unit: string }[] = [
  { key: 'cpu_usage',    label: 'CPU Usage',    color: '#8b5cf6', unit: '%' },
  { key: 'memory_usage', label: 'Memory Usage', color: '#10b981', unit: '%' },
  { key: 'request_rate', label: 'Request Rate', color: '#f59e0b', unit: 'req/s' },
  { key: 'error_rate',   label: 'Error Rate',   color: '#ef4444', unit: '%' },
];

interface DeviceMetric {
  id: string;
  name: string;
  platform: string;
  status: 'online' | 'offline';
  cpu: number;
  mem: number;
  disk: number;
}

function UsageBar({ value, warn = 70, crit = 90 }: { value: number; warn?: number; crit?: number }) {
  const color = value === 0 ? 'bg-gray-200' : value >= crit ? 'bg-red-500' : value >= warn ? 'bg-yellow-400' : 'bg-green-500';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs text-gray-500 w-8 text-right">{value > 0 ? `${value}%` : '—'}</span>
    </div>
  );
}

const parsePromValue = (result: any[], ipHint: string): number => {
  const match = result.find((r: any) => r.metric?.instance?.startsWith(ipHint));
  if (!match) return 0;
  return parseFloat(match.value?.[1]) || 0;
};

function ClientMetricsTable() {
  const [devices, setDevices] = useState<DeviceMetric[]>([]);
  const [loadingDevices, setLoadingDevices] = useState(true);
  const [noDevices, setNoDevices] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoadingDevices(true);
      setNoDevices(false);

      // Fetch devices
      let rawDevices: any[] = [];
      try {
        const res = await deviceApi.getDevices();
        rawDevices = res.data?.data ?? [];
      } catch {
        if (!cancelled) {
          setDevices([]);
          setNoDevices(true);
          setLoadingDevices(false);
        }
        return;
      }

      if (rawDevices.length === 0) {
        if (!cancelled) {
          setDevices([]);
          setNoDevices(true);
          setLoadingDevices(false);
        }
        return;
      }

      // Build initial metrics with zeros
      const metrics: DeviceMetric[] = rawDevices.map((d: any) => ({
        id: d.id,
        name: d.name,
        platform: d.platform ?? 'unknown',
        status: d.status === 'online' ? 'online' : 'offline',
        cpu: 0,
        mem: 0,
        disk: 0,
      }));

      // Fetch Prometheus metrics for all three signals in parallel
      let cpuResult: any[] = [];
      let memResult: any[] = [];
      let diskResult: any[] = [];

      try {
        const [cpuRes, memRes, diskRes] = await Promise.all([
          prometheusApi.query('100 - avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100'),
          prometheusApi.query('(1 - avg by(instance) (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100'),
          prometheusApi.query('(1 - avg by(instance) (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})) * 100'),
        ]);
        cpuResult  = cpuRes.data?.data?.result  ?? [];
        memResult  = memRes.data?.data?.result  ?? [];
        diskResult = diskRes.data?.data?.result ?? [];
      } catch {
        // Prometheus unavailable — leave all metrics as 0
      }

      // Merge Prometheus values by IP prefix for online devices
      const merged = metrics.map((m, i) => {
        const raw = rawDevices[i];
        if (m.status !== 'online' || !raw.ip_address) return m;
        const ip = raw.ip_address as string;
        return {
          ...m,
          cpu:  Math.round(parsePromValue(cpuResult,  ip)),
          mem:  Math.round(parsePromValue(memResult,  ip)),
          disk: Math.round(parsePromValue(diskResult, ip)),
        };
      });

      if (!cancelled) {
        setDevices(merged);
        setLoadingDevices(false);
      }
    };

    load();
    return () => { cancelled = true; };
  }, []);

  const onlineCount = devices.filter(d => d.status === 'online').length;

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
      <div className="flex items-center gap-2 mb-4">
        <ComputerDesktopIcon className="w-4 h-4 text-gray-500" />
        <h2 className="text-sm font-semibold text-gray-700">Client Device Metrics</h2>
        {!loadingDevices && !noDevices && (
          <span className="ml-auto text-xs text-gray-400">{onlineCount}/{devices.length} online</span>
        )}
      </div>

      {loadingDevices ? (
        <p className="text-sm text-gray-500">Loading device metrics…</p>
      ) : noDevices ? (
        <p className="text-sm text-gray-500">No devices found</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="border-b border-gray-100">
                <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide pb-2 pr-4">Device</th>
                <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide pb-2 pr-4 w-20">Status</th>
                <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide pb-2 pr-4">CPU</th>
                <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide pb-2 pr-4">Memory</th>
                <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide pb-2">Disk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {devices.map(dev => (
                <tr key={dev.id} className="hover:bg-gray-50 transition-colors">
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dev.status === 'online' ? 'bg-green-500' : 'bg-gray-300'}`} />
                      <span className="text-sm font-medium text-gray-800">{dev.name}</span>
                      <span className="text-xs text-gray-400 capitalize">{dev.platform}</span>
                    </div>
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                      dev.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
                    }`}>
                      {dev.status}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 min-w-[120px]"><UsageBar value={dev.cpu} /></td>
                  <td className="py-2.5 pr-4 min-w-[120px]"><UsageBar value={dev.mem} warn={80} /></td>
                  <td className="py-2.5 min-w-[120px]"><UsageBar value={dev.disk} warn={75} crit={90} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function MonitoringView() {
  const [services, setServices] = useState<ServiceHealth[]>([]);
  const [kpis, setKpis] = useState<KPI[]>([]);
  const [metricsData, setMetricsData] = useState<Record<MetricKey, MetricPoint[]>>({
    cpu_usage: [], memory_usage: [], request_rate: [], error_rate: [],
  });
  const [selectedMetric, setSelectedMetric] = useState<MetricKey>('cpu_usage');
  const [timeRange, setTimeRange] = useState('1h');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [grafanaDashboards, setGrafanaDashboards] = useState<any[]>([]);

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 30000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const loadAll = async () => {
    try {
      await Promise.all([loadHealth(), loadMetrics(), loadGrafana()]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const loadHealth = async () => {
    try {
      const res = await healthApi.getOverallHealth();
      setServices(res.data.services || []);
    } catch {}
  };

  const parseRange = (r: string) => {
    const unit = r.slice(-1);
    const val = parseInt(r.slice(0, -1));
    if (unit === 'm') return val * 60;
    if (unit === 'h') return val * 3600;
    if (unit === 'd') return val * 86400;
    return 3600;
  };

  const loadMetrics = async () => {
    try {
      // KPIs
      const kpiRes = await prometheusApi.getKPIs(timeRange);
      const k = kpiRes.data.kpis || {};
      setKpis([
        {
          label: 'Service Uptime',
          value: k.serviceUptime?.data?.result?.[0]?.value?.[1]
            ? `${parseFloat(k.serviceUptime.data.result[0].value[1]).toFixed(1)}%`
            : 'N/A',
          icon: ServerIcon,
          color: 'text-green-600',
          bg: 'bg-green-50',
        },
        {
          label: 'Total Requests',
          value: k.totalRequests?.data?.result?.[0]?.value?.[1]
            ? parseInt(k.totalRequests.data.result[0].value[1]).toLocaleString()
            : 'N/A',
          icon: ChartBarIcon,
          color: 'text-blue-600',
          bg: 'bg-blue-50',
        },
        {
          label: 'Error Rate',
          value: k.errorRate?.data?.result?.[0]?.value?.[1]
            ? `${parseFloat(k.errorRate.data.result[0].value[1]).toFixed(2)}%`
            : 'N/A',
          icon: CircleStackIcon,
          color: 'text-red-600',
          bg: 'bg-red-50',
        },
        {
          label: 'Avg Response',
          value: k.avgResponseTime?.data?.result?.[0]?.value?.[1]
            ? `${(parseFloat(k.avgResponseTime.data.result[0].value[1]) * 1000).toFixed(0)}ms`
            : 'N/A',
          icon: CpuChipIcon,
          color: 'text-purple-600',
          bg: 'bg-purple-50',
        },
        {
          label: 'Active Users',
          value: k.activeUsers?.data?.result?.[0]?.value?.[1]
            ? parseInt(k.activeUsers.data.result[0].value[1]).toLocaleString()
            : 'N/A',
          icon: ServerIcon,
          color: 'text-indigo-600',
          bg: 'bg-indigo-50',
        },
        {
          label: 'Devices',
          value: k.connectedDevices?.data?.result?.[0]?.value?.[1]
            ? parseInt(k.connectedDevices.data.result[0].value[1]).toLocaleString()
            : 'N/A',
          icon: CpuChipIcon,
          color: 'text-teal-600',
          bg: 'bg-teal-50',
        },
      ]);

      // Time series
      const queries: Record<MetricKey, string> = {
        cpu_usage:    '100 - avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100',
        memory_usage: '(1 - avg(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100',
        request_rate: 'sum(rate(http_requests_total[5m]))',
        error_rate:   'sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100',
      };
      const now = Math.floor(Date.now() / 1000);
      const start = now - parseRange(timeRange);

      const results = await Promise.all(
        (Object.entries(queries) as [MetricKey, string][]).map(async ([key, q]) => {
          try {
            const r = await prometheusApi.getTimeseries(q, start, now, '30s');
            return {
              key,
              data: (r.data.data?.[0]?.values || []).map((pt: any) => ({
                time: new Date(pt.timestamp).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
                value: parseFloat(pt.value) || 0,
              })),
            };
          } catch {
            return { key, data: [] };
          }
        })
      );

      const map: Record<MetricKey, MetricPoint[]> = { cpu_usage: [], memory_usage: [], request_rate: [], error_rate: [] };
      results.forEach(({ key, data }) => { map[key] = data; });
      setMetricsData(map);
    } catch {}
  };

  const loadGrafana = async () => {
    try {
      const res = await grafanaApi.getOpenDirectoryDashboards();
      setGrafanaDashboards(res.data.dashboards || []);
    } catch {}
  };

  const refresh = () => {
    setRefreshing(true);
    loadAll();
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':   return <CheckCircleIcon className="h-4 w-4 text-green-500" />;
      case 'unhealthy': return <XCircleIcon className="h-4 w-4 text-red-500" />;
      default:          return <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500" />;
    }
  };

  const healthyCount = services.filter(s => s.status === 'healthy').length;
  const currentMetric = METRIC_OPTIONS.find(m => m.key === selectedMetric)!;
  const chartData = metricsData[selectedMetric];

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse space-y-6">
          <div className="grid grid-cols-3 gap-4">
            {[...Array(6)].map((_, i) => <div key={i} className="h-20 bg-gray-200 rounded-xl" />)}
          </div>
          <div className="h-64 bg-gray-200 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Monitoring</h1>
          <p className="text-sm text-gray-500 mt-1">
            {healthyCount}/{services.length} services healthy
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={timeRange}
            onChange={e => setTimeRange(e.target.value)}
            className="text-sm border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="15m">Last 15 min</option>
            <option value="1h">Last hour</option>
            <option value="3h">Last 3 hours</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
          </select>
          <button
            onClick={refresh}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50"
          >
            <ArrowPathIcon className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Service health */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <h2 className="text-sm font-semibold text-gray-700 mb-4">Service Health</h2>
        {services.length === 0 ? (
          <p className="text-sm text-gray-500">No service data available</p>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {services.map(svc => (
              <div key={svc.name} className="flex items-center justify-between border border-gray-100 rounded-lg px-3 py-2">
                <div className="flex items-center gap-2 min-w-0">
                  {getStatusIcon(svc.status)}
                  <span className="text-sm font-medium text-gray-800 truncate">{svc.name.replace(' Service', '')}</span>
                </div>
                {svc.responseTime && (
                  <span className="text-xs text-gray-400 ml-2 shrink-0">{svc.responseTime}ms</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* KPI cards */}
      {kpis.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {kpis.map((kpi, i) => (
            <div key={i} className={`${kpi.bg} rounded-xl p-4`}>
              <div className="flex items-center justify-between mb-1">
                <p className={`text-xs font-medium ${kpi.color}`}>{kpi.label}</p>
                <kpi.icon className={`h-4 w-4 ${kpi.color}`} />
              </div>
              <p className={`text-2xl font-bold ${kpi.color}`}>{kpi.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Time series chart */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-700">Metrics</h2>
          <div className="flex gap-2">
            {METRIC_OPTIONS.map(m => (
              <button
                key={m.key}
                onClick={() => setSelectedMetric(m.key)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  selectedMetric === m.key
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        {chartData.length > 0 ? (
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="metricGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={currentMetric.color} stopOpacity={0.2} />
                    <stop offset="95%" stopColor={currentMetric.color} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="time" tick={{ fontSize: 11 }} interval="preserveStartEnd" />
                <YAxis
                  tick={{ fontSize: 11 }}
                  label={{ value: currentMetric.unit, angle: -90, position: 'insideLeft', style: { fontSize: 11 } }}
                />
                <Tooltip
                  formatter={(v: any) => [`${typeof v === 'number' ? v.toFixed(2) : v} ${currentMetric.unit}`, currentMetric.label]}
                />
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke={currentMetric.color}
                  strokeWidth={2}
                  fill="url(#metricGrad)"
                  dot={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-56 flex items-center justify-center text-gray-400 text-sm">
            <div className="text-center">
              <ChartBarIcon className="w-10 h-10 mx-auto mb-2 text-gray-300" />
              No metric data available — Prometheus may not be connected
            </div>
          </div>
        )}
      </div>

      {/* Client device metrics */}
      <ClientMetricsTable />

      {/* Grafana dashboards (if configured) */}
      {grafanaDashboards.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-3">Grafana Dashboards</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {grafanaDashboards.map(d => (
              <a
                key={d.uid}
                href={`${process.env.NEXT_PUBLIC_GRAFANA_URL}${d.url}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between border border-gray-200 rounded-lg px-4 py-3 hover:bg-gray-50 transition-colors group"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">{d.title}</p>
                  {d.folderTitle && <p className="text-xs text-gray-500 truncate">{d.folderTitle}</p>}
                </div>
                <span className="text-xs text-blue-600 group-hover:text-blue-700 ml-2 shrink-0">Open →</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
