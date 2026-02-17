'use client';

import React, { useState, useEffect } from 'react';
import { ChartBarIcon, ServerIcon, CpuChipIcon, CircleStackIcon } from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { prometheusApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

interface KPI {
  label: string;
  value: string | number;
  change?: string;
  trend?: 'up' | 'down' | 'stable';
  icon: React.ComponentType<{ className?: string }>;
  color: string;
}

interface MetricData {
  timestamp: number;
  value: number;
  label?: string;
}

export default function PrometheusIntegration() {
  const [kpis, setKPIs] = useState<KPI[]>([]);
  const [metricsData, setMetricsData] = useState<Record<string, MetricData[]>>({});
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('1h');
  const [selectedMetric, setSelectedMetric] = useState('cpu_usage');

  useEffect(() => {
    fetchData();
  }, [timeRange]);

  const fetchData = async () => {
    try {
      setLoading(true);
      
      // Fetch KPIs
      const kpisResponse = await prometheusApi.getKPIs(timeRange);
      const kpisData = kpisResponse.data.kpis;

      // Transform KPIs into display format
      const transformedKPIs: KPI[] = [
        {
          label: 'Service Uptime',
          value: kpisData.serviceUptime?.data?.result?.[0]?.value?.[1] 
            ? `${parseFloat(kpisData.serviceUptime.data.result[0].value[1]).toFixed(1)}%`
            : 'N/A',
          icon: ServerIcon,
          color: 'text-green-600',
        },
        {
          label: 'Total Requests',
          value: kpisData.totalRequests?.data?.result?.[0]?.value?.[1] 
            ? parseInt(kpisData.totalRequests.data.result[0].value[1]).toLocaleString()
            : 'N/A',
          icon: ChartBarIcon,
          color: 'text-blue-600',
        },
        {
          label: 'Error Rate',
          value: kpisData.errorRate?.data?.result?.[0]?.value?.[1] 
            ? `${parseFloat(kpisData.errorRate.data.result[0].value[1]).toFixed(2)}%`
            : 'N/A',
          icon: CircleStackIcon,
          color: 'text-red-600',
        },
        {
          label: 'Avg Response Time',
          value: kpisData.avgResponseTime?.data?.result?.[0]?.value?.[1] 
            ? `${(parseFloat(kpisData.avgResponseTime.data.result[0].value[1]) * 1000).toFixed(0)}ms`
            : 'N/A',
          icon: CpuChipIcon,
          color: 'text-purple-600',
        },
        {
          label: 'Active Users',
          value: kpisData.activeUsers?.data?.result?.[0]?.value?.[1] 
            ? parseInt(kpisData.activeUsers.data.result[0].value[1]).toLocaleString()
            : 'N/A',
          icon: ServerIcon,
          color: 'text-indigo-600',
        },
        {
          label: 'Connected Devices',
          value: kpisData.connectedDevices?.data?.result?.[0]?.value?.[1] 
            ? parseInt(kpisData.connectedDevices.data.result[0].value[1]).toLocaleString()
            : 'N/A',
          icon: CpuChipIcon,
          color: 'text-teal-600',
        },
      ];

      setKPIs(transformedKPIs);

      // Fetch time series data for charts
      await fetchTimeSeriesData();
    } catch (error) {
      toast.error(`Failed to fetch metrics: ${formatError(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchTimeSeriesData = async () => {
    try {
      const queries = {
        cpu_usage: '100 - avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100',
        memory_usage: '(1 - avg(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100',
        request_rate: 'sum(rate(http_requests_total[5m]))',
        error_rate: 'sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100',
      };

      const now = Math.floor(Date.now() / 1000);
      const start = now - parseTimeRange(timeRange);
      
      const timeSeriesPromises = Object.entries(queries).map(async ([metric, query]) => {
        try {
          const response = await prometheusApi.getTimeseries(query, start, now, '30s');
          return {
            metric,
            data: response.data.data?.[0]?.values?.map((point: any) => ({
              timestamp: point.timestamp,
              value: parseFloat(point.value) || 0,
              time: new Date(point.timestamp).toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
              }),
            })) || [],
          };
        } catch (error) {
          return { metric, data: [] };
        }
      });

      const results = await Promise.all(timeSeriesPromises);
      const metricsMap = results.reduce((acc, { metric, data }) => {
        acc[metric] = data;
        return acc;
      }, {} as Record<string, MetricData[]>);

      setMetricsData(metricsMap);
    } catch (error) {
      console.error('Failed to fetch time series data:', error);
    }
  };

  const parseTimeRange = (range: string): number => {
    const unit = range.slice(-1);
    const value = parseInt(range.slice(0, -1));
    
    switch (unit) {
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 60 * 60 * 24;
      default: return 3600; // 1 hour default
    }
  };

  const getMetricConfig = (metric: string) => {
    const configs = {
      cpu_usage: { title: 'CPU Usage (%)', color: '#8884d8', unit: '%' },
      memory_usage: { title: 'Memory Usage (%)', color: '#82ca9d', unit: '%' },
      request_rate: { title: 'Request Rate (req/s)', color: '#ffc658', unit: 'req/s' },
      error_rate: { title: 'Error Rate (%)', color: '#ff7c7c', unit: '%' },
    };
    return configs[metric as keyof typeof configs] || { title: 'Metric', color: '#8884d8', unit: '' };
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-20 bg-gray-200 rounded"></div>
            ))}
          </div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ChartBarIcon className="h-6 w-6 text-red-600" />
              <h2 className="text-lg font-medium text-gray-900">Metrics (Prometheus)</h2>
            </div>
            <div className="flex items-center space-x-2">
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
              >
                <option value="5m">Last 5 minutes</option>
                <option value="15m">Last 15 minutes</option>
                <option value="30m">Last 30 minutes</option>
                <option value="1h">Last hour</option>
                <option value="3h">Last 3 hours</option>
                <option value="6h">Last 6 hours</option>
                <option value="12h">Last 12 hours</option>
                <option value="24h">Last 24 hours</option>
              </select>
              <button
                onClick={fetchData}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Refresh
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {kpis.map((kpi, index) => (
            <div key={index} className="bg-gray-50 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">{kpi.label}</p>
                  <p className={`text-2xl font-bold ${kpi.color}`}>{kpi.value}</p>
                </div>
                <kpi.icon className={`h-8 w-8 ${kpi.color}`} />
              </div>
            </div>
          ))}
        </div>

        {/* Metric Selector */}
        <div className="flex items-center space-x-4">
          <label htmlFor="metric-select" className="text-sm font-medium text-gray-700">
            View Metric:
          </label>
          <select
            id="metric-select"
            value={selectedMetric}
            onChange={(e) => setSelectedMetric(e.target.value)}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
          >
            <option value="cpu_usage">CPU Usage</option>
            <option value="memory_usage">Memory Usage</option>
            <option value="request_rate">Request Rate</option>
            <option value="error_rate">Error Rate</option>
          </select>
        </div>

        {/* Time Series Chart */}
        {metricsData[selectedMetric] && metricsData[selectedMetric].length > 0 && (
          <div className="bg-gray-50 rounded-lg p-4">
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              {getMetricConfig(selectedMetric).title}
            </h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={metricsData[selectedMetric]}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="time" 
                    tick={{ fontSize: 12 }}
                    interval="preserveStartEnd"
                  />
                  <YAxis 
                    tick={{ fontSize: 12 }}
                    label={{ 
                      value: getMetricConfig(selectedMetric).unit, 
                      angle: -90, 
                      position: 'insideLeft' 
                    }}
                  />
                  <Tooltip 
                    labelFormatter={(value) => `Time: ${value}`}
                    formatter={(value) => [
                      `${typeof value === 'number' ? value.toFixed(2) : value} ${getMetricConfig(selectedMetric).unit}`,
                      getMetricConfig(selectedMetric).title
                    ]}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="value" 
                    stroke={getMetricConfig(selectedMetric).color}
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Service Status Overview */}
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Service Status</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {['Identity Service', 'Auth Service', 'Device Service', 'Policy Service'].map((service, index) => (
              <div key={service} className="flex items-center justify-between p-3 bg-white rounded border">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                  <span className="text-sm font-medium text-gray-900">{service}</span>
                </div>
                <span className="text-xs text-gray-500">Healthy</span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex justify-center">
          <a
            href={process.env.NEXT_PUBLIC_PROMETHEUS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Open Prometheus Console →
          </a>
        </div>
      </div>
    </div>
  );
}