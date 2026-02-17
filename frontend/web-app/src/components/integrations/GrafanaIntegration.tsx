'use client';

import React, { useState, useEffect } from 'react';
import { ChartBarIcon, PresentationChartLineIcon, Cog6ToothIcon } from '@heroicons/react/24/outline';
import { grafanaApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

interface Dashboard {
  id: number;
  uid: string;
  title: string;
  tags: string[];
  uri: string;
  url: string;
  slug: string;
  type: string;
  folderTitle: string;
}

interface EmbedOptions {
  theme: 'light' | 'dark';
  from: string;
  to: string;
  refresh?: string;
}

export default function GrafanaIntegration() {
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [embedUrl, setEmbedUrl] = useState<string | null>(null);
  const [selectedDashboard, setSelectedDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [embedOptions, setEmbedOptions] = useState<EmbedOptions>({
    theme: 'light',
    from: 'now-1h',
    to: 'now',
    refresh: '30s',
  });

  useEffect(() => {
    fetchDashboards();
  }, []);

  const fetchDashboards = async () => {
    try {
      setLoading(true);
      const response = await grafanaApi.getOpenDirectoryDashboards();
      setDashboards(response.data.dashboards || []);
      
      // Auto-select the first dashboard if available
      if (response.data.dashboards?.length > 0) {
        selectDashboard(response.data.dashboards[0]);
      }
    } catch (error) {
      toast.error(`Failed to fetch Grafana dashboards: ${formatError(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const selectDashboard = async (dashboard: Dashboard) => {
    try {
      setSelectedDashboard(dashboard);
      const response = await grafanaApi.getDashboardEmbedUrl(dashboard.uid, embedOptions);
      setEmbedUrl(response.data.embedUrl);
    } catch (error) {
      toast.error(`Failed to generate embed URL: ${formatError(error)}`);
    }
  };

  const setupOpenDirectoryIntegration = async () => {
    try {
      setLoading(true);
      await grafanaApi.setupOpenDirectory();
      toast.success('OpenDirectory Grafana integration setup completed');
      fetchDashboards();
    } catch (error) {
      toast.error(`Setup failed: ${formatError(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const refreshDashboard = () => {
    if (selectedDashboard) {
      selectDashboard(selectedDashboard);
    }
  };

  const updateEmbedOptions = (options: Partial<EmbedOptions>) => {
    const newOptions = { ...embedOptions, ...options };
    setEmbedOptions(newOptions);
    
    if (selectedDashboard) {
      grafanaApi.getDashboardEmbedUrl(selectedDashboard.uid, newOptions)
        .then(response => setEmbedUrl(response.data.embedUrl))
        .catch(error => toast.error(`Failed to update embed URL: ${formatError(error)}`));
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
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
              <ChartBarIcon className="h-6 w-6 text-orange-600" />
              <h2 className="text-lg font-medium text-gray-900">Monitoring (Grafana)</h2>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={setupOpenDirectoryIntegration}
                className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Cog6ToothIcon className="h-4 w-4 mr-2" />
                Setup Integration
              </button>
              <button
                onClick={refreshDashboard}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <PresentationChartLineIcon className="h-4 w-4 mr-2" />
                Refresh
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6">
        {dashboards.length === 0 ? (
          <div className="text-center py-12">
            <ChartBarIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No dashboards found</h3>
            <p className="mt-1 text-sm text-gray-500">
              Get started by setting up the OpenDirectory integration.
            </p>
            <div className="mt-6">
              <button
                onClick={setupOpenDirectoryIntegration}
                className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Cog6ToothIcon className="h-4 w-4 mr-2" />
                Setup OpenDirectory Integration
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Dashboard Selector */}
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <label htmlFor="dashboard-select" className="block text-sm font-medium text-gray-700 mb-1">
                  Dashboard
                </label>
                <select
                  id="dashboard-select"
                  value={selectedDashboard?.uid || ''}
                  onChange={(e) => {
                    const dashboard = dashboards.find(d => d.uid === e.target.value);
                    if (dashboard) selectDashboard(dashboard);
                  }}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                >
                  <option value="">Select a dashboard</option>
                  {dashboards.map((dashboard) => (
                    <option key={dashboard.uid} value={dashboard.uid}>
                      {dashboard.title}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex gap-2">
                <div>
                  <label htmlFor="theme-select" className="block text-sm font-medium text-gray-700 mb-1">
                    Theme
                  </label>
                  <select
                    id="theme-select"
                    value={embedOptions.theme}
                    onChange={(e) => updateEmbedOptions({ theme: e.target.value as 'light' | 'dark' })}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  >
                    <option value="light">Light</option>
                    <option value="dark">Dark</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="timerange-select" className="block text-sm font-medium text-gray-700 mb-1">
                    Time Range
                  </label>
                  <select
                    id="timerange-select"
                    value={embedOptions.from}
                    onChange={(e) => updateEmbedOptions({ from: e.target.value, to: 'now' })}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  >
                    <option value="now-5m">Last 5 minutes</option>
                    <option value="now-15m">Last 15 minutes</option>
                    <option value="now-30m">Last 30 minutes</option>
                    <option value="now-1h">Last hour</option>
                    <option value="now-3h">Last 3 hours</option>
                    <option value="now-6h">Last 6 hours</option>
                    <option value="now-12h">Last 12 hours</option>
                    <option value="now-24h">Last 24 hours</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="refresh-select" className="block text-sm font-medium text-gray-700 mb-1">
                    Refresh
                  </label>
                  <select
                    id="refresh-select"
                    value={embedOptions.refresh || ''}
                    onChange={(e) => updateEmbedOptions({ refresh: e.target.value || undefined })}
                    className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  >
                    <option value="">No refresh</option>
                    <option value="5s">5 seconds</option>
                    <option value="10s">10 seconds</option>
                    <option value="30s">30 seconds</option>
                    <option value="1m">1 minute</option>
                    <option value="5m">5 minutes</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Embedded Dashboard */}
            {embedUrl && (
              <div className="border border-gray-200 rounded-lg overflow-hidden">
                <iframe
                  src={embedUrl}
                  width="100%"
                  height="600"
                  frameBorder="0"
                  title={selectedDashboard?.title || 'Grafana Dashboard'}
                  className="w-full"
                />
              </div>
            )}

            {/* Dashboard Info */}
            {selectedDashboard && (
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900">
                      {selectedDashboard.title}
                    </h3>
                    <p className="text-sm text-gray-500">
                      {selectedDashboard.folderTitle && `Folder: ${selectedDashboard.folderTitle}`}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selectedDashboard.tags?.map((tag) => (
                      <span
                        key={tag}
                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="mt-2">
                  <a
                    href={`${process.env.NEXT_PUBLIC_GRAFANA_URL}${selectedDashboard.url}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-600 hover:text-blue-500"
                  >
                    Open in Grafana →
                  </a>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}