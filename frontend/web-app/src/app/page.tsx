'use client';

import React, { useState, useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { 
  UserGroupIcon, 
  ChartBarIcon, 
  ShieldCheckIcon, 
  PresentationChartLineIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  WifiIcon,
  CpuChipIcon,
  RectangleGroupIcon
} from '@heroicons/react/24/outline';

import LLDAPIntegration from '@/components/integrations/LLDAPIntegration';
import GrafanaIntegration from '@/components/integrations/GrafanaIntegration';
import PrometheusIntegration from '@/components/integrations/PrometheusIntegration';
import VaultIntegration from '@/components/integrations/VaultIntegration';
import NetworkInfrastructureIntegration from '@/components/integrations/NetworkInfrastructureIntegration';
import ServicesDashboard from '@/components/dashboard/ServicesDashboard';
import { healthApi } from '@/lib/api';

interface ServiceHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  lastCheck: string;
}

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [serviceHealth, setServiceHealth] = useState<ServiceHealth[]>([]);
  const [healthLoading, setHealthLoading] = useState(true);

  useEffect(() => {
    fetchServiceHealth();
    // Set up periodic health checks
    const interval = setInterval(fetchServiceHealth, 30000); // Every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchServiceHealth = async () => {
    try {
      const response = await healthApi.getOverallHealth();
      setServiceHealth(response.data.services || []);
    } catch (error) {
      console.error('Failed to fetch service health:', error);
    } finally {
      setHealthLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'unhealthy':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      default:
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: PresentationChartLineIcon },
    { id: 'services', label: 'Services', icon: CpuChipIcon },
    { id: 'users', label: 'User Directory', icon: UserGroupIcon },
    { id: 'network', label: 'Network Infrastructure', icon: WifiIcon },
    { id: 'monitoring', label: 'Monitoring', icon: ChartBarIcon },
    { id: 'metrics', label: 'Metrics', icon: ChartBarIcon },
    { id: 'secrets', label: 'Secrets', icon: ShieldCheckIcon },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <Toaster position="top-right" />
      
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">OpenDirectory</h1>
              <p className="text-sm text-gray-600">Service Integration Dashboard</p>
            </div>
            
            {/* Service Health Indicators */}
            <div className="flex items-center space-x-4">
              {!healthLoading && serviceHealth.length > 0 && (
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600">Services:</span>
                  {serviceHealth.map((service) => (
                    <div key={service.name} className="flex items-center space-x-1" title={service.name}>
                      {getStatusIcon(service.status)}
                      <span className="text-xs text-gray-500">{service.name.replace(' Service', '')}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-8" aria-label="Tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
              >
                <tab.icon className="h-5 w-5" />
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* Welcome Section */}
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center space-x-3 mb-4">
                <PresentationChartLineIcon className="h-8 w-8 text-blue-600" />
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">Welcome to OpenDirectory</h2>
                  <p className="text-gray-600">Integrated identity management and monitoring platform</p>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-6 mt-6">
                <div className="bg-purple-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <CpuChipIcon className="h-8 w-8 text-purple-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-purple-600">Services</p>
                      <p className="text-lg font-bold text-purple-900">
                        {serviceHealth.filter(s => s.status === 'healthy').length}/{serviceHealth.length}
                      </p>
                    </div>
                  </div>
                  <p className="text-sm text-purple-700 mt-2">Module management</p>
                </div>

                <div className="bg-blue-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <UserGroupIcon className="h-8 w-8 text-blue-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-blue-600">LLDAP</p>
                      <p className="text-lg font-bold text-blue-900">User Directory</p>
                    </div>
                  </div>
                  <p className="text-sm text-blue-700 mt-2">Manage users and groups</p>
                </div>

                <div className="bg-orange-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <ChartBarIcon className="h-8 w-8 text-orange-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-orange-600">Grafana</p>
                      <p className="text-lg font-bold text-orange-900">Dashboards</p>
                    </div>
                  </div>
                  <p className="text-sm text-orange-700 mt-2">Visual monitoring</p>
                </div>

                <div className="bg-red-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <ChartBarIcon className="h-8 w-8 text-red-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-red-600">Prometheus</p>
                      <p className="text-lg font-bold text-red-900">Metrics</p>
                    </div>
                  </div>
                  <p className="text-sm text-red-700 mt-2">System metrics</p>
                </div>

                <div className="bg-green-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <WifiIcon className="h-8 w-8 text-green-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-green-600">Network</p>
                      <p className="text-lg font-bold text-green-900">Infrastructure</p>
                    </div>
                  </div>
                  <p className="text-sm text-green-700 mt-2">DNS, DHCP, File Shares</p>
                </div>

                <div className="bg-yellow-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <ShieldCheckIcon className="h-8 w-8 text-yellow-600 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-yellow-600">Vault</p>
                      <p className="text-lg font-bold text-yellow-900">Secrets</p>
                    </div>
                  </div>
                  <p className="text-sm text-yellow-700 mt-2">Secure storage</p>
                </div>
              </div>
            </div>

            {/* Service Status Overview */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Service Status</h3>
              {healthLoading ? (
                <div className="animate-pulse space-y-2">
                  <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                  <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {serviceHealth.map((service) => (
                    <div key={service.name} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          {getStatusIcon(service.status)}
                          <span className="font-medium text-gray-900">{service.name}</span>
                        </div>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                          service.status === 'healthy' 
                            ? 'bg-green-100 text-green-800'
                            : service.status === 'unhealthy'
                            ? 'bg-red-100 text-red-800'
                            : 'bg-yellow-100 text-yellow-800'
                        }`}>
                          {service.status}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">
                        Last check: {new Date(service.lastCheck).toLocaleTimeString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Quick Actions */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
                <a
                  href="/unifi"
                  className="flex items-center justify-center px-4 py-3 border border-blue-300 rounded-md shadow-sm bg-blue-50 text-sm font-medium text-blue-700 hover:bg-blue-100 transition-colors"
                >
                  <RectangleGroupIcon className="h-5 w-5 mr-2" />
                  Modern UI
                </a>
                <button
                  onClick={() => setActiveTab('services')}
                  className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  <CpuChipIcon className="h-5 w-5 mr-2" />
                  Manage Services
                </button>
                <button
                  onClick={() => setActiveTab('users')}
                  className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  <UserGroupIcon className="h-5 w-5 mr-2" />
                  Manage Users
                </button>
                <button
                  onClick={() => setActiveTab('network')}
                  className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  <WifiIcon className="h-5 w-5 mr-2" />
                  Network Setup
                </button>
                <button
                  onClick={() => setActiveTab('monitoring')}
                  className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  <ChartBarIcon className="h-5 w-5 mr-2" />
                  View Dashboards
                </button>
                <button
                  onClick={() => setActiveTab('metrics')}
                  className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  <ChartBarIcon className="h-5 w-5 mr-2" />
                  Check Metrics
                </button>
                <button
                  onClick={() => setActiveTab('secrets')}
                  className="flex items-center justify-center px-4 py-3 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  <ShieldCheckIcon className="h-5 w-5 mr-2" />
                  Manage Secrets
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'services' && <ServicesDashboard />}
        {activeTab === 'users' && <LLDAPIntegration />}
        {activeTab === 'network' && <NetworkInfrastructureIntegration />}
        {activeTab === 'monitoring' && <GrafanaIntegration />}
        {activeTab === 'metrics' && <PrometheusIntegration />}
        {activeTab === 'secrets' && <VaultIntegration />}
      </main>
    </div>
  );
}