'use client';

import React, { useState, useEffect } from 'react';
import {
  CubeIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  PlayIcon,
  StopIcon,
  Cog6ToothIcon,
  ChartBarIcon,
  WifiIcon,
  ShieldCheckIcon,
  PrinterIcon,
  ComputerDesktopIcon,
  CloudIcon,
  CpuChipIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  EllipsisVerticalIcon
} from '@heroicons/react/24/outline';
import { configApi, gatewayApi } from '@/lib/api';
import toast from 'react-hot-toast';

interface Application {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  port: number;
  status: 'healthy' | 'unhealthy' | 'unknown' | 'disabled';
  features: Record<string, boolean>;
  category: 'Core' | 'Infrastructure' | 'Security' | 'Analytics' | 'Integrations';
  icon: React.ComponentType<any>;
  color: string;
  lastUpdated: string;
}

export default function ApplicationsView() {
  const [applications, setApplications] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedApp, setSelectedApp] = useState<Application | null>(null);

  const categories = ['All', 'Core', 'Infrastructure', 'Security', 'Analytics', 'Integrations'];

  const iconMap: Record<string, { icon: React.ComponentType<any>; color: string; category: string }> = {
    'network-infrastructure': { icon: WifiIcon, color: 'blue', category: 'Infrastructure' },
    'security-suite': { icon: ShieldCheckIcon, color: 'red', category: 'Security' },
    'printer-service': { icon: PrinterIcon, color: 'gray', category: 'Infrastructure' },
    'device-management': { icon: ComputerDesktopIcon, color: 'indigo', category: 'Core' },
    'monitoring-analytics': { icon: ChartBarIcon, color: 'green', category: 'Analytics' },
    'policy-compliance': { icon: ShieldCheckIcon, color: 'yellow', category: 'Security' },
    'backup-disaster': { icon: CloudIcon, color: 'purple', category: 'Infrastructure' },
    'automation-workflows': { icon: CpuChipIcon, color: 'orange', category: 'Infrastructure' },
    'container-orchestration': { icon: CpuChipIcon, color: 'blue', category: 'Infrastructure' },
    'enterprise-integrations': { icon: CubeIcon, color: 'green', category: 'Integrations' },
    'ai-intelligence': { icon: ChartBarIcon, color: 'purple', category: 'Analytics' }
  };

  useEffect(() => {
    loadApplications();
  }, []);

  const loadApplications = async () => {
    try {
      const [modulesRes, servicesRes] = await Promise.all([
        configApi.getModules(),
        gatewayApi.getServices()
      ]);

      const modules = modulesRes.data || {};
      const services = servicesRes.data || [];

      const apps: Application[] = Object.entries(modules).map(([id, config]: [string, any]) => {
        const service = services.find((s: any) => s.name === id);
        const iconConfig = iconMap[id] || { icon: CubeIcon, color: 'gray', category: 'Core' };
        
        return {
          id,
          name: config.name || id.replace(/-/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
          description: config.description || `${iconConfig.category} service for OpenDirectory`,
          enabled: config.enabled || false,
          port: config.port || 3000,
          status: config.enabled 
            ? (service?.status || 'unknown')
            : 'disabled',
          features: config.features || {},
          category: iconConfig.category as Application['category'],
          icon: iconConfig.icon,
          color: iconConfig.color,
          lastUpdated: new Date().toISOString()
        };
      });

      setApplications(apps);
    } catch (error) {
      console.error('Failed to load applications:', error);
      toast.error('Failed to load applications');
    } finally {
      setLoading(false);
    }
  };

  const toggleApplication = async (appId: string, enabled: boolean) => {
    try {
      await configApi.updateModule(appId, { enabled });
      toast.success(`Application ${enabled ? 'enabled' : 'disabled'} successfully`);
      loadApplications(); // Reload to get updated status
    } catch (error) {
      console.error('Failed to update application:', error);
      toast.error('Failed to update application');
    }
  };

  const filteredApplications = applications.filter(app => {
    const matchesSearch = app.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         app.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'All' || app.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600';
      case 'unhealthy': return 'text-red-600';
      case 'disabled': return 'text-gray-400';
      default: return 'text-yellow-600';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircleIcon className="w-5 h-5" />;
      case 'unhealthy': return <XCircleIcon className="w-5 h-5" />;
      case 'disabled': return <StopIcon className="w-5 h-5" />;
      default: return <ExclamationTriangleIcon className="w-5 h-5" />;
    }
  };

  const getColorClasses = (color: string) => {
    const colorMap = {
      blue: { bg: 'bg-blue-100', text: 'text-blue-600', ring: 'ring-blue-500' },
      red: { bg: 'bg-red-100', text: 'text-red-600', ring: 'ring-red-500' },
      green: { bg: 'bg-green-100', text: 'text-green-600', ring: 'ring-green-500' },
      purple: { bg: 'bg-purple-100', text: 'text-purple-600', ring: 'ring-purple-500' },
      yellow: { bg: 'bg-yellow-100', text: 'text-yellow-600', ring: 'ring-yellow-500' },
      indigo: { bg: 'bg-indigo-100', text: 'text-indigo-600', ring: 'ring-indigo-500' },
      orange: { bg: 'bg-orange-100', text: 'text-orange-600', ring: 'ring-orange-500' },
      gray: { bg: 'bg-gray-100', text: 'text-gray-600', ring: 'ring-gray-500' }
    };
    return colorMap[color as keyof typeof colorMap] || colorMap.gray;
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-64 mb-8"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
                <div className="h-20 bg-gray-200 rounded"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Applications</h1>
          <p className="text-sm text-gray-500 mt-1">
            Manage and monitor your OpenDirectory services
          </p>
        </div>
        
        <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-4">
          {/* Search */}
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <MagnifyingGlassIcon className="h-4 w-4 text-gray-400" />
            </div>
            <input
              type="text"
              placeholder="Search applications..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Category Filter */}
          <div className="relative">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="block w-full pl-3 pr-10 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 appearance-none bg-white"
            >
              {categories.map(category => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
            <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
              <FunnelIcon className="h-4 w-4 text-gray-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Applications Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredApplications.map((app) => {
          const colors = getColorClasses(app.color);
          
          return (
            <div
              key={app.id}
              className={`bg-white rounded-xl shadow-sm border border-gray-100 p-6 hover:shadow-md transition-all duration-200 cursor-pointer ${
                selectedApp?.id === app.id ? `ring-2 ${colors.ring}` : ''
              }`}
              onClick={() => setSelectedApp(app)}
            >
              {/* App Header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className={`w-10 h-10 ${colors.bg} rounded-lg flex items-center justify-center`}>
                    <app.icon className={`w-6 h-6 ${colors.text}`} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900">{app.name}</h3>
                    <p className="text-xs text-gray-500">{app.category}</p>
                  </div>
                </div>
                
                <button className="text-gray-400 hover:text-gray-600">
                  <EllipsisVerticalIcon className="w-5 h-5" />
                </button>
              </div>

              {/* Status */}
              <div className="flex items-center justify-between mb-4">
                <div className={`flex items-center space-x-2 ${getStatusColor(app.status)}`}>
                  {getStatusIcon(app.status)}
                  <span className="text-sm font-medium capitalize">{app.status}</span>
                </div>
                
                {/* Toggle Switch */}
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={app.enabled}
                    onChange={(e) => toggleApplication(app.id, e.target.checked)}
                    className="sr-only peer"
                    onClick={(e) => e.stopPropagation()}
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>

              {/* Description */}
              <p className="text-sm text-gray-600 mb-4 line-clamp-2">{app.description}</p>

              {/* Features */}
              {Object.keys(app.features).length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-medium text-gray-700">Features:</p>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(app.features).slice(0, 3).map(([feature, enabled]) => (
                      <span
                        key={feature}
                        className={`px-2 py-1 text-xs rounded-full ${
                          enabled 
                            ? 'bg-green-100 text-green-700' 
                            : 'bg-gray-100 text-gray-500'
                        }`}
                      >
                        {feature.replace(/-/g, ' ')}
                      </span>
                    ))}
                    {Object.keys(app.features).length > 3 && (
                      <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-500">
                        +{Object.keys(app.features).length - 3} more
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Port info */}
              <div className="mt-4 pt-4 border-t border-gray-100">
                <div className="flex justify-between text-xs text-gray-500">
                  <span>Port: {app.port}</span>
                  <span>Updated: {new Date(app.lastUpdated).toLocaleDateString()}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* No results */}
      {filteredApplications.length === 0 && (
        <div className="text-center py-12">
          <CubeIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No applications found</h3>
          <p className="text-sm text-gray-500">
            Try adjusting your search or filter criteria
          </p>
        </div>
      )}

      {/* Application Detail Modal */}
      {selectedApp && (
        <div 
          className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedApp(null)}
        >
          <div 
            className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-4">
                  <div className={`w-12 h-12 ${getColorClasses(selectedApp.color).bg} rounded-xl flex items-center justify-center`}>
                    <selectedApp.icon className={`w-8 h-8 ${getColorClasses(selectedApp.color).text}`} />
                  </div>
                  <div>
                    <h2 className="text-xl font-semibold text-gray-900">{selectedApp.name}</h2>
                    <p className="text-sm text-gray-500">{selectedApp.category} • Port {selectedApp.port}</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedApp(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <XCircleIcon className="w-6 h-6" />
                </button>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">Description</h3>
                  <p className="text-gray-600">{selectedApp.description}</p>
                </div>

                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Features</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {Object.entries(selectedApp.features).map(([feature, enabled]) => (
                      <div key={feature} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <span className="text-sm text-gray-900">{feature.replace(/-/g, ' ')}</span>
                        <div className={`w-2 h-2 rounded-full ${enabled ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end space-x-3">
                  <button
                    onClick={() => setSelectedApp(null)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
                  >
                    Close
                  </button>
                  <button
                    onClick={() => {
                      toggleApplication(selectedApp.id, !selectedApp.enabled);
                      setSelectedApp(null);
                    }}
                    className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors ${
                      selectedApp.enabled 
                        ? 'bg-red-600 hover:bg-red-700' 
                        : 'bg-green-600 hover:bg-green-700'
                    }`}
                  >
                    {selectedApp.enabled ? 'Disable' : 'Enable'} Application
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}