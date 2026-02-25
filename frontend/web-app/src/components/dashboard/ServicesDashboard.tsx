'use client';

import React, { useState, useEffect } from 'react';
import { 
  CpuChipIcon,
  CloudIcon,
  ShieldCheckIcon,
  WifiIcon,
  PrinterIcon,
  ComputerDesktopIcon,
  ChartBarIcon,
  BackupIcon,
  PlayIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi, configApi } from '@/lib/api';
import toast from 'react-hot-toast';

interface Service {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  port?: number;
  description?: string;
  lastCheck?: string;
  responseTime?: number;
}

interface Module {
  id: string;
  name: string;
  enabled: boolean;
  port: number;
  features: Record<string, boolean>;
  description?: string;
}

export default function ServicesDashboard() {
  const [services, setServices] = useState<Service[]>([]);
  const [modules, setModules] = useState<Module[]>([]);
  const [loading, setLoading] = useState(true);
  const [healthData, setHealthData] = useState<any>(null);

  useEffect(() => {
    loadDashboardData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const [servicesResponse, modulesResponse, healthResponse] = await Promise.all([
        gatewayApi.getServices(),
        configApi.getModules(),
        healthApi.getDetailedHealth()
      ]);

      setServices(servicesResponse.data || []);
      setModules(Object.entries(modulesResponse.data || {}).map(([id, config]: [string, any]) => ({
        id,
        ...config
      })));
      setHealthData(healthResponse.data);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const toggleModule = async (moduleId: string, enabled: boolean) => {
    try {
      await configApi.updateModule(moduleId, { enabled });
      toast.success(`Module ${moduleId} ${enabled ? 'enabled' : 'disabled'}`);
      loadDashboardData();
    } catch (error) {
      toast.error(`Failed to ${enabled ? 'enable' : 'disable'} module`);
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

  const getModuleIcon = (moduleId: string) => {
    const iconMap: Record<string, any> = {
      'network-infrastructure': WifiIcon,
      'security-suite': ShieldCheckIcon,
      'printer-service': PrinterIcon,
      'device-management': ComputerDesktopIcon,
      'monitoring-analytics': ChartBarIcon,
      'backup-disaster': CloudIcon,
      'automation-workflows': PlayIcon,
      'container-orchestration': CpuChipIcon,
      'ai-intelligence': ChartBarIcon,
    };
    
    const Icon = iconMap[moduleId] || CpuChipIcon;
    return <Icon className="h-6 w-6" />;
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="bg-white rounded-lg shadow p-6">
                <div className="h-6 bg-gray-200 rounded w-3/4 mb-4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/2"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const healthyServices = services.filter(s => s.status === 'healthy').length;
  const totalServices = services.length;
  const enabledModules = modules.filter(m => m.enabled).length;

  return (
    <div className="space-y-6">
      {/* Dashboard Header */}
      <div className="bg-white rounded-lg shadow p-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">Services Dashboard</h1>
        
        {/* System Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-blue-50 rounded-lg p-4">
            <div className="flex items-center">
              <CheckCircleIcon className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-blue-600">System Health</p>
                <p className="text-lg font-bold text-blue-900">
                  {healthData?.status === 'healthy' ? 'Healthy' : 
                   healthData?.status === 'degraded' ? 'Degraded' : 'Critical'}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-green-50 rounded-lg p-4">
            <div className="flex items-center">
              <CpuChipIcon className="h-8 w-8 text-green-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-green-600">Active Services</p>
                <p className="text-lg font-bold text-green-900">{healthyServices}/{totalServices}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-purple-50 rounded-lg p-4">
            <div className="flex items-center">
              <PlayIcon className="h-8 w-8 text-purple-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-purple-600">Enabled Modules</p>
                <p className="text-lg font-bold text-purple-900">{enabledModules}/{modules.length}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-orange-50 rounded-lg p-4">
            <div className="flex items-center">
              <ChartBarIcon className="h-8 w-8 text-orange-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-orange-600">Uptime</p>
                <p className="text-lg font-bold text-orange-900">
                  {healthData?.gateway?.uptime ? 
                    Math.floor(healthData.gateway.uptime / 3600) + 'h' : 'N/A'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Module Management */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Module Management</h2>
          <p className="text-sm text-gray-600">Enable or disable OpenDirectory modules</p>
        </div>
        
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {modules.map((module) => {
              const service = services.find(s => s.name === module.id);
              
              return (
                <div key={module.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      <div className={`p-2 rounded-lg ${
                        module.enabled ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-400'
                      }`}>
                        {getModuleIcon(module.id)}
                      </div>
                      <div>
                        <h3 className="text-sm font-medium text-gray-900">{module.name}</h3>
                        <p className="text-xs text-gray-500">Port: {module.port}</p>
                        {service && (
                          <div className="flex items-center space-x-1 mt-1">
                            {getStatusIcon(service.status)}
                            <span className="text-xs text-gray-500">{service.status}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        className="sr-only peer"
                        checked={module.enabled}
                        onChange={(e) => toggleModule(module.id, e.target.checked)}
                        disabled={module.id === 'authentication-service' || module.id === 'configuration-service'}
                      />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
                  
                  {module.description && (
                    <p className="text-xs text-gray-500 mt-2">{module.description}</p>
                  )}
                  
                  {module.enabled && module.features && (
                    <div className="mt-3">
                      <p className="text-xs font-medium text-gray-700 mb-2">Features:</p>
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(module.features).map(([feature, enabled]) => (
                          <span
                            key={feature}
                            className={`px-2 py-1 text-xs rounded ${
                              enabled 
                                ? 'bg-green-100 text-green-800' 
                                : 'bg-gray-100 text-gray-500'
                            }`}
                          >
                            {feature}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Service Status Details */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Service Status</h2>
          <p className="text-sm text-gray-600">Real-time status of all running services</p>
        </div>
        
        <div className="p-6">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Service
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Port
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Response Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Check
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {services.map((service, index) => (
                  <tr key={service.name} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-8 w-8">
                          {getModuleIcon(service.name)}
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">{service.name}</div>
                          <div className="text-sm text-gray-500">{service.description}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(service.status)}
                        <span className={`ml-2 text-sm ${
                          service.status === 'healthy' ? 'text-green-600' :
                          service.status === 'unhealthy' ? 'text-red-600' : 'text-yellow-600'
                        }`}>
                          {service.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {service.port || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {service.responseTime ? `${service.responseTime}ms` : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {service.lastCheck ? new Date(service.lastCheck).toLocaleTimeString() : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}