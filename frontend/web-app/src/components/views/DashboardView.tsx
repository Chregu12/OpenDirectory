'use client';

import React, { useState, useEffect } from 'react';
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  ChartBarIcon,
  CpuChipIcon,
  CloudIcon,
  ShieldCheckIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi, configApi } from '@/lib/api';

interface DashboardStats {
  totalServices: number;
  healthyServices: number;
  warningServices: number;
  criticalServices: number;
  uptime: string;
  memoryUsage: string;
  enabledModules: number;
  totalModules: number;
}

interface ServiceHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  responseTime?: number;
  lastCheck: string;
}

export default function DashboardView() {
  const [dashboardStats, setDashboardStats] = useState<DashboardStats>({
    totalServices: 0,
    healthyServices: 0,
    warningServices: 0,
    criticalServices: 0,
    uptime: '0h 0m',
    memoryUsage: '0%',
    enabledModules: 0,
    totalModules: 0
  });
  
  const [recentServices, setRecentServices] = useState<ServiceHealth[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 10000); // Every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const [servicesRes, healthRes, configRes] = await Promise.all([
        gatewayApi.getServices(),
        healthApi.getDetailedHealth(),
        configApi.getModules()
      ]);

      const services = servicesRes.data || [];
      const healthData = healthRes.data;
      const modules = configRes.data || {};

      const healthy = services.filter((s: any) => s.status === 'healthy').length;
      const warning = services.filter((s: any) => s.status === 'unknown').length;
      const critical = services.filter((s: any) => s.status === 'unhealthy').length;

      const enabledCount = Object.values(modules).filter((m: any) => m.enabled).length;
      const totalCount = Object.keys(modules).length;

      const uptime = healthData?.gateway?.uptime || 0;
      const hours = Math.floor(uptime / 3600);
      const minutes = Math.floor((uptime % 3600) / 60);

      const memoryUsage = healthData?.gateway?.memory;
      const memoryPercent = memoryUsage 
        ? Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100)
        : 0;

      setDashboardStats({
        totalServices: services.length,
        healthyServices: healthy,
        warningServices: warning,
        criticalServices: critical,
        uptime: `${hours}h ${minutes}m`,
        memoryUsage: `${memoryPercent}%`,
        enabledModules: enabledCount,
        totalModules: totalCount
      });

      // Get recent services (last 5)
      const sortedServices = services
        .sort((a: any, b: any) => new Date(b.lastCheck || 0).getTime() - new Date(a.lastCheck || 0).getTime())
        .slice(0, 5);
      
      setRecentServices(sortedServices);

    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600';
      case 'unhealthy': return 'text-red-600';
      default: return 'text-yellow-600';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'unhealthy': return <XCircleIcon className="w-5 h-5 text-red-500" />;
      default: return <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />;
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-64 mb-8"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
                <div className="h-8 bg-gray-200 rounded w-1/2"></div>
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">System Overview</h1>
          <p className="text-sm text-gray-500 mt-1">Real-time status of your OpenDirectory infrastructure</p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          <span>Live updates</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                <CheckCircleIcon className="w-6 h-6 text-green-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Healthy Services</p>
              <div className="flex items-center">
                <p className="text-2xl font-semibold text-gray-900">
                  {dashboardStats.healthyServices}
                </p>
                <span className="ml-2 text-xs text-gray-500">
                  / {dashboardStats.totalServices}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-green-500 mr-1" />
              <span className="text-green-600">+2.4%</span>
              <span className="text-gray-500 ml-1">from last hour</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                <CpuChipIcon className="w-6 h-6 text-blue-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Active Modules</p>
              <div className="flex items-center">
                <p className="text-2xl font-semibold text-gray-900">
                  {dashboardStats.enabledModules}
                </p>
                <span className="ml-2 text-xs text-gray-500">
                  / {dashboardStats.totalModules}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full transition-all duration-300" 
                style={{ 
                  width: `${dashboardStats.totalModules > 0 ? (dashboardStats.enabledModules / dashboardStats.totalModules) * 100 : 0}%` 
                }}
              ></div>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
                <ChartBarIcon className="w-6 h-6 text-purple-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Memory Usage</p>
              <div className="flex items-center">
                <p className="text-2xl font-semibold text-gray-900">
                  {dashboardStats.memoryUsage}
                </p>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm">
              <ArrowTrendingDownIcon className="w-4 h-4 text-green-500 mr-1" />
              <span className="text-green-600">-1.2%</span>
              <span className="text-gray-500 ml-1">from last hour</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center">
                <CloudIcon className="w-6 h-6 text-orange-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">System Uptime</p>
              <div className="flex items-center">
                <p className="text-2xl font-semibold text-gray-900">
                  {dashboardStats.uptime}
                </p>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
              <span className="text-gray-500">Running stable</span>
            </div>
          </div>
        </div>
      </div>

      {/* Service Health and Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Service Activities */}
        <div className="lg:col-span-2 bg-white rounded-xl shadow-sm border border-gray-100">
          <div className="p-6 border-b border-gray-100">
            <h3 className="text-lg font-semibold text-gray-900">Service Health</h3>
            <p className="text-sm text-gray-500 mt-1">Recent service status updates</p>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {recentServices.map((service, index) => (
                <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    {getStatusIcon(service.status)}
                    <div className="ml-3">
                      <p className="text-sm font-medium text-gray-900">{service.name}</p>
                      <p className="text-xs text-gray-500">
                        Last check: {new Date(service.lastCheck).toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      service.status === 'healthy' 
                        ? 'bg-green-100 text-green-800' 
                        : service.status === 'unhealthy'
                        ? 'bg-red-100 text-red-800'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {service.status}
                    </span>
                    {service.responseTime && (
                      <p className="text-xs text-gray-500 mt-1">{service.responseTime}ms</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100">
          <div className="p-6 border-b border-gray-100">
            <h3 className="text-lg font-semibold text-gray-900">Quick Actions</h3>
            <p className="text-sm text-gray-500 mt-1">Common tasks</p>
          </div>
          <div className="p-6 space-y-3">
            <button className="w-full flex items-center justify-between p-3 text-left bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors">
              <div className="flex items-center">
                <CpuChipIcon className="w-5 h-5 text-blue-600 mr-3" />
                <span className="text-sm font-medium text-gray-900">Manage Services</span>
              </div>
              <span className="text-xs text-blue-600">→</span>
            </button>

            <button className="w-full flex items-center justify-between p-3 text-left bg-green-50 hover:bg-green-100 rounded-lg transition-colors">
              <div className="flex items-center">
                <ShieldCheckIcon className="w-5 h-5 text-green-600 mr-3" />
                <span className="text-sm font-medium text-gray-900">Security Status</span>
              </div>
              <span className="text-xs text-green-600">→</span>
            </button>

            <button className="w-full flex items-center justify-between p-3 text-left bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors">
              <div className="flex items-center">
                <ChartBarIcon className="w-5 h-5 text-purple-600 mr-3" />
                <span className="text-sm font-medium text-gray-900">View Analytics</span>
              </div>
              <span className="text-xs text-purple-600">→</span>
            </button>

            <button className="w-full flex items-center justify-between p-3 text-left bg-gray-50 hover:bg-gray-100 rounded-lg transition-colors">
              <div className="flex items-center">
                <CloudIcon className="w-5 h-5 text-gray-600 mr-3" />
                <span className="text-sm font-medium text-gray-900">System Logs</span>
              </div>
              <span className="text-xs text-gray-600">→</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}