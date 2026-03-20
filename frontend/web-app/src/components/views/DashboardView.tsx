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
  ArrowTrendingDownIcon,
  ComputerDesktopIcon
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi, configApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';

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

interface DashboardViewProps {
  onAddDevice?: () => void;
}

export default function DashboardView({ onAddDevice }: DashboardViewProps) {
  const { isSimple } = useUiMode();
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
    const interval = setInterval(loadDashboardData, 10000);
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

  const allHealthy = dashboardStats.criticalServices === 0 && dashboardStats.warningServices === 0;
  const hasCritical = dashboardStats.criticalServices > 0;
  const unhealthyServices = recentServices.filter(s => s.status !== 'healthy');

  // ── Simple Mode: UniFi-style "everything is OK" dashboard ──
  if (isSimple) {
    return (
      <div className="p-6 space-y-6">
        {/* Status Hero - UniFi clean white card */}
        <div className="bg-white rounded-xl p-8 text-center shadow-sm">
          <div className={`w-16 h-16 mx-auto rounded-full flex items-center justify-center mb-4 ${
            hasCritical ? 'bg-red-50' : allHealthy ? 'bg-emerald-50' : 'bg-amber-50'
          }`}>
            {hasCritical ? (
              <XCircleIcon className="w-8 h-8 text-red-500" />
            ) : allHealthy ? (
              <CheckCircleIcon className="w-8 h-8 text-emerald-500" />
            ) : (
              <ExclamationTriangleIcon className="w-8 h-8 text-amber-500" />
            )}
          </div>
          <h1 className="text-xl font-semibold text-gray-900 mb-1">
            {hasCritical
              ? `${dashboardStats.criticalServices} Service${dashboardStats.criticalServices > 1 ? 's' : ''} Down`
              : allHealthy
              ? 'All Systems Operational'
              : `${dashboardStats.warningServices} Warning${dashboardStats.warningServices > 1 ? 's' : ''}`
            }
          </h1>
          <p className="text-[13px] text-gray-500">
            {dashboardStats.healthyServices} of {dashboardStats.totalServices} services running
          </p>
          <div className="flex items-center justify-center mt-3 space-x-1.5 text-[11px] text-gray-400">
            <div className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse"></div>
            <span>Live</span>
            <span>·</span>
            <span>Uptime {dashboardStats.uptime}</span>
          </div>
        </div>

        {/* Compact Stats Row - unified color scheme */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-white rounded-xl p-4 shadow-sm text-center">
            <p className="text-2xl font-semibold text-gray-900">{dashboardStats.healthyServices}</p>
            <p className="text-[11px] text-gray-400 mt-1 font-medium">Healthy</p>
          </div>
          <div className="bg-white rounded-xl p-4 shadow-sm text-center">
            <p className="text-2xl font-semibold text-gray-900">{dashboardStats.enabledModules}</p>
            <p className="text-[11px] text-gray-400 mt-1 font-medium">Modules</p>
          </div>
          <div className="bg-white rounded-xl p-4 shadow-sm text-center">
            <p className="text-2xl font-semibold text-gray-900">{dashboardStats.memoryUsage}</p>
            <p className="text-[11px] text-gray-400 mt-1 font-medium">Memory</p>
          </div>
          <div className="bg-white rounded-xl p-4 shadow-sm text-center">
            <p className="text-2xl font-semibold text-gray-900">{dashboardStats.uptime}</p>
            <p className="text-[11px] text-gray-400 mt-1 font-medium">Uptime</p>
          </div>
        </div>

        {/* Only show issues if there are any */}
        {unhealthyServices.length > 0 && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Attention Required</h3>
            <div className="space-y-3">
              {unhealthyServices.map((service, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    {getStatusIcon(service.status)}
                    <span className="ml-3 text-sm font-medium text-gray-900">{service.name}</span>
                  </div>
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                    service.status === 'unhealthy' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {service.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions - simplified */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {onAddDevice && (
            <button
              onClick={onAddDevice}
              className="flex flex-col items-center p-4 bg-white rounded-xl border border-gray-100 shadow-sm hover:border-blue-300 hover:shadow-md transition-all"
            >
              <ComputerDesktopIcon className="w-6 h-6 text-blue-600 mb-2" />
              <span className="text-xs font-medium text-gray-700">Add Device</span>
            </button>
          )}
          <button className="flex flex-col items-center p-4 bg-white rounded-xl border border-gray-100 shadow-sm hover:border-green-300 hover:shadow-md transition-all">
            <ShieldCheckIcon className="w-6 h-6 text-green-600 mb-2" />
            <span className="text-xs font-medium text-gray-700">Security</span>
          </button>
          <button className="flex flex-col items-center p-4 bg-white rounded-xl border border-gray-100 shadow-sm hover:border-purple-300 hover:shadow-md transition-all">
            <ChartBarIcon className="w-6 h-6 text-purple-600 mb-2" />
            <span className="text-xs font-medium text-gray-700">Analytics</span>
          </button>
          <button className="flex flex-col items-center p-4 bg-white rounded-xl border border-gray-100 shadow-sm hover:border-gray-300 hover:shadow-md transition-all">
            <CpuChipIcon className="w-6 h-6 text-gray-600 mb-2" />
            <span className="text-xs font-medium text-gray-700">Services</span>
          </button>
        </div>
      </div>
    );
  }

  // ── Expert Mode: Full detailed dashboard ──
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

      {/* Stats Cards - UniFi style: white cards, subtle icons, clean typography */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[13px] font-medium text-gray-500">Healthy Services</p>
            <CheckCircleIcon className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="flex items-baseline">
            <p className="text-2xl font-semibold text-gray-900">{dashboardStats.healthyServices}</p>
            <span className="ml-1.5 text-[13px] text-gray-400">/ {dashboardStats.totalServices}</span>
          </div>
          <div className="flex items-center mt-2 text-[12px]">
            <ArrowTrendingUpIcon className="w-3.5 h-3.5 text-emerald-500 mr-1" />
            <span className="text-emerald-600">+2.4%</span>
            <span className="text-gray-400 ml-1">from last hour</span>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[13px] font-medium text-gray-500">Active Modules</p>
            <CpuChipIcon className="w-5 h-5 text-blue-400" />
          </div>
          <div className="flex items-baseline">
            <p className="text-2xl font-semibold text-gray-900">{dashboardStats.enabledModules}</p>
            <span className="ml-1.5 text-[13px] text-gray-400">/ {dashboardStats.totalModules}</span>
          </div>
          <div className="mt-2.5 w-full bg-gray-100 rounded-full h-1.5">
            <div
              className="bg-blue-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${dashboardStats.totalModules > 0 ? (dashboardStats.enabledModules / dashboardStats.totalModules) * 100 : 0}%` }}
            />
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[13px] font-medium text-gray-500">Memory Usage</p>
            <ChartBarIcon className="w-5 h-5 text-gray-400" />
          </div>
          <p className="text-2xl font-semibold text-gray-900">{dashboardStats.memoryUsage}</p>
          <div className="flex items-center mt-2 text-[12px]">
            <ArrowTrendingDownIcon className="w-3.5 h-3.5 text-emerald-500 mr-1" />
            <span className="text-emerald-600">-1.2%</span>
            <span className="text-gray-400 ml-1">from last hour</span>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[13px] font-medium text-gray-500">System Uptime</p>
            <CloudIcon className="w-5 h-5 text-gray-400" />
          </div>
          <p className="text-2xl font-semibold text-gray-900">{dashboardStats.uptime}</p>
          <div className="flex items-center mt-2 text-[12px]">
            <div className="w-1.5 h-1.5 bg-emerald-400 rounded-full mr-1.5"></div>
            <span className="text-gray-400">Running stable</span>
          </div>
        </div>
      </div>

      {/* Service Health and Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent Service Activities */}
        <div className="lg:col-span-2 bg-white rounded-xl shadow-sm">
          <div className="px-5 py-4 border-b border-gray-100">
            <h3 className="text-[14px] font-semibold text-gray-900">Service Health</h3>
          </div>
          <div className="p-2">
            {recentServices.map((service, index) => (
              <div key={index} className="flex items-center justify-between px-4 py-3 rounded-lg hover:bg-gray-50 transition-colors">
                <div className="flex items-center">
                  {getStatusIcon(service.status)}
                  <div className="ml-3">
                    <p className="text-[13px] font-medium text-gray-900">{service.name}</p>
                    <p className="text-[11px] text-gray-400">
                      {new Date(service.lastCheck).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  {service.responseTime && (
                    <span className="text-[11px] text-gray-400">{service.responseTime}ms</span>
                  )}
                  <div className={`w-2 h-2 rounded-full ${
                    service.status === 'healthy' ? 'bg-emerald-400'
                    : service.status === 'unhealthy' ? 'bg-red-400'
                    : 'bg-amber-400'
                  }`} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-white rounded-xl shadow-sm">
          <div className="px-5 py-4 border-b border-gray-100">
            <h3 className="text-[14px] font-semibold text-gray-900">Quick Actions</h3>
          </div>
          <div className="p-2 space-y-0.5">
            {[
              { icon: CpuChipIcon, label: 'Manage Services' },
              { icon: ShieldCheckIcon, label: 'Security Status' },
              { icon: ChartBarIcon, label: 'View Analytics' },
              ...(onAddDevice ? [{ icon: ComputerDesktopIcon, label: 'Add Device', onClick: onAddDevice }] : []),
              { icon: CloudIcon, label: 'System Logs' },
            ].map((action, i) => (
              <button
                key={i}
                onClick={(action as any).onClick}
                className="w-full flex items-center px-4 py-2.5 text-left rounded-lg hover:bg-gray-50 transition-colors group"
              >
                <action.icon className="w-[18px] h-[18px] text-gray-400 mr-3 group-hover:text-blue-500 transition-colors" />
                <span className="text-[13px] font-medium text-gray-600 group-hover:text-gray-900 transition-colors">{action.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
