'use client';

import React, { useState, useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import {
  HomeIcon,
  RectangleGroupIcon,
  ComputerDesktopIcon,
  CubeIcon,
  Cog6ToothIcon,
  ChartBarIcon,
  BellIcon,
  UserCircleIcon,
  MagnifyingGlassIcon,
  Bars3Icon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi } from '@/lib/api';

interface LayoutProps {
  children: React.ReactNode;
  activeView: string;
  onViewChange: (view: string) => void;
}

interface SystemStats {
  services: number;
  healthyServices: number;
  modules: number;
  uptime: string;
}

export default function UnifiLayout({ children, activeView, onViewChange }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [systemStats, setSystemStats] = useState<SystemStats>({
    services: 0,
    healthyServices: 0,
    modules: 0,
    uptime: '0h'
  });
  const [notifications, setNotifications] = useState<number>(0);

  const navigationItems = [
    { id: 'dashboard', name: 'Dashboard', icon: HomeIcon },
    { id: 'topology', name: 'Network', icon: RectangleGroupIcon },
    { id: 'devices', name: 'Devices', icon: ComputerDesktopIcon },
    { id: 'applications', name: 'Applications', icon: CubeIcon },
    { id: 'monitoring', name: 'Insights', icon: ChartBarIcon },
    { id: 'settings', name: 'Settings', icon: Cog6ToothIcon },
  ];

  useEffect(() => {
    loadSystemStats();
    const interval = setInterval(loadSystemStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadSystemStats = async () => {
    try {
      const [servicesRes, healthRes] = await Promise.all([
        gatewayApi.getServices(),
        healthApi.getDetailedHealth()
      ]);

      const services = servicesRes.data || [];
      const healthyCount = services.filter((s: any) => s.status === 'healthy').length;
      const uptime = healthRes.data?.gateway?.uptime 
        ? Math.floor(healthRes.data.gateway.uptime / 3600) + 'h'
        : '0h';

      setSystemStats({
        services: services.length,
        healthyServices: healthyCount,
        modules: healthRes.data?.modules?.length || 0,
        uptime
      });
    } catch (error) {
      console.error('Failed to load system stats:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex">
      <Toaster 
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1f2937',
            color: '#ffffff',
            borderRadius: '8px'
          }
        }}
      />

      {/* Sidebar */}
      <div className={`${sidebarOpen ? 'block' : 'hidden'} fixed inset-0 z-50 lg:relative lg:block lg:inset-auto lg:z-auto`}>
        <div className={`${sidebarOpen ? 'opacity-100' : 'opacity-0'} fixed inset-0 bg-gray-600 lg:hidden`} onClick={() => setSidebarOpen(false)} />
        
        <div className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0 fixed lg:relative inset-y-0 left-0 z-50 w-64 bg-white border-r border-gray-200 transform transition-transform duration-300 ease-in-out lg:transform-none`}>
          {/* Logo Area */}
          <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">OD</span>
              </div>
              <span className="text-xl font-semibold text-gray-900">OpenDirectory</span>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden text-gray-400 hover:text-gray-600"
            >
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>

          {/* Navigation */}
          <nav className="mt-6 px-3">
            <div className="space-y-1">
              {navigationItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    onViewChange(item.id);
                    setSidebarOpen(false);
                  }}
                  className={`${
                    activeView === item.id
                      ? 'bg-blue-50 border-r-2 border-blue-600 text-blue-700'
                      : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                  } group flex items-center px-3 py-2 text-sm font-medium rounded-l-lg w-full text-left transition-colors duration-150`}
                >
                  <item.icon className={`${
                    activeView === item.id ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-600'
                  } mr-3 h-5 w-5 transition-colors duration-150`} />
                  {item.name}
                </button>
              ))}
            </div>
          </nav>

          {/* System Stats */}
          <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200 bg-gray-50">
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-gray-600">
                <span>Services</span>
                <span className="text-green-600">{systemStats.healthyServices}/{systemStats.services}</span>
              </div>
              <div className="flex justify-between text-xs text-gray-600">
                <span>Uptime</span>
                <span>{systemStats.uptime}</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-1">
                <div 
                  className="bg-green-500 h-1 rounded-full" 
                  style={{ 
                    width: `${systemStats.services > 0 ? (systemStats.healthyServices / systemStats.services) * 100 : 0}%` 
                  }}
                ></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Header */}
        <header className="bg-white border-b border-gray-200 h-16 flex items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden text-gray-400 hover:text-gray-600"
            >
              <Bars3Icon className="w-6 h-6" />
            </button>
            
            {/* Search Bar */}
            <div className="hidden sm:block relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-4 w-4 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search services, devices..."
                className="block w-64 pl-10 pr-3 py-2 border border-gray-300 rounded-lg leading-5 bg-gray-50 placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 text-sm"
              />
            </div>
          </div>

          <div className="flex items-center space-x-4">
            {/* Notifications */}
            <button className="relative text-gray-400 hover:text-gray-600">
              <BellIcon className="w-6 h-6" />
              {notifications > 0 && (
                <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
                  {notifications}
                </span>
              )}
            </button>

            {/* User Menu */}
            <div className="flex items-center space-x-3">
              <div className="hidden sm:block text-right">
                <p className="text-sm font-medium text-gray-700">Admin User</p>
                <p className="text-xs text-gray-500">System Administrator</p>
              </div>
              <UserCircleIcon className="w-8 h-8 text-gray-400" />
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  );
}