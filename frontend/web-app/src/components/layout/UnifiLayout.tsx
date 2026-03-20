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
  XMarkIcon,
  ShareIcon,
  BeakerIcon,
  ShieldExclamationIcon,
  DocumentTextIcon,
  WrenchScrewdriverIcon,
  ShieldCheckIcon,
  CloudArrowUpIcon,
  Square3Stack3DIcon,
  ClipboardDocumentCheckIcon,
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';

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
  const { isExpert, toggleMode } = useUiMode();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [systemStats, setSystemStats] = useState<SystemStats>({
    services: 0,
    healthyServices: 0,
    modules: 0,
    uptime: '0h'
  });
  const [notifications, setNotifications] = useState<number>(0);

  const allNavigationItems = [
    { id: 'dashboard', name: 'Dashboard', icon: HomeIcon, simple: true },
    { id: 'topology', name: 'Network', icon: RectangleGroupIcon, simple: false },
    { id: 'devices', name: 'Devices', icon: ComputerDesktopIcon, simple: true },
    { id: 'applications', name: 'Applications', icon: CubeIcon, simple: false },
    { id: 'app-store', name: 'App Store', icon: Square3Stack3DIcon, simple: true },
    { id: 'policies', name: 'Policies', icon: DocumentTextIcon, simple: true },
    { id: 'security-scanner', name: 'Security', icon: ShieldExclamationIcon, simple: true },
    { id: 'antivirus', name: 'Antivirus', icon: ShieldCheckIcon, simple: true },
    { id: 'compliance', name: 'Compliance', icon: ClipboardDocumentCheckIcon, simple: false },
    { id: 'monitoring', name: 'Monitoring', icon: ChartBarIcon, simple: true },
    { id: 'backup', name: 'Backup', icon: CloudArrowUpIcon, simple: true },
    { id: 'graph-explorer', name: 'Graph Explorer', icon: ShareIcon, simple: false },
    { id: 'policy-simulator', name: 'Policy Simulator', icon: BeakerIcon, simple: false },
    { id: 'wizards', name: 'Assistenten', icon: WrenchScrewdriverIcon, simple: false },
    { id: 'settings', name: 'Settings', icon: Cog6ToothIcon, simple: true },
  ];

  const navigationItems = isExpert
    ? allNavigationItems
    : allNavigationItems.filter(item => item.simple);

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

  const healthPercent = systemStats.services > 0
    ? (systemStats.healthyServices / systemStats.services) * 100
    : 0;

  return (
    <div className="min-h-screen bg-[#f4f5f7] flex">
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#ffffff',
            color: '#111827',
            borderRadius: '10px',
            border: 'none',
            boxShadow: '0 4px 12px rgb(0 0 0 / 0.08), 0 1px 3px rgb(0 0 0 / 0.04)'
          }
        }}
      />

      {/* ── Sidebar (White - UniFi Style) ── */}
      <div className={`${sidebarOpen ? 'block' : 'hidden'} fixed inset-0 z-50 lg:relative lg:block lg:inset-auto lg:z-auto`}>
        {/* Mobile overlay */}
        <div
          className={`${sidebarOpen ? 'opacity-100' : 'opacity-0'} fixed inset-0 bg-black/20 backdrop-blur-sm lg:hidden transition-opacity`}
          onClick={() => setSidebarOpen(false)}
        />

        <div className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0 fixed lg:relative inset-y-0 left-0 z-50 w-[240px] bg-white transform transition-transform duration-300 ease-in-out lg:transform-none flex flex-col shadow-[1px_0_0_0_#e5e7eb]`}>

          {/* Logo Area */}
          <div className="flex items-center h-14 px-5">
            <div className="flex items-center space-x-2.5">
              <div className="w-7 h-7 bg-blue-500 rounded-md flex items-center justify-center">
                <span className="text-white font-bold text-[11px]">OD</span>
              </div>
              <span className="text-[15px] font-semibold text-gray-900 tracking-tight">OpenDirectory</span>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden ml-auto text-gray-400 hover:text-gray-600"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 mt-1 px-3 overflow-y-auto">
            <div className="space-y-0.5">
              {navigationItems.map((item) => {
                const isActive = activeView === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      onViewChange(item.id);
                      setSidebarOpen(false);
                    }}
                    className={`group flex items-center w-full px-2.5 py-[9px] text-[13px] font-medium rounded-md transition-all duration-100 ${
                      isActive
                        ? 'bg-[#f0f1f3] text-blue-600'
                        : 'text-gray-500 hover:text-gray-900 hover:bg-[#f7f8f9]'
                    }`}
                  >
                    <item.icon className={`mr-2.5 h-[18px] w-[18px] flex-shrink-0 transition-colors duration-100 ${
                      isActive ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500'
                    }`} />
                    {item.name}
                  </button>
                );
              })}
            </div>
          </nav>

          {/* System Stats Footer */}
          <div className="px-4 py-3 border-t border-gray-100">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-[11px] text-gray-400 font-medium">Services</span>
                <div className="flex items-center space-x-1.5">
                  <div className={`w-1.5 h-1.5 rounded-full ${healthPercent === 100 ? 'bg-emerald-400' : healthPercent > 50 ? 'bg-amber-400' : 'bg-red-400'}`} />
                  <span className="text-[11px] font-medium text-gray-600">{systemStats.healthyServices}/{systemStats.services}</span>
                </div>
              </div>
              <div className="w-full bg-gray-100 rounded-full h-[3px]">
                <div
                  className={`h-[3px] rounded-full transition-all duration-500 ${healthPercent === 100 ? 'bg-emerald-400' : healthPercent > 50 ? 'bg-amber-400' : 'bg-red-400'}`}
                  style={{ width: `${healthPercent}%` }}
                />
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[11px] text-gray-400 font-medium">Uptime</span>
                <span className="text-[11px] text-gray-500">{systemStats.uptime}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Main Content ── */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header */}
        <header className="bg-white h-14 flex items-center justify-between px-5 shadow-[0_1px_0_0_#e5e7eb] flex-shrink-0 z-10">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden text-gray-400 hover:text-gray-600"
            >
              <Bars3Icon className="w-5 h-5" />
            </button>

            {/* Search Bar */}
            <div className="hidden sm:block relative">
              <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-4 w-4 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search..."
                className="block w-52 pl-8 pr-3 py-1.5 border-0 rounded-md bg-[#f4f5f7] placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:bg-white text-[13px] transition-all"
              />
            </div>
          </div>

          <div className="flex items-center space-x-1">
            {/* Notifications */}
            <button className="relative p-2 text-gray-400 hover:text-gray-600 rounded-md hover:bg-gray-50 transition-colors">
              <BellIcon className="w-[18px] h-[18px]" />
              {notifications > 0 && (
                <span className="absolute top-1 right-1 bg-red-500 text-white text-[9px] rounded-full w-3.5 h-3.5 flex items-center justify-center font-semibold">
                  {notifications}
                </span>
              )}
            </button>

            {/* Simple / Expert Mode Toggle */}
            <button
              onClick={toggleMode}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-md text-[12px] font-medium transition-all duration-150 hover:bg-gray-50"
              title={isExpert ? 'Switch to Simple Mode' : 'Switch to Expert Mode'}
            >
              <span className="text-gray-400">{isExpert ? 'Expert' : 'Simple'}</span>
              <div className={`relative w-7 h-[16px] rounded-full transition-colors duration-200 ${isExpert ? 'bg-blue-500' : 'bg-gray-200'}`}>
                <div className={`absolute top-[2px] w-3 h-3 rounded-full bg-white shadow-sm transition-transform duration-200 ${isExpert ? 'translate-x-[14px]' : 'translate-x-[2px]'}`} />
              </div>
            </button>

            {/* Divider */}
            <div className="h-5 w-px bg-gray-200 mx-1" />

            {/* User Menu */}
            <button className="flex items-center space-x-2 px-2 py-1.5 rounded-md hover:bg-gray-50 transition-colors">
              <div className="hidden sm:block text-right">
                <p className="text-[12px] font-medium text-gray-700 leading-tight">Admin</p>
              </div>
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center ring-2 ring-white">
                <span className="text-white text-[10px] font-semibold">A</span>
              </div>
            </button>
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
