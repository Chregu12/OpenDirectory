'use client';

import React, { useState } from 'react';
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
  UserGroupIcon,
  WifiIcon,
  PrinterIcon,
  DocumentTextIcon,
  LockClosedIcon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/outline';

interface LayoutProps {
  children: React.ReactNode;
  activeView: string;
  onViewChange: (view: string) => void;
  enabledModules?: string[];
}

type NavItem =
  | { type: 'item'; id: string; name: string; icon: React.ComponentType<{ className?: string }> }
  | { type: 'divider'; label: string };

// Nav items that require a specific module to be enabled
const NAV_REQUIRED_MODULE: Record<string, string> = {
  monitoring:     'monitoring-analytics',
  secrets:        'secrets-management',
  devices:        'device-management',
  printers:       'device-management',
  infrastructure: 'network-infrastructure',
  security:       'security-suite',
};

export default function UnifiLayout({ children, activeView, onViewChange, enabledModules }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [notifications] = useState<number>(0);

  const ALL_NAV_ITEMS: NavItem[] = [
    { type: 'item', id: 'dashboard',      name: 'Dashboard',      icon: HomeIcon },
    { type: 'item', id: 'devices',        name: 'Devices',         icon: ComputerDesktopIcon },
    { type: 'item', id: 'printers',       name: 'Printers',        icon: PrinterIcon },
    { type: 'item', id: 'topology',       name: 'Network',         icon: RectangleGroupIcon },
    { type: 'item', id: 'infrastructure', name: 'Infrastructure',  icon: WifiIcon },
    { type: 'item', id: 'users',          name: 'Users',           icon: UserGroupIcon },
    { type: 'item', id: 'applications',   name: 'Applications',    icon: CubeIcon },
    { type: 'item', id: 'monitoring',     name: 'Monitoring',      icon: ChartBarIcon },
    { type: 'divider', label: 'Governance' },
    { type: 'item', id: 'policies',       name: 'Policies',        icon: DocumentTextIcon },
    { type: 'item', id: 'security',       name: 'Security',        icon: ShieldExclamationIcon },
    { type: 'item', id: 'secrets',        name: 'Secrets',         icon: LockClosedIcon },
    { type: 'divider', label: '' },
    { type: 'item', id: 'settings',       name: 'Settings',        icon: Cog6ToothIcon },
  ];

  // Hide nav items whose controlling module is disabled
  const navigationItems = ALL_NAV_ITEMS.filter(item => {
    if (item.type === 'divider') return true;
    const required = NAV_REQUIRED_MODULE[item.id];
    if (!required) return true;                          // no module gate → always show
    if (!enabledModules || enabledModules.length === 0) return true; // not loaded yet → show all
    return enabledModules.includes(required);
  });

  return (
    /* Full viewport height, no scroll on the outer shell */
    <div className="h-screen bg-gray-50 flex overflow-hidden">
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: { background: '#1f2937', color: '#ffffff', borderRadius: '8px' },
        }}
      />

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-gray-600 bg-opacity-50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar — flex column so the version text is pushed to the bottom */}
      <div
        className={`
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
          lg:translate-x-0
          fixed lg:relative inset-y-0 left-0 z-50
          w-64 bg-white border-r border-gray-200
          flex flex-col
          transform transition-transform duration-300 ease-in-out lg:transform-none
          h-full
        `}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200 shrink-0">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">OD</span>
            </div>
            <span className="text-xl font-semibold text-gray-900">OpenDirectory</span>
          </div>
          <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-gray-400 hover:text-gray-600">
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        {/* Navigation — grows to fill space */}
        <nav className="flex-1 mt-6 px-3 overflow-y-auto">
          <div className="space-y-0.5">
            {navigationItems.map((item, idx) => {
              if (item.type === 'divider') {
                return item.label ? (
                  <div key={`divider-${idx}`} className="px-3 pt-5 pb-1">
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-400">
                      {item.label}
                    </span>
                  </div>
                ) : (
                  <hr key={`divider-${idx}`} className="border-gray-100 mx-3 my-2" />
                );
              }
              return (
                <button
                  key={item.id}
                  onClick={() => { onViewChange(item.id); setSidebarOpen(false); }}
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
              );
            })}
          </div>
        </nav>

        {/* Version — pinned at the bottom inside flex column */}
        <div className="shrink-0 border-t border-gray-100 p-4">
          <p className="text-xs text-gray-400 text-center">OpenDirectory v1.0</p>
        </div>
      </div>

      {/* Main content — flex column, fills remaining width, scrolls independently */}
      <div className="flex-1 flex flex-col min-w-0 h-full">
        {/* Top header */}
        <header className="shrink-0 bg-white border-b border-gray-200 h-16 flex items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <button onClick={() => setSidebarOpen(!sidebarOpen)} className="lg:hidden text-gray-400 hover:text-gray-600">
              <Bars3Icon className="w-6 h-6" />
            </button>
            <div className="hidden sm:block relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-4 w-4 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search services, devices..."
                className="block w-64 pl-10 pr-3 py-2 border border-gray-300 rounded-lg leading-5 bg-gray-50 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 text-sm"
              />
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <button className="relative text-gray-400 hover:text-gray-600">
              <BellIcon className="w-6 h-6" />
              {notifications > 0 && (
                <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
                  {notifications}
                </span>
              )}
            </button>
            <div className="flex items-center space-x-3">
              <div className="hidden sm:block text-right">
                <p className="text-sm font-medium text-gray-700">Admin User</p>
                <p className="text-xs text-gray-500">System Administrator</p>
              </div>
              <UserCircleIcon className="w-8 h-8 text-gray-400" />
            </div>
          </div>
        </header>

        {/* Page content — scrolls independently */}
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
