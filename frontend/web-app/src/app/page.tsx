'use client';

import React, { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import UnifiLayout from '@/components/layout/UnifiLayout';
import DashboardView from '@/components/views/DashboardView';
import TopologyView from '@/components/views/TopologyView';
import ApplicationsView from '@/components/views/ApplicationsView';
import DevicesView from '@/components/views/DevicesView';
import UsersView from '@/components/views/UsersView';
import InfrastructureView from '@/components/views/InfrastructureView';
import MonitoringView from '@/components/views/MonitoringView';
import SecretsView from '@/components/views/SecretsView';
import SettingsView from '@/components/views/SettingsView';
import PolicyView from '@/components/views/PolicyView';
import SecurityView from '@/components/views/SecurityView';
import PrintersView from '@/components/views/PrintersView';

// Maps integration-service module IDs → nav item IDs they control visibility for
const MODULE_NAV_MAP: Record<string, string> = {
  'monitoring-analytics':   'monitoring',
  'secrets-management':     'secrets',
  'device-management':      'devices',
  'network-infrastructure': 'infrastructure',
  'security-suite':         'security',
};

export default function App() {
  const [activeView,    setActiveView]    = useState('dashboard');
  // Start with all optional modules enabled so nothing flickers hidden on load
  const [enabledModules, setEnabledModules] = useState<string[]>(Object.keys(MODULE_NAV_MAP));

  // Fetch real module state from the integration service
  useEffect(() => {
    api.get('/api/config/modules')
      .then(res => {
        const data = res.data as Record<string, { enabled: boolean }>;
        const enabled = Object.entries(data).filter(([, v]) => v.enabled).map(([k]) => k);
        setEnabledModules(enabled);
      })
      .catch(() => { /* keep defaults on error */ });
  }, []);

  const handleModuleChange = (moduleId: string, enabled: boolean) => {
    setEnabledModules(prev =>
      enabled ? [...prev, moduleId] : prev.filter(m => m !== moduleId)
    );
    // If the user is currently on a view that just got hidden, go to dashboard
    const navId = MODULE_NAV_MAP[moduleId];
    if (!enabled && navId && activeView === navId) {
      setActiveView('dashboard');
    }
  };

  const renderActiveView = () => {
    switch (activeView) {
      case 'dashboard':      return <DashboardView />;
      case 'topology':       return <TopologyView />;
      case 'devices':        return <DevicesView />;
      case 'applications':   return <ApplicationsView />;
      case 'infrastructure': return <InfrastructureView />;
      case 'users':          return <UsersView />;
      case 'monitoring':     return <MonitoringView />;
      case 'secrets':        return <SecretsView />;
      case 'security':       return <SecurityView />;
      case 'printers':       return <PrintersView />;
      case 'policies':       return <PolicyView />;
      case 'settings':
        return (
          <div className="p-6">
            <SettingsView enabledModules={enabledModules} onModuleChange={handleModuleChange} />
          </div>
        );
      default: return <DashboardView />;
    }
  };

  return (
    <UnifiLayout activeView={activeView} onViewChange={setActiveView} enabledModules={enabledModules}>
      {renderActiveView()}
    </UnifiLayout>
  );
}
