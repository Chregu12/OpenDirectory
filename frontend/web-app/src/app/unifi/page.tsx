'use client';

import React, { useState } from 'react';
import UnifiLayout from '@/components/layout/UnifiLayout';
import DashboardView from '@/components/views/DashboardView';
import TopologyView from '@/components/views/TopologyView';
import DevicesView from '@/components/views/DevicesView';
import ApplicationsView from '@/components/views/ApplicationsView';
import PoliciesView from '@/components/views/PoliciesView';
import GraphExplorerView from '@/components/views/GraphExplorerView';
import PolicySimulatorView from '@/components/views/PolicySimulatorView';
import SecurityScannerView from '@/components/views/SecurityScannerView';
import AntivirusView from '@/components/views/AntivirusView';
import MonitoringView from '@/components/views/MonitoringView';
import ServicesDashboard from '@/components/dashboard/ServicesDashboard';

const SettingsView = () => (
  <div className="p-6">
    <ServicesDashboard />
  </div>
);

export default function UnifiApp() {
  const [activeView, setActiveView] = useState('dashboard');

  const renderActiveView = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardView />;
      case 'topology':
        return <TopologyView />;
      case 'devices':
        return <DevicesView />;
      case 'applications':
        return <ApplicationsView />;
      case 'graph-explorer':
        return <GraphExplorerView />;
      case 'policy-simulator':
        return <PolicySimulatorView />;
      case 'security-scanner':
        return <SecurityScannerView />;
      case 'antivirus':
        return <AntivirusView />;
      case 'policies':
        return <PoliciesView />;
      case 'monitoring':
        return <MonitoringView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <UnifiLayout activeView={activeView} onViewChange={setActiveView}>
      {renderActiveView()}
    </UnifiLayout>
  );
}
