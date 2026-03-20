'use client';

import React, { useState, useEffect } from 'react';
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
import SetupWizard from '@/components/setup/SetupWizard';
import DeviceEnrollmentWizard from '@/components/setup/DeviceEnrollmentWizard';
import { configApi } from '@/lib/api';

const SettingsView = () => (
  <div className="p-6">
    <ServicesDashboard />
  </div>
);

export default function UnifiApp() {
  const [activeView, setActiveView] = useState('dashboard');
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [showEnrollmentWizard, setShowEnrollmentWizard] = useState(false);
  const [setupChecked, setSetupChecked] = useState(false);

  // Check if first-run setup wizard should be shown
  useEffect(() => {
    const checkSetupStatus = async () => {
      if (typeof window !== 'undefined' && localStorage.getItem('od_setup_completed')) {
        setSetupChecked(true);
        return;
      }
      try {
        const response = await configApi.getSetupStatus();
        if (response.data?.data?.isFirstRun) {
          setShowSetupWizard(true);
        }
      } catch {
        if (typeof window !== 'undefined' && !localStorage.getItem('od_setup_completed')) {
          setShowSetupWizard(true);
        }
      } finally {
        setSetupChecked(true);
      }
    };
    checkSetupStatus();
  }, []);

  const handleSetupComplete = () => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('od_setup_completed', 'true');
    }
    setShowSetupWizard(false);
    // After setup wizard → launch enrollment wizard
    setShowEnrollmentWizard(true);
  };

  const renderActiveView = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardView onAddDevice={() => setShowEnrollmentWizard(true)} />;
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
        return <DashboardView onAddDevice={() => setShowEnrollmentWizard(true)} />;
    }
  };

  return (
    <UnifiLayout activeView={activeView} onViewChange={setActiveView}>
      {/* First-run Setup Wizard */}
      {showSetupWizard && setupChecked && (
        <SetupWizard onComplete={handleSetupComplete} />
      )}

      {/* Device Enrollment Wizard */}
      {showEnrollmentWizard && (
        <DeviceEnrollmentWizard onClose={() => setShowEnrollmentWizard(false)} />
      )}

      {renderActiveView()}
    </UnifiLayout>
  );
}
