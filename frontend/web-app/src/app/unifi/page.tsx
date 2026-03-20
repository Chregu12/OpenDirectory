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
import NetworkConfigWizard from '@/components/setup/NetworkConfigWizard';
import UserManagementWizard from '@/components/setup/UserManagementWizard';
import PrinterSetupWizard from '@/components/setup/PrinterSetupWizard';
import SecuritySetupWizard from '@/components/setup/SecuritySetupWizard';
import MonitoringAlertingWizard from '@/components/setup/MonitoringAlertingWizard';
import BackupRecoveryWizard from '@/components/setup/BackupRecoveryWizard';
import AppDeploymentWizard from '@/components/setup/AppDeploymentWizard';
import PolicyCreationWizard from '@/components/setup/PolicyCreationWizard';
import { configApi } from '@/lib/api';

const SettingsView = () => (
  <div className="p-6">
    <ServicesDashboard />
  </div>
);

interface WizardsViewProps {
  onOpenNetwork: () => void;
  onOpenUser: () => void;
  onOpenPrinter: () => void;
  onOpenSecurity: () => void;
  onOpenMonitoring: () => void;
  onOpenBackup: () => void;
  onOpenAppDeploy: () => void;
  onOpenPolicy: () => void;
}

const WizardsView = ({ onOpenNetwork, onOpenUser, onOpenPrinter, onOpenSecurity, onOpenMonitoring, onOpenBackup, onOpenAppDeploy, onOpenPolicy }: WizardsViewProps) => (
  <div className="p-6 space-y-6">
    <div>
      <h2 className="text-xl font-bold text-gray-900">Setup-Assistenten</h2>
      <p className="text-sm text-gray-500 mt-1">Geführte Konfiguration für die wichtigsten Bereiche.</p>
    </div>

    {/* Infrastruktur */}
    <div>
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Infrastruktur</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <button
          onClick={onOpenNetwork}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-blue-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-blue-200 transition-colors">
            <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A9.015 9.015 0 003 12c0-1.605.42-3.113 1.157-4.418" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Netzwerk-Konfiguration</h3>
          <p className="text-sm text-gray-500">DNS, DHCP und File Shares einrichten. Quick Setup oder Schritt-für-Schritt.</p>
          <span className="inline-block mt-3 text-sm text-blue-600 font-medium">Assistent starten →</span>
        </button>

        <button
          onClick={onOpenUser}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-indigo-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-indigo-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-indigo-200 transition-colors">
            <svg className="h-6 w-6 text-indigo-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Benutzer-Verwaltung</h3>
          <p className="text-sm text-gray-500">Gruppen und Benutzer anlegen, CSV-Import, Berechtigungen konfigurieren.</p>
          <span className="inline-block mt-3 text-sm text-indigo-600 font-medium">Assistent starten →</span>
        </button>

        <button
          onClick={onOpenPrinter}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-orange-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-orange-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-orange-200 transition-colors">
            <svg className="h-6 w-6 text-orange-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6.72 13.829c-.24.03-.48.062-.72.096m.72-.096a42.415 42.415 0 0110.56 0m-10.56 0L6.34 18m10.94-4.171c.24.03.48.062.72.096m-.72-.096L17.66 18m0 0l.229 2.523a1.125 1.125 0 01-1.12 1.227H7.231c-.662 0-1.18-.568-1.12-1.227L6.34 18m11.318 0h1.091A2.25 2.25 0 0021 15.75V9.456c0-1.081-.768-2.015-1.837-2.175a48.055 48.055 0 00-1.913-.247M6.34 18H5.25A2.25 2.25 0 013 15.75V9.456c0-1.081.768-2.015 1.837-2.175a48.041 48.041 0 011.913-.247m10.5 0a48.536 48.536 0 00-10.5 0m10.5 0V3.375c0-.621-.504-1.125-1.125-1.125h-8.25c-.621 0-1.125.504-1.125 1.125v3.659M18 10.5h.008v.008H18V10.5zm-3 0h.008v.008H15V10.5z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Drucker-Setup</h3>
          <p className="text-sm text-gray-500">Drucker finden, konfigurieren, Gruppen und Berechtigungen, Deployment.</p>
          <span className="inline-block mt-3 text-sm text-orange-600 font-medium">Assistent starten →</span>
        </button>
      </div>
    </div>

    {/* Sicherheit & Compliance */}
    <div>
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Sicherheit & Compliance</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <button
          onClick={onOpenSecurity}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-red-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-red-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-red-200 transition-colors">
            <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Security-Setup</h3>
          <p className="text-sm text-gray-500">Antivirus, DLP und Compliance-Frameworks konfigurieren.</p>
          <span className="inline-block mt-3 text-sm text-red-600 font-medium">Assistent starten →</span>
        </button>

        <button
          onClick={onOpenPolicy}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-amber-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-amber-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-amber-200 transition-colors">
            <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Policy-Erstellung</h3>
          <p className="text-sm text-gray-500">Richtlinien erstellen, konfigurieren und an Gruppen zuweisen.</p>
          <span className="inline-block mt-3 text-sm text-amber-600 font-medium">Assistent starten →</span>
        </button>

        <button
          onClick={onOpenAppDeploy}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-violet-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-violet-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-violet-200 transition-colors">
            <svg className="h-6 w-6 text-violet-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 16.875h3.375m0 0h3.375m-3.375 0V13.5m0 3.375v3.375M6 10.5h2.25a2.25 2.25 0 002.25-2.25V6a2.25 2.25 0 00-2.25-2.25H6A2.25 2.25 0 003.75 6v2.25A2.25 2.25 0 006 10.5zm0 9.75h2.25A2.25 2.25 0 0010.5 18v-2.25a2.25 2.25 0 00-2.25-2.25H6a2.25 2.25 0 00-2.25 2.25V18A2.25 2.25 0 006 20.25zm9.75-9.75H18a2.25 2.25 0 002.25-2.25V6A2.25 2.25 0 0018 3.75h-2.25A2.25 2.25 0 0013.5 6v2.25a2.25 2.25 0 002.25 2.25z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">App-Verteilung</h3>
          <p className="text-sm text-gray-500">App-Katalog befüllen, Apps auswählen und an Geräte verteilen.</p>
          <span className="inline-block mt-3 text-sm text-violet-600 font-medium">Assistent starten →</span>
        </button>
      </div>
    </div>

    {/* Betrieb & Monitoring */}
    <div>
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Betrieb & Monitoring</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <button
          onClick={onOpenMonitoring}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-cyan-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-cyan-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-cyan-200 transition-colors">
            <svg className="h-6 w-6 text-cyan-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Monitoring & Alerting</h3>
          <p className="text-sm text-gray-500">Metriken, Alert-Schwellwerte und Benachrichtigungen einrichten.</p>
          <span className="inline-block mt-3 text-sm text-cyan-600 font-medium">Assistent starten →</span>
        </button>

        <button
          onClick={onOpenBackup}
          className="text-left bg-white rounded-xl border-2 border-gray-200 p-6 hover:border-emerald-400 hover:shadow-lg transition-all group"
        >
          <div className="w-12 h-12 bg-emerald-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-emerald-200 transition-colors">
            <svg className="h-6 w-6 text-emerald-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75v3.75m0 0l-1.5-1.5m1.5 1.5l1.5-1.5" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-1">Backup & Recovery</h3>
          <p className="text-sm text-gray-500">Backup-Zeitplan erstellen, Speicherort und Verschlüsselung konfigurieren.</p>
          <span className="inline-block mt-3 text-sm text-emerald-600 font-medium">Assistent starten →</span>
        </button>
      </div>
    </div>
  </div>
);

export default function UnifiApp() {
  const [activeView, setActiveView] = useState('dashboard');
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [showEnrollmentWizard, setShowEnrollmentWizard] = useState(false);
  const [showNetworkWizard, setShowNetworkWizard] = useState(false);
  const [showUserWizard, setShowUserWizard] = useState(false);
  const [showPrinterWizard, setShowPrinterWizard] = useState(false);
  const [showSecurityWizard, setShowSecurityWizard] = useState(false);
  const [showMonitoringWizard, setShowMonitoringWizard] = useState(false);
  const [showBackupWizard, setShowBackupWizard] = useState(false);
  const [showAppDeployWizard, setShowAppDeployWizard] = useState(false);
  const [showPolicyWizard, setShowPolicyWizard] = useState(false);
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
      case 'wizards':
        return (
          <WizardsView
            onOpenNetwork={() => setShowNetworkWizard(true)}
            onOpenUser={() => setShowUserWizard(true)}
            onOpenPrinter={() => setShowPrinterWizard(true)}
            onOpenSecurity={() => setShowSecurityWizard(true)}
            onOpenMonitoring={() => setShowMonitoringWizard(true)}
            onOpenBackup={() => setShowBackupWizard(true)}
            onOpenAppDeploy={() => setShowAppDeployWizard(true)}
            onOpenPolicy={() => setShowPolicyWizard(true)}
          />
        );
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

      {/* Settings Wizards */}
      {showNetworkWizard && (
        <NetworkConfigWizard onClose={() => setShowNetworkWizard(false)} />
      )}
      {showUserWizard && (
        <UserManagementWizard onClose={() => setShowUserWizard(false)} />
      )}
      {showPrinterWizard && (
        <PrinterSetupWizard onClose={() => setShowPrinterWizard(false)} />
      )}

      {/* New Wizards */}
      {showSecurityWizard && (
        <SecuritySetupWizard onClose={() => setShowSecurityWizard(false)} />
      )}
      {showMonitoringWizard && (
        <MonitoringAlertingWizard onClose={() => setShowMonitoringWizard(false)} />
      )}
      {showBackupWizard && (
        <BackupRecoveryWizard onClose={() => setShowBackupWizard(false)} />
      )}
      {showAppDeployWizard && (
        <AppDeploymentWizard onClose={() => setShowAppDeployWizard(false)} />
      )}
      {showPolicyWizard && (
        <PolicyCreationWizard onClose={() => setShowPolicyWizard(false)} />
      )}

      {renderActiveView()}
    </UnifiLayout>
  );
}
