'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
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
import IdentityProviderView from '@/components/views/IdentityProviderView';
import EnrollmentHubView from '@/components/views/EnrollmentHubView';
import PermissionsView from '@/components/views/PermissionsView';
import AntivirusView from '@/components/views/AntivirusView';
import AuditView from '@/components/views/AuditView';
import BackupView from '@/components/views/BackupView';
import AppStoreView from '@/components/views/AppStoreView';
import ComplianceView from '@/components/views/ComplianceView';
import SecurityScannerView from '@/components/views/SecurityScannerView';
import BlueprintsView from '@/components/views/BlueprintsView';
import RoadmapView from '@/components/views/RoadmapView';
import PIMView from '@/components/views/PIMView';
import LicenseKioskView from '@/components/views/LicenseKioskView';
import OnboardingWizard from '@/components/setup/OnboardingWizard';
import SyncView from '@/components/views/SyncView';
import IntegrationsView from '@/components/views/IntegrationsView';
import MFAView from '@/components/views/MFAView';
import SSPRView from '@/components/views/SSPRView';
import ConditionalAccessView from '@/components/views/ConditionalAccessView';
import AlertingView from '@/components/views/AlertingView';
import CertificatesView from '@/components/views/CertificatesView';
import RadiusView from '@/components/views/RadiusView';
import ServiceHealthView from '@/components/views/ServiceHealthView';

const MODULE_NAV_MAP: Record<string, string> = {
  'monitoring-analytics':   'monitoring',
  'secrets-management':     'secrets',
  'device-management':      'devices',
  'network-infrastructure': 'infrastructure',
  'security-suite':         'security',
};

const VALID_VIEWS = new Set([
  'dashboard','topology','devices','applications','infrastructure',
  'users','monitoring','secrets','security','printers','policies','settings',
  'identity','enrollment','permissions',
  'antivirus','audit','backup','appstore','compliance','scanner',
  'blueprints','sync','integrations','roadmap','pim','licenses',
  'mfa','sspr','conditionalaccess','alerting','certificates','radius','servicehealth',
]);

export default function ViewPage() {
  const router = useRouter();
  const params = useParams();
  const viewParam = Array.isArray(params.view) ? params.view[0] : (params.view ?? 'dashboard');
  const activeView = VALID_VIEWS.has(viewParam) ? viewParam : 'dashboard';

  const [enabledModules, setEnabledModules] = useState<string[]>(Object.keys(MODULE_NAV_MAP));
  const [currentUser,    setCurrentUser]    = useState<{ name: string; role: string } | null>(null);
  const [authChecked,    setAuthChecked]    = useState(false);
  const [onboarded,      setOnboarded]      = useState(true);

  useEffect(() => {
    const stored = typeof window !== 'undefined' ? localStorage.getItem('auth_user') : null;
    if (!stored) { router.push('/login'); return; }
    try { setCurrentUser(JSON.parse(stored)); } catch { router.push('/login'); return; }
    // Check onboarding
    const od = typeof window !== 'undefined' ? localStorage.getItem('od_onboarded') : 'true';
    setOnboarded(!!od);
    setAuthChecked(true);
  }, [router]);

  useEffect(() => {
    if (!authChecked) return;
    api.get('/api/config/modules')
      .then(res => {
        const data = res.data as Record<string, { enabled: boolean }>;
        const enabled = Object.entries(data).filter(([, v]) => v.enabled).map(([k]) => k);
        setEnabledModules(enabled);
      })
      .catch(() => {});
  }, [authChecked]);

  const handleViewChange = (view: string) => {
    router.push(`/${view}`);
  };

  const handleModuleChange = (moduleId: string, enabled: boolean) => {
    setEnabledModules(prev =>
      enabled ? [...prev, moduleId] : prev.filter(m => m !== moduleId)
    );
    const navId = MODULE_NAV_MAP[moduleId];
    if (!enabled && navId && activeView === navId) router.push('/dashboard');
  };

  const renderView = () => {
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
      case 'identity':       return <IdentityProviderView />;
      case 'enrollment':     return <EnrollmentHubView />;
      case 'permissions':    return <PermissionsView />;
      case 'antivirus':      return <AntivirusView />;
      case 'audit':          return <AuditView />;
      case 'backup':         return <BackupView />;
      case 'appstore':       return <AppStoreView />;
      case 'compliance':     return <ComplianceView />;
      case 'scanner':        return <SecurityScannerView />;
      case 'blueprints':     return <BlueprintsView />;
      case 'sync':           return <SyncView />;
      case 'integrations':   return <IntegrationsView />;
      case 'roadmap':        return <RoadmapView onViewChange={handleViewChange} />;
      case 'pim':            return <PIMView />;
      case 'licenses':           return <LicenseKioskView />;
      case 'mfa':                return <MFAView />;
      case 'sspr':               return <SSPRView />;
      case 'conditionalaccess':  return <ConditionalAccessView />;
      case 'alerting':           return <AlertingView />;
      case 'certificates':       return <CertificatesView />;
      case 'radius':             return <RadiusView />;
      case 'servicehealth':      return <ServiceHealthView />;
      case 'settings':
        return (
          <div className="p-6">
            <SettingsView enabledModules={enabledModules} onModuleChange={handleModuleChange} />
          </div>
        );
      default: return <DashboardView />;
    }
  };

  if (!authChecked) return null;

  // Show onboarding wizard overlay when not yet onboarded (except on settings page)
  if (!onboarded && activeView !== 'settings') {
    return <OnboardingWizard />;
  }

  return (
    <UnifiLayout
      activeView={activeView}
      onViewChange={handleViewChange}
      enabledModules={enabledModules}
      currentUser={currentUser}
    >
      {renderView()}
    </UnifiLayout>
  );
}
