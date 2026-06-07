'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { api } from '@/lib/api';
import UnifiLayout from '@/components/layout/UnifiLayout';

// ─── Views ────────────────────────────────────────────────────────────────────
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
import SyncView from '@/components/views/SyncView';
import IntegrationsView from '@/components/views/IntegrationsView';
import MFAView from '@/components/views/MFAView';
import SSPRView from '@/components/views/SSPRView';
import ConditionalAccessView from '@/components/views/ConditionalAccessView';
import AlertingView from '@/components/views/AlertingView';
import CertificatesView from '@/components/views/CertificatesView';
import LDAPSchemaBrowserView from '@/components/views/LDAPSchemaBrowserView';
import RadiusView from '@/components/views/RadiusView';
import ServiceHealthView from '@/components/views/ServiceHealthView';
import ThreatDashboardView from '@/components/views/ThreatDashboardView';
import GraphExplorerView from '@/components/views/GraphExplorerView';
import PolicySimulatorView from '@/components/views/PolicySimulatorView';

// ABM-style 3-column views
import DeviceFleetView from '@/components/views/DeviceFleetView';
import ServicePrincipalsView from '@/components/views/ServicePrincipalsView';

// Quick actions + wizards
import QuickActionsBar from '@/components/views/QuickActionsBar';
import EnrollmentWizard from '@/components/views/EnrollmentWizard';
import UserOnboardingWizard from '@/components/views/UserOnboardingWizard';
import ServicePrincipalWizard from '@/components/views/ServicePrincipalWizard';
import PolicyDeployWizard from '@/components/views/PolicyDeployWizard';
import ComplianceSnapshot from '@/components/views/ComplianceSnapshot';
import OnboardingWizard from '@/components/setup/OnboardingWizard';

// Advanced infrastructure views
import TrustManagementView from '@/components/views/TrustManagementView';
import KerberosAdminView from '@/components/views/KerberosAdminView';
import ReplicationView from '@/components/views/ReplicationView';
import AutomationView from '@/components/views/AutomationView';

// ─── Module gating ────────────────────────────────────────────────────────────

const MODULE_NAV_MAP: Record<string, string> = {
  'monitoring-analytics':   'monitoring',
  'secrets-management':     'secrets',
  'device-management':      'devices',
  'network-infrastructure': 'infrastructure',
  'security-suite':         'security',
};

const VALID_VIEWS = new Set([
  'dashboard', 'topology', 'devices', 'applications', 'infrastructure',
  'users', 'monitoring', 'secrets', 'security', 'threats', 'printers', 'policies', 'settings',
  'identity', 'enrollment', 'permissions',
  'antivirus', 'audit', 'backup', 'appstore', 'compliance', 'scanner',
  'blueprints', 'sync', 'integrations', 'roadmap', 'pim', 'licenses',
  'mfa', 'sspr', 'conditionalaccess', 'alerting', 'certificates', 'radius', 'servicehealth',
  'ldap-schema',
  // ABM-style 3-column views
  'fleet', 'serviceprincipals',
  // Advanced infrastructure views
  'trusts', 'kerberos', 'replication',
  // Automation
  'automation',
  // Graph Explorer + Policy Simulator
  'graph', 'simulator',
]);

// Views that display the QuickActionsBar
const VIEWS_WITH_QUICK_ACTIONS = new Set(['dashboard', 'fleet', 'serviceprincipals']);

// Views that use the ABM 3-column layout (manage their own ABMShell internally)
const ABM_VIEWS = new Set(['fleet', 'serviceprincipals', 'users']);

// ─── Scrollable content wrapper for standard views ────────────────────────────

function ContentPage({ children, withQuickActions, quickActionsProps }: {
  children: React.ReactNode;
  withQuickActions?: boolean;
  quickActionsProps?: {
    onEnrollDevice: () => void;
    onNewUser: () => void;
    onServicePrincipal: () => void;
    onDeployPolicy: () => void;
    onComplianceSnapshot: () => void;
  };
}) {
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      {withQuickActions && quickActionsProps && (
        <QuickActionsBar {...quickActionsProps} />
      )}
      {children}
    </div>
  );
}

// ─── Page component ───────────────────────────────────────────────────────────

export default function ViewPage() {
  const router = useRouter();
  const params = useParams();
  const viewParam = Array.isArray(params.view) ? params.view[0] : (params.view ?? 'dashboard');
  const activeView = VALID_VIEWS.has(viewParam) ? viewParam : 'dashboard';

  const [enabledModules, setEnabledModules] = useState<string[]>(Object.keys(MODULE_NAV_MAP));
  const [currentUser,    setCurrentUser]    = useState<{ name: string; role: string } | null>(null);
  const [authChecked,    setAuthChecked]    = useState(false);
  const [onboarded,      setOnboarded]      = useState(true);

  // Wizard / panel open state
  const [showEnrollWizard,  setShowEnrollWizard]  = useState(false);
  const [showUserWizard,    setShowUserWizard]    = useState(false);
  const [showSPWizard,      setShowSPWizard]      = useState(false);
  const [showPolicyWizard,  setShowPolicyWizard]  = useState(false);
  const [showCompliance,    setShowCompliance]    = useState(false);

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

  const handleViewChange = (view: string) => router.push(`/${view}`);

  const handleModuleChange = (moduleId: string, enabled: boolean) => {
    setEnabledModules(prev => enabled ? [...prev, moduleId] : prev.filter(m => m !== moduleId));
    const navId = MODULE_NAV_MAP[moduleId];
    if (!enabled && navId && activeView === navId) router.push('/dashboard');
  };

  const quickActionsProps = {
    onEnrollDevice:       () => setShowEnrollWizard(true),
    onNewUser:            () => setShowUserWizard(true),
    onServicePrincipal:   () => setShowSPWizard(true),
    onDeployPolicy:       () => setShowPolicyWizard(true),
    onComplianceSnapshot: () => setShowCompliance(true),
  };

  const renderView = () => {
    const hasQA = VIEWS_WITH_QUICK_ACTIONS.has(activeView);

    // ABM 3-column views — manage their own internal ABMShell layout
    if (ABM_VIEWS.has(activeView)) {
      switch (activeView) {
        case 'fleet':
          return <DeviceFleetView />;
        case 'serviceprincipals':
          return <ServicePrincipalsView onCreateNew={() => setShowSPWizard(true)} />;
        case 'users':
          return <UsersView onCreateNew={() => setShowUserWizard(true)} />;
      }
    }

    // Standard full-width views wrapped in a scrollable container
    const content = (() => {
      switch (activeView) {
        case 'dashboard':         return <DashboardView />;
        case 'topology':          return <TopologyView />;
        case 'devices':           return <DevicesView />;
        case 'applications':      return <ApplicationsView />;
        case 'infrastructure':    return <InfrastructureView />;
        case 'monitoring':        return <MonitoringView />;
        case 'secrets':           return <SecretsView />;
        case 'security':          return <SecurityView />;
        case 'threats':           return <ThreatDashboardView />;
        case 'printers':          return <PrintersView />;
        case 'policies':          return <PolicyView />;
        case 'automation':        return <AutomationView />;
        case 'identity':          return <IdentityProviderView />;
        case 'enrollment':        return <EnrollmentHubView />;
        case 'permissions':       return <PermissionsView />;
        case 'antivirus':         return <AntivirusView />;
        case 'audit':             return <AuditView />;
        case 'backup':            return <BackupView />;
        case 'appstore':          return <AppStoreView />;
        case 'compliance':        return <ComplianceView />;
        case 'scanner':           return <SecurityScannerView />;
        case 'blueprints':        return <BlueprintsView />;
        case 'sync':              return <SyncView />;
        case 'integrations':      return <IntegrationsView />;
        case 'roadmap':           return <RoadmapView onViewChange={handleViewChange} />;
        case 'pim':               return <PIMView />;
        case 'licenses':          return <LicenseKioskView />;
        case 'mfa':               return <MFAView />;
        case 'sspr':              return <SSPRView />;
        case 'conditionalaccess': return <ConditionalAccessView />;
        case 'alerting':          return <AlertingView />;
        case 'certificates':      return <CertificatesView />;
        case 'ldap-schema':       return <LDAPSchemaBrowserView />;
        case 'radius':            return <RadiusView />;
        case 'servicehealth':     return <ServiceHealthView />;
        case 'trusts':            return <TrustManagementView />;
        case 'kerberos':          return <KerberosAdminView />;
        case 'replication':       return <ReplicationView />;
        case 'graph':             return <GraphExplorerView />;
        case 'simulator':         return <PolicySimulatorView />;
        case 'settings':
          return (
            <div className="p-6">
              <SettingsView enabledModules={enabledModules} onModuleChange={handleModuleChange} />
            </div>
          );
        default:
          return <DashboardView />;
      }
    })();

    return (
      <ContentPage withQuickActions={hasQA} quickActionsProps={hasQA ? quickActionsProps : undefined}>
        {content}
      </ContentPage>
    );
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

      {/* ── Wizard overlays ─────────────────────────────────────────────────── */}
      {showEnrollWizard && (
        <EnrollmentWizard onClose={() => setShowEnrollWizard(false)} />
      )}
      {showUserWizard && (
        <UserOnboardingWizard onClose={() => setShowUserWizard(false)} />
      )}
      {showSPWizard && (
        <ServicePrincipalWizard onClose={() => setShowSPWizard(false)} />
      )}
      {showPolicyWizard && (
        <PolicyDeployWizard onClose={() => setShowPolicyWizard(false)} />
      )}
      {showCompliance && (
        <ComplianceSnapshot
          onClose={() => setShowCompliance(false)}
          onViewChange={handleViewChange}
        />
      )}
    </UnifiLayout>
  );
}
