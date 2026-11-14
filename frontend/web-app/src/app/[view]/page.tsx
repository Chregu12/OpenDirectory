'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useParams, useSearchParams } from 'next/navigation';
import { VALID_VIEWS } from '@/lib/views';
import { api } from '@/lib/api';
import { directoryUsers } from '@/lib/directoryUsers';
import { ensureSession, SessionError } from '@/lib/auth';
import UnifiLayout from '@/components/layout/UnifiLayout';
import CompanyRegistrationReviewsView from '@/components/views/CompanyRegistrationReviewsView';
import CompanyOffboardingAccessView from '@/components/views/CompanyOffboardingAccessView';
import DeviceReturnsView from '@/components/views/DeviceReturnsView';
import CompanyAppsView from '@/components/views/CompanyAppsView';
import EmployeeInvitationManager from '@/components/views/EmployeeInvitationManager';
import ServiceAvailabilityGate from '@/components/shared/ServiceAvailabilityGate';

// ─── Views ────────────────────────────────────────────────────────────────────
import WorkspaceOverview from '@/components/views/WorkspaceOverview';
import DashboardView from '@/components/views/DashboardView';
import TopologyView from '@/components/views/TopologyView';
import CompanyApplicationsView from '@/components/views/CompanyApplicationsView';
import DevicesView from '@/components/views/DeviceInventoryView';
import UsersView from '@/components/views/UsersView';
import InfrastructureView from '@/components/views/InfrastructureView';
import MonitoringView from '@/components/views/MonitoringView';
import SecretsView from '@/components/views/SecretsView';
import SettingsView from '@/components/views/SettingsView';
import PolicyView from '@/components/views/PolicyGovernanceView';
import SecurityView from '@/components/views/SecurityView';
import PrintersView from '@/components/views/PrintersView';
import IdentityProviderView from '@/components/views/IdentityProviderView';
import EnrollmentHubView from '@/components/views/EnrollmentHubView';
import AntivirusView from '@/components/views/AntivirusView';
import AuditView from '@/components/views/AuditView';
import BackupView from '@/components/views/BackupView';
import AppStoreView from '@/components/views/AppStoreView';
import ComplianceView from '@/components/views/ComplianceView';
import SecurityScannerView from '@/components/views/SecurityScannerView';
import BlueprintsView from '@/components/views/BlueprintConfigurationView';
import CompanyBlueprintsView from '@/components/views/CompanyBlueprintsView';
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

// New ABM×UniFi views
import SubscriptionView from '@/components/views/SubscriptionView';
import ActivityView from '@/components/views/ActivityView';
import LocationsView from '@/components/views/LocationsView';
import OrganizationView from '@/components/views/OrganizationView';
import UserGroupsView from '@/components/views/UserGroupsView';
import RolesView from '@/components/views/RolesView';
import CompanyRolesView from '@/components/views/CompanyRolesView';
import AssignmentView from '@/components/views/AssignmentView';
import AppsBooksView from '@/components/views/AppsBooksView';

// Quick actions + wizards
import QuickActionsBar from '@/components/views/QuickActionsBar';
import EnrollmentWizard from '@/components/views/EnrollmentWizard';
import ServicePrincipalWizard from '@/components/views/ServicePrincipalWizard';
import PolicyDeployWizard from '@/components/views/PolicyDeployWizard';
import ComplianceSnapshot from '@/components/views/ComplianceSnapshot';
import OnboardingWizard from '@/components/setup/OnboardingWizard';

// Advanced infrastructure views
import TrustManagementView from '@/components/views/TrustManagementView';
import KerberosAdminView from '@/components/views/KerberosAdminView';
import ReplicationView from '@/components/views/ReplicationView';
import AutomationView from '@/components/views/CompanyAutomationView';

// ─── Placeholder for views not yet implemented ────────────────────────────────

function PlaceholderView({ title }: { title: string }) {
  return (
    <div style={{ padding: '32px 28px', minHeight: '100vh', background: 'var(--bg-base)' }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>{title}</h1>
      <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8 }}>
        This view is under construction.
      </p>
    </div>
  );
}

// ─── Module gating ────────────────────────────────────────────────────────────

const MODULE_NAV_MAP: Record<string, string> = {
  'monitoring-analytics':   'monitoring',
  'secrets-management':     'secrets',
  'device-management':      'devices',
  'network-infrastructure': 'infrastructure',
  'security-suite':         'security',
};

// Views that display the QuickActionsBar
const VIEWS_WITH_QUICK_ACTIONS = new Set(['fleet', 'serviceprincipals']);

// Views that use the ABM 3-column layout (manage their own ABMShell internally)
const ABM_VIEWS = new Set(['fleet', 'serviceprincipals', 'users']);

const EXTENSION_SERVICES: Record<string, [string, string]> = {
  threats: ['security-scanner', 'Bedrohungsanalyse'],
  antivirus: ['antivirus-protection', 'Antivirus'], scanner: ['security-scanner', 'Security Scanner'],
  conditionalaccess: ['conditional-access', 'Conditional Access'], certificates: ['certificate-authority', 'Zertifikate / PKI'],
  compliance: ['compliance-engine', 'Compliance'], printers: ['printer-service', 'Drucker'],
  infrastructure: ['network-infrastructure', 'Netzwerk-Infrastruktur'], radius: ['network-infrastructure', 'RADIUS / 802.1X'],
  secrets: ['vault-integration', 'Secrets'], topology: ['network-infrastructure', 'Netzwerk'],
};

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
    <div className="od-content">
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
  const searchParams = useSearchParams();
  const viewParam = Array.isArray(params.view) ? params.view[0] : (params.view ?? 'dashboard');
  const activeView = VALID_VIEWS.has(viewParam) ? viewParam : 'dashboard';

  const [enabledModules, setEnabledModules] = useState<string[]>(Object.keys(MODULE_NAV_MAP));
  const [currentUser,    setCurrentUser]    = useState<{ name: string; username: string; role: string; roles?: string[] } | null>(null);
  const [authChecked,    setAuthChecked]    = useState(false);
  const [authError, setAuthError] = useState('');
  const [onboarded,      setOnboarded]      = useState(true);
  const [companyOwner, setCompanyOwner] = useState<boolean | null>(null);

  // Wizard / panel open state
  const [showEnrollWizard,  setShowEnrollWizard]  = useState(false);
  const [showSPWizard,      setShowSPWizard]      = useState(false);
  const [showPolicyWizard,  setShowPolicyWizard]  = useState(false);
  const [showCompliance,    setShowCompliance]    = useState(false);

  useEffect(() => {
    let mounted = true;
    const failed = (error: SessionError) => {
      if (!mounted) return;
      setAuthChecked(false); setCurrentUser(null); setAuthError(error.message);
      if (error.status === 401) router.replace('/login');
    };
    const check = () => ensureSession(true).then(session => {
      if (!mounted) return;
      setCurrentUser(session.user); setOnboarded(!!localStorage.getItem('od_onboarded'));
      setAuthError(''); setAuthChecked(true);
    }).catch(failed);
    const onError = (event: Event) => failed((event as CustomEvent<SessionError>).detail);
    const onVisibility = () => { if (document.visibilityState === 'visible') void check(); };
    void check();
    const timer = window.setInterval(check, 30000);
    window.addEventListener('od:session-error', onError);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      mounted = false; window.clearInterval(timer);
      window.removeEventListener('od:session-error', onError);
      document.removeEventListener('visibilitychange', onVisibility);
    };
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

  useEffect(() => {
    let active = true;
    if (authChecked && !onboarded) {
      setCompanyOwner(null);
      directoryUsers.access().then(access => { if (active) setCompanyOwner(access.companyOwner === true); }).catch(() => { if (active) setCompanyOwner(false); });
    }
    return () => { active = false; };
  }, [authChecked, onboarded]);

  const handleViewChange = (view: string) => router.push(`/${view}`);

  const handleModuleChange = (moduleId: string, enabled: boolean) => {
    setEnabledModules(prev => enabled ? [...prev, moduleId] : prev.filter(m => m !== moduleId));
    const navId = MODULE_NAV_MAP[moduleId];
    if (!enabled && navId && activeView === navId) router.push('/dashboard');
  };

  const quickActionsProps = {
    onEnrollDevice:       () => setShowEnrollWizard(true),
    onNewUser:            () => router.push('/users?create=1'),
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
          return <DevicesView selectedDeviceId={searchParams.get('selected')} />;
        case 'serviceprincipals':
          return <ServicePrincipalsView onCreateNew={() => setShowSPWizard(true)} />;
        case 'users':
          return <UsersView selectedUserId={searchParams.get('selected')} createRequested={searchParams.get('create') === '1'} onCreateHandled={() => router.replace('/users')} />;
      }
    }

    // Standard full-width views wrapped in a scrollable container
    const content = (() => {
      switch (activeView) {
        case 'dashboard':         return currentUser?.roles?.includes('admin') ? <DashboardView /> : <WorkspaceOverview />;
        case 'topology':          return <TopologyView />;
        case 'devices':           return <DevicesView selectedDeviceId={searchParams.get('selected')} createRequested={searchParams.get('create') === '1'} onCreateHandled={() => router.replace('/devices')} />;
        case 'applications':      return <CompanyApplicationsView />;
        case 'infrastructure':    return <InfrastructureView />;
        case 'monitoring':        return <MonitoringView />;
        case 'secrets':           return <SecretsView />;
        case 'security':          return <SecurityView />;
        case 'threats':           return <ThreatDashboardView />;
        case 'printers':          return <PrintersView />;
        case 'policies':          return <PolicyView />;
        case 'automation':        return <AutomationView />;
        case 'company-apps':      return <CompanyAppsView />;
        case 'employee-invitations': return <EmployeeInvitationManager />;
        case 'identity':          return <IdentityProviderView />;
        case 'enrollment':        return <EnrollmentHubView />;
        case 'company-roles':      return <CompanyRolesView />;
        case 'permissions':       return <RolesView />;
        case 'antivirus':         return <AntivirusView />;
        case 'audit':             return <AuditView />;
        case 'backup':            return <BackupView />;
        case 'appstore':          return <AppStoreView />;
        case 'compliance':        return <ComplianceView />;
        case 'scanner':           return <SecurityScannerView />;
        case 'blueprints':        return <BlueprintsView />;
        case 'company-blueprints': return <CompanyBlueprintsView />;
        case 'sync':              return <SyncView />;
        case 'integrations':      return <IntegrationsView />;
        case 'roadmap':           return <RoadmapView onViewChange={handleViewChange} />;
        case 'pim':               return <PIMView />;
        case 'licenses':          return <LicenseKioskView createRequested={searchParams.get('create') === '1'} initialProduct={searchParams.get('product') || ''} initialVendor={searchParams.get('vendor') || ''} onCreateHandled={() => router.replace('/licenses')} />;
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
        case 'subscription':      return <SubscriptionView />;
        case 'activity':          return <ActivityView />;
        case 'locations':         return <LocationsView />;
        case 'organization':      return <OrganizationView />;
        case 'registration-reviews': return <CompanyRegistrationReviewsView />;
        case 'usergroups':        return <UserGroupsView />;
        case 'roles':             return <RolesView />;
        case 'offboarding-access': return <CompanyOffboardingAccessView />;
        case 'device-returns': return <DeviceReturnsView />;
        case 'assignment':        return <AssignmentView />;
        case 'appsbooks':         return <AppsBooksView />;
        case 'gpo':               return <PolicyView />;
        case 'settings':
          return (
            <div>
              <SettingsView enabledModules={enabledModules} onModuleChange={handleModuleChange} />
            </div>
          );
        default:
          return <DashboardView />;
      }
    })();

    return (
      <ContentPage withQuickActions={hasQA} quickActionsProps={hasQA ? quickActionsProps : undefined}>
        {EXTENSION_SERVICES[activeView] ? <ServiceAvailabilityGate service={EXTENSION_SERVICES[activeView][0]} label={EXTENSION_SERVICES[activeView][1]}>{content}</ServiceAvailabilityGate> : content}
      </ContentPage>
    );
  };

  if (!authChecked) return <main className="p-8" role="status">{authError || 'Sitzung wird geprüft …'}</main>;

  // Show onboarding wizard overlay when not yet onboarded (except on settings page)
  if (!onboarded && activeView !== 'settings' && activeView !== 'offboarding-access' && activeView !== 'device-returns' && companyOwner === null) return <main className="p-8" role="status">Firmen-Onboarding wird geprüft …</main>;
  if (!onboarded && activeView !== 'settings' && activeView !== 'offboarding-access' && activeView !== 'device-returns' && !companyOwner) {
    return <OnboardingWizard currentUser={currentUser} />;
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
