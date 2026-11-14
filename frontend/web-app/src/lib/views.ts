import type { ComponentType, SVGProps } from 'react';
import type { DirectoryAccess } from './directoryUsers';
import { DocumentTextIcon, ArchiveBoxIcon, ArrowDownOnSquareStackIcon, ArrowPathIcon, ArrowUturnLeftIcon, BellAlertIcon, BoltIcon, BugAntIcon, BuildingOfficeIcon, ChartBarIcon, ClipboardDocumentCheckIcon, ClipboardDocumentListIcon, Cog6ToothIcon, ComputerDesktopIcon, CubeIcon, DevicePhoneMobileIcon, DocumentCheckIcon, FingerPrintIcon, FlagIcon, FunnelIcon, HomeIcon, KeyIcon, LockClosedIcon, MagnifyingGlassCircleIcon, PrinterIcon, PuzzlePieceIcon, RectangleGroupIcon, RectangleStackIcon, ServerStackIcon, ShieldCheckIcon, ShieldExclamationIcon, ShoppingBagIcon, SignalIcon, TagIcon, UserGroupIcon, WifiIcon } from '@heroicons/react/24/outline';

export const NAVIGATION_GROUPS = ['Übersicht', 'Unternehmen & Personen', 'Geräte', 'Apps & Lizenzen', 'Blueprints', 'Automatisierung & Integrationen', 'Administration'] as const;
export interface ViewDefinition {
  id: string;
  name: string;
  group: typeof NAVIGATION_GROUPS[number];
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  keywords: string[];
  module?: string;
  service?: string;
  audience: 'self' | 'permissions' | 'owner' | 'owner-or-admin' | 'platform';
  permissions?: string[];
  roles?: string[];
  navigation?: boolean;
  canonical?: string;
}

// Presentation only. Every read and action still uses its canonical server authority.
export const VIEWS: ViewDefinition[] = [
  { id: 'dashboard', name: 'Übersicht', group: 'Übersicht', icon: HomeIcon, keywords: ['Dashboard', 'dashboard'], audience: 'self' },
  { id: 'organization', name: 'Organisation', group: 'Unternehmen & Personen', icon: BuildingOfficeIcon, keywords: ['Organisation', 'organization'], audience: 'permissions', permissions: ['organization.read', 'ous.read'] },
  { id: 'registration-reviews', name: 'Firmenprüfung', group: 'Administration', icon: DocumentCheckIcon, keywords: ['Firmenprüfung', 'registration-reviews'], audience: 'permissions', permissions: ['company.registrations.review'] },
  { id: 'users', name: 'Mitarbeitende', group: 'Unternehmen & Personen', icon: UserGroupIcon, keywords: ['Benutzer', 'users'], audience: 'permissions', permissions: ['users.read', 'users.create', 'users.sessions.invalidate'] },
  { id: 'employee-invitations', name: 'Einladungen', group: 'Unternehmen & Personen', icon: UserGroupIcon, keywords: ['Mitarbeitereinladungen', 'employee-invitations'], audience: 'owner' },
  { id: 'usergroups', name: 'Gruppen', group: 'Unternehmen & Personen', icon: UserGroupIcon, keywords: ['Gruppen', 'usergroups'], audience: 'permissions', permissions: ['groups.read', 'groups.create'] },
  { id: 'company-roles', name: 'Firmenrollen', group: 'Administration', icon: KeyIcon, keywords: ['Firmenrollen', 'company-roles', 'Bereiche', 'OU-Rechte'], audience: 'permissions', permissions: ['company.roles.read'] },
  { id: 'permissions', name: 'Rollen & Rechte', group: 'Administration', icon: KeyIcon, keywords: ['Rollen & Rechte', 'permissions'], audience: 'permissions', permissions: ['identities.roles.read'] },
  { id: 'pim', name: 'PIM', group: 'Administration', icon: ShieldCheckIcon, keywords: ['PIM', 'pim'], audience: 'self' },
  { id: 'offboarding-access', name: 'Offboarding: Rollen & PIM', group: 'Unternehmen & Personen', icon: KeyIcon, keywords: ['Austritt: Rollen & PIM', 'offboarding-access'], audience: 'permissions', permissions: ['identities.roles.read', 'pim.eligibilities.read'] },
  { id: 'mfa', name: 'MFA / 2FA', group: 'Administration', icon: DevicePhoneMobileIcon, keywords: ['MFA / 2FA', 'mfa'], audience: 'self' },
  { id: 'sspr', name: 'Passwort zurücksetzen', group: 'Administration', icon: ArrowUturnLeftIcon, keywords: ['Passwort-Reset', 'sspr'], audience: 'self' },
  { id: 'identity', name: 'Identitätsanbieter', group: 'Administration', icon: FingerPrintIcon, keywords: ['Identity Provider', 'identity'], audience: 'platform' },
  { id: 'sync', name: 'Verzeichnis-Sync', group: 'Automatisierung & Integrationen', icon: ArrowPathIcon, keywords: ['Verzeichnis-Sync', 'sync'], audience: 'platform' },
  { id: 'devices', name: 'Geräte', group: 'Geräte', icon: ComputerDesktopIcon, keywords: ['Geräte', 'devices'], audience: 'owner-or-admin', roles: ['device-enrollment-operator'], module: 'device-management' },
  { id: 'device-returns', name: 'Geräterückgaben', group: 'Geräte', icon: ArrowUturnLeftIcon, keywords: ['Geräterückgaben', 'device-returns'], audience: 'owner-or-admin', roles: ['device-enrollment-operator'] },
  { id: 'enrollment', name: 'Enrollment', group: 'Geräte', icon: ArrowDownOnSquareStackIcon, keywords: ['Enrollment', 'enrollment'], audience: 'platform', service: 'quick-actions' },
  { id: 'blueprints', name: 'Plattform-Blueprints', group: 'Blueprints', icon: RectangleStackIcon, keywords: ['Blueprints', 'blueprints'], audience: 'platform', roles: ['policy-reader', 'policy-administrator', 'policy-deployment-operator', 'policy-publication-reviewer'] },
  { id: 'company-blueprints', name: 'Firmen-Blueprints', group: 'Blueprints', icon: RectangleStackIcon, keywords: ['Firmen-Blueprints', 'company-blueprints'], audience: 'owner-or-admin' },
  { id: 'printers', name: 'Drucker', group: 'Geräte', icon: PrinterIcon, keywords: ['Drucker', 'printers'], audience: 'platform', module: 'device-management', service: 'printer-service' },
  { id: 'applications', name: 'Apps & Lizenzen', group: 'Apps & Lizenzen', icon: CubeIcon, keywords: ['Anwendungen', 'applications'], audience: 'owner-or-admin' },
  { id: 'appstore', name: 'App Store', group: 'Apps & Lizenzen', icon: ShoppingBagIcon, keywords: ['App Store', 'appstore'], audience: 'platform', service: 'app-store' },
  { id: 'licenses', name: 'Lizenzverwaltung', group: 'Apps & Lizenzen', icon: TagIcon, keywords: ['Lizenz-Kiosk', 'licenses'], audience: 'permissions', permissions: ['licenses.users.read', 'licenses.groups.read'] },
  { id: 'monitoring', name: 'Monitoring', group: 'Administration', icon: ChartBarIcon, keywords: ['Monitoring', 'monitoring'], audience: 'platform', module: 'monitoring-analytics' },
  { id: 'servicehealth', name: 'Dienstzustand', group: 'Administration', icon: SignalIcon, keywords: ['Service Health', 'servicehealth'], audience: 'platform' },
  { id: 'audit', name: 'Audit Log', group: 'Administration', icon: ClipboardDocumentListIcon, keywords: ['Audit Log', 'audit'], audience: 'platform' },
  { id: 'alerting', name: 'Benachrichtigungen', group: 'Administration', icon: BellAlertIcon, keywords: ['Benachrichtigungen', 'alerting'], audience: 'platform' },
  { id: 'integrations', name: 'Integrationen', group: 'Automatisierung & Integrationen', icon: PuzzlePieceIcon, keywords: ['Integrationen', 'integrations'], audience: 'platform' },
  { id: 'backup', name: 'Sicherung & Wiederherstellung', group: 'Administration', icon: ArchiveBoxIcon, keywords: ['Backup & DR', 'backup'], audience: 'platform' },
  { id: 'settings', name: 'Einstellungen', group: 'Administration', icon: Cog6ToothIcon, keywords: ['Einstellungen', 'settings'], audience: 'platform', roles: ['gateway-administrator', 'gateway-key-administrator', 'gateway-webhook-administrator'] },
  { id: 'topology', name: 'Netzwerk', group: 'Administration', icon: RectangleGroupIcon, keywords: ['Netzwerk', 'topology'], audience: 'platform', service: 'network-infrastructure' },
  { id: 'infrastructure', name: 'Infrastruktur', group: 'Administration', icon: ServerStackIcon, keywords: ['Infrastruktur', 'infrastructure'], audience: 'platform', module: 'network-infrastructure', service: 'network-infrastructure' },
  { id: 'radius', name: 'RADIUS / 802.1X', group: 'Administration', icon: WifiIcon, keywords: ['RADIUS / 802.1X', 'radius'], audience: 'platform', service: 'network-infrastructure' },
  { id: 'security', name: 'Security', group: 'Administration', icon: ShieldExclamationIcon, keywords: ['Security', 'security'], audience: 'platform', module: 'security-suite' },
  { id: 'antivirus', name: 'Antivirus', group: 'Administration', icon: BugAntIcon, keywords: ['Antivirus', 'antivirus'], audience: 'platform', service: 'antivirus-protection' },
  { id: 'conditionalaccess', name: 'Conditional Access', group: 'Administration', icon: FunnelIcon, keywords: ['Conditional Access', 'conditionalaccess'], audience: 'platform', service: 'conditional-access' },
  { id: 'certificates', name: 'Zertifikate / PKI', group: 'Administration', icon: DocumentCheckIcon, keywords: ['Zertifikate / PKI', 'certificates'], audience: 'platform', service: 'certificate-authority' },
  { id: 'compliance', name: 'Compliance', group: 'Administration', icon: ClipboardDocumentCheckIcon, keywords: ['Compliance', 'compliance'], audience: 'platform', service: 'compliance-engine' },
  { id: 'scanner', name: 'Security Scanner', group: 'Administration', icon: MagnifyingGlassCircleIcon, keywords: ['Security Scanner', 'scanner'], audience: 'platform', service: 'security-scanner' },
  { id: 'secrets', name: 'Secrets', group: 'Administration', icon: LockClosedIcon, keywords: ['Secrets', 'secrets'], audience: 'platform', module: 'secrets-management', service: 'vault-integration' },
  { id: 'roadmap', name: 'Roadmap & TODO', group: 'Administration', icon: FlagIcon, keywords: ['Roadmap & TODO', 'roadmap'], audience: 'platform', navigation: false },
  { id: 'policies', name: 'Richtlinien', group: 'Blueprints', icon: DocumentTextIcon, keywords: ['Richtlinien', 'policies'], audience: 'permissions', permissions: ['policies.publication-actors.read'], roles: ['policy-reader', 'policy-administrator', 'policy-deployment-operator', 'policy-publication-reviewer'] },
  { id: 'company-apps', name: 'Firmen-App-Konten', group: 'Automatisierung & Integrationen', icon: KeyIcon, keywords: ['Firmen-App-Konten', 'company-apps'], audience: 'owner' },
  { id: 'automation', name: 'Automationen', group: 'Automatisierung & Integrationen', icon: BoltIcon, keywords: ['Automationen', 'automation'], audience: 'owner' },
  { id: 'fleet', canonical: 'devices', name: 'Erweiterte Geräteansicht', group: 'Administration', icon: Cog6ToothIcon, keywords: ['fleet'], audience: 'platform', navigation: false },
  { id: 'serviceprincipals', name: 'Service Principals', group: 'Administration', icon: Cog6ToothIcon, keywords: ['serviceprincipals'], audience: 'platform', navigation: false },
  { id: 'subscription', name: 'Abonnement', group: 'Administration', icon: Cog6ToothIcon, keywords: ['subscription'], audience: 'platform', navigation: false },
  { id: 'activity', name: 'Aktivitäten', group: 'Administration', icon: Cog6ToothIcon, keywords: ['activity'], audience: 'platform', navigation: false },
  { id: 'locations', name: 'Standorte', group: 'Administration', icon: Cog6ToothIcon, keywords: ['locations'], audience: 'platform', navigation: false },
  { id: 'roles', canonical: 'permissions', name: 'Rollen & Rechte', group: 'Administration', icon: Cog6ToothIcon, keywords: ['roles'], audience: 'platform', navigation: false },
  { id: 'assignment', canonical: 'devices', name: 'Zuweisungshistorie', group: 'Administration', icon: Cog6ToothIcon, keywords: ['assignment'], audience: 'platform', navigation: false },
  { id: 'appsbooks', name: 'Apps und Bücher', group: 'Administration', icon: Cog6ToothIcon, keywords: ['appsbooks'], audience: 'platform', navigation: false },
  { id: 'gpo', canonical: 'policies', name: 'Gruppenrichtlinien', group: 'Administration', icon: Cog6ToothIcon, keywords: ['gpo'], audience: 'platform', navigation: false },
  { id: 'ldap-schema', name: 'LDAP-Schema', group: 'Administration', icon: Cog6ToothIcon, keywords: ['ldap-schema'], audience: 'platform', navigation: false },
  { id: 'trusts', name: 'Vertrauensstellungen', group: 'Administration', icon: Cog6ToothIcon, keywords: ['trusts'], audience: 'platform', navigation: false },
  { id: 'kerberos', name: 'Kerberos', group: 'Administration', icon: Cog6ToothIcon, keywords: ['kerberos'], audience: 'platform', navigation: false },
  { id: 'replication', name: 'Replikation', group: 'Administration', icon: Cog6ToothIcon, keywords: ['replication'], audience: 'platform', navigation: false },
  { id: 'graph', name: 'Objektgraph', group: 'Administration', icon: Cog6ToothIcon, keywords: ['graph'], audience: 'platform', navigation: false },
  { id: 'simulator', name: 'Richtliniensimulation', group: 'Administration', icon: Cog6ToothIcon, keywords: ['simulator'], audience: 'platform', navigation: false },
  { id: 'threats', name: 'Bedrohungen', group: 'Administration', icon: Cog6ToothIcon, keywords: ['threats'], audience: 'platform', navigation: false },
];
export const VIEW_BY_ID = Object.fromEntries(VIEWS.map(view => [view.id, view]));
export const VALID_VIEWS = new Set(VIEWS.map(view => view.id));
export interface NavigationContext {
  access: DirectoryAccess | null;
  platformAdmin: boolean;
  roles?: string[];
  enabledModules?: string[];
  configuredServices: string[] | null;
}
export function visibleViews(context: NavigationContext) {
  return VIEWS.filter(view => {
    if (view.navigation === false) return false;
    if (view.module && context.enabledModules && !context.enabledModules.includes(view.module)) return false;
    if (view.service && context.configuredServices && !context.configuredServices.includes(view.service)) return false;
    if (view.audience === 'self') return true;
    if (!context.access || context.access.demoMode || !context.access.userId) return false;
    if (view.audience === 'owner') return context.access.companyOwner === true;
    if (view.audience === 'owner-or-admin') return context.access.companyOwner === true || context.platformAdmin || view.roles?.some(role => context.roles?.includes(role)) === true;
    if (view.audience === 'permissions') return view.permissions?.some(permission => context.access!.permissions.includes(permission)) === true || view.roles?.some(role => context.roles?.includes(role)) === true;
    return context.platformAdmin || view.roles?.some(role => context.roles?.includes(role)) === true;
  });
}
