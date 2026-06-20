'use client';

import React from 'react';
import {
  HomeIcon, CreditCardIcon, BoltIcon, MapPinIcon,
  UserIcon, UsersIcon, ShieldCheckIcon, KeyIcon,
  ShieldExclamationIcon, LockClosedIcon, ArrowPathIcon,
  IdentificationIcon, ArrowsRightLeftIcon,
  ComputerDesktopIcon, DevicePhoneMobileIcon,
  ClipboardDocumentListIcon, DocumentDuplicateIcon,
  PrinterIcon, ShoppingBagIcon, TagIcon, CubeIcon,
  BookOpenIcon, CheckBadgeIcon, LockOpenIcon,
  DocumentTextIcon, CircleStackIcon, MagnifyingGlassIcon,
  ExclamationTriangleIcon, DocumentIcon, DocumentCheckIcon,
  ChartBarIcon, BellIcon, HeartIcon, ArchiveBoxIcon,
  GlobeAltIcon, ServerIcon, SignalIcon, TicketIcon,
  PuzzlePieceIcon, RocketLaunchIcon, BeakerIcon,
  SparklesIcon, Cog6ToothIcon, XMarkIcon,
} from '@heroicons/react/24/outline';
import { useTheme } from '@/hooks/useTheme';

// ─── Navigation definition ────────────────────────────────────────────────────

export interface NavItemDef {
  id: string;
  label: string;
  icon: React.FC<React.SVGProps<SVGSVGElement>>;
  hasList?: boolean;
}

export interface NavDividerDef {
  divider: true;
}

export type NavEntry = NavItemDef | NavDividerDef;

export const NAV_ITEMS: NavEntry[] = [
  { id: 'dashboard',         label: 'Dashboard',          icon: HomeIcon },
  { id: 'subscription',      label: 'Subscription',        icon: CreditCardIcon },
  { id: 'activity',          label: 'Activity',            icon: BoltIcon },
  { id: 'locations',         label: 'Locations',           icon: MapPinIcon },
  { divider: true },
  { id: 'users',             label: 'Users',               icon: UserIcon, hasList: true },
  { id: 'usergroups',        label: 'User Groups',         icon: UsersIcon },
  { id: 'roles',             label: 'Roles',               icon: ShieldCheckIcon },
  { id: 'permissions',       label: 'Privileges',          icon: KeyIcon },
  { id: 'pim',               label: 'Privileged Access',   icon: ShieldExclamationIcon },
  { id: 'mfa',               label: 'MFA / 2FA',           icon: LockClosedIcon },
  { id: 'sspr',              label: 'Password Reset',      icon: ArrowPathIcon },
  { id: 'identity',          label: 'Identity Provider',   icon: IdentificationIcon },
  { id: 'sync',              label: 'Directory Sync',      icon: ArrowsRightLeftIcon },
  { divider: true },
  { id: 'fleet',             label: 'Devices',             icon: ComputerDesktopIcon, hasList: true },
  { id: 'enrollment',        label: 'Enrollment',          icon: DevicePhoneMobileIcon },
  { id: 'assignment',        label: 'Assignment History',  icon: ClipboardDocumentListIcon },
  { id: 'blueprints',        label: 'Blueprints',          icon: DocumentDuplicateIcon },
  { id: 'antivirus',         label: 'Antivirus',           icon: ShieldCheckIcon },
  { id: 'printers',          label: 'Printers',            icon: PrinterIcon },
  { divider: true },
  { id: 'serviceprincipals', label: 'Service Principals',  icon: KeyIcon, hasList: true },
  { id: 'appsbooks',         label: 'Apps and Books',      icon: BookOpenIcon },
  { id: 'appstore',          label: 'App Store',           icon: ShoppingBagIcon },
  { id: 'licenses',          label: 'License Kiosk',       icon: TagIcon },
  { id: 'applications',      label: 'Applications',        icon: CubeIcon },
  { divider: true },
  { id: 'compliance',        label: 'Compliance',          icon: CheckBadgeIcon },
  { id: 'conditionalaccess', label: 'Conditional Access',  icon: LockOpenIcon },
  { id: 'certificates',      label: 'Certificates / PKI',  icon: DocumentTextIcon },
  { id: 'ldap-schema',       label: 'LDAP Schema',         icon: CircleStackIcon },
  { id: 'scanner',           label: 'Security Scanner',    icon: MagnifyingGlassIcon },
  { id: 'security',          label: 'Security',            icon: ShieldCheckIcon },
  { id: 'threats',           label: 'Threats',             icon: ExclamationTriangleIcon },
  { id: 'secrets',           label: 'Secrets',             icon: LockClosedIcon },
  { divider: true },
  { id: 'gpo',               label: 'Group Policy',        icon: DocumentCheckIcon },
  { id: 'policies',          label: 'Policies',            icon: DocumentIcon },
  { id: 'automation',        label: 'Automation',          icon: BoltIcon },
  { id: 'audit',             label: 'Audit Log',           icon: MagnifyingGlassIcon },
  { id: 'monitoring',        label: 'Monitoring',          icon: ChartBarIcon },
  { id: 'alerting',          label: 'Alerts',              icon: BellIcon },
  { id: 'servicehealth',     label: 'Service Health',      icon: HeartIcon },
  { id: 'backup',            label: 'Backup & DR',         icon: ArchiveBoxIcon },
  { id: 'topology',          label: 'Network',             icon: GlobeAltIcon },
  { id: 'infrastructure',    label: 'Infrastructure',      icon: ServerIcon },
  { id: 'radius',            label: 'RADIUS / 802.1X',     icon: SignalIcon },
  { id: 'trusts',            label: 'Forest & Trusts',     icon: GlobeAltIcon },
  { id: 'kerberos',          label: 'Kerberos Admin',      icon: TicketIcon },
  { id: 'replication',       label: 'Replication',         icon: ArrowPathIcon },
  { divider: true },
  { id: 'integrations',      label: 'Integrations',        icon: PuzzlePieceIcon },
  { id: 'roadmap',           label: 'Roadmap',             icon: RocketLaunchIcon },
  { id: 'simulator',         label: 'Policy Simulator',    icon: BeakerIcon },
  { id: 'graph',             label: 'Graph Explorer',      icon: SparklesIcon },
  { id: 'settings',          label: 'Settings',            icon: Cog6ToothIcon },
];

// ─── Module gating ────────────────────────────────────────────────────────────

const NAV_REQUIRED_MODULE: Record<string, string> = {
  monitoring:     'monitoring-analytics',
  secrets:        'secrets-management',
  devices:        'device-management',
  printers:       'device-management',
  infrastructure: 'network-infrastructure',
  security:       'security-suite',
};

// ─── Helper ───────────────────────────────────────────────────────────────────

function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

// ─── Sidebar component ────────────────────────────────────────────────────────

interface SidebarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  enabledModules?: string[];
  currentUser?: { name: string; role: string } | null;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export default function Sidebar({
  activeView,
  onViewChange,
  enabledModules,
  currentUser,
  mobileOpen,
  onMobileClose,
}: SidebarProps) {
  const { theme, toggleTheme } = useTheme();
  const userInitials = currentUser?.name ? getInitials(currentUser.name) : 'OD';

  // Filter items by module availability
  const visibleItems = NAV_ITEMS.filter(entry => {
    if ('divider' in entry) return true;
    const required = NAV_REQUIRED_MODULE[entry.id];
    if (!required) return true;
    if (!enabledModules || enabledModules.length === 0) return true;
    return enabledModules.includes(required);
  });

  const handleItemClick = (id: string) => {
    onViewChange(id);
    onMobileClose();
  };

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 lg:hidden"
          style={{ background: 'rgba(0,0,0,0.4)' }}
          onClick={onMobileClose}
        />
      )}

      {/* Sidebar panel */}
      <aside
        className={`${mobileOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          bottom: 0,
          width: 'var(--apple-sidebar-width)',
          background: 'var(--bg-sidebar)',
          borderRight: '1px solid var(--border-color)',
          zIndex: 50,
          transition: 'transform 0.3s ease',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Org header / logo */}
        <div
          style={{
            height: 'var(--apple-topbar-height)',
            borderBottom: '1px solid var(--border-color)',
            padding: '0 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            flexShrink: 0,
          }}
        >
          <div
            style={{
              width: 32,
              height: 32,
              background: 'var(--accent-blue)',
              borderRadius: 4,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <span style={{ color: 'var(--text-on-accent)', fontWeight: 700, fontSize: 12 }}>OD</span>
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <p
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: 'var(--text-primary)',
                lineHeight: 1.2,
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              OpenDirectory
            </p>
            <p style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.2 }}>
              opendirectory.local
            </p>
          </div>
          <button
            onClick={onMobileClose}
            aria-label="Close sidebar"
            className="lg:hidden"
            style={{ color: 'var(--text-secondary)', padding: 4, flexShrink: 0, background: 'none', border: 'none', cursor: 'pointer' }}
          >
            <XMarkIcon style={{ width: 18, height: 18 }} />
          </button>
        </div>

        {/* Navigation list */}
        <nav role="navigation" aria-label="Main navigation" style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
          {visibleItems.map((entry, idx) => {
            if ('divider' in entry) {
              return (
                <div
                  key={`divider-${idx}`}
                  style={{ height: 1, background: 'rgba(255,255,255,0.1)', margin: '4px 12px' }}
                />
              );
            }

            const isActive = activeView === entry.id;
            return (
              <button
                key={entry.id}
                onClick={() => handleItemClick(entry.id)}
                aria-current={isActive ? 'page' : undefined}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  width: 'calc(100% - 16px)',
                  margin: '1px 8px',
                  padding: '6px 10px',
                  background: isActive ? 'var(--apple-blue)' : 'transparent',
                  border: 'none',
                  borderRadius: 7,
                  cursor: 'pointer',
                  fontSize: 13,
                  fontWeight: isActive ? 600 : 400,
                  color: isActive ? '#ffffff' : 'rgba(255,255,255,0.75)',
                  textAlign: 'left',
                  transition: 'background 0.15s',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
                onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.08)'; }}
                onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
              >
                <entry.icon style={{ width: 16, height: 16, flexShrink: 0 }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{entry.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Dark mode toggle + user footer */}
        <div
          style={{
            borderTop: '1px solid var(--border-color)',
            flexShrink: 0,
          }}
        >
          {/* Theme toggle */}
          <div style={{ padding: '8px 14px 0' }}>
            <button
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                width: '100%',
                padding: '6px 12px',
                fontSize: 12,
                color: 'var(--text-secondary)',
                background: 'none',
                border: 'none',
                borderRadius: 'var(--border-radius)',
                cursor: 'pointer',
              }}
            >
              {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
            </button>
          </div>
          {/* User info */}
          <div
            style={{
              padding: '8px 14px 12px',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <div
              style={{
                width: 30,
                height: 30,
                borderRadius: '50%',
                background: 'var(--accent-blue)',
                color: 'var(--text-on-accent)',
                fontSize: 11,
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              {userInitials}
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <p
                style={{
                  fontSize: 12,
                  fontWeight: 500,
                  color: 'var(--text-primary)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {currentUser?.name ?? 'Administrator'}
              </p>
              <p
                style={{
                  fontSize: 11,
                  color: 'var(--text-secondary)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {currentUser?.role ?? 'Admin'}
              </p>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
