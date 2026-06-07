'use client';

import React from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';

// ─── Navigation definition ────────────────────────────────────────────────────

export interface NavItemDef {
  id: string;
  label: string;
  icon: string;
  hasList?: boolean;
}

export interface NavDividerDef {
  divider: true;
}

export type NavEntry = NavItemDef | NavDividerDef;

export const NAV_ITEMS: NavEntry[] = [
  { id: 'dashboard',         label: 'Dashboard',          icon: '🏠' },
  { id: 'subscription',      label: 'Subscription',        icon: '💳' },
  { id: 'activity',          label: 'Activity',            icon: '⚡' },
  { id: 'locations',         label: 'Locations',           icon: '📍' },
  { divider: true },
  { id: 'users',             label: 'Users',               icon: '👤', hasList: true },
  { id: 'usergroups',        label: 'User Groups',         icon: '👥' },
  { id: 'roles',             label: 'Roles',               icon: '🎭' },
  { id: 'permissions',       label: 'Privileges',          icon: '🔐' },
  { id: 'pim',               label: 'Privileged Access',   icon: '🛡' },
  { id: 'mfa',               label: 'MFA / 2FA',           icon: '🔒' },
  { id: 'sspr',              label: 'Password Reset',      icon: '↩' },
  { id: 'identity',          label: 'Identity Provider',   icon: '🪪' },
  { id: 'sync',              label: 'Directory Sync',      icon: '🔄' },
  { divider: true },
  { id: 'fleet',             label: 'Devices',             icon: '💻', hasList: true },
  { id: 'enrollment',        label: 'Enrollment',          icon: '📲' },
  { id: 'assignment',        label: 'Assignment History',  icon: '📋' },
  { id: 'blueprints',        label: 'Blueprints',          icon: '🗂' },
  { id: 'antivirus',         label: 'Antivirus',           icon: '🛡' },
  { id: 'printers',          label: 'Printers',            icon: '🖨' },
  { divider: true },
  { id: 'serviceprincipals', label: 'Service Principals',  icon: '🔑', hasList: true },
  { id: 'appsbooks',         label: 'Apps and Books',      icon: '📚' },
  { id: 'appstore',          label: 'App Store',           icon: '🛍' },
  { id: 'licenses',          label: 'License Kiosk',       icon: '🏷' },
  { id: 'applications',      label: 'Applications',        icon: '📦' },
  { divider: true },
  { id: 'compliance',        label: 'Compliance',          icon: '✅' },
  { id: 'conditionalaccess', label: 'Conditional Access',  icon: '🔐' },
  { id: 'certificates',      label: 'Certificates / PKI',  icon: '📜' },
  { id: 'scanner',           label: 'Security Scanner',    icon: '🔍' },
  { id: 'security',          label: 'Security',            icon: '🛡' },
  { id: 'threats',           label: 'Threats',             icon: '🐛' },
  { id: 'secrets',           label: 'Secrets',             icon: '🔏' },
  { divider: true },
  { id: 'gpo',               label: 'Group Policy',        icon: '📋' },
  { id: 'policies',          label: 'Policies',            icon: '📄' },
  { id: 'audit',             label: 'Audit Log',           icon: '🔍' },
  { id: 'monitoring',        label: 'Monitoring',          icon: '📊' },
  { id: 'alerting',          label: 'Alerts',              icon: '🔔' },
  { id: 'servicehealth',     label: 'Service Health',      icon: '💓' },
  { id: 'backup',            label: 'Backup & DR',         icon: '🗄' },
  { id: 'topology',          label: 'Network',             icon: '🌐' },
  { id: 'infrastructure',    label: 'Infrastructure',      icon: '🖥' },
  { id: 'radius',            label: 'RADIUS / 802.1X',     icon: '📡' },
  { id: 'trusts',            label: 'Forest & Trusts',     icon: '🌐' },
  { id: 'kerberos',          label: 'Kerberos Admin',      icon: '🎫' },
  { id: 'replication',       label: 'Replication',         icon: '🔄' },
  { divider: true },
  { id: 'integrations',      label: 'Integrations',        icon: '🔌' },
  { id: 'roadmap',           label: 'Roadmap',             icon: '🚀' },
  { id: 'settings',          label: 'Settings',            icon: '⚙' },
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
          background: '#F5F5F7',
          borderRight: '1px solid var(--apple-gray-2)',
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
            borderBottom: '1px solid var(--apple-gray-2)',
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
              background: 'var(--apple-blue)',
              borderRadius: 8,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <span style={{ color: 'white', fontWeight: 700, fontSize: 12 }}>OD</span>
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <p
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: 'var(--apple-text-primary)',
                lineHeight: 1.2,
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              OpenDirectory
            </p>
            <p style={{ fontSize: 11, color: 'var(--apple-text-secondary)', lineHeight: 1.2 }}>
              opendirectory.local
            </p>
          </div>
          <button
            onClick={onMobileClose}
            className="lg:hidden"
            style={{ color: 'var(--apple-gray-5)', padding: 4, flexShrink: 0 }}
          >
            <XMarkIcon style={{ width: 18, height: 18 }} />
          </button>
        </div>

        {/* Navigation list */}
        <nav style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
          {visibleItems.map((entry, idx) => {
            if ('divider' in entry) {
              return (
                <div
                  key={`divider-${idx}`}
                  style={{
                    height: 1,
                    background: 'var(--apple-gray-2)',
                    margin: '6px 12px',
                  }}
                />
              );
            }

            const isActive = activeView === entry.id;
            return (
              <button
                key={entry.id}
                onClick={() => handleItemClick(entry.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  width: 'calc(100% - 12px)',
                  padding: '6px 12px',
                  margin: '1px 6px',
                  fontSize: 13,
                  fontWeight: isActive ? 500 : 400,
                  textAlign: 'left',
                  background: isActive ? 'var(--apple-blue)' : 'transparent',
                  color: isActive ? '#ffffff' : 'var(--apple-text-primary)',
                  border: 'none',
                  borderRadius: 7,
                  cursor: 'pointer',
                  transition: 'background 0.12s, color 0.12s',
                  boxSizing: 'border-box',
                }}
                onMouseEnter={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,0,0,0.06)';
                  }
                }}
                onMouseLeave={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLButtonElement).style.background = 'transparent';
                  }
                }}
              >
                <span style={{ fontSize: 14, flexShrink: 0, lineHeight: 1, width: 18, textAlign: 'center' }}>
                  {entry.icon}
                </span>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {entry.label}
                </span>
              </button>
            );
          })}
        </nav>

        {/* User footer */}
        <div
          style={{
            padding: '12px 14px',
            borderTop: '1px solid var(--apple-gray-2)',
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            flexShrink: 0,
          }}
        >
          <div
            style={{
              width: 30,
              height: 30,
              borderRadius: '50%',
              background: 'var(--apple-blue)',
              color: 'white',
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
                color: 'var(--apple-text-primary)',
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
                color: 'var(--apple-text-secondary)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {currentUser?.role ?? 'Admin'}
            </p>
          </div>
        </div>
      </aside>
    </>
  );
}
