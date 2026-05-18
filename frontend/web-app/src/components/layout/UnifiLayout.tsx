'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { api, authApi } from '@/lib/api';
import { Toaster } from 'react-hot-toast';
import {
  HomeIcon,
  ComputerDesktopIcon,
  Cog6ToothIcon,
  ChartBarIcon,
  BellIcon,
  MagnifyingGlassIcon,
  Bars3Icon,
  XMarkIcon,
  UserGroupIcon,
  WifiIcon,
  PrinterIcon,
  DocumentTextIcon,
  LockClosedIcon,
  ShieldExclamationIcon,
  FingerPrintIcon,
  ArrowDownOnSquareStackIcon,
  KeyIcon,
  BugAntIcon,
  ClipboardDocumentListIcon,
  ArchiveBoxIcon,
  ShoppingBagIcon,
  ClipboardDocumentCheckIcon,
  CubeIcon,
  RectangleGroupIcon,
  MagnifyingGlassCircleIcon,
  ServerStackIcon,
} from '@heroicons/react/24/outline';

// ─── Search catalog ───────────────────────────────────────────────────────────
type SearchItem = { id: string; name: string; view: string; type: string };

const SEARCH_ITEMS: SearchItem[] = [
  { id: 'dashboard',    name: 'Dashboard',           view: 'dashboard',    type: 'Seite' },
  { id: 'devices',      name: 'Geräte',              view: 'devices',      type: 'Seite' },
  { id: 'users',        name: 'Benutzer',            view: 'users',        type: 'Seite' },
  { id: 'policies',     name: 'Richtlinien',         view: 'policies',     type: 'Seite' },
  { id: 'applications', name: 'Anwendungen',         view: 'applications', type: 'Seite' },
  { id: 'security',     name: 'Sicherheit',          view: 'security',     type: 'Seite' },
  { id: 'identity',     name: 'Identity Provider',   view: 'identity',     type: 'Seite' },
  { id: 'enrollment',   name: 'Enrollment Hub',      view: 'enrollment',   type: 'Seite' },
  { id: 'monitoring',   name: 'Monitoring',          view: 'monitoring',   type: 'Seite' },
  { id: 'secrets',      name: 'Secrets',             view: 'secrets',      type: 'Seite' },
  { id: 'printers',     name: 'Drucker',             view: 'printers',     type: 'Seite' },
  { id: 'permissions',  name: 'Berechtigungen',      view: 'permissions',  type: 'Seite' },
  { id: 'antivirus',    name: 'Antivirus',           view: 'antivirus',    type: 'Seite' },
  { id: 'audit',        name: 'Audit Log',           view: 'audit',        type: 'Seite' },
  { id: 'backup',       name: 'Backup & DR',         view: 'backup',       type: 'Seite' },
  { id: 'appstore',     name: 'App Store',           view: 'appstore',     type: 'Seite' },
  { id: 'compliance',   name: 'Compliance',          view: 'compliance',   type: 'Seite' },
  { id: 'scanner',      name: 'Security Scanner',    view: 'scanner',      type: 'Seite' },
];

// ─── Notifications ────────────────────────────────────────────────────────────
interface Notification {
  id: string;
  title: string;
  message?: string;
  time: string;
  read: boolean;
  type: 'enrollment' | 'compliance' | 'pim' | 'security' | 'warning' | 'info';
}

const NOTIF_COLOR: Record<Notification['type'], string> = {
  enrollment: 'bg-blue-400',
  compliance: 'bg-orange-400',
  pim:        'bg-purple-400',
  security:   'bg-red-500',
  warning:    'bg-orange-400',
  info:       'bg-blue-400',
};

interface LayoutProps {
  children: React.ReactNode;
  activeView: string;
  onViewChange: (view: string) => void;
  enabledModules?: string[];
  currentUser?: { name: string; role: string } | null;
}

type NavItem =
  | { type: 'item'; id: string; name: string; icon: React.ComponentType<{ className?: string }> }
  | { type: 'section'; label: string };

// Nav items that require a specific module to be enabled
const NAV_REQUIRED_MODULE: Record<string, string> = {
  monitoring:     'monitoring-analytics',
  secrets:        'secrets-management',
  devices:        'device-management',
  printers:       'device-management',
  infrastructure: 'network-infrastructure',
  security:       'security-suite',
};

// Get user initials from name
function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

export default function UnifiLayout({ children, activeView, onViewChange, enabledModules, currentUser }: LayoutProps) {
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [searchResults, setSearchResults] = useState<SearchItem[]>(SEARCH_ITEMS.filter(i => i.type === 'Seite'));
  const [searching, setSearching] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const notifRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter(n => !n.read).length;

  // Load real alerts from backend services
  useEffect(() => {
    if (!currentUser) return;

    const loadAlerts = async () => {
      const alerts: Notification[] = [];

      // Fetch escalation alerts from least-privilege service
      try {
        const res = await api.get('/api/permissions/escalation-alerts');
        const data = Array.isArray(res.data) ? res.data : [];
        for (const a of data.slice(0, 3)) {
          alerts.push({
            id: `esc-${a.id ?? a.userId}`,
            title: 'Privilege Escalation',
            message: `Benutzer ${a.user_id ?? a.userId} hat Admin-Rechte auf ${a.admin_count} Ressourcen`,
            type: 'warning' as const,
            time: a.detected_at ? new Date(a.detected_at).toLocaleString('de-CH') : 'Gerade eben',
            read: false,
          });
        }
      } catch {}

      // Fetch recent audit events from auth service
      try {
        const res = await api.get('/api/audit/events?limit=5');
        const events = Array.isArray(res.data) ? res.data : [];
        for (const e of events.filter((ev: any) => ev.severity === 'warning' || ev.event_type === 'login_failed').slice(0, 2)) {
          alerts.push({
            id: `audit-${e.id}`,
            title: e.event_type === 'login_failed' ? 'Anmeldung fehlgeschlagen' : 'Sicherheitsereignis',
            message: e.message,
            type: 'warning' as const,
            time: new Date(e.created_at).toLocaleString('de-CH'),
            read: false,
          });
        }
      } catch {}

      // Show a "system ready" info if no alerts
      if (alerts.length === 0) {
        alerts.push({
          id: 'system-ok',
          title: 'System betriebsbereit',
          message: 'Alle Dienste laufen normal.',
          type: 'info' as const,
          time: new Date().toLocaleString('de-CH'),
          read: false,
        });
      }

      setNotifications(alerts);
    };

    loadAlerts();
    const interval = setInterval(loadAlerts, 30000);
    return () => clearInterval(interval);
  }, [currentUser]);

  // Cmd+K / Ctrl+K → open search; Escape → close overlays
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(true);
      }
      if (e.key === 'Escape') {
        setSearchOpen(false);
        setNotifOpen(false);
        setUserMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    if (searchOpen) setTimeout(() => searchInputRef.current?.focus(), 50);
  }, [searchOpen]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const performSearch = async (query: string) => {
    if (!query.trim()) {
      setSearchResults(SEARCH_ITEMS.filter(i => i.type === 'Seite'));
      return;
    }

    setSearching(true);
    const q = query.toLowerCase();

    // Always include matching pages
    const pageMatches = SEARCH_ITEMS.filter(i => i.type === 'Seite' && i.name.toLowerCase().includes(q));

    // Fetch real users and devices in parallel
    const [usersRes, devicesRes] = await Promise.allSettled([
      api.get('/api/users').catch(() => api.get('/api/lldap/users')),
      api.get('/api/devices').catch(() => api.get('/api/devices/registry')),
    ]);

    const dynamicResults: SearchItem[] = [...pageMatches];

    if (usersRes.status === 'fulfilled') {
      const users = Array.isArray(usersRes.value?.data) ? usersRes.value.data
        : usersRes.value?.data?.users ?? usersRes.value?.data?.data ?? [];
      for (const u of users) {
        const name = u.displayName ?? u.name ?? u.username ?? u.id ?? '';
        if (name.toLowerCase().includes(q) || (u.email ?? '').toLowerCase().includes(q)) {
          dynamicResults.push({ id: `user-${u.id ?? u.username}`, name, view: 'users', type: 'user' });
        }
      }
    }

    if (devicesRes.status === 'fulfilled') {
      const devs = Array.isArray(devicesRes.value?.data) ? devicesRes.value.data
        : devicesRes.value?.data?.devices ?? devicesRes.value?.data?.data ?? [];
      for (const d of devs) {
        const name = d.hostname ?? d.name ?? d.id ?? '';
        if (name.toLowerCase().includes(q)) {
          dynamicResults.push({ id: `device-${d.id ?? d.hostname}`, name, view: 'devices', type: 'device' });
        }
      }
    }

    setSearchResults(dynamicResults);
    setSearching(false);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setSearchQuery(val);
    if (searchTimeoutRef.current) clearTimeout(searchTimeoutRef.current);
    searchTimeoutRef.current = setTimeout(() => performSearch(val), 300);
  };

  const markAllRead = () => setNotifications(prev => prev.map(n => ({ ...n, read: true })));

  const handleLogout = async () => {
    try {
      await authApi.logout();
    } catch (_) {}
    localStorage.removeItem('auth_user');
    router.push('/login');
  };

  // Navigation structure — ABM-style sections
  const ALL_NAV_ITEMS: NavItem[] = [
    { type: 'section', label: 'Übersicht' },
    { type: 'item', id: 'dashboard',      name: 'Dashboard',         icon: HomeIcon },

    { type: 'section', label: 'Verzeichnis' },
    { type: 'item', id: 'users',          name: 'Benutzer',          icon: UserGroupIcon },
    { type: 'item', id: 'permissions',    name: 'Rollen & Rechte',   icon: KeyIcon },
    { type: 'item', id: 'identity',       name: 'Identity Provider', icon: FingerPrintIcon },
    { type: 'item', id: 'enrollment',     name: 'Enrollment',        icon: ArrowDownOnSquareStackIcon },

    { type: 'section', label: 'Geräte' },
    { type: 'item', id: 'devices',        name: 'Geräte',            icon: ComputerDesktopIcon },
    { type: 'item', id: 'antivirus',      name: 'Antivirus',         icon: BugAntIcon },
    { type: 'item', id: 'appstore',       name: 'App Store',         icon: ShoppingBagIcon },
    { type: 'item', id: 'printers',       name: 'Drucker',           icon: PrinterIcon },
    { type: 'item', id: 'applications',   name: 'Anwendungen',       icon: CubeIcon },

    { type: 'section', label: 'Netzwerk & Infra' },
    { type: 'item', id: 'topology',       name: 'Netzwerk',          icon: RectangleGroupIcon },
    { type: 'item', id: 'infrastructure', name: 'Infrastruktur',     icon: ServerStackIcon },
    { type: 'item', id: 'monitoring',     name: 'Monitoring',        icon: ChartBarIcon },

    { type: 'section', label: 'Sicherheit' },
    { type: 'item', id: 'security',       name: 'Security',          icon: ShieldExclamationIcon },
    { type: 'item', id: 'compliance',     name: 'Compliance',        icon: ClipboardDocumentCheckIcon },
    { type: 'item', id: 'scanner',        name: 'Security Scanner',  icon: MagnifyingGlassCircleIcon },
    { type: 'item', id: 'secrets',        name: 'Secrets',           icon: LockClosedIcon },

    { type: 'section', label: 'Betrieb' },
    { type: 'item', id: 'audit',          name: 'Audit Log',         icon: ClipboardDocumentListIcon },
    { type: 'item', id: 'backup',         name: 'Backup & DR',       icon: ArchiveBoxIcon },
    { type: 'item', id: 'settings',       name: 'Einstellungen',     icon: Cog6ToothIcon },
  ];

  // Hide nav items whose controlling module is disabled
  const navigationItems = ALL_NAV_ITEMS.filter(item => {
    if (item.type === 'section') return true;
    const required = NAV_REQUIRED_MODULE[item.id];
    if (!required) return true;
    if (!enabledModules || enabledModules.length === 0) return true;
    return enabledModules.includes(required);
  });

  const userInitials = currentUser?.name ? getInitials(currentUser.name) : 'OD';

  // Sidebar content — shared between desktop and mobile overlay
  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Org header */}
      <div
        style={{
          height: 'var(--apple-topbar-height)',
          borderBottom: '1px solid var(--apple-gray-2)',
          padding: '0 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
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
        <div style={{ minWidth: 0 }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', lineHeight: 1.2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            OpenDirectory
          </p>
          <p style={{ fontSize: 11, color: 'var(--apple-text-secondary)', lineHeight: 1.2 }}>
            opendirectory.local
          </p>
        </div>
        <button
          onClick={() => setSidebarOpen(false)}
          className="lg:hidden ml-auto"
          style={{ color: 'var(--apple-gray-5)', padding: 4, flexShrink: 0 }}
        >
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
        {navigationItems.map((item, idx) => {
          if (item.type === 'section') {
            return (
              <div
                key={`section-${idx}`}
                style={{
                  padding: '16px 16px 4px 16px',
                  fontSize: 11,
                  fontWeight: 600,
                  color: 'var(--apple-gray-6)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                }}
              >
                {item.label}
              </div>
            );
          }

          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => { onViewChange(item.id); setSidebarOpen(false); }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                width: '100%',
                padding: '6px 16px',
                fontSize: 14,
                fontWeight: 400,
                textAlign: 'left',
                background: isActive ? 'var(--apple-blue-light)' : 'transparent',
                color: isActive ? 'var(--apple-blue)' : 'var(--apple-text-primary)',
                borderLeft: isActive ? '2px solid var(--apple-blue)' : '2px solid transparent',
                borderRight: 'none',
                borderTop: 'none',
                borderBottom: 'none',
                cursor: 'pointer',
                transition: 'background 0.15s, color 0.15s',
              }}
              onMouseEnter={e => {
                if (!isActive) {
                  (e.currentTarget as HTMLButtonElement).style.background = '#F5F5F7';
                }
              }}
              onMouseLeave={e => {
                if (!isActive) {
                  (e.currentTarget as HTMLButtonElement).style.background = 'transparent';
                }
              }}
            >
              <item.icon
                style={{
                  width: 16,
                  height: 16,
                  flexShrink: 0,
                  color: isActive ? 'var(--apple-blue)' : 'var(--apple-gray-6)',
                }}
              />
              {item.name}
            </button>
          );
        })}
      </nav>
    </div>
  );

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--apple-gray-1)' }}>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1D1D1F',
            color: '#ffffff',
            borderRadius: '10px',
            fontSize: 13,
          },
        }}
      />

      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 lg:hidden"
          style={{ background: 'rgba(0,0,0,0.4)' }}
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar — desktop: always visible; mobile: slide-in overlay */}
      <aside
        className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          bottom: 0,
          width: 'var(--apple-sidebar-width)',
          background: '#FFFFFF',
          borderRight: '1px solid var(--apple-gray-2)',
          zIndex: 50,
          transition: 'transform 0.3s ease',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <SidebarContent />
      </aside>

      {/* Main area — offset by sidebar width on desktop */}
      <div
        style={{
          marginLeft: 0,
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minWidth: 0,
          height: '100%',
        }}
        className="lg:ml-[240px]"
      >
        {/* Top bar */}
        <header
          style={{
            height: 'var(--apple-topbar-height)',
            background: '#FFFFFF',
            borderBottom: '1px solid var(--apple-gray-2)',
            display: 'flex',
            alignItems: 'center',
            padding: '0 20px',
            gap: 12,
            flexShrink: 0,
            position: 'sticky',
            top: 0,
            zIndex: 30,
          }}
        >
          {/* Hamburger — mobile only */}
          <button
            className="lg:hidden"
            onClick={() => setSidebarOpen(true)}
            style={{ color: 'var(--apple-gray-6)', padding: 4, flexShrink: 0 }}
          >
            <Bars3Icon className="w-5 h-5" />
          </button>

          {/* App name — mobile only, desktop has it in sidebar */}
          <span
            className="lg:hidden"
            style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)', flexShrink: 0 }}
          >
            OpenDirectory
          </span>

          {/* Search bar */}
          <div style={{ flex: 1, display: 'flex', justifyContent: 'center' }}>
            <button
              onClick={() => setSearchOpen(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                width: '100%',
                maxWidth: 280,
                background: 'var(--apple-gray-1)',
                border: 'none',
                borderRadius: 8,
                padding: '7px 12px',
                color: 'var(--apple-gray-5)',
                fontSize: 14,
                cursor: 'text',
                textAlign: 'left',
              }}
            >
              <MagnifyingGlassIcon style={{ width: 15, height: 15, flexShrink: 0 }} />
              <span style={{ flex: 1, color: 'var(--apple-gray-5)' }}>Search...</span>
              <kbd
                style={{
                  fontSize: 11,
                  background: 'var(--apple-gray-2)',
                  color: 'var(--apple-gray-6)',
                  borderRadius: 4,
                  padding: '1px 5px',
                  fontFamily: 'inherit',
                }}
              >
                ⌘K
              </kbd>
            </button>
          </div>

          {/* Right actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            {/* Bell */}
            <div ref={notifRef} style={{ position: 'relative' }}>
              <button
                onClick={() => { setNotifOpen(o => !o); setUserMenuOpen(false); }}
                style={{
                  position: 'relative',
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 6,
                  color: 'var(--apple-gray-6)',
                  borderRadius: 8,
                  display: 'flex',
                  alignItems: 'center',
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
              >
                <BellIcon style={{ width: 20, height: 20 }} />
                {unreadCount > 0 && (
                  <span
                    style={{
                      position: 'absolute',
                      top: 2,
                      right: 2,
                      width: 16,
                      height: 16,
                      background: '#FF3B30',
                      color: 'white',
                      fontSize: 10,
                      fontWeight: 600,
                      borderRadius: '50%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {unreadCount}
                  </span>
                )}
              </button>

              {/* Notification dropdown */}
              {notifOpen && (
                <div
                  style={{
                    position: 'absolute',
                    top: 'calc(100% + 8px)',
                    right: 0,
                    width: 320,
                    background: 'white',
                    borderRadius: 12,
                    border: '1px solid var(--apple-gray-2)',
                    boxShadow: '0 8px 32px rgba(0,0,0,0.12)',
                    zIndex: 100,
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 16px',
                      borderBottom: '1px solid var(--apple-gray-2)',
                    }}
                  >
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>
                      Benachrichtigungen
                    </span>
                    <button
                      onClick={markAllRead}
                      style={{ fontSize: 12, color: 'var(--apple-blue)', background: 'none', border: 'none', cursor: 'pointer' }}
                    >
                      Alle gelesen
                    </button>
                  </div>
                  <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                    {notifications.map(n => (
                      <div
                        key={n.id}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: 10,
                          padding: '10px 16px',
                          background: !n.read ? '#EAF4FF40' : 'transparent',
                          borderBottom: '1px solid var(--apple-gray-1)',
                        }}
                      >
                        <span
                          className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${NOTIF_COLOR[n.type]}`}
                          style={{ flexShrink: 0, marginTop: 5 }}
                        />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ fontSize: 12, color: 'var(--apple-text-primary)', lineHeight: 1.4 }}>{n.title}</p>
                          {n.message && (
                            <p style={{ fontSize: 11, color: 'var(--apple-text-secondary)', marginTop: 2, lineHeight: 1.4 }}>
                              {n.message}
                            </p>
                          )}
                          <p style={{ fontSize: 11, color: 'var(--apple-text-tertiary)', marginTop: 2 }}>{n.time}</p>
                        </div>
                        {!n.read && (
                          <span
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: '50%',
                              background: 'var(--apple-blue)',
                              flexShrink: 0,
                              marginTop: 5,
                            }}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* User avatar + dropdown */}
            <div ref={userMenuRef} style={{ position: 'relative' }}>
              <button
                onClick={() => { setUserMenuOpen(o => !o); setNotifOpen(false); }}
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: '50%',
                  background: 'var(--apple-blue)',
                  color: 'white',
                  fontSize: 12,
                  fontWeight: 600,
                  border: 'none',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                {userInitials}
              </button>

              {/* User dropdown */}
              {userMenuOpen && (
                <div
                  style={{
                    position: 'absolute',
                    top: 'calc(100% + 8px)',
                    right: 0,
                    width: 200,
                    background: 'white',
                    borderRadius: 12,
                    border: '1px solid var(--apple-gray-2)',
                    boxShadow: '0 8px 32px rgba(0,0,0,0.12)',
                    zIndex: 100,
                    overflow: 'hidden',
                  }}
                >
                  <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--apple-gray-2)' }}>
                    <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>
                      {currentUser?.name ?? '—'}
                    </p>
                    <p style={{ fontSize: 12, color: 'var(--apple-text-secondary)', marginTop: 2 }}>
                      {currentUser?.role ?? ''}
                    </p>
                  </div>
                  <button
                    onClick={handleLogout}
                    style={{
                      display: 'block',
                      width: '100%',
                      padding: '10px 16px',
                      fontSize: 13,
                      color: '#FF3B30',
                      background: 'none',
                      border: 'none',
                      textAlign: 'left',
                      cursor: 'pointer',
                    }}
                    onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    Abmelden
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page content */}
        <main style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
          {children}
        </main>
      </div>

      {/* ─── Global Search Overlay ──────────────────────────────────────────── */}
      {searchOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center"
          style={{ background: 'rgba(0,0,0,0.4)', paddingTop: 96, paddingLeft: 16, paddingRight: 16 }}
          onClick={() => setSearchOpen(false)}
        >
          <div
            style={{
              background: 'white',
              borderRadius: 16,
              boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
              width: '100%',
              maxWidth: 520,
            }}
            onClick={e => e.stopPropagation()}
          >
            {/* Search input row */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '12px 16px',
                borderBottom: '1px solid var(--apple-gray-2)',
              }}
            >
              <MagnifyingGlassIcon style={{ width: 18, height: 18, color: 'var(--apple-gray-5)', flexShrink: 0 }} />
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Suche nach Seiten, Nutzern, Geräten..."
                value={searchQuery}
                onChange={handleSearchChange}
                style={{
                  flex: 1,
                  fontSize: 15,
                  border: 'none',
                  outline: 'none',
                  color: 'var(--apple-text-primary)',
                  background: 'transparent',
                }}
              />
              <button
                onClick={() => setSearchOpen(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--apple-gray-5)', padding: 2 }}
              >
                <XMarkIcon style={{ width: 18, height: 18 }} />
              </button>
            </div>

            {/* Results */}
            {searching && (
              <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', padding: '12px 16px' }}>Suche läuft...</p>
            )}
            {!searching && searchResults.length > 0 && (
              <ul style={{ listStyle: 'none', margin: 0, padding: '6px 0', maxHeight: 320, overflowY: 'auto' }}>
                {searchResults.map(item => (
                  <li key={item.id}>
                    <button
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        width: '100%',
                        padding: '8px 16px',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        textAlign: 'left',
                      }}
                      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                      onClick={() => { onViewChange(item.view); setSearchOpen(false); setSearchQuery(''); }}
                    >
                      <span
                        style={{
                          fontSize: 11,
                          background: 'var(--apple-gray-1)',
                          color: 'var(--apple-gray-6)',
                          borderRadius: 4,
                          padding: '2px 6px',
                          width: 56,
                          textAlign: 'center',
                          flexShrink: 0,
                        }}
                      >
                        {item.type}
                      </span>
                      <span style={{ fontSize: 14, color: 'var(--apple-text-primary)' }}>{item.name}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {!searching && searchQuery.trim().length > 0 && searchResults.length === 0 && (
              <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', padding: '12px 16px' }}>
                Keine Ergebnisse für &ldquo;{searchQuery}&rdquo;
              </p>
            )}
            {!searching && searchQuery.trim().length === 0 && (
              <p style={{ fontSize: 12, color: 'var(--apple-text-tertiary)', padding: '10px 16px' }}>
                Tippe, um zu suchen. Drücke Escape zum Schliessen.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
