'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { api, authApi } from '@/lib/api';
import { Toaster } from 'react-hot-toast';
import {
  MagnifyingGlassIcon,
  BellIcon,
  Bars3Icon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import Sidebar from './Sidebar';

// ─── Search catalog ───────────────────────────────────────────────────────────
type SearchItem = { id: string; name: string; view: string; type: string };

const SEARCH_ITEMS: SearchItem[] = [
  { id: 'dashboard',         name: 'Dashboard',          view: 'dashboard',         type: 'page' },
  { id: 'fleet',             name: 'Devices',             view: 'fleet',             type: 'page' },
  { id: 'users',             name: 'Users',               view: 'users',             type: 'page' },
  { id: 'serviceprincipals', name: 'Service Principals',  view: 'serviceprincipals', type: 'page' },
  { id: 'compliance',        name: 'Compliance',          view: 'compliance',        type: 'page' },
  { id: 'audit',             name: 'Audit Log',           view: 'audit',             type: 'page' },
  { id: 'policies',          name: 'Policies',            view: 'policies',          type: 'page' },
  { id: 'security',          name: 'Security',            view: 'security',          type: 'page' },
  { id: 'monitoring',        name: 'Monitoring',          view: 'monitoring',        type: 'page' },
  { id: 'secrets',           name: 'Secrets',             view: 'secrets',           type: 'page' },
  { id: 'devices',           name: 'Devices (Legacy)',    view: 'devices',           type: 'page' },
  { id: 'identity',          name: 'Identity Provider',   view: 'identity',          type: 'page' },
  { id: 'enrollment',        name: 'Enrollment Hub',      view: 'enrollment',        type: 'page' },
  { id: 'pim',               name: 'Privileged Access',   view: 'pim',               type: 'page' },
  { id: 'mfa',               name: 'MFA / 2FA',           view: 'mfa',               type: 'page' },
  { id: 'sspr',              name: 'Password Reset',      view: 'sspr',              type: 'page' },
  { id: 'conditionalaccess', name: 'Conditional Access',  view: 'conditionalaccess', type: 'page' },
  { id: 'certificates',      name: 'Certificates / PKI',  view: 'certificates',      type: 'page' },
  { id: 'radius',            name: 'RADIUS / 802.1X',     view: 'radius',            type: 'page' },
  { id: 'servicehealth',     name: 'Service Health',      view: 'servicehealth',     type: 'page' },
  { id: 'alerting',          name: 'Alerts',              view: 'alerting',          type: 'page' },
  { id: 'blueprints',        name: 'Blueprints',          view: 'blueprints',        type: 'page' },
  { id: 'antivirus',         name: 'Antivirus',           view: 'antivirus',         type: 'page' },
  { id: 'appstore',          name: 'App Store',           view: 'appstore',          type: 'page' },
  { id: 'licenses',          name: 'License Kiosk',       view: 'licenses',          type: 'page' },
  { id: 'backup',            name: 'Backup & DR',         view: 'backup',            type: 'page' },
  { id: 'integrations',      name: 'Integrations',        view: 'integrations',      type: 'page' },
  { id: 'roadmap',           name: 'Roadmap',             view: 'roadmap',           type: 'page' },
  { id: 'scanner',           name: 'Security Scanner',    view: 'scanner',           type: 'page' },
  { id: 'sync',              name: 'Directory Sync',      view: 'sync',              type: 'page' },
  { id: 'settings',          name: 'Settings',            view: 'settings',          type: 'page' },
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
  enrollment: '#60a5fa',
  compliance: '#fb923c',
  pim:        '#c084fc',
  security:   '#f87171',
  warning:    '#fb923c',
  info:       '#60a5fa',
};

interface LayoutProps {
  children: React.ReactNode;
  activeView: string;
  onViewChange: (view: string) => void;
  enabledModules?: string[];
  currentUser?: { name: string; role: string } | null;
}

export default function UnifiLayout({ children, activeView, onViewChange, enabledModules, currentUser }: LayoutProps) {
  const router = useRouter();
  const [sidebarOpen,   setSidebarOpen]   = useState(false);
  const [searchOpen,    setSearchOpen]    = useState(false);
  const [searchQuery,   setSearchQuery]   = useState('');
  const [notifOpen,     setNotifOpen]     = useState(false);
  const [userMenuOpen,  setUserMenuOpen]  = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [searchResults, setSearchResults] = useState<SearchItem[]>(SEARCH_ITEMS);
  const [searching,     setSearching]     = useState(false);

  const searchInputRef   = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const notifRef         = useRef<HTMLDivElement>(null);
  const userMenuRef      = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter(n => !n.read).length;

  // Load real alerts
  useEffect(() => {
    if (!currentUser) return;
    const loadAlerts = async () => {
      const alerts: Notification[] = [];
      try {
        const res = await api.get('/api/permissions/escalation-alerts');
        const data = Array.isArray(res.data) ? res.data : [];
        for (const a of data.slice(0, 3)) {
          alerts.push({
            id: `esc-${a.id ?? a.userId}`,
            title: 'Privilege Escalation',
            message: `User ${a.user_id ?? a.userId} has admin rights on ${a.admin_count} resources`,
            type: 'warning',
            time: a.detected_at ? new Date(a.detected_at).toLocaleString() : 'Just now',
            read: false,
          });
        }
      } catch {}
      try {
        const res = await api.get('/api/audit/events?limit=5');
        const events = Array.isArray(res.data) ? res.data : [];
        for (const e of events.filter((ev: any) => ev.severity === 'warning' || ev.event_type === 'login_failed').slice(0, 2)) {
          alerts.push({
            id: `audit-${e.id}`,
            title: e.event_type === 'login_failed' ? 'Login Failed' : 'Security Event',
            message: e.message,
            type: 'warning',
            time: new Date(e.created_at).toLocaleString(),
            read: false,
          });
        }
      } catch {}
      if (alerts.length === 0) {
        alerts.push({ id: 'system-ok', title: 'System Ready', message: 'All services running normally.', type: 'info', time: new Date().toLocaleString(), read: false });
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
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); setSearchOpen(true); }
      if (e.key === 'Escape') { setSearchOpen(false); setNotifOpen(false); setUserMenuOpen(false); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    if (searchOpen) setTimeout(() => searchInputRef.current?.focus(), 50);
  }, [searchOpen]);

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false);
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) setUserMenuOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const performSearch = async (query: string) => {
    if (!query.trim()) { setSearchResults(SEARCH_ITEMS); return; }
    setSearching(true);
    const q = query.toLowerCase();
    const pageMatches = SEARCH_ITEMS.filter(i => i.name.toLowerCase().includes(q));
    const [usersRes, devicesRes] = await Promise.allSettled([
      api.get('/api/users').catch(() => api.get('/api/lldap/users')),
      api.get('/api/devices').catch(() => api.get('/api/devices/registry')),
    ]);
    const dynamicResults: SearchItem[] = [...pageMatches];
    if (usersRes.status === 'fulfilled') {
      const users = Array.isArray(usersRes.value?.data) ? usersRes.value.data : usersRes.value?.data?.users ?? [];
      for (const u of users) {
        const name = u.displayName ?? u.name ?? u.username ?? u.id ?? '';
        if (name.toLowerCase().includes(q) || (u.email ?? '').toLowerCase().includes(q)) {
          dynamicResults.push({ id: `user-${u.id ?? u.username}`, name, view: 'users', type: 'user' });
        }
      }
    }
    if (devicesRes.status === 'fulfilled') {
      const devs = Array.isArray(devicesRes.value?.data) ? devicesRes.value.data : devicesRes.value?.data?.devices ?? [];
      for (const d of devs) {
        const name = d.hostname ?? d.name ?? d.id ?? '';
        if (name.toLowerCase().includes(q)) {
          dynamicResults.push({ id: `device-${d.id ?? d.hostname}`, name, view: 'fleet', type: 'device' });
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
    try { await authApi.logout(); } catch {}
    localStorage.removeItem('auth_user');
    router.push('/login');
  };

  const userInitials = (() => {
    const name = currentUser?.name;
    if (!name) return 'OD';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    return name.slice(0, 2).toUpperCase();
  })();

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#F5F5F7' }}>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: { background: '#1D1D1F', color: '#ffffff', borderRadius: '10px', fontSize: 13 },
        }}
      />

      {/* Sidebar — ~240px wide (CSS var --apple-sidebar-width) */}
      <Sidebar
        activeView={activeView}
        onViewChange={onViewChange}
        enabledModules={enabledModules}
        currentUser={currentUser}
        mobileOpen={sidebarOpen}
        onMobileClose={() => setSidebarOpen(false)}
      />

      {/* Main area — offset by sidebar width on desktop */}
      <div
        className="lg:ml-[240px]"
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minWidth: 0,
          height: '100%',
          overflow: 'hidden',
        }}
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
            zIndex: 30,
          }}
        >
          {/* Hamburger — mobile only */}
          <button
            className="lg:hidden"
            onClick={() => setSidebarOpen(true)}
            style={{ color: 'var(--apple-gray-6)', padding: 4, flexShrink: 0, background: 'none', border: 'none', cursor: 'pointer' }}
          >
            <Bars3Icon style={{ width: 20, height: 20 }} />
          </button>

          {/* App name — mobile only */}
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
                display: 'flex', alignItems: 'center', gap: 6,
                width: '100%', maxWidth: 280,
                background: 'var(--apple-gray-1)', border: 'none',
                borderRadius: 8, padding: '7px 12px',
                color: 'var(--apple-gray-5)', fontSize: 14,
                cursor: 'text', textAlign: 'left',
              }}
            >
              <MagnifyingGlassIcon style={{ width: 15, height: 15, flexShrink: 0 }} />
              <span style={{ flex: 1 }}>Search...</span>
              <kbd style={{ fontSize: 11, background: 'var(--apple-gray-2)', color: 'var(--apple-gray-6)', borderRadius: 4, padding: '1px 5px', fontFamily: 'inherit' }}>
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
                  position: 'relative', background: 'transparent', border: 'none',
                  cursor: 'pointer', padding: 6, color: 'var(--apple-gray-6)',
                  borderRadius: 8, display: 'flex', alignItems: 'center',
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
              >
                <BellIcon style={{ width: 20, height: 20 }} />
                {unreadCount > 0 && (
                  <span style={{
                    position: 'absolute', top: 2, right: 2, width: 16, height: 16,
                    background: '#FF3B30', color: 'white', fontSize: 10, fontWeight: 600,
                    borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    {unreadCount}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 8px)', right: 0, width: 320,
                  background: 'white', borderRadius: 12, border: '1px solid var(--apple-gray-2)',
                  boxShadow: '0 8px 32px rgba(0,0,0,0.12)', zIndex: 100, overflow: 'hidden',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid var(--apple-gray-2)' }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>Notifications</span>
                    <button onClick={markAllRead} style={{ fontSize: 12, color: 'var(--apple-blue)', background: 'none', border: 'none', cursor: 'pointer' }}>
                      Mark all read
                    </button>
                  </div>
                  <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                    {notifications.map(n => (
                      <div key={n.id} style={{
                        display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 16px',
                        background: !n.read ? '#EAF4FF40' : 'transparent',
                        borderBottom: '1px solid var(--apple-gray-1)',
                      }}>
                        <span style={{ width: 8, height: 8, borderRadius: '50%', background: NOTIF_COLOR[n.type], flexShrink: 0, marginTop: 4 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ fontSize: 12, color: 'var(--apple-text-primary)', lineHeight: 1.4 }}>{n.title}</p>
                          {n.message && <p style={{ fontSize: 11, color: 'var(--apple-text-secondary)', marginTop: 2 }}>{n.message}</p>}
                          <p style={{ fontSize: 11, color: 'var(--apple-text-tertiary)', marginTop: 2 }}>{n.time}</p>
                        </div>
                        {!n.read && <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--apple-blue)', flexShrink: 0, marginTop: 5 }} />}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* User avatar */}
            <div ref={userMenuRef} style={{ position: 'relative' }}>
              <button
                onClick={() => { setUserMenuOpen(o => !o); setNotifOpen(false); }}
                style={{
                  width: 32, height: 32, borderRadius: '50%',
                  background: 'var(--apple-blue)', color: 'white',
                  fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}
              >
                {userInitials}
              </button>

              {userMenuOpen && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 8px)', right: 0, width: 200,
                  background: 'white', borderRadius: 12, border: '1px solid var(--apple-gray-2)',
                  boxShadow: '0 8px 32px rgba(0,0,0,0.12)', zIndex: 100, overflow: 'hidden',
                }}>
                  <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--apple-gray-2)' }}>
                    <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>{currentUser?.name ?? '—'}</p>
                    <p style={{ fontSize: 12, color: 'var(--apple-text-secondary)', marginTop: 2 }}>{currentUser?.role ?? ''}</p>
                  </div>
                  <button
                    onClick={() => { setUserMenuOpen(false); onViewChange('settings'); }}
                    style={{ display: 'block', width: '100%', padding: '10px 16px', fontSize: 13, color: 'var(--apple-text-primary)', background: 'none', border: 'none', textAlign: 'left', cursor: 'pointer' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    Settings
                  </button>
                  <button
                    onClick={handleLogout}
                    style={{ display: 'block', width: '100%', padding: '10px 16px', fontSize: 13, color: '#FF3B30', background: 'none', border: 'none', textAlign: 'left', cursor: 'pointer' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page content — fills remaining height, children control their own scroll */}
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {children}
        </main>
      </div>

      {/* Global Search Overlay */}
      {searchOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center"
          style={{ background: 'rgba(0,0,0,0.4)', paddingTop: 96, paddingLeft: 16, paddingRight: 16 }}
          onClick={() => setSearchOpen(false)}
        >
          <div
            style={{ background: 'white', borderRadius: 16, boxShadow: '0 20px 60px rgba(0,0,0,0.2)', width: '100%', maxWidth: 520 }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: '1px solid var(--apple-gray-2)' }}>
              <MagnifyingGlassIcon style={{ width: 18, height: 18, color: 'var(--apple-gray-5)', flexShrink: 0 }} />
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search pages, users, devices..."
                value={searchQuery}
                onChange={handleSearchChange}
                style={{ flex: 1, fontSize: 15, border: 'none', outline: 'none', color: 'var(--apple-text-primary)', background: 'transparent' }}
              />
              <button onClick={() => setSearchOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--apple-gray-5)', padding: 2 }}>
                <XMarkIcon style={{ width: 18, height: 18 }} />
              </button>
            </div>
            {searching && <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', padding: '12px 16px' }}>Searching...</p>}
            {!searching && searchResults.length > 0 && (
              <ul style={{ listStyle: 'none', margin: 0, padding: '6px 0', maxHeight: 320, overflowY: 'auto' }}>
                {searchResults.slice(0, 20).map(item => (
                  <li key={item.id}>
                    <button
                      style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: '8px 16px', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                      onClick={() => { onViewChange(item.view); setSearchOpen(false); setSearchQuery(''); }}
                    >
                      <span style={{ fontSize: 11, background: 'var(--apple-gray-1)', color: 'var(--apple-gray-6)', borderRadius: 4, padding: '2px 6px', width: 48, textAlign: 'center', flexShrink: 0 }}>
                        {item.type}
                      </span>
                      <span style={{ fontSize: 14, color: 'var(--apple-text-primary)' }}>{item.name}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {!searching && searchQuery.trim().length > 0 && searchResults.length === 0 && (
              <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)', padding: '12px 16px' }}>No results for &ldquo;{searchQuery}&rdquo;</p>
            )}
            {!searching && searchQuery.trim().length === 0 && (
              <p style={{ fontSize: 12, color: 'var(--apple-text-tertiary)', padding: '10px 16px' }}>Type to search. Press Escape to close.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
