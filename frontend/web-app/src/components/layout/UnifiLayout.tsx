'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { api, authApi } from '@/lib/api';
import { Toaster } from 'react-hot-toast';
import {
  HomeIcon,
  RectangleGroupIcon,
  ComputerDesktopIcon,
  CubeIcon,
  Cog6ToothIcon,
  ChartBarIcon,
  BellIcon,
  UserCircleIcon,
  MagnifyingGlassIcon,
  Bars3Icon,
  XMarkIcon,
  UserGroupIcon,
  WifiIcon,
  PrinterIcon,
  DocumentTextIcon,
  LockClosedIcon,
  ShieldExclamationIcon,
  ArrowRightOnRectangleIcon,
  FingerPrintIcon,
  ArrowDownOnSquareStackIcon,
  KeyIcon,
  BugAntIcon,
  ClipboardDocumentListIcon,
  ArchiveBoxIcon,
  ShoppingBagIcon,
  ClipboardDocumentCheckIcon,
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
  { id: 'antivirus',   name: 'Antivirus',           view: 'antivirus',    type: 'Seite' },
  { id: 'audit',       name: 'Audit Log',           view: 'audit',        type: 'Seite' },
  { id: 'backup',      name: 'Backup & DR',         view: 'backup',       type: 'Seite' },
  { id: 'appstore',    name: 'App Store',           view: 'appstore',     type: 'Seite' },
  { id: 'compliance',  name: 'Compliance',          view: 'compliance',   type: 'Seite' },
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
  | { type: 'divider'; label: string };

// Nav items that require a specific module to be enabled
const NAV_REQUIRED_MODULE: Record<string, string> = {
  monitoring:     'monitoring-analytics',
  secrets:        'secrets-management',
  devices:        'device-management',
  printers:       'device-management',
  infrastructure: 'network-infrastructure',
  security:       'security-suite',
};

export default function UnifiLayout({ children, activeView, onViewChange, enabledModules, currentUser }: LayoutProps) {
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [searchResults, setSearchResults] = useState<SearchItem[]>(SEARCH_ITEMS.filter(i => i.type === 'Seite'));
  const [searching, setSearching] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);

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

  // Cmd+K / Ctrl+K → open search
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(true);
      }
      if (e.key === 'Escape') {
        setSearchOpen(false);
        setNotifOpen(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    if (searchOpen) setTimeout(() => searchInputRef.current?.focus(), 50);
  }, [searchOpen]);

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
      await authApi.logout(); // clears httpOnly cookie on server
    } catch (_) {}
    localStorage.removeItem('auth_user');
    router.push('/login');
  };

  const ALL_NAV_ITEMS: NavItem[] = [
    { type: 'item', id: 'dashboard',      name: 'Dashboard',       icon: HomeIcon },
    { type: 'divider', label: 'Identity & Enrollment' },
    { type: 'item', id: 'identity',       name: 'Identity Provider', icon: FingerPrintIcon },
    { type: 'item', id: 'enrollment',     name: 'Enrollment Hub',  icon: ArrowDownOnSquareStackIcon },
    { type: 'divider', label: 'Geräte & Apps' },
    { type: 'item', id: 'devices',        name: 'Devices',         icon: ComputerDesktopIcon },
    { type: 'item', id: 'antivirus',      name: 'Antivirus',       icon: BugAntIcon },
    { type: 'item', id: 'appstore',       name: 'App Store',       icon: ShoppingBagIcon },
    { type: 'item', id: 'printers',       name: 'Printers',        icon: PrinterIcon },
    { type: 'item', id: 'applications',   name: 'Applications',    icon: CubeIcon },
    { type: 'divider', label: 'Infrastruktur' },
    { type: 'item', id: 'topology',       name: 'Network',         icon: RectangleGroupIcon },
    { type: 'item', id: 'infrastructure', name: 'Infrastructure',  icon: WifiIcon },
    { type: 'item', id: 'users',          name: 'Users',           icon: UserGroupIcon },
    { type: 'item', id: 'monitoring',     name: 'Monitoring',      icon: ChartBarIcon },
    { type: 'divider', label: 'Governance' },
    { type: 'item', id: 'policies',       name: 'Policies',        icon: DocumentTextIcon },
    { type: 'item', id: 'compliance',     name: 'Compliance',      icon: ClipboardDocumentCheckIcon },
    { type: 'item', id: 'security',       name: 'Security',        icon: ShieldExclamationIcon },
    { type: 'item', id: 'secrets',        name: 'Secrets',         icon: LockClosedIcon },
    { type: 'item', id: 'permissions',    name: 'Berechtigungen',  icon: KeyIcon },
    { type: 'item', id: 'audit',          name: 'Audit Log',       icon: ClipboardDocumentListIcon },
    { type: 'item', id: 'backup',         name: 'Backup & DR',     icon: ArchiveBoxIcon },
    { type: 'divider', label: '' },
    { type: 'item', id: 'settings',       name: 'Settings',        icon: Cog6ToothIcon },
  ];

  // Hide nav items whose controlling module is disabled
  const navigationItems = ALL_NAV_ITEMS.filter(item => {
    if (item.type === 'divider') return true;
    const required = NAV_REQUIRED_MODULE[item.id];
    if (!required) return true;                          // no module gate → always show
    if (!enabledModules || enabledModules.length === 0) return true; // not loaded yet → show all
    return enabledModules.includes(required);
  });

  return (
    /* Full viewport height, no scroll on the outer shell */
    <div className="h-screen bg-gray-50 flex overflow-hidden">
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: { background: '#1f2937', color: '#ffffff', borderRadius: '8px' },
        }}
      />

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-gray-600 bg-opacity-50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar — flex column so the version text is pushed to the bottom */}
      <div
        className={`
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
          lg:translate-x-0
          fixed lg:relative inset-y-0 left-0 z-50
          w-64 bg-white border-r border-gray-200
          flex flex-col
          transform transition-transform duration-300 ease-in-out lg:transform-none
          h-full
        `}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200 shrink-0">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">OD</span>
            </div>
            <span className="text-xl font-semibold text-gray-900">OpenDirectory</span>
          </div>
          <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-gray-400 hover:text-gray-600">
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        {/* Navigation — grows to fill space */}
        <nav className="flex-1 mt-6 px-3 overflow-y-auto">
          <div className="space-y-0.5">
            {navigationItems.map((item, idx) => {
              if (item.type === 'divider') {
                return item.label ? (
                  <div key={`divider-${idx}`} className="px-3 pt-5 pb-1">
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-400">
                      {item.label}
                    </span>
                  </div>
                ) : (
                  <hr key={`divider-${idx}`} className="border-gray-100 mx-3 my-2" />
                );
              }
              return (
                <button
                  key={item.id}
                  onClick={() => { onViewChange(item.id); setSidebarOpen(false); }}
                  className={`${
                    activeView === item.id
                      ? 'bg-blue-50 border-r-2 border-blue-600 text-blue-700'
                      : 'text-gray-700 hover:text-gray-900 hover:bg-gray-50'
                  } group flex items-center px-3 py-2 text-sm font-medium rounded-l-lg w-full text-left transition-colors duration-150`}
                >
                  <item.icon className={`${
                    activeView === item.id ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-600'
                  } mr-3 h-5 w-5 transition-colors duration-150`} />
                  {item.name}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Version — pinned at the bottom inside flex column */}
        <div className="shrink-0 border-t border-gray-100 p-4">
          <p className="text-xs text-gray-400 text-center">OpenDirectory v1.0</p>
        </div>
      </div>

      {/* Main content — flex column, fills remaining width, scrolls independently */}
      <div className="flex-1 flex flex-col min-w-0 h-full">
        {/* Top header */}
        <header className="shrink-0 bg-white border-b border-gray-200 h-16 flex items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <button onClick={() => setSidebarOpen(!sidebarOpen)} className="lg:hidden text-gray-400 hover:text-gray-600">
              <Bars3Icon className="w-6 h-6" />
            </button>
            <button
              onClick={() => setSearchOpen(true)}
              className="hidden sm:flex items-center gap-2 w-64 pl-3 pr-3 py-2 border border-gray-300 rounded-lg bg-gray-50 text-gray-400 text-sm hover:bg-white hover:border-gray-400 transition-colors"
            >
              <MagnifyingGlassIcon className="h-4 w-4 shrink-0" />
              <span className="flex-1 text-left text-gray-400">Suchen...</span>
              <kbd className="hidden md:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-xs bg-gray-100 text-gray-500 rounded border border-gray-200">
                <span>⌘</span><span>K</span>
              </kbd>
            </button>
          </div>

          <div className="flex items-center space-x-4">
            <button onClick={() => setNotifOpen(o => !o)} className="relative text-gray-400 hover:text-gray-600">
              <BellIcon className="w-6 h-6" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </button>
            <div className="flex items-center space-x-3">
              <div className="hidden sm:block text-right">
                <p className="text-sm font-medium text-gray-700">{currentUser?.name ?? '—'}</p>
                <p className="text-xs text-gray-500">{currentUser?.role ?? ''}</p>
              </div>
              <UserCircleIcon className="w-8 h-8 text-gray-400" />
              <button
                onClick={handleLogout}
                title="Sign out"
                className="text-gray-400 hover:text-gray-600 transition-colors"
              >
                <ArrowRightOnRectangleIcon className="w-5 h-5" />
              </button>
            </div>
          </div>
        </header>

        {/* Page content — scrolls independently */}
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>

      {/* ─── Global Search Overlay ──────────────────────────────────────────── */}
      {searchOpen && (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-50 z-50 flex items-start justify-center pt-24 px-4" onClick={() => setSearchOpen(false)}>
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-100">
              <MagnifyingGlassIcon className="w-5 h-5 text-gray-400 shrink-0" />
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Suche nach Seiten, Nutzern, Geräten, Apps..."
                value={searchQuery}
                onChange={handleSearchChange}
                className="flex-1 text-sm focus:outline-none text-gray-900"
              />
              <button onClick={() => setSearchOpen(false)} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-5 h-5" /></button>
            </div>
            {searching && (
              <p className="text-xs text-gray-400 px-4 py-3">Suche läuft...</p>
            )}
            {!searching && searchResults.length > 0 && (
              <ul className="py-2 max-h-72 overflow-y-auto">
                {searchResults.map(item => (
                  <li key={item.id}>
                    <button
                      className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 text-left"
                      onClick={() => { onViewChange(item.view); setSearchOpen(false); setSearchQuery(''); }}
                    >
                      <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded w-16 text-center shrink-0">{item.type}</span>
                      <span className="text-sm text-gray-900">{item.name}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {!searching && searchQuery.trim().length > 0 && searchResults.length === 0 && (
              <p className="text-sm text-gray-400 px-4 py-4">Keine Ergebnisse für "{searchQuery}"</p>
            )}
            {!searching && searchQuery.trim().length === 0 && (
              <p className="text-xs text-gray-400 px-4 py-3">Tippe, um zu suchen. Drücke Escape zum Schliessen.</p>
            )}
          </div>
        </div>
      )}

      {/* ─── Notification Panel ─────────────────────────────────────────────── */}
      {notifOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setNotifOpen(false)} />
          <div className="fixed top-16 right-0 w-80 bg-white border-l border-gray-200 shadow-xl z-50 h-[calc(100vh-4rem)] flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
              <h3 className="text-sm font-semibold text-gray-900">Benachrichtigungen</h3>
              <div className="flex items-center gap-2">
                <button onClick={markAllRead} className="text-xs text-blue-600 hover:underline">Alle gelesen</button>
                <button onClick={() => setNotifOpen(false)} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-4 h-4" /></button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto py-2">
              {notifications.map(n => (
                <div key={n.id} className={`flex items-start gap-3 px-4 py-3 hover:bg-gray-50 transition-colors ${!n.read ? 'bg-blue-50/40' : ''}`}>
                  <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${NOTIF_COLOR[n.type]}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-gray-800 leading-snug">{n.title}</p>
                    {n.message && <p className="text-xs text-gray-600 mt-0.5 leading-snug">{n.message}</p>}
                    <p className="text-xs text-gray-400 mt-0.5">{n.time}</p>
                  </div>
                  {!n.read && <span className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0 mt-2" />}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
