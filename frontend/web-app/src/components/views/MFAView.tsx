'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  UserGroupIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  QrCodeIcon,
  DevicePhoneMobileIcon,
  KeyIcon,
  CogIcon,
  InformationCircleIcon,
  ChevronDownIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type Tab = 'uebersicht' | 'richtlinien' | 'anleitung';

type MFAMethod = 'TOTP' | 'WebAuthn' | 'SMS';

interface UserMFAStatus {
  id: string;
  username: string;
  email: string;
  displayName: string;
  mfaEnabled: boolean;
  lastMfaUsed: string | null;
  enrolledMethods: MFAMethod[];
  department: string;
}

interface MFAPolicy {
  enforceForAll: boolean;
  enforceForAdmins: boolean;
  exemptGroups: string[];
  allowedMethods: {
    totp: boolean;
    webauthn: boolean;
    sms: boolean;
  };
}

interface MFAStats {
  totalUsers: number;
  mfaEnabledCount: number;
  pendingEnforcement: number;
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_USERS: UserMFAStatus[] = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@company.local',
    displayName: 'System Admin',
    mfaEnabled: true,
    lastMfaUsed: '2026-05-28T08:12:00Z',
    enrolledMethods: ['TOTP', 'WebAuthn'],
    department: 'IT',
  },
  {
    id: '2',
    username: 'j.mueller',
    email: 'j.mueller@company.local',
    displayName: 'Julia Müller',
    mfaEnabled: true,
    lastMfaUsed: '2026-05-27T14:33:00Z',
    enrolledMethods: ['TOTP'],
    department: 'Finance',
  },
  {
    id: '3',
    username: 't.schmidt',
    email: 't.schmidt@company.local',
    displayName: 'Thomas Schmidt',
    mfaEnabled: false,
    lastMfaUsed: null,
    enrolledMethods: [],
    department: 'HR',
  },
  {
    id: '4',
    username: 'k.weber',
    email: 'k.weber@company.local',
    displayName: 'Kathrin Weber',
    mfaEnabled: false,
    lastMfaUsed: null,
    enrolledMethods: [],
    department: 'Sales',
  },
  {
    id: '5',
    username: 'm.bauer',
    email: 'm.bauer@company.local',
    displayName: 'Markus Bauer',
    mfaEnabled: true,
    lastMfaUsed: '2026-05-28T07:01:00Z',
    enrolledMethods: ['WebAuthn'],
    department: 'Engineering',
  },
];

const MOCK_POLICY: MFAPolicy = {
  enforceForAll: false,
  enforceForAdmins: true,
  exemptGroups: [],
  allowedMethods: { totp: true, webauthn: true, sms: false },
};

const MOCK_GROUPS = ['Service Accounts', 'Contractors', 'Read-Only Users'];

const SETUP_STEPS = [
  {
    step: 1,
    title: 'Authenticator-App installieren',
    description: 'Laden Sie eine TOTP-Authenticator-App herunter, z. B. Google Authenticator, Microsoft Authenticator oder Authy.',
    icon: DevicePhoneMobileIcon,
  },
  {
    step: 2,
    title: 'QR-Code scannen',
    description: 'Öffnen Sie die App, tippen Sie auf "Konto hinzufügen" und scannen Sie den QR-Code oder geben Sie den Schlüssel manuell ein.',
    icon: QrCodeIcon,
  },
  {
    step: 3,
    title: 'Code eingeben und bestätigen',
    description: 'Geben Sie den 6-stelligen Code aus der App ein, um die Einrichtung abzuschliessen.',
    icon: CheckCircleIcon,
  },
  {
    step: 4,
    title: 'Wiederherstellungscodes sichern',
    description: 'Speichern Sie die Wiederherstellungscodes an einem sicheren Ort. Diese werden benötigt, falls Sie den Zugang zur Authenticator-App verlieren.',
    icon: KeyIcon,
  },
];

// ─── Helper components ────────────────────────────────────────────────────────

function Badge({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium" style={{ background: 'var(--success-light)', color: 'var(--success)', border: '1px solid var(--success)' }}>
      <CheckCircleIcon className="h-3.5 w-3.5" />
      Aktiv
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium" style={{ background: 'var(--danger-light)', color: 'var(--danger)', border: '1px solid var(--danger)' }}>
      <XCircleIcon className="h-3.5 w-3.5" />
      Deaktiviert
    </span>
  );
}

function MethodBadge({ method }: { method: MFAMethod }) {
  const styles: Record<MFAMethod, React.CSSProperties> = {
    TOTP:    { background: 'var(--accent-light)',  color: 'var(--accent)',  border: '1px solid var(--accent)' },
    WebAuthn:{ background: 'rgba(124,58,237,0.15)', color: '#a78bfa',       border: '1px solid rgba(124,58,237,0.4)' },
    SMS:     { background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid var(--warning)' },
  };
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium" style={styles[method]}>
      {method}
    </span>
  );
}

function Toggle({
  enabled,
  onChange,
  label,
  description,
}: {
  enabled: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description?: string;
}) {
  return (
    <div className="flex items-start justify-between py-3">
      <div className="flex-1 pr-4">
        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{label}</p>
        {description && <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{description}</p>}
      </div>
      <button
        type="button"
        onClick={() => onChange(!enabled)}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus:outline-none`}
        style={{ background: enabled ? 'var(--accent)' : 'var(--bg-surface-raised)' }}
        role="switch"
        aria-checked={enabled}
      >
        <span
          className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-sm transition-transform ${
            enabled ? 'translate-x-5' : 'translate-x-0.5'
          }`}
        />
      </button>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  iconStyle,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  iconStyle: React.CSSProperties;
}) {
  return (
    <div className="rounded-xl p-4 flex items-center gap-3" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
      <div className="h-10 w-10 rounded-xl flex items-center justify-center" style={iconStyle}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>{value}</p>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function MFAView() {
  const [activeTab, setActiveTab] = useState<Tab>('uebersicht');
  const [users, setUsers] = useState<UserMFAStatus[]>(MOCK_USERS);
  const [policy, setPolicy] = useState<MFAPolicy>(MOCK_POLICY);
  const [stats, setStats] = useState<MFAStats>({
    totalUsers: MOCK_USERS.length,
    mfaEnabledCount: MOCK_USERS.filter(u => u.mfaEnabled).length,
    pendingEnforcement: MOCK_USERS.filter(u => !u.mfaEnabled).length,
  });
  const [loading, setLoading] = useState(false);
  const [exemptGroupsOpen, setExemptGroupsOpen] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [usersRes] = await Promise.all([
        api.get('/api/mfa/users').catch(() => null),
      ]);
      if (usersRes?.data?.users?.length) {
        setUsers(usersRes.data.users);
        setStats({
          totalUsers: usersRes.data.users.length,
          mfaEnabledCount: usersRes.data.users.filter((u: UserMFAStatus) => u.mfaEnabled).length,
          pendingEnforcement: usersRes.data.users.filter((u: UserMFAStatus) => !u.mfaEnabled).length,
        });
      }
    } catch {
      // Use mock data on failure
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleEnforceMFA = async (userId: string) => {
    try {
      await api.post(`/api/mfa/users/${userId}/enforce`).catch(() => null);
      setUsers(prev =>
        prev.map(u => (u.id === userId ? { ...u, mfaEnabled: true } : u))
      );
    } catch { /* silent */ }
  };

  const handleDisableMFA = async (userId: string) => {
    try {
      await api.post(`/api/auth/mfa/disable`, { userId }).catch(() => null);
      setUsers(prev =>
        prev.map(u =>
          u.id === userId ? { ...u, mfaEnabled: false, enrolledMethods: [], lastMfaUsed: null } : u
        )
      );
    } catch { /* silent */ }
  };

  const handleSavePolicy = async () => {
    try {
      await api.put('/api/mfa/policy', policy).catch(() => null);
    } catch { /* silent */ }
  };

  const toggleExemptGroup = (group: string) => {
    setPolicy(prev => ({
      ...prev,
      exemptGroups: prev.exemptGroups.includes(group)
        ? prev.exemptGroups.filter(g => g !== group)
        : [...prev.exemptGroups, group],
    }));
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: 'uebersicht', label: 'Übersicht' },
    { id: 'richtlinien', label: 'Richtlinien' },
    { id: 'anleitung', label: 'Setup-Anleitung' },
  ];

  return (
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center shadow-sm" style={{ background: 'var(--accent)' }}>
            <ShieldCheckIcon className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>Multi-Faktor-Authentifizierung</h1>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Verwaltung und Richtlinien für MFA / 2FA</p>
          </div>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 text-sm rounded-lg transition-colors"
          style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}
        >
          <ArrowPathIcon className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Aktualisieren
        </button>
      </div>

      {/* ── Stats ──────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Gesamte Benutzer"
          value={stats.totalUsers}
          icon={UserGroupIcon}
          iconStyle={{ background: 'var(--accent-light)', color: 'var(--accent)' }}
        />
        <StatCard
          label="MFA aktiviert"
          value={stats.mfaEnabledCount}
          icon={ShieldCheckIcon}
          iconStyle={{ background: 'var(--success-light)', color: 'var(--success)' }}
        />
        <StatCard
          label="Ausstehende Durchsetzungen"
          value={stats.pendingEnforcement}
          icon={ExclamationTriangleIcon}
          iconStyle={{ background: 'var(--warning-light)', color: 'var(--warning)' }}
        />
      </div>

      {/* ── Tabs ───────────────────────────────────────────────────────────── */}
      <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
        <div className="flex" style={{ borderBottom: '1px solid var(--border)' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="px-5 py-3 text-sm font-medium transition-colors"
              style={activeTab === tab.id
                ? { color: 'var(--accent)', borderBottom: '2px solid var(--accent)', background: 'var(--accent-light)' }
                : { color: 'var(--text-muted)', borderBottom: '2px solid transparent' }
              }
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab: Übersicht ──────────────────────────────────────────────── */}
        {activeTab === 'uebersicht' && (
          <div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Benutzer</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Status</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Letzter MFA-Einsatz</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Methoden</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Abteilung</th>
                    <th className="text-right px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Aktionen</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user.id} className="transition-colors" style={{ borderBottom: '1px solid var(--border)' }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                    >
                      <td className="px-5 py-3">
                        <div>
                          <p className="font-medium" style={{ color: 'var(--text-primary)' }}>{user.displayName}</p>
                          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{user.email}</p>
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <Badge enabled={user.mfaEnabled} />
                      </td>
                      <td className="px-5 py-3" style={{ color: 'var(--text-muted)' }}>
                        {user.lastMfaUsed
                          ? new Date(user.lastMfaUsed).toLocaleString('de-CH', {
                              day: '2-digit',
                              month: '2-digit',
                              year: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                            })
                          : '—'}
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex gap-1 flex-wrap">
                          {user.enrolledMethods.length > 0
                            ? user.enrolledMethods.map(m => <MethodBadge key={m} method={m} />)
                            : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Keine</span>}
                        </div>
                      </td>
                      <td className="px-5 py-3" style={{ color: 'var(--text-muted)' }}>{user.department}</td>
                      <td className="px-5 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {!user.mfaEnabled && (
                            <button
                              onClick={() => handleEnforceMFA(user.id)}
                              className="px-3 py-1 text-xs font-medium text-white rounded-lg transition-colors"
                              style={{ background: 'var(--accent)' }}
                            >
                              MFA erzwingen
                            </button>
                          )}
                          {user.mfaEnabled && (
                            <button
                              onClick={() => handleDisableMFA(user.id)}
                              className="px-3 py-1 text-xs font-medium rounded-lg transition-colors"
                              style={{ color: 'var(--danger)', background: 'var(--danger-light)', border: '1px solid var(--danger)' }}
                            >
                              MFA deaktivieren
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {users.length === 0 && (
              <div className="text-center py-12" style={{ color: 'var(--text-muted)' }}>
                <ShieldExclamationIcon className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p className="text-sm">Keine Benutzer gefunden</p>
              </div>
            )}
          </div>
        )}

        {/* ── Tab: Richtlinien ────────────────────────────────────────────── */}
        {activeTab === 'richtlinien' && (
          <div className="p-5 space-y-6 max-w-2xl">

            {/* Enforcement */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Durchsetzung</h2>
              <div className="rounded-xl px-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div style={{ borderBottom: '1px solid var(--border)' }}>
                  <Toggle
                    enabled={policy.enforceForAll}
                    onChange={v => setPolicy(p => ({ ...p, enforceForAll: v }))}
                    label="MFA für alle Benutzer erzwingen"
                    description="Alle Benutzer müssen MFA bei der nächsten Anmeldung einrichten."
                  />
                </div>
                <Toggle
                  enabled={policy.enforceForAdmins}
                  onChange={v => setPolicy(p => ({ ...p, enforceForAdmins: v }))}
                  label="MFA für Admins erzwingen"
                  description="Administratoren müssen zwingend MFA verwenden."
                />
              </div>
            </section>

            {/* Exempt groups */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Ausnahmen</h2>
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setExemptGroupsOpen(o => !o)}
                  className="w-full flex items-center justify-between px-4 py-2.5 rounded-xl text-sm transition-colors"
                  style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                >
                  <span>
                    {policy.exemptGroups.length > 0
                      ? policy.exemptGroups.join(', ')
                      : 'Gruppen auswählen…'}
                  </span>
                  <ChevronDownIcon className={`h-4 w-4 transition-transform ${exemptGroupsOpen ? 'rotate-180' : ''}`} style={{ color: 'var(--text-muted)' }} />
                </button>
                {exemptGroupsOpen && (
                  <div className="absolute z-10 mt-1 w-full rounded-xl overflow-hidden shadow-lg" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)' }}>
                    {MOCK_GROUPS.map(group => (
                      <button
                        key={group}
                        type="button"
                        onClick={() => toggleExemptGroup(group)}
                        className="w-full flex items-center justify-between px-4 py-2.5 text-sm transition-colors"
                        style={{ color: 'var(--text-secondary)' }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                      >
                        <span>{group}</span>
                        {policy.exemptGroups.includes(group) && (
                          <CheckCircleIcon className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <p className="text-xs mt-1.5 flex items-center gap-1" style={{ color: 'var(--text-muted)' }}>
                <InformationCircleIcon className="h-3.5 w-3.5" />
                Gruppen, die von der MFA-Pflicht ausgenommen sind.
              </p>
            </section>

            {/* Allowed methods */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Erlaubte Methoden</h2>
              <div className="rounded-xl px-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div style={{ borderBottom: '1px solid var(--border)' }}>
                  <Toggle
                    enabled={policy.allowedMethods.totp}
                    onChange={v => setPolicy(p => ({ ...p, allowedMethods: { ...p.allowedMethods, totp: v } }))}
                    label="TOTP (Authenticator-App)"
                    description="Zeitbasierte Einmalpasswörter via Authenticator-App."
                  />
                </div>
                <div style={{ borderBottom: '1px solid var(--border)' }}>
                  <Toggle
                    enabled={policy.allowedMethods.webauthn}
                    onChange={v => setPolicy(p => ({ ...p, allowedMethods: { ...p.allowedMethods, webauthn: v } }))}
                    label="WebAuthn / FIDO2"
                    description="Hardware-Sicherheitsschlüssel oder Biometrie (Face ID, Touch ID)."
                  />
                </div>
                <Toggle
                  enabled={policy.allowedMethods.sms}
                  onChange={v => setPolicy(p => ({ ...p, allowedMethods: { ...p.allowedMethods, sms: v } }))}
                  label="SMS-Code"
                  description="Einmalcode per SMS. Weniger sicher — nur falls TOTP/WebAuthn nicht verfügbar."
                />
              </div>
            </section>

            <button
              onClick={handleSavePolicy}
              className="px-5 py-2 text-sm font-medium text-white rounded-xl transition-colors shadow-sm"
              style={{ background: 'var(--accent)' }}
            >
              Richtlinien speichern
            </button>
          </div>
        )}

        {/* ── Tab: Setup-Anleitung ────────────────────────────────────────── */}
        {activeTab === 'anleitung' && (
          <div className="p-5 max-w-2xl space-y-6">
            <div className="flex items-start gap-3 p-4 rounded-xl" style={{ background: 'var(--accent-light)', border: '1px solid var(--accent)' }}>
              <InformationCircleIcon className="h-5 w-5 mt-0.5 shrink-0" style={{ color: 'var(--accent)' }} />
              <p className="text-sm" style={{ color: 'var(--text-primary)' }}>
                Diese Anleitung zeigt Benutzern, wie sie MFA in OpenDirectory einrichten. Sie können diese
                Schritte als E-Mail-Vorlage oder im Benutzerportal veröffentlichen.
              </p>
            </div>

            {/* Steps */}
            <ol className="space-y-4">
              {SETUP_STEPS.map(({ step, title, description, icon: Icon }) => (
                <li key={step} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="h-9 w-9 rounded-full text-white flex items-center justify-center text-sm font-semibold shrink-0" style={{ background: 'var(--accent)' }}>
                      {step}
                    </div>
                    {step < SETUP_STEPS.length && (
                      <div className="w-px flex-1 mt-2" style={{ background: 'var(--border)' }} />
                    )}
                  </div>
                  <div className="pb-4">
                    <div className="flex items-center gap-2 mb-1">
                      <Icon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                      <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</p>
                    </div>
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{description}</p>
                  </div>
                </li>
              ))}
            </ol>

            {/* QR Code mockup */}
            <div className="rounded-xl p-5 flex flex-col items-center gap-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
              <p className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Beispiel-QR-Code (Vorschau)</p>
              <div className="h-36 w-36 rounded-xl flex items-center justify-center" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
                <QrCodeIcon className="h-20 w-20" style={{ color: 'var(--text-muted)' }} />
              </div>
              <div className="text-center">
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Manueller Schlüssel:</p>
                <code className="text-xs font-mono px-2 py-1 rounded-lg mt-1 inline-block" style={{ color: 'var(--text-secondary)', background: 'var(--bg-overlay)' }}>
                  JBSWY3DPEHPK3PXP
                </code>
              </div>
              <div className="flex gap-2">
                <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-secondary)', boxShadow: 'var(--card-shadow)' }}>
                  <CogIcon className="h-3.5 w-3.5" />
                  In App eingeben
                </span>
                <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium text-white" style={{ background: 'var(--accent)' }}>
                  <CheckCircleIcon className="h-3.5 w-3.5" />
                  Code bestätigen
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
