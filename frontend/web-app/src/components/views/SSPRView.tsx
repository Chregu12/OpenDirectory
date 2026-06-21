'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  KeyIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  UserIcon,
  EnvelopeIcon,
  DevicePhoneMobileIcon,
  QuestionMarkCircleIcon,
  ShieldCheckIcon,
  PlusIcon,
  TrashIcon,
  PencilIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type Tab = 'anfragen' | 'konfiguration' | 'fragen';

type ResetStatus = 'abgeschlossen' | 'fehlgeschlagen' | 'ausstehend';
type ResetMethod = 'email' | 'sms' | 'sicherheitsfragen' | 'mfa';

interface ResetRequest {
  id: string;
  userId: string;
  username: string;
  email: string;
  displayName: string;
  status: ResetStatus;
  method: ResetMethod;
  requestedAt: string;
  completedAt: string | null;
  failureReason: string | null;
  ipAddress: string;
}

interface SSPRConfig {
  enabled: boolean;
  emailVerification: boolean;
  smsVerification: boolean;
  securityQuestions: boolean;
  minVerificationMethods: number;
  requireMfaOnReset: boolean;
  resetLinkExpiryMinutes: number;
}

interface SecurityQuestion {
  id: string;
  question: string;
  category: string;
}

interface SSPRStats {
  resetsToday: number;
  resetsThisWeek: number;
  failedAttempts: number;
  avgResetTimeMinutes: number;
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_REQUESTS: ResetRequest[] = [
  {
    id: '1',
    userId: 'u1',
    username: 'j.mueller',
    email: 'j.mueller@company.local',
    displayName: 'Julia Müller',
    status: 'abgeschlossen',
    method: 'email',
    requestedAt: '2026-05-28T07:34:00Z',
    completedAt: '2026-05-28T07:36:22Z',
    failureReason: null,
    ipAddress: '192.168.1.42',
  },
  {
    id: '2',
    userId: 'u2',
    username: 't.schmidt',
    email: 't.schmidt@company.local',
    displayName: 'Thomas Schmidt',
    status: 'fehlgeschlagen',
    method: 'sicherheitsfragen',
    requestedAt: '2026-05-27T15:11:00Z',
    completedAt: null,
    failureReason: 'Zu viele falsche Antworten',
    ipAddress: '10.0.0.55',
  },
  {
    id: '3',
    userId: 'u3',
    username: 'k.weber',
    email: 'k.weber@company.local',
    displayName: 'Kathrin Weber',
    status: 'ausstehend',
    method: 'email',
    requestedAt: '2026-05-28T09:02:00Z',
    completedAt: null,
    failureReason: null,
    ipAddress: '172.16.0.11',
  },
  {
    id: '4',
    userId: 'u4',
    username: 'm.bauer',
    email: 'm.bauer@company.local',
    displayName: 'Markus Bauer',
    status: 'abgeschlossen',
    method: 'mfa',
    requestedAt: '2026-05-26T11:20:00Z',
    completedAt: '2026-05-26T11:21:05Z',
    failureReason: null,
    ipAddress: '192.168.2.88',
  },
];

const MOCK_CONFIG: SSPRConfig = {
  enabled: true,
  emailVerification: true,
  smsVerification: false,
  securityQuestions: true,
  minVerificationMethods: 2,
  requireMfaOnReset: false,
  resetLinkExpiryMinutes: 30,
};

const MOCK_QUESTIONS: SecurityQuestion[] = [
  { id: '1', question: 'Wie lautet der Geburtsname Ihrer Mutter?', category: 'Familie' },
  { id: '2', question: 'Wie hiess Ihr erstes Haustier?', category: 'Persönlich' },
  { id: '3', question: 'In welcher Stadt wurden Sie geboren?', category: 'Persönlich' },
  { id: '4', question: 'Wie lautet der Name Ihrer ersten Schule?', category: 'Bildung' },
];

const MOCK_STATS: SSPRStats = {
  resetsToday: 3,
  resetsThisWeek: 12,
  failedAttempts: 2,
  avgResetTimeMinutes: 2,
};

// ─── Helper components ────────────────────────────────────────────────────────

const STATUS_BADGE: Record<ResetStatus, React.CSSProperties> = {
  abgeschlossen: { background: 'var(--success-light)', color: 'var(--success)', border: '1px solid var(--success)' },
  fehlgeschlagen: { background: 'var(--danger-light)',  color: 'var(--danger)',  border: '1px solid var(--danger)' },
  ausstehend:    { background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid var(--warning)' },
};

const STATUS_ICONS: Record<ResetStatus, React.ComponentType<{ className?: string }>> = {
  abgeschlossen: CheckCircleIcon,
  fehlgeschlagen: XCircleIcon,
  ausstehend: ClockIcon,
};

const METHOD_LABELS: Record<ResetMethod, string> = {
  email: 'E-Mail',
  sms: 'SMS',
  sicherheitsfragen: 'Sicherheitsfragen',
  mfa: 'MFA',
};

const METHOD_ICONS: Record<ResetMethod, React.ComponentType<{ className?: string }>> = {
  email: EnvelopeIcon,
  sms: DevicePhoneMobileIcon,
  sicherheitsfragen: QuestionMarkCircleIcon,
  mfa: ShieldCheckIcon,
};

function StatusBadge({ status }: { status: ResetStatus }) {
  const Icon = STATUS_ICONS[status];
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium" style={STATUS_BADGE[status]}>
      <Icon className="h-3.5 w-3.5" />
      {status.charAt(0).toUpperCase() + status.slice(1)}
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
        className="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus:outline-none"
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
  suffix,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  iconStyle: React.CSSProperties;
  suffix?: string;
}) {
  return (
    <div className="rounded-xl p-4 flex items-center gap-3" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
      <div className="h-10 w-10 rounded-xl flex items-center justify-center shrink-0" style={iconStyle}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
          {value}
          {suffix && <span className="text-sm font-normal ml-1" style={{ color: 'var(--text-muted)' }}>{suffix}</span>}
        </p>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  padding: '8px 12px',
  fontSize: '0.875rem',
  border: '1px solid var(--border-strong)',
  borderRadius: '0.5rem',
  outline: 'none',
  background: 'var(--bg-surface)',
  color: 'var(--text-primary)',
};

// ─── Main component ───────────────────────────────────────────────────────────

export default function SSPRView() {
  const [activeTab, setActiveTab] = useState<Tab>('anfragen');
  const [requests, setRequests] = useState<ResetRequest[]>(MOCK_REQUESTS);
  const [config, setConfig] = useState<SSPRConfig>(MOCK_CONFIG);
  const [questions, setQuestions] = useState<SecurityQuestion[]>(MOCK_QUESTIONS);
  const [stats, setStats] = useState<SSPRStats>(MOCK_STATS);
  const [loading, setLoading] = useState(false);
  const [editingQuestion, setEditingQuestion] = useState<SecurityQuestion | null>(null);
  const [newQuestion, setNewQuestion] = useState('');
  const [newCategory, setNewCategory] = useState('Persönlich');
  const [showAddQuestion, setShowAddQuestion] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [reqRes, cfgRes, statsRes] = await Promise.all([
        api.get('/api/sspr/requests').catch(() => null),
        api.get('/api/sspr/config').catch(() => null),
        api.get('/api/sspr/stats').catch(() => null),
      ]);
      if (reqRes?.data?.requests?.length) setRequests(reqRes.data.requests);
      if (cfgRes?.data) setConfig(cfgRes.data);
      if (statsRes?.data) setStats(statsRes.data);
    } catch {
      // Use mock data on failure
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSaveConfig = async () => {
    try {
      await api.put('/api/sspr/config', config).catch(() => null);
    } catch { /* silent */ }
  };

  const handleDeleteQuestion = async (id: string) => {
    try {
      await api.delete(`/api/sspr/questions/${id}`).catch(() => null);
      setQuestions(prev => prev.filter(q => q.id !== id));
    } catch { /* silent */ }
  };

  const handleAddQuestion = async () => {
    if (!newQuestion.trim()) return;
    const q: SecurityQuestion = {
      id: String(Date.now()),
      question: newQuestion.trim(),
      category: newCategory,
    };
    try {
      await api.post('/api/sspr/questions', q).catch(() => null);
      setQuestions(prev => [...prev, q]);
      setNewQuestion('');
      setNewCategory('Persönlich');
      setShowAddQuestion(false);
    } catch { /* silent */ }
  };

  const handleUpdateQuestion = async () => {
    if (!editingQuestion) return;
    try {
      await api.put(`/api/sspr/questions/${editingQuestion.id}`, editingQuestion).catch(() => null);
      setQuestions(prev => prev.map(q => q.id === editingQuestion.id ? editingQuestion : q));
      setEditingQuestion(null);
    } catch { /* silent */ }
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: 'anfragen', label: 'Reset-Anfragen' },
    { id: 'konfiguration', label: 'Konfiguration' },
    { id: 'fragen', label: 'Sicherheitsfragen' },
  ];

  const CATEGORIES = ['Persönlich', 'Familie', 'Bildung', 'Beruf', 'Sonstiges'];

  return (
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center shadow-sm" style={{ background: 'var(--accent)' }}>
            <KeyIcon className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>Self-Service Passwort-Reset</h1>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Konfiguration und Überwachung von SSPR-Anfragen</p>
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
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          label="Resets heute"
          value={stats.resetsToday}
          icon={CheckCircleIcon}
          iconStyle={{ background: 'var(--success-light)', color: 'var(--success)' }}
        />
        <StatCard
          label="Resets diese Woche"
          value={stats.resetsThisWeek}
          icon={ArrowPathIcon}
          iconStyle={{ background: 'var(--accent-light)', color: 'var(--accent)' }}
        />
        <StatCard
          label="Fehlversuche"
          value={stats.failedAttempts}
          icon={ExclamationTriangleIcon}
          iconStyle={{ background: 'var(--danger-light)', color: 'var(--danger)' }}
        />
        <StatCard
          label="Durchschnittliche Reset-Zeit"
          value={stats.avgResetTimeMinutes}
          suffix="Min."
          icon={ClockIcon}
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

        {/* ── Tab: Reset-Anfragen ─────────────────────────────────────────── */}
        {activeTab === 'anfragen' && (
          <div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Benutzer</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Status</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Methode</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Zeitstempel</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>IP-Adresse</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map(req => {
                    const MethodIcon = METHOD_ICONS[req.method];
                    return (
                      <tr key={req.id} className="transition-colors" style={{ borderBottom: '1px solid var(--border)' }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                      >
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-7 w-7 rounded-full flex items-center justify-center shrink-0" style={{ background: 'var(--bg-surface-raised)' }}>
                              <UserIcon className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                            </div>
                            <div>
                              <p className="font-medium" style={{ color: 'var(--text-primary)' }}>{req.displayName}</p>
                              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{req.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <StatusBadge status={req.status} />
                        </td>
                        <td className="px-5 py-3">
                          <span className="inline-flex items-center gap-1" style={{ color: 'var(--text-secondary)' }}>
                            <MethodIcon className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                            {METHOD_LABELS[req.method]}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                          {new Date(req.requestedAt).toLocaleString('de-CH', {
                            day: '2-digit',
                            month: '2-digit',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </td>
                        <td className="px-5 py-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{req.ipAddress}</td>
                        <td className="px-5 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                          {req.status === 'abgeschlossen' && req.completedAt && (
                            <span style={{ color: 'var(--success)' }}>
                              {Math.round(
                                (new Date(req.completedAt).getTime() - new Date(req.requestedAt).getTime()) / 60000
                              )} Min.
                            </span>
                          )}
                          {req.status === 'fehlgeschlagen' && req.failureReason && (
                            <span style={{ color: 'var(--danger)' }}>{req.failureReason}</span>
                          )}
                          {req.status === 'ausstehend' && (
                            <span style={{ color: 'var(--warning)' }}>Wartet auf Bestätigung</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {requests.length === 0 && (
              <div className="text-center py-12" style={{ color: 'var(--text-muted)' }}>
                <ArrowPathIcon className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p className="text-sm">Keine Reset-Anfragen vorhanden</p>
              </div>
            )}
          </div>
        )}

        {/* ── Tab: Konfiguration ─────────────────────────────────────────── */}
        {activeTab === 'konfiguration' && (
          <div className="p-5 space-y-6 max-w-2xl">

            {/* Master toggle */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Allgemein</h2>
              <div className="rounded-xl px-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <Toggle
                  enabled={config.enabled}
                  onChange={v => setConfig(c => ({ ...c, enabled: v }))}
                  label="SSPR aktiviert"
                  description="Erlaubt Benutzern, ihr Passwort selbst zurückzusetzen."
                />
              </div>
            </section>

            {/* Verification methods */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Verifikationsmethoden</h2>
              <div className="rounded-xl px-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div style={{ borderBottom: '1px solid var(--border)' }}>
                  <Toggle
                    enabled={config.emailVerification}
                    onChange={v => setConfig(c => ({ ...c, emailVerification: v }))}
                    label="E-Mail-Verifikation"
                    description="Sendet einen Reset-Link an die hinterlegte E-Mail-Adresse."
                  />
                </div>
                <div style={{ borderBottom: '1px solid var(--border)' }}>
                  <Toggle
                    enabled={config.smsVerification}
                    onChange={v => setConfig(c => ({ ...c, smsVerification: v }))}
                    label="SMS-Verifikation"
                    description="Sendet einen Einmalcode per SMS. Erfordert konfiguriertes SMS-Gateway."
                  />
                </div>
                <Toggle
                  enabled={config.securityQuestions}
                  onChange={v => setConfig(c => ({ ...c, securityQuestions: v }))}
                  label="Sicherheitsfragen"
                  description="Benutzer beantworten vorregistrierte Sicherheitsfragen."
                />
              </div>
            </section>

            {/* Min methods */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Mindestanzahl Verifikationsmethoden</h2>
              <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div className="flex items-center gap-4">
                  <input
                    type="number"
                    min={1}
                    max={3}
                    value={config.minVerificationMethods}
                    onChange={e =>
                      setConfig(c => ({
                        ...c,
                        minVerificationMethods: Math.min(3, Math.max(1, Number(e.target.value))),
                      }))
                    }
                    className="w-20 focus:ring-2"
                    style={{ ...inputStyle, width: '5rem' }}
                  />
                  <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Methode(n) muss der Benutzer bei einem Reset bestätigen (1–3)</p>
                </div>
              </div>
            </section>

            {/* Security */}
            <section>
              <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>Sicherheit</h2>
              <div className="rounded-xl px-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div style={{ borderBottom: '1px solid var(--border)' }}>
                  <Toggle
                    enabled={config.requireMfaOnReset}
                    onChange={v => setConfig(c => ({ ...c, requireMfaOnReset: v }))}
                    label="MFA-Verifizierung beim Reset erforderlich"
                    description="Benutzer mit aktiviertem MFA müssen sich zusätzlich via MFA verifizieren."
                  />
                </div>
                <div className="flex items-start justify-between py-3">
                  <div className="flex-1 pr-4">
                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Reset-Link Ablauf</p>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Gültigkeit des E-Mail-Reset-Links in Minuten.</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min={5}
                      max={1440}
                      value={config.resetLinkExpiryMinutes}
                      onChange={e =>
                        setConfig(c => ({
                          ...c,
                          resetLinkExpiryMinutes: Math.min(1440, Math.max(5, Number(e.target.value))),
                        }))
                      }
                      style={{ ...inputStyle, width: '5rem' }}
                    />
                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>Min.</span>
                  </div>
                </div>
              </div>
            </section>

            <button
              onClick={handleSaveConfig}
              className="px-5 py-2 text-sm font-medium text-white rounded-xl transition-colors shadow-sm"
              style={{ background: 'var(--accent)' }}
            >
              Konfiguration speichern
            </button>
          </div>
        )}

        {/* ── Tab: Sicherheitsfragen ──────────────────────────────────────── */}
        {activeTab === 'fragen' && (
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                {questions.length} Frage{questions.length !== 1 ? 'n' : ''} konfiguriert
              </p>
              <button
                onClick={() => setShowAddQuestion(o => !o)}
                className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-white rounded-lg transition-colors shadow-sm"
                style={{ background: 'var(--accent)' }}
              >
                <PlusIcon className="h-4 w-4" />
                Frage hinzufügen
              </button>
            </div>

            {/* Add question form */}
            {showAddQuestion && (
              <div className="rounded-xl p-4 space-y-3" style={{ background: 'var(--accent-light)', border: '1px solid var(--accent)' }}>
                <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Neue Sicherheitsfrage</p>
                <div className="space-y-2">
                  <textarea
                    value={newQuestion}
                    onChange={e => setNewQuestion(e.target.value)}
                    placeholder="Fragetext eingeben…"
                    rows={2}
                    style={{ ...inputStyle, width: '100%', resize: 'none' }}
                  />
                  <div className="flex items-center gap-2">
                    <select
                      value={newCategory}
                      onChange={e => setNewCategory(e.target.value)}
                      style={inputStyle}
                    >
                      {CATEGORIES.map(cat => (
                        <option key={cat} value={cat}>{cat}</option>
                      ))}
                    </select>
                    <button
                      onClick={handleAddQuestion}
                      disabled={!newQuestion.trim()}
                      className="px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                      style={{ background: 'var(--accent)' }}
                    >
                      Hinzufügen
                    </button>
                    <button
                      onClick={() => { setShowAddQuestion(false); setNewQuestion(''); }}
                      className="px-4 py-2 text-sm font-medium rounded-lg transition-colors"
                      style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
                    >
                      Abbrechen
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Questions list */}
            <div className="space-y-2">
              {questions.map(q => (
                <div key={q.id} className="rounded-xl p-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                  {editingQuestion?.id === q.id ? (
                    <div className="space-y-2">
                      <textarea
                        value={editingQuestion.question}
                        onChange={e => setEditingQuestion({ ...editingQuestion, question: e.target.value })}
                        rows={2}
                        style={{ ...inputStyle, width: '100%', resize: 'none' }}
                      />
                      <div className="flex items-center gap-2">
                        <select
                          value={editingQuestion.category}
                          onChange={e => setEditingQuestion({ ...editingQuestion, category: e.target.value })}
                          style={inputStyle}
                        >
                          {CATEGORIES.map(cat => (
                            <option key={cat} value={cat}>{cat}</option>
                          ))}
                        </select>
                        <button
                          onClick={handleUpdateQuestion}
                          className="px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors"
                          style={{ background: 'var(--accent)' }}
                        >
                          Speichern
                        </button>
                        <button
                          onClick={() => setEditingQuestion(null)}
                          className="px-4 py-2 text-sm font-medium rounded-lg transition-colors"
                          style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
                        >
                          Abbrechen
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-2">
                        <QuestionMarkCircleIcon className="h-4 w-4 mt-0.5 shrink-0" style={{ color: 'var(--accent)' }} />
                        <div>
                          <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{q.question}</p>
                          <span className="text-xs mt-0.5 inline-block" style={{ color: 'var(--text-muted)' }}>
                            Kategorie: {q.category}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => setEditingQuestion(q)}
                          className="p-1.5 rounded-lg transition-colors"
                          title="Bearbeiten"
                          style={{ color: 'var(--text-muted)' }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = 'var(--accent)'; (e.currentTarget as HTMLElement).style.background = 'var(--accent-light)'; }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'; (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteQuestion(q.id)}
                          className="p-1.5 rounded-lg transition-colors"
                          title="Löschen"
                          style={{ color: 'var(--text-muted)' }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = 'var(--danger)'; (e.currentTarget as HTMLElement).style.background = 'var(--danger-light)'; }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'; (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {questions.length === 0 && !showAddQuestion && (
              <div className="text-center py-12" style={{ color: 'var(--text-muted)' }}>
                <QuestionMarkCircleIcon className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p className="text-sm">Keine Sicherheitsfragen konfiguriert</p>
                <p className="text-xs mt-1">Klicken Sie auf "Frage hinzufügen", um zu beginnen.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
