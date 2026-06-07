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

const STATUS_STYLES: Record<ResetStatus, string> = {
  abgeschlossen: 'bg-green-50 text-green-700 border-green-200',
  fehlgeschlagen: 'bg-red-50 text-red-700 border-red-200',
  ausstehend: 'bg-yellow-50 text-yellow-700 border-yellow-200',
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
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${STATUS_STYLES[status]}`}>
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
        <p className="text-sm font-medium text-gray-900">{label}</p>
        {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
      </div>
      <button
        type="button"
        onClick={() => onChange(!enabled)}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#0071E3] focus-visible:ring-offset-2 ${
          enabled ? 'bg-[#0071E3]' : 'bg-gray-200'
        }`}
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
  color,
  suffix,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  suffix?: string;
}) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4 flex items-center gap-3">
      <div className={`h-10 w-10 rounded-xl flex items-center justify-center shrink-0 ${color}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="text-2xl font-semibold text-gray-900">
          {value}
          {suffix && <span className="text-sm font-normal text-gray-400 ml-1">{suffix}</span>}
        </p>
        <p className="text-xs text-gray-500 mt-0.5">{label}</p>
      </div>
    </div>
  );
}

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
    <div className="min-h-screen bg-[#F2F2F7] p-6 space-y-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-[#0071E3] flex items-center justify-center shadow-sm">
            <KeyIcon className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Self-Service Passwort-Reset</h1>
            <p className="text-sm text-gray-500">Konfiguration und Überwachung von SSPR-Anfragen</p>
          </div>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors shadow-sm"
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
          color="bg-green-50 text-green-600"
        />
        <StatCard
          label="Resets diese Woche"
          value={stats.resetsThisWeek}
          icon={ArrowPathIcon}
          color="bg-blue-50 text-blue-600"
        />
        <StatCard
          label="Fehlversuche"
          value={stats.failedAttempts}
          icon={ExclamationTriangleIcon}
          color="bg-red-50 text-red-600"
        />
        <StatCard
          label="Durchschnittliche Reset-Zeit"
          value={stats.avgResetTimeMinutes}
          suffix="Min."
          icon={ClockIcon}
          color="bg-orange-50 text-orange-600"
        />
      </div>

      {/* ── Tabs ───────────────────────────────────────────────────────────── */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <div className="flex border-b border-gray-100">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-3 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'text-[#0071E3] border-b-2 border-[#0071E3] bg-blue-50/40'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
              }`}
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
                  <tr className="border-b border-gray-100 bg-gray-50/50">
                    <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Benutzer</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Methode</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Zeitstempel</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">IP-Adresse</th>
                    <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {requests.map(req => {
                    const MethodIcon = METHOD_ICONS[req.method];
                    return (
                      <tr key={req.id} className="hover:bg-gray-50/50 transition-colors">
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-7 w-7 rounded-full bg-gray-100 flex items-center justify-center shrink-0">
                              <UserIcon className="h-4 w-4 text-gray-500" />
                            </div>
                            <div>
                              <p className="font-medium text-gray-900">{req.displayName}</p>
                              <p className="text-xs text-gray-400">{req.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <StatusBadge status={req.status} />
                        </td>
                        <td className="px-5 py-3">
                          <span className="inline-flex items-center gap-1 text-gray-600">
                            <MethodIcon className="h-4 w-4 text-gray-400" />
                            {METHOD_LABELS[req.method]}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-gray-500 text-xs">
                          {new Date(req.requestedAt).toLocaleString('de-CH', {
                            day: '2-digit',
                            month: '2-digit',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </td>
                        <td className="px-5 py-3 text-gray-400 text-xs font-mono">{req.ipAddress}</td>
                        <td className="px-5 py-3 text-xs text-gray-500">
                          {req.status === 'abgeschlossen' && req.completedAt && (
                            <span className="text-green-600">
                              {Math.round(
                                (new Date(req.completedAt).getTime() - new Date(req.requestedAt).getTime()) / 60000
                              )} Min.
                            </span>
                          )}
                          {req.status === 'fehlgeschlagen' && req.failureReason && (
                            <span className="text-red-500">{req.failureReason}</span>
                          )}
                          {req.status === 'ausstehend' && (
                            <span className="text-yellow-600">Wartet auf Bestätigung</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {requests.length === 0 && (
              <div className="text-center py-12 text-gray-400">
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
              <h2 className="text-sm font-semibold text-gray-700 mb-1">Allgemein</h2>
              <div className="bg-gray-50 rounded-xl border border-gray-100 px-4">
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
              <h2 className="text-sm font-semibold text-gray-700 mb-1">Verifikationsmethoden</h2>
              <div className="bg-gray-50 rounded-xl border border-gray-100 px-4 divide-y divide-gray-100">
                <Toggle
                  enabled={config.emailVerification}
                  onChange={v => setConfig(c => ({ ...c, emailVerification: v }))}
                  label="E-Mail-Verifikation"
                  description="Sendet einen Reset-Link an die hinterlegte E-Mail-Adresse."
                />
                <Toggle
                  enabled={config.smsVerification}
                  onChange={v => setConfig(c => ({ ...c, smsVerification: v }))}
                  label="SMS-Verifikation"
                  description="Sendet einen Einmalcode per SMS. Erfordert konfiguriertes SMS-Gateway."
                />
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
              <h2 className="text-sm font-semibold text-gray-700 mb-1">Mindestanzahl Verifikationsmethoden</h2>
              <div className="bg-gray-50 rounded-xl border border-gray-100 p-4">
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
                    className="w-20 px-3 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3] focus:border-transparent"
                  />
                  <p className="text-sm text-gray-500">Methode(n) muss der Benutzer bei einem Reset bestätigen (1–3)</p>
                </div>
              </div>
            </section>

            {/* Security */}
            <section>
              <h2 className="text-sm font-semibold text-gray-700 mb-1">Sicherheit</h2>
              <div className="bg-gray-50 rounded-xl border border-gray-100 px-4 divide-y divide-gray-100">
                <Toggle
                  enabled={config.requireMfaOnReset}
                  onChange={v => setConfig(c => ({ ...c, requireMfaOnReset: v }))}
                  label="MFA-Verifizierung beim Reset erforderlich"
                  description="Benutzer mit aktiviertem MFA müssen sich zusätzlich via MFA verifizieren."
                />
                <div className="flex items-start justify-between py-3">
                  <div className="flex-1 pr-4">
                    <p className="text-sm font-medium text-gray-900">Reset-Link Ablauf</p>
                    <p className="text-xs text-gray-500 mt-0.5">Gültigkeit des E-Mail-Reset-Links in Minuten.</p>
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
                      className="w-20 px-3 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3] focus:border-transparent"
                    />
                    <span className="text-sm text-gray-500">Min.</span>
                  </div>
                </div>
              </div>
            </section>

            <button
              onClick={handleSaveConfig}
              className="px-5 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-xl hover:bg-[#005BB5] transition-colors shadow-sm"
            >
              Konfiguration speichern
            </button>
          </div>
        )}

        {/* ── Tab: Sicherheitsfragen ──────────────────────────────────────── */}
        {activeTab === 'fragen' && (
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-500">
                {questions.length} Frage{questions.length !== 1 ? 'n' : ''} konfiguriert
              </p>
              <button
                onClick={() => setShowAddQuestion(o => !o)}
                className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#005BB5] transition-colors shadow-sm"
              >
                <PlusIcon className="h-4 w-4" />
                Frage hinzufügen
              </button>
            </div>

            {/* Add question form */}
            {showAddQuestion && (
              <div className="bg-blue-50 border border-blue-100 rounded-xl p-4 space-y-3">
                <p className="text-sm font-semibold text-gray-800">Neue Sicherheitsfrage</p>
                <div className="space-y-2">
                  <textarea
                    value={newQuestion}
                    onChange={e => setNewQuestion(e.target.value)}
                    placeholder="Fragetext eingeben…"
                    rows={2}
                    className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3] focus:border-transparent resize-none"
                  />
                  <div className="flex items-center gap-2">
                    <select
                      value={newCategory}
                      onChange={e => setNewCategory(e.target.value)}
                      className="px-3 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3] focus:border-transparent"
                    >
                      {CATEGORIES.map(cat => (
                        <option key={cat} value={cat}>{cat}</option>
                      ))}
                    </select>
                    <button
                      onClick={handleAddQuestion}
                      disabled={!newQuestion.trim()}
                      className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#005BB5] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Hinzufügen
                    </button>
                    <button
                      onClick={() => { setShowAddQuestion(false); setNewQuestion(''); }}
                      className="px-4 py-2 text-sm font-medium text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
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
                <div key={q.id} className="bg-gray-50 border border-gray-100 rounded-xl p-4">
                  {editingQuestion?.id === q.id ? (
                    <div className="space-y-2">
                      <textarea
                        value={editingQuestion.question}
                        onChange={e => setEditingQuestion({ ...editingQuestion, question: e.target.value })}
                        rows={2}
                        className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3] focus:border-transparent resize-none"
                      />
                      <div className="flex items-center gap-2">
                        <select
                          value={editingQuestion.category}
                          onChange={e => setEditingQuestion({ ...editingQuestion, category: e.target.value })}
                          className="px-3 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3] focus:border-transparent"
                        >
                          {CATEGORIES.map(cat => (
                            <option key={cat} value={cat}>{cat}</option>
                          ))}
                        </select>
                        <button
                          onClick={handleUpdateQuestion}
                          className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#005BB5] transition-colors"
                        >
                          Speichern
                        </button>
                        <button
                          onClick={() => setEditingQuestion(null)}
                          className="px-4 py-2 text-sm font-medium text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                        >
                          Abbrechen
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-2">
                        <QuestionMarkCircleIcon className="h-4 w-4 text-[#0071E3] mt-0.5 shrink-0" />
                        <div>
                          <p className="text-sm text-gray-900">{q.question}</p>
                          <span className="text-xs text-gray-400 mt-0.5 inline-block">
                            Kategorie: {q.category}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => setEditingQuestion(q)}
                          className="p-1.5 text-gray-400 hover:text-[#0071E3] hover:bg-blue-50 rounded-lg transition-colors"
                          title="Bearbeiten"
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteQuestion(q.id)}
                          className="p-1.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                          title="Löschen"
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
              <div className="text-center py-12 text-gray-400">
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
