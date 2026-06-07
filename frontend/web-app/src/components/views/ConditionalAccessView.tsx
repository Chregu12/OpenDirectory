'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  PlusIcon,
  XMarkIcon,
  PencilIcon,
  TrashIcon,
  MapPinIcon,
  DevicePhoneMobileIcon,
  ClockIcon,
  UserGroupIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  FunnelIcon,
  ArrowPathIcon,
  LockClosedIcon,
  ComputerDesktopIcon,
  KeyIcon,
  SignalIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

type PolicyAction = 'allow' | 'block' | 'mfa' | 'compliant';
type RiskLevel = 'any' | 'low' | 'medium' | 'high';
type PolicyTab = 'richtlinien' | 'ereignisse' | 'locations' | 'risiko';
type EventResult = 'allowed' | 'blocked' | 'mfa_required';

interface ConditionalPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  users: string[];
  allUsers: boolean;
  conditions: {
    locations: string[];
    blockedLocations: string[];
    deviceCompliant: boolean;
    hybridJoined: boolean;
    riskLevel: RiskLevel;
    apps: string[];
    allApps: boolean;
    timeWindow?: { start: string; end: string };
  };
  action: PolicyAction;
  sessionDuration?: number;
  createdAt: string;
}

interface LoginEvent {
  id: string;
  user: string;
  app: string;
  ip: string;
  location: string;
  device: string;
  riskScore: number;
  result: EventResult;
  timestamp: string;
}

interface NamedLocation {
  id: string;
  name: string;
  type: 'ip' | 'country';
  values: string[];
  trusted: boolean;
}

interface RiskConfig {
  loginFrequencyWeight: number;
  impossibleTravelEnabled: boolean;
  leakedCredentialsCheck: boolean;
  deviceComplianceWeight: number;
  anomalyThreshold: number;
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_POLICIES: ConditionalPolicy[] = [
  {
    id: '1',
    name: 'MFA für externe Anmeldungen',
    description: 'Erzwingt MFA für alle Anmeldungen außerhalb des Unternehmensnetzwerks',
    enabled: true,
    users: [],
    allUsers: true,
    conditions: {
      locations: [],
      blockedLocations: ['CN', 'RU', 'KP'],
      deviceCompliant: false,
      hybridJoined: false,
      riskLevel: 'any',
      apps: [],
      allApps: true,
      timeWindow: undefined,
    },
    action: 'mfa',
    sessionDuration: 480,
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: '2',
    name: 'Admin-Zugang blockieren (Hochrisiko)',
    description: 'Blockiert Admin-Konten bei hohem Risiko-Score',
    enabled: true,
    users: ['admins', 'it-admins'],
    allUsers: false,
    conditions: {
      locations: [],
      blockedLocations: [],
      deviceCompliant: true,
      hybridJoined: false,
      riskLevel: 'high',
      apps: [],
      allApps: true,
    },
    action: 'block',
    createdAt: new Date(Date.now() - 86400000 * 15).toISOString(),
  },
  {
    id: '3',
    name: 'Konformes Gerät für sensible Apps',
    description: 'Zugriff auf sensible Apps nur von konformen Geräten',
    enabled: false,
    users: [],
    allUsers: true,
    conditions: {
      locations: [],
      blockedLocations: [],
      deviceCompliant: true,
      hybridJoined: false,
      riskLevel: 'any',
      apps: ['Finanzen', 'HR-System', 'Kundendaten'],
      allApps: false,
    },
    action: 'compliant',
    createdAt: new Date(Date.now() - 86400000 * 7).toISOString(),
  },
];

const MOCK_EVENTS: LoginEvent[] = [
  { id: '1', user: 'alice@firma.local', app: 'Nextcloud', ip: '192.168.1.10', location: 'CH', device: 'MacBook Pro', riskScore: 5, result: 'allowed', timestamp: new Date(Date.now() - 300000).toISOString() },
  { id: '2', user: 'bob@firma.local', app: 'Grafana', ip: '203.0.113.50', location: 'DE', device: 'Windows Laptop', riskScore: 42, result: 'mfa_required', timestamp: new Date(Date.now() - 900000).toISOString() },
  { id: '3', user: 'unknown@extern.com', app: 'Admin-Panel', ip: '185.220.101.5', location: 'RU', device: 'Unbekannt', riskScore: 95, result: 'blocked', timestamp: new Date(Date.now() - 1800000).toISOString() },
  { id: '4', user: 'carol@firma.local', app: 'HR-System', ip: '10.0.0.5', location: 'CH', device: 'iPad', riskScore: 12, result: 'allowed', timestamp: new Date(Date.now() - 3600000).toISOString() },
  { id: '5', user: 'david@firma.local', app: 'Nextcloud', ip: '198.51.100.20', location: 'US', device: 'iPhone', riskScore: 28, result: 'mfa_required', timestamp: new Date(Date.now() - 7200000).toISOString() },
  { id: '6', user: 'attacker@evil.io', app: 'Admin-Panel', ip: '45.77.65.211', location: 'CN', device: 'Unbekannt', riskScore: 99, result: 'blocked', timestamp: new Date(Date.now() - 10800000).toISOString() },
];

const MOCK_LOCATIONS: NamedLocation[] = [
  { id: '1', name: 'Büro Zürich', type: 'ip', values: ['192.168.1.0/24', '10.0.0.0/8'], trusted: true },
  { id: '2', name: 'Büro Berlin', type: 'ip', values: ['172.16.0.0/12'], trusted: true },
  { id: '3', name: 'Erlaubte Länder (DACH)', type: 'country', values: ['CH', 'DE', 'AT'], trusted: true },
  { id: '4', name: 'Risikoländer', type: 'country', values: ['CN', 'RU', 'KP', 'IR'], trusted: false },
];

const MOCK_RISK_CONFIG: RiskConfig = {
  loginFrequencyWeight: 30,
  impossibleTravelEnabled: true,
  leakedCredentialsCheck: true,
  deviceComplianceWeight: 40,
  anomalyThreshold: 70,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(ts: string) {
  return new Date(ts).toLocaleString('de-CH', { dateStyle: 'short', timeStyle: 'short' });
}

function fmtRelative(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'gerade eben';
  if (m < 60) return `vor ${m} Min.`;
  const h = Math.floor(m / 60);
  if (h < 24) return `vor ${h} Std.`;
  return `vor ${Math.floor(h / 24)} Tagen`;
}

const ACTION_LABELS: Record<PolicyAction, string> = {
  allow: 'Zulassen',
  block: 'Blockieren',
  mfa: 'MFA erforderlich',
  compliant: 'Konformes Gerät',
};

const ACTION_STYLES: Record<PolicyAction, string> = {
  allow: 'bg-green-50 text-green-700 border-green-200',
  block: 'bg-red-50 text-red-700 border-red-200',
  mfa: 'bg-blue-50 text-blue-700 border-blue-200',
  compliant: 'bg-purple-50 text-purple-700 border-purple-200',
};

const RESULT_LABELS: Record<EventResult, string> = {
  allowed: 'Zugelassen',
  blocked: 'Blockiert',
  mfa_required: 'MFA gefordert',
};

const RESULT_STYLES: Record<EventResult, string> = {
  allowed: 'bg-green-50 text-green-700 border-green-200',
  blocked: 'bg-red-50 text-red-700 border-red-200',
  mfa_required: 'bg-yellow-50 text-yellow-700 border-yellow-200',
};

function RiskBadge({ score }: { score: number }) {
  const style =
    score >= 70 ? 'bg-red-100 text-red-800 border-red-200' :
    score >= 35 ? 'bg-orange-100 text-orange-800 border-orange-200' :
    'bg-green-100 text-green-800 border-green-200';
  const label = score >= 70 ? 'Hoch' : score >= 35 ? 'Mittel' : 'Niedrig';
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${style}`}>
      {label} ({score})
    </span>
  );
}

// ─── Policy Modal ─────────────────────────────────────────────────────────────

interface PolicyModalProps {
  policy?: ConditionalPolicy;
  onClose: () => void;
  onSaved: (p: ConditionalPolicy) => void;
}

function PolicyModal({ policy, onClose, onSaved }: PolicyModalProps) {
  const [form, setForm] = useState<Omit<ConditionalPolicy, 'id' | 'createdAt'>>({
    name: policy?.name ?? '',
    description: policy?.description ?? '',
    enabled: policy?.enabled ?? true,
    users: policy?.users ?? [],
    allUsers: policy?.allUsers ?? true,
    conditions: {
      locations: policy?.conditions.locations ?? [],
      blockedLocations: policy?.conditions.blockedLocations ?? [],
      deviceCompliant: policy?.conditions.deviceCompliant ?? false,
      hybridJoined: policy?.conditions.hybridJoined ?? false,
      riskLevel: policy?.conditions.riskLevel ?? 'any',
      apps: policy?.conditions.apps ?? [],
      allApps: policy?.conditions.allApps ?? true,
      timeWindow: policy?.conditions.timeWindow,
    },
    action: policy?.action ?? 'mfa',
    sessionDuration: policy?.sessionDuration,
  });
  const [saving, setSaving] = useState(false);
  const [allowedIp, setAllowedIp] = useState('');
  const [blockedCountry, setBlockedCountry] = useState('');
  const [appInput, setAppInput] = useState('');
  const [userInput, setUserInput] = useState('');

  const save = async () => {
    if (!form.name.trim()) {
      toast.error('Name ist ein Pflichtfeld');
      return;
    }
    setSaving(true);
    try {
      const payload = { ...form, id: policy?.id ?? String(Date.now()), createdAt: policy?.createdAt ?? new Date().toISOString() };
      if (policy) {
        await api.put(`/api/conditional-access/policies/${policy.id}`, payload).catch(() => {});
      } else {
        await api.post('/api/conditional-access/policies', payload).catch(() => {});
      }
      toast.success(policy ? 'Richtlinie aktualisiert' : 'Richtlinie erstellt');
      onSaved(payload as ConditionalPolicy);
      onClose();
    } finally {
      setSaving(false);
    }
  };

  const addToList = (field: 'locations' | 'blockedLocations', value: string, setter: (v: string) => void) => {
    if (!value.trim()) return;
    setForm(f => ({ ...f, conditions: { ...f.conditions, [field]: [...f.conditions[field], value.trim()] } }));
    setter('');
  };

  const removeFromList = (field: 'locations' | 'blockedLocations', idx: number) => {
    setForm(f => ({ ...f, conditions: { ...f.conditions, [field]: f.conditions[field].filter((_, i) => i !== idx) } }));
  };

  const addApp = () => {
    if (!appInput.trim()) return;
    setForm(f => ({ ...f, conditions: { ...f.conditions, apps: [...f.conditions.apps, appInput.trim()], allApps: false } }));
    setAppInput('');
  };

  const addUser = () => {
    if (!userInput.trim()) return;
    setForm(f => ({ ...f, users: [...f.users, userInput.trim()], allUsers: false }));
    setUserInput('');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">
            {policy ? 'Richtlinie bearbeiten' : 'Neue Richtlinie'}
          </h2>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-gray-100 transition-colors">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-5">
          {/* Basic */}
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
              <input
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                placeholder="z.B. MFA für externe Zugriffe"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Beschreibung</label>
              <textarea
                value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                rows={2}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3] resize-none"
                placeholder="Optionale Beschreibung"
              />
            </div>
          </div>

          {/* Zuweisungen */}
          <div>
            <h3 className="text-sm font-semibold text-gray-800 mb-2 flex items-center gap-2">
              <UserGroupIcon className="w-4 h-4 text-[#0071E3]" />
              Zuweisungen
            </h3>
            <label className="flex items-center gap-2 cursor-pointer mb-2">
              <input
                type="checkbox"
                checked={form.allUsers}
                onChange={e => setForm(f => ({ ...f, allUsers: e.target.checked }))}
                className="w-4 h-4 accent-[#0071E3]"
              />
              <span className="text-sm text-gray-700">Alle Benutzer</span>
            </label>
            {!form.allUsers && (
              <div>
                <div className="flex gap-2 mb-2">
                  <input
                    value={userInput}
                    onChange={e => setUserInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addUser()}
                    className="flex-1 border border-gray-200 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                    placeholder="Benutzer oder Gruppe hinzufügen"
                  />
                  <button onClick={addUser} className="px-3 py-1.5 bg-[#0071E3] text-white text-sm rounded-lg hover:bg-[#005BBE] transition-colors">
                    +
                  </button>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {form.users.map((u, i) => (
                    <span key={i} className="inline-flex items-center gap-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-full px-2.5 py-0.5 text-xs">
                      {u}
                      <button onClick={() => setForm(f => ({ ...f, users: f.users.filter((_, idx) => idx !== i) }))} className="hover:text-blue-900">
                        <XMarkIcon className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Bedingungen */}
          <div>
            <h3 className="text-sm font-semibold text-gray-800 mb-2 flex items-center gap-2">
              <FunnelIcon className="w-4 h-4 text-[#0071E3]" />
              Bedingungen
            </h3>
            <div className="space-y-3 bg-gray-50 rounded-xl p-4">
              {/* Standort */}
              <div>
                <p className="text-xs font-medium text-gray-600 mb-1.5 flex items-center gap-1.5">
                  <MapPinIcon className="w-3.5 h-3.5" /> Standort (erlaubte IPs/Subnetze)
                </p>
                <div className="flex gap-2 mb-1.5">
                  <input
                    value={allowedIp}
                    onChange={e => setAllowedIp(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addToList('locations', allowedIp, setAllowedIp)}
                    className="flex-1 border border-gray-200 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3] bg-white"
                    placeholder="192.168.1.0/24 oder CH"
                  />
                  <button onClick={() => addToList('locations', allowedIp, setAllowedIp)} className="px-2.5 py-1.5 bg-green-600 text-white text-xs rounded-lg hover:bg-green-700">+</button>
                </div>
                <div className="flex flex-wrap gap-1">
                  {form.conditions.locations.map((loc, i) => (
                    <span key={i} className="inline-flex items-center gap-1 bg-green-50 text-green-700 border border-green-200 rounded-full px-2 py-0.5 text-xs">
                      {loc}
                      <button onClick={() => removeFromList('locations', i)}><XMarkIcon className="w-3 h-3" /></button>
                    </span>
                  ))}
                </div>
              </div>

              {/* Blockierte Länder */}
              <div>
                <p className="text-xs font-medium text-gray-600 mb-1.5 flex items-center gap-1.5">
                  <XCircleIcon className="w-3.5 h-3.5 text-red-500" /> Blockierte Länder (ISO-Code)
                </p>
                <div className="flex gap-2 mb-1.5">
                  <input
                    value={blockedCountry}
                    onChange={e => setBlockedCountry(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addToList('blockedLocations', blockedCountry, setBlockedCountry)}
                    className="flex-1 border border-gray-200 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3] bg-white"
                    placeholder="z.B. CN, RU, KP"
                  />
                  <button onClick={() => addToList('blockedLocations', blockedCountry, setBlockedCountry)} className="px-2.5 py-1.5 bg-red-500 text-white text-xs rounded-lg hover:bg-red-600">+</button>
                </div>
                <div className="flex flex-wrap gap-1">
                  {form.conditions.blockedLocations.map((loc, i) => (
                    <span key={i} className="inline-flex items-center gap-1 bg-red-50 text-red-700 border border-red-200 rounded-full px-2 py-0.5 text-xs">
                      {loc}
                      <button onClick={() => removeFromList('blockedLocations', i)}><XMarkIcon className="w-3 h-3" /></button>
                    </span>
                  ))}
                </div>
              </div>

              {/* Gerätezustand */}
              <div>
                <p className="text-xs font-medium text-gray-600 mb-1.5 flex items-center gap-1.5">
                  <ComputerDesktopIcon className="w-3.5 h-3.5" /> Gerätezustand
                </p>
                <div className="space-y-1.5">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={form.conditions.deviceCompliant} onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, deviceCompliant: e.target.checked } }))} className="w-3.5 h-3.5 accent-[#0071E3]" />
                    <span className="text-xs text-gray-700">Konformes Gerät erforderlich</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={form.conditions.hybridJoined} onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, hybridJoined: e.target.checked } }))} className="w-3.5 h-3.5 accent-[#0071E3]" />
                    <span className="text-xs text-gray-700">Hybrid-joined erforderlich</span>
                  </label>
                </div>
              </div>

              {/* Risiko & App & Zeit */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5">
                    <SignalIcon className="w-3.5 h-3.5" /> Risiko-Level
                  </p>
                  <select
                    value={form.conditions.riskLevel}
                    onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, riskLevel: e.target.value as RiskLevel } }))}
                    className="w-full border border-gray-200 rounded-lg px-2.5 py-1.5 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30"
                  >
                    <option value="any">Beliebig</option>
                    <option value="low">Niedrig</option>
                    <option value="medium">Mittel</option>
                    <option value="high">Hoch</option>
                  </select>
                </div>
                <div>
                  <p className="text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5">
                    <ClockIcon className="w-3.5 h-3.5" /> Zeitfenster
                  </p>
                  <div className="flex items-center gap-1">
                    <input
                      type="time"
                      value={form.conditions.timeWindow?.start ?? ''}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, timeWindow: { start: e.target.value, end: f.conditions.timeWindow?.end ?? '18:00' } } }))}
                      className="flex-1 border border-gray-200 rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none"
                    />
                    <span className="text-xs text-gray-400">–</span>
                    <input
                      type="time"
                      value={form.conditions.timeWindow?.end ?? ''}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, timeWindow: { start: f.conditions.timeWindow?.start ?? '08:00', end: e.target.value } } }))}
                      className="flex-1 border border-gray-200 rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none"
                    />
                  </div>
                </div>
              </div>

              {/* Apps */}
              <div>
                <p className="text-xs font-medium text-gray-600 mb-1.5">Apps</p>
                <label className="flex items-center gap-2 cursor-pointer mb-1.5">
                  <input type="checkbox" checked={form.conditions.allApps} onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, allApps: e.target.checked } }))} className="w-3.5 h-3.5 accent-[#0071E3]" />
                  <span className="text-xs text-gray-700">Alle Apps</span>
                </label>
                {!form.conditions.allApps && (
                  <div>
                    <div className="flex gap-2 mb-1.5">
                      <input value={appInput} onChange={e => setAppInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && addApp()} className="flex-1 border border-gray-200 rounded-lg px-3 py-1.5 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30" placeholder="App-Name" />
                      <button onClick={addApp} className="px-2.5 py-1.5 bg-[#0071E3] text-white text-xs rounded-lg hover:bg-[#005BBE]">+</button>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {form.conditions.apps.map((a, i) => (
                        <span key={i} className="inline-flex items-center gap-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-full px-2 py-0.5 text-xs">
                          {a}
                          <button onClick={() => setForm(f => ({ ...f, conditions: { ...f.conditions, apps: f.conditions.apps.filter((_, idx) => idx !== i) } }))}><XMarkIcon className="w-3 h-3" /></button>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Zugriffssteuerung */}
          <div>
            <h3 className="text-sm font-semibold text-gray-800 mb-2 flex items-center gap-2">
              <LockClosedIcon className="w-4 h-4 text-[#0071E3]" />
              Zugriffssteuerung
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {(['allow', 'block', 'mfa', 'compliant'] as PolicyAction[]).map(a => (
                <label key={a} className={`flex items-center gap-3 p-3 border-2 rounded-xl cursor-pointer transition-all ${form.action === a ? 'border-[#0071E3] bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}>
                  <input type="radio" name="action" value={a} checked={form.action === a} onChange={() => setForm(f => ({ ...f, action: a }))} className="w-4 h-4 accent-[#0071E3]" />
                  <div>
                    <p className="text-sm font-medium text-gray-800">{ACTION_LABELS[a]}</p>
                  </div>
                </label>
              ))}
            </div>
            <div className="mt-3">
              <label className="block text-xs font-medium text-gray-600 mb-1">Session-Dauer Limit (Minuten, optional)</label>
              <input
                type="number"
                value={form.sessionDuration ?? ''}
                onChange={e => setForm(f => ({ ...f, sessionDuration: e.target.value ? Number(e.target.value) : undefined }))}
                className="w-40 border border-gray-200 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                placeholder="z.B. 480"
                min={1}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-100">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900 transition-colors">Abbrechen</button>
          <button onClick={save} disabled={saving} className="px-5 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#005BBE] disabled:opacity-50 transition-colors">
            {saving ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Location Modal ───────────────────────────────────────────────────────────

function LocationModal({ onClose, onSaved }: { onClose: () => void; onSaved: (loc: NamedLocation) => void }) {
  const [name, setName] = useState('');
  const [type, setType] = useState<'ip' | 'country'>('ip');
  const [values, setValues] = useState('');
  const [trusted, setTrusted] = useState(true);

  const save = () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    const loc: NamedLocation = {
      id: String(Date.now()),
      name: name.trim(),
      type,
      values: values.split(/[\s,]+/).map(v => v.trim()).filter(Boolean),
      trusted,
    };
    onSaved(loc);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Standort hinzufügen</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-gray-100"><XMarkIcon className="w-5 h-5 text-gray-500" /></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]" placeholder="z.B. Büro Zürich" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Typ</label>
            <select value={type} onChange={e => setType(e.target.value as 'ip' | 'country')} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30">
              <option value="ip">IP-Range / Subnetz</option>
              <option value="country">Länder (ISO-Code)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Werte (kommagetrennt)</label>
            <textarea value={values} onChange={e => setValues(e.target.value)} rows={3} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 resize-none" placeholder={type === 'ip' ? '192.168.1.0/24, 10.0.0.0/8' : 'CH, DE, AT'} />
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={trusted} onChange={e => setTrusted(e.target.checked)} className="w-4 h-4 accent-[#0071E3]" />
            <span className="text-sm text-gray-700">Als vertrauenswürdig markieren</span>
          </label>
        </div>
        <div className="flex items-center justify-end gap-3 mt-5">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">Abbrechen</button>
          <button onClick={save} className="px-5 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#005BBE]">Speichern</button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ConditionalAccessView() {
  const [tab, setTab] = useState<PolicyTab>('richtlinien');
  const [policies, setPolicies] = useState<ConditionalPolicy[]>([]);
  const [events, setEvents] = useState<LoginEvent[]>([]);
  const [locations, setLocations] = useState<NamedLocation[]>([]);
  const [riskConfig, setRiskConfig] = useState<RiskConfig>(MOCK_RISK_CONFIG);
  const [loading, setLoading] = useState(true);
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [editPolicy, setEditPolicy] = useState<ConditionalPolicy | undefined>();
  const [showLocationModal, setShowLocationModal] = useState(false);
  const [eventFilter, setEventFilter] = useState<EventResult | 'all'>('all');

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [polRes, evtRes, locRes] = await Promise.allSettled([
        api.get('/api/conditional-access/policies'),
        api.get('/api/conditional-access/events'),
        api.get('/api/conditional-access/locations'),
      ]);
      setPolicies(polRes.status === 'fulfilled' ? polRes.value.data : MOCK_POLICIES);
      setEvents(evtRes.status === 'fulfilled' ? evtRes.value.data : MOCK_EVENTS);
      setLocations(locRes.status === 'fulfilled' ? locRes.value.data : MOCK_LOCATIONS);
    } catch {
      setPolicies(MOCK_POLICIES);
      setEvents(MOCK_EVENTS);
      setLocations(MOCK_LOCATIONS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // Stats
  const totalPolicies = policies.length;
  const activePolicies = policies.filter(p => p.enabled).length;
  const blockedToday = events.filter(e => e.result === 'blocked').length;
  const mfaToday = events.filter(e => e.result === 'mfa_required').length;

  const togglePolicy = async (id: string) => {
    setPolicies(ps => ps.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));
    try {
      const p = policies.find(p => p.id === id);
      if (p) await api.patch(`/api/conditional-access/policies/${id}`, { enabled: !p.enabled }).catch(() => {});
    } catch { /* ignore */ }
  };

  const deletePolicy = async (id: string) => {
    if (!confirm('Richtlinie wirklich löschen?')) return;
    setPolicies(ps => ps.filter(p => p.id !== id));
    await api.delete(`/api/conditional-access/policies/${id}`).catch(() => {});
    toast.success('Richtlinie gelöscht');
  };

  const filteredEvents = eventFilter === 'all' ? events : events.filter(e => e.result === eventFilter);

  const TABS: { key: PolicyTab; label: string }[] = [
    { key: 'richtlinien', label: 'Richtlinien' },
    { key: 'ereignisse', label: 'Anmelde-Ereignisse' },
    { key: 'locations', label: 'Named Locations' },
    { key: 'risiko', label: 'Risiko-Konfiguration' },
  ];

  return (
    <div className="min-h-screen bg-[#F2F2F7] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Conditional Access</h1>
          <p className="text-sm text-gray-500 mt-0.5">Zero Trust Zugriffsverwaltung</p>
        </div>
        <button onClick={loadData} className="p-2 rounded-lg bg-white border border-gray-200 hover:bg-gray-50 transition-colors shadow-sm">
          <ArrowPathIcon className={`w-5 h-5 text-gray-500 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Richtlinien gesamt', value: totalPolicies, icon: ShieldCheckIcon, color: 'text-blue-600', bg: 'bg-blue-50' },
          { label: 'Aktiv', value: activePolicies, icon: CheckCircleIcon, color: 'text-green-600', bg: 'bg-green-50' },
          { label: 'Blockierte Anmeldungen heute', value: blockedToday, icon: XCircleIcon, color: 'text-red-600', bg: 'bg-red-50' },
          { label: 'MFA-Challenges heute', value: mfaToday, icon: KeyIcon, color: 'text-yellow-600', bg: 'bg-yellow-50' },
        ].map(stat => (
          <div key={stat.label} className="bg-white rounded-xl shadow-sm p-4 flex items-center gap-3">
            <div className={`${stat.bg} rounded-lg p-2.5`}>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
              <p className="text-xs text-gray-500">{stat.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <div className="flex border-b border-gray-100">
          {TABS.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-5 py-3.5 text-sm font-medium transition-colors ${
                tab === t.key
                  ? 'text-[#0071E3] border-b-2 border-[#0071E3]'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* Tab 1: Richtlinien */}
          {tab === 'richtlinien' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <p className="text-sm text-gray-500">{totalPolicies} Richtlinien konfiguriert</p>
                <button
                  onClick={() => { setEditPolicy(undefined); setShowPolicyModal(true); }}
                  className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#005BBE] transition-colors"
                >
                  <PlusIcon className="w-4 h-4" />
                  Neue Richtlinie
                </button>
              </div>

              {loading ? (
                <div className="text-center py-10 text-gray-400 text-sm">Lade Richtlinien…</div>
              ) : policies.length === 0 ? (
                <div className="text-center py-10 text-gray-400 text-sm">Keine Richtlinien vorhanden</div>
              ) : (
                <div className="space-y-3">
                  {policies.map(policy => (
                    <div key={policy.id} className="border border-gray-100 rounded-xl p-4 hover:border-gray-200 transition-colors">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium text-gray-900 text-sm">{policy.name}</span>
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${ACTION_STYLES[policy.action]}`}>
                              {ACTION_LABELS[policy.action]}
                            </span>
                          </div>
                          {policy.description && (
                            <p className="text-xs text-gray-500 mt-0.5">{policy.description}</p>
                          )}
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            <span className="inline-flex items-center gap-1 bg-gray-100 text-gray-600 rounded-full px-2.5 py-0.5 text-xs">
                              <UserGroupIcon className="w-3 h-3" />
                              {policy.allUsers ? 'Alle Benutzer' : policy.users.join(', ')}
                            </span>
                            {policy.conditions.riskLevel !== 'any' && (
                              <span className="inline-flex items-center gap-1 bg-orange-50 text-orange-700 border border-orange-200 rounded-full px-2.5 py-0.5 text-xs">
                                <SignalIcon className="w-3 h-3" />
                                Risiko: {policy.conditions.riskLevel === 'low' ? 'Niedrig' : policy.conditions.riskLevel === 'medium' ? 'Mittel' : 'Hoch'}
                              </span>
                            )}
                            {policy.conditions.deviceCompliant && (
                              <span className="inline-flex items-center gap-1 bg-purple-50 text-purple-700 border border-purple-200 rounded-full px-2.5 py-0.5 text-xs">
                                <ComputerDesktopIcon className="w-3 h-3" />
                                Konformes Gerät
                              </span>
                            )}
                            {policy.conditions.blockedLocations.length > 0 && (
                              <span className="inline-flex items-center gap-1 bg-red-50 text-red-700 border border-red-200 rounded-full px-2.5 py-0.5 text-xs">
                                <GlobeAltIcon className="w-3 h-3" />
                                {policy.conditions.blockedLocations.length} blockierte Länder
                              </span>
                            )}
                            {!policy.conditions.allApps && policy.conditions.apps.length > 0 && (
                              <span className="inline-flex items-center gap-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-full px-2.5 py-0.5 text-xs">
                                {policy.conditions.apps.length} Apps
                              </span>
                            )}
                            {policy.conditions.timeWindow && (
                              <span className="inline-flex items-center gap-1 bg-gray-100 text-gray-600 rounded-full px-2.5 py-0.5 text-xs">
                                <ClockIcon className="w-3 h-3" />
                                {policy.conditions.timeWindow.start}–{policy.conditions.timeWindow.end}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {/* Toggle */}
                          <button
                            onClick={() => togglePolicy(policy.id)}
                            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${policy.enabled ? 'bg-[#0071E3]' : 'bg-gray-300'}`}
                          >
                            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${policy.enabled ? 'translate-x-4' : 'translate-x-1'}`} />
                          </button>
                          <button
                            onClick={() => { setEditPolicy(policy); setShowPolicyModal(true); }}
                            className="p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
                          >
                            <PencilIcon className="w-4 h-4 text-gray-500" />
                          </button>
                          <button
                            onClick={() => deletePolicy(policy.id)}
                            className="p-1.5 rounded-lg hover:bg-red-50 transition-colors"
                          >
                            <TrashIcon className="w-4 h-4 text-red-400" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Anmelde-Ereignisse */}
          {tab === 'ereignisse' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <p className="text-sm text-gray-500">{filteredEvents.length} Ereignisse</p>
                <div className="flex items-center gap-2">
                  <FunnelIcon className="w-4 h-4 text-gray-400" />
                  <select
                    value={eventFilter}
                    onChange={e => setEventFilter(e.target.value as EventResult | 'all')}
                    className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30"
                  >
                    <option value="all">Alle Ergebnisse</option>
                    <option value="allowed">Zugelassen</option>
                    <option value="blocked">Blockiert</option>
                    <option value="mfa_required">MFA gefordert</option>
                  </select>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs font-medium text-gray-500 border-b border-gray-100">
                      <th className="pb-2 pr-4">Benutzer</th>
                      <th className="pb-2 pr-4">App</th>
                      <th className="pb-2 pr-4">IP / Standort</th>
                      <th className="pb-2 pr-4">Gerät</th>
                      <th className="pb-2 pr-4">Risiko</th>
                      <th className="pb-2 pr-4">Ergebnis</th>
                      <th className="pb-2">Zeitstempel</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map(ev => (
                      <tr key={ev.id} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                        <td className="py-2.5 pr-4">
                          <span className="font-medium text-gray-800">{ev.user}</span>
                        </td>
                        <td className="py-2.5 pr-4 text-gray-600">{ev.app}</td>
                        <td className="py-2.5 pr-4">
                          <div className="text-xs">
                            <p className="text-gray-700">{ev.ip}</p>
                            <p className="text-gray-400">{ev.location}</p>
                          </div>
                        </td>
                        <td className="py-2.5 pr-4 text-gray-600 text-xs">{ev.device}</td>
                        <td className="py-2.5 pr-4">
                          <RiskBadge score={ev.riskScore} />
                        </td>
                        <td className="py-2.5 pr-4">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${RESULT_STYLES[ev.result]}`}>
                            {RESULT_LABELS[ev.result]}
                          </span>
                        </td>
                        <td className="py-2.5 text-xs text-gray-500">{fmtRelative(ev.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 3: Named Locations */}
          {tab === 'locations' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <p className="text-sm text-gray-500">{locations.length} Standorte konfiguriert</p>
                <button
                  onClick={() => setShowLocationModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#005BBE] transition-colors"
                >
                  <PlusIcon className="w-4 h-4" />
                  Standort hinzufügen
                </button>
              </div>
              <div className="space-y-3">
                {locations.map(loc => (
                  <div key={loc.id} className="border border-gray-100 rounded-xl p-4 flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className={`rounded-lg p-2 mt-0.5 ${loc.trusted ? 'bg-green-50' : 'bg-red-50'}`}>
                        {loc.type === 'ip' ? (
                          <SignalIcon className={`w-5 h-5 ${loc.trusted ? 'text-green-600' : 'text-red-500'}`} />
                        ) : (
                          <GlobeAltIcon className={`w-5 h-5 ${loc.trusted ? 'text-green-600' : 'text-red-500'}`} />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-gray-900 text-sm">{loc.name}</span>
                          <span className={`text-xs px-2 py-0.5 rounded-full border ${loc.trusted ? 'bg-green-50 text-green-700 border-green-200' : 'bg-red-50 text-red-700 border-red-200'}`}>
                            {loc.trusted ? 'Vertrauenswürdig' : 'Blockiert'}
                          </span>
                          <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">
                            {loc.type === 'ip' ? 'IP-Range' : 'Länder'}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-1 mt-1.5">
                          {loc.values.map((v, i) => (
                            <span key={i} className="text-xs bg-gray-100 text-gray-600 rounded-full px-2 py-0.5">{v}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => { setLocations(ls => ls.filter(l => l.id !== loc.id)); toast.success('Standort entfernt'); }}
                      className="p-1.5 rounded-lg hover:bg-red-50 transition-colors shrink-0"
                    >
                      <TrashIcon className="w-4 h-4 text-red-400" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 4: Risiko-Konfiguration */}
          {tab === 'risiko' && (
            <div className="max-w-2xl space-y-6">
              <p className="text-sm text-gray-500">Konfigurieren Sie die Gewichtung der Risikofaktoren für die Berechnung des Risiko-Scores.</p>

              {/* Login Frequency */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-sm font-medium text-gray-700">Anmeldehäufigkeit (Gewichtung)</label>
                  <span className="text-sm font-semibold text-[#0071E3]">{riskConfig.loginFrequencyWeight}%</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={riskConfig.loginFrequencyWeight}
                  onChange={e => setRiskConfig(c => ({ ...c, loginFrequencyWeight: Number(e.target.value) }))}
                  className="w-full accent-[#0071E3]"
                />
                <div className="flex justify-between text-xs text-gray-400 mt-0.5">
                  <span>0%</span><span>100%</span>
                </div>
              </div>

              {/* Impossible Travel */}
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                <div>
                  <p className="text-sm font-medium text-gray-800">Impossible Travel-Erkennung</p>
                  <p className="text-xs text-gray-500 mt-0.5">Erkennt physikalisch unmögliche Standortwechsel</p>
                </div>
                <button
                  onClick={() => setRiskConfig(c => ({ ...c, impossibleTravelEnabled: !c.impossibleTravelEnabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${riskConfig.impossibleTravelEnabled ? 'bg-[#0071E3]' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${riskConfig.impossibleTravelEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>

              {/* Leaked Credentials */}
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                <div>
                  <p className="text-sm font-medium text-gray-800">Kompromittierte Zugangsdaten prüfen</p>
                  <p className="text-xs text-gray-500 mt-0.5">Abgleich mit bekannten Datenleck-Datenbanken</p>
                </div>
                <button
                  onClick={() => setRiskConfig(c => ({ ...c, leakedCredentialsCheck: !c.leakedCredentialsCheck }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${riskConfig.leakedCredentialsCheck ? 'bg-[#0071E3]' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${riskConfig.leakedCredentialsCheck ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>

              {/* Device Compliance Weight */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-sm font-medium text-gray-700">Gerätecompliance (Gewichtung)</label>
                  <span className="text-sm font-semibold text-[#0071E3]">{riskConfig.deviceComplianceWeight}%</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={riskConfig.deviceComplianceWeight}
                  onChange={e => setRiskConfig(c => ({ ...c, deviceComplianceWeight: Number(e.target.value) }))}
                  className="w-full accent-[#0071E3]"
                />
                <div className="flex justify-between text-xs text-gray-400 mt-0.5">
                  <span>0%</span><span>100%</span>
                </div>
              </div>

              {/* Anomaly Threshold */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-sm font-medium text-gray-700">Anomalie-Schwellenwert</label>
                  <span className="text-sm font-semibold text-[#0071E3]">{riskConfig.anomalyThreshold}</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={riskConfig.anomalyThreshold}
                  onChange={e => setRiskConfig(c => ({ ...c, anomalyThreshold: Number(e.target.value) }))}
                  className="w-full accent-[#0071E3]"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Ab Score {riskConfig.anomalyThreshold} wird eine Risiko-Warnung ausgelöst
                </p>
              </div>

              <button
                onClick={async () => {
                  await api.put('/api/conditional-access/risk-config', riskConfig).catch(() => {});
                  toast.success('Risiko-Konfiguration gespeichert');
                }}
                className="px-5 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#005BBE] transition-colors"
              >
                Konfiguration speichern
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Modals */}
      {showPolicyModal && (
        <PolicyModal
          policy={editPolicy}
          onClose={() => { setShowPolicyModal(false); setEditPolicy(undefined); }}
          onSaved={saved => {
            if (editPolicy) {
              setPolicies(ps => ps.map(p => p.id === saved.id ? saved : p));
            } else {
              setPolicies(ps => [...ps, saved]);
            }
          }}
        />
      )}
      {showLocationModal && (
        <LocationModal
          onClose={() => setShowLocationModal(false)}
          onSaved={loc => setLocations(ls => [...ls, loc])}
        />
      )}
    </div>
  );
}
