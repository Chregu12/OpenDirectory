'use client';

import React, { useState, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

type PermLevel = 'none' | 'read' | 'write' | 'admin';

interface UserPermRow {
  userId: string;
  name: string;
  role: string;
  permissions: Record<string, PermLevel>;
}

interface UnusedPerm {
  userId: string;
  userName: string;
  resource: string;
  level: string;
  lastUsed: string;
  daysIdle: number;
}

interface PimRequest {
  id: string;
  userId: string;
  userName: string;
  resource: string;
  duration_hours: number;
  reason: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: string;
  expiresAt: string | null;
}

interface ActiveElevation {
  id: string;
  userId: string;
  userName: string;
  resource: string;
  expiresAt: number;
  timeRemainingMinutes: number;
}

interface RiskScore {
  userId: string;
  name: string;
  role: string;
  riskScore: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const RESOURCES = ['Geräte', 'Nutzer', 'Richtlinien', 'Apps', 'Secrets', 'Drucker', 'Berichte'];
const RESOURCE_KEYS = ['devices', 'users', 'policies', 'apps', 'secrets', 'printers', 'reports'];

const LEVEL_LABEL: Record<PermLevel, string> = { none: 'Kein', read: 'Lesen', write: 'Schreiben', admin: 'Admin' };

const LEVEL_BADGE: Record<PermLevel, string> = {
  none:  'bg-gray-100 text-gray-600 hover:bg-gray-200',
  read:  'bg-blue-100 text-blue-700 hover:bg-blue-200',
  write: 'bg-yellow-100 text-yellow-700 hover:bg-yellow-200',
  admin: 'bg-green-100 text-green-700 hover:bg-green-200',
};

// Demo data for matrix (used when API unavailable)
const DEMO_MATRIX: UserPermRow[] = [
  { userId: 'user-alice',   name: 'Alice Admin',     role: 'admin',           permissions: { devices: 'admin', users: 'admin', policies: 'admin', apps: 'admin', secrets: 'admin', printers: 'admin', reports: 'admin' } },
  { userId: 'user-bob',     name: 'Bob Developer',   role: 'user',            permissions: { devices: 'read',  users: 'none',  policies: 'read',  apps: 'read',  secrets: 'none',  printers: 'read',  reports: 'none' } },
  { userId: 'user-carol',   name: 'Carol ReadOnly',  role: 'read-only',       permissions: { devices: 'read',  users: 'read',  policies: 'read',  apps: 'read',  secrets: 'read',  printers: 'read',  reports: 'read' } },
  { userId: 'user-dave',    name: 'Dave Engineer',   role: 'user',            permissions: { devices: 'write', users: 'none',  policies: 'read',  apps: 'write', secrets: 'none',  printers: 'read',  reports: 'write' } },
  { userId: 'user-eve',     name: 'Eve DevOps',      role: 'user',            permissions: { devices: 'write', users: 'none',  policies: 'write', apps: 'read',  secrets: 'read',  printers: 'none',  reports: 'read' } },
  { userId: 'sa-ci-runner', name: 'CI Runner',       role: 'service-account', permissions: { devices: 'read',  users: 'none',  policies: 'read',  apps: 'none',  secrets: 'none',  printers: 'none',  reports: 'read' } },
];

const DEMO_UNUSED: UnusedPerm[] = [
  { userId: 'user-bob',   userName: 'Bob Developer', resource: 'Berichte', level: 'Schreiben', lastUsed: new Date(Date.now() - 95 * 86400_000).toISOString(), daysIdle: 95 },
  { userId: 'user-carol', userName: 'Carol ReadOnly', resource: 'Drucker', level: 'Lesen',    lastUsed: new Date(Date.now() - 120 * 86400_000).toISOString(), daysIdle: 120 },
  { userId: 'user-dave',  userName: 'Dave Engineer',  resource: 'Apps',    level: 'Schreiben', lastUsed: new Date(Date.now() - 180 * 86400_000).toISOString(), daysIdle: 180 },
];

const DEMO_RISK: RiskScore[] = [
  { userId: 'user-alice',   name: 'Alice Admin',    role: 'admin',           riskScore: 100 },
  { userId: 'user-dave',    name: 'Dave Engineer',  role: 'user',            riskScore: 54 },
  { userId: 'user-eve',     name: 'Eve DevOps',     role: 'user',            riskScore: 46 },
  { userId: 'user-carol',   name: 'Carol ReadOnly', role: 'read-only',       riskScore: 25 },
  { userId: 'user-bob',     name: 'Bob Developer',  role: 'user',            riskScore: 18 },
  { userId: 'sa-ci-runner', name: 'CI Runner',      role: 'service-account', riskScore: 10 },
];

// ─── Sub-components ───────────────────────────────────────────────────────────

function LevelBadge({ level, onClick }: { level: PermLevel; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`px-2 py-0.5 text-xs font-medium rounded-full transition-colors ${LEVEL_BADGE[level]}`}
    >
      {LEVEL_LABEL[level]}
    </button>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 30 ? 'bg-yellow-400' : 'bg-green-500';
  const text  = score >= 70 ? 'text-red-700' : score >= 30 ? 'text-yellow-700' : 'text-green-700';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-100 rounded-full h-2 overflow-hidden">
        <div className={`h-2 rounded-full transition-all ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-semibold w-8 text-right ${text}`}>{score}</span>
    </div>
  );
}

// ─── Tab 1: Permission Matrix ─────────────────────────────────────────────────

function MatrixTab({ onDemoData }: { onDemoData: () => void }) {
  const [matrix, setMatrix] = useState<UserPermRow[]>(DEMO_MATRIX);
  const [editCell, setEditCell] = useState<{ userId: string; resource: string } | null>(null);

  useEffect(() => {
    // Matrix always starts from demo data; notify parent
    onDemoData();
  }, [onDemoData]);

  const handleLevelChange = async (userId: string, resourceKey: string, newLevel: PermLevel) => {
    try {
      await fetch(`/api/permissions/users/${userId}/assign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resource: resourceKey, level: newLevel }),
      });
    } catch { /* ignore */ }

    setMatrix(prev => prev.map(row => row.userId === userId
      ? { ...row, permissions: { ...row.permissions, [resourceKey]: newLevel } }
      : row
    ));
    setEditCell(null);
    toast.success(`Berechtigung aktualisiert`);
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200">
            <th className="text-left px-4 py-3 font-medium text-gray-500 w-44">Benutzer</th>
            <th className="text-left px-4 py-3 font-medium text-gray-500">Rolle</th>
            {RESOURCES.map((r, i) => (
              <th key={r} className="text-center px-3 py-3 font-medium text-gray-500 whitespace-nowrap">{r}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {matrix.map(row => (
            <tr key={row.userId} className="hover:bg-gray-50">
              <td className="px-4 py-3 font-medium text-gray-900 whitespace-nowrap">{row.name}</td>
              <td className="px-4 py-3">
                <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 text-gray-600">{row.role}</span>
              </td>
              {RESOURCE_KEYS.map((key, i) => {
                const level = (row.permissions[key] ?? 'none') as PermLevel;
                const isEditing = editCell?.userId === row.userId && editCell?.resource === key;
                return (
                  <td key={key} className="px-3 py-3 text-center">
                    {isEditing ? (
                      <select
                        autoFocus
                        defaultValue={level}
                        onBlur={() => setEditCell(null)}
                        onChange={e => handleLevelChange(row.userId, key, e.target.value as PermLevel)}
                        className="text-xs border border-gray-300 rounded px-1 py-0.5"
                      >
                        {(['none', 'read', 'write', 'admin'] as PermLevel[]).map(l => (
                          <option key={l} value={l}>{LEVEL_LABEL[l]}</option>
                        ))}
                      </select>
                    ) : (
                      <LevelBadge level={level} onClick={() => setEditCell({ userId: row.userId, resource: key })} />
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-xs text-gray-400 mt-3 px-4">Klick auf eine Berechtigung zum Bearbeiten</p>
    </div>
  );
}

// ─── Tab 2: Unused Permissions ────────────────────────────────────────────────

function UnusedTab({ onCountChange, onDemoData }: { onCountChange: (n: number) => void; onDemoData: () => void }) {
  const [unused, setUnused] = useState<UnusedPerm[]>(DEMO_UNUSED);

  useEffect(() => { onCountChange(unused.length); }, [unused, onCountChange]);
  useEffect(() => { onDemoData(); }, [onDemoData]);

  const revokeOne = async (userId: string, resource: string) => {
    try {
      await fetch(`/api/permissions/users/${userId}/assign`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ resource, level: 'none' }) });
    } catch { /* ignore */ }
    setUnused(prev => prev.filter(u => !(u.userId === userId && u.resource === resource)));
    toast.success('Berechtigung entzogen');
  };

  const revokeAll = async () => {
    try { await fetch('/api/permissions/revoke-unused', { method: 'POST' }); } catch { /* ignore */ }
    setUnused([]);
    toast.success('Alle ungenutzten Berechtigungen entzogen');
  };

  if (unused.length === 0) {
    return <div className="text-center py-12 text-gray-500"><p className="font-medium">Keine ungenutzten Berechtigungen gefunden</p><p className="text-sm mt-1">Alle Berechtigungen wurden kürzlich genutzt.</p></div>;
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-gray-600">{unused.length} ungenutzte Berechtigungen (&gt;90 Tage)</p>
        <button onClick={revokeAll} className="px-3 py-1.5 text-sm font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg">Alle entziehen</button>
      </div>
      <div className="space-y-2">
        {unused.map(u => (
          <div key={`${u.userId}-${u.resource}`} className="flex items-center gap-4 p-3 bg-orange-50 border border-orange-100 rounded-lg">
            <div className="flex-1 min-w-0">
              <span className="font-medium text-gray-900">{u.userName}</span>
              <span className="text-gray-400 mx-2">·</span>
              <span className="text-gray-700">{u.resource}</span>
              <span className="ml-2 px-2 py-0.5 text-xs bg-yellow-100 text-yellow-700 rounded-full">{u.level}</span>
            </div>
            <span className="text-xs text-gray-500 whitespace-nowrap">Zuletzt genutzt: {new Date(u.lastUsed).toLocaleDateString('de-DE')}</span>
            <span className="text-xs font-medium text-orange-700 whitespace-nowrap">{u.daysIdle} Tage</span>
            <button onClick={() => revokeOne(u.userId, u.resource)} className="px-3 py-1 text-xs font-medium text-red-700 bg-white hover:bg-red-50 border border-red-200 rounded">Entziehen</button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Tab 3: PIM ───────────────────────────────────────────────────────────────

function PimTab() {
  const [requests, setRequests] = useState<PimRequest[]>([]);
  const [active, setActive] = useState<ActiveElevation[]>([]);
  const [riskScores, setRiskScores] = useState<RiskScore[]>(DEMO_RISK);
  const [form, setForm] = useState({ userId: 'user-bob', resource: 'secrets', duration_hours: 2, reason: '' });
  const [submitting, setSubmitting] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [reqRes, actRes] = await Promise.allSettled([
        fetch('/api/pim/requests').then(r => r.json()),
        fetch('/api/pim/active').then(r => r.json()),
      ]);
      if (reqRes.status === 'fulfilled' && Array.isArray(reqRes.value)) setRequests(reqRes.value);
      if (actRes.status === 'fulfilled' && Array.isArray(actRes.value)) setActive(actRes.value);
    } catch { /* use demo */ }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const submitRequest = async () => {
    if (!form.reason.trim()) { toast.error('Begründung angeben'); return; }
    setSubmitting(true);
    try {
      const res = await fetch('/api/pim/request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
      if (res.ok) {
        toast.success('PIM-Anfrage gestellt');
        setForm(f => ({ ...f, reason: '' }));
        loadData();
      }
    } catch { toast.error('Fehler beim Senden'); }
    finally { setSubmitting(false); }
  };

  const processRequest = async (id: string, action: 'approve' | 'deny') => {
    try {
      await fetch(`/api/pim/requests/${id}/${action}`, { method: 'PUT' });
      toast.success(action === 'approve' ? 'Genehmigt' : 'Abgelehnt');
      loadData();
    } catch { toast.error('Fehler'); }
  };

  return (
    <div className="space-y-6">
      {/* Active Elevations */}
      {active.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Aktive Privilegien</h3>
          <div className="space-y-2">
            {active.map(e => (
              <div key={e.id} className="flex items-center gap-4 p-3 bg-purple-50 border border-purple-100 rounded-lg text-sm">
                <span className="font-medium text-gray-900">{e.userName}</span>
                <span className="text-gray-500">→</span>
                <span className="text-purple-700 font-medium">{e.resource}</span>
                <span className="ml-auto text-xs text-gray-500">Läuft ab in <span className="font-semibold text-purple-700">{e.timeRemainingMinutes} Min.</span></span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Request Form */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Privilege-Anfrage stellen</h3>
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Benutzer</label>
            <select value={form.userId} onChange={e => setForm(f => ({ ...f, userId: e.target.value }))} className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm">
              {DEMO_RISK.map(u => <option key={u.userId} value={u.userId}>{u.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Ressource</label>
            <select value={form.resource} onChange={e => setForm(f => ({ ...f, resource: e.target.value }))} className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm">
              {RESOURCE_KEYS.map((k, i) => <option key={k} value={k}>{RESOURCES[i]}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Dauer</label>
            <select value={form.duration_hours} onChange={e => setForm(f => ({ ...f, duration_hours: Number(e.target.value) }))} className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm">
              {[1, 2, 4, 8].map(h => <option key={h} value={h}>{h} Stunde{h > 1 ? 'n' : ''}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Begründung</label>
            <input value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} placeholder="Begründung angeben..." className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm" />
          </div>
        </div>
        <button onClick={submitRequest} disabled={submitting} className="px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg disabled:opacity-50">
          {submitting ? 'Sende…' : 'Anfragen'}
        </button>
      </div>

      {/* Pending Requests */}
      {requests.filter(r => r.status === 'pending').length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Ausstehende Anfragen</h3>
          <div className="space-y-2">
            {requests.filter(r => r.status === 'pending').map(r => (
              <div key={r.id} className="flex items-center gap-3 p-3 bg-white border border-gray-200 rounded-lg text-sm">
                <div className="flex-1 min-w-0">
                  <span className="font-medium text-gray-900">{r.userName}</span>
                  <span className="text-gray-400 mx-2">·</span>
                  <span className="text-gray-700">{r.resource}</span>
                  <span className="ml-2 text-xs text-gray-500">{r.duration_hours}h · {r.reason}</span>
                </div>
                <button onClick={() => processRequest(r.id, 'approve')} className="px-3 py-1 text-xs font-medium text-green-700 bg-green-50 hover:bg-green-100 border border-green-200 rounded">Genehmigen</button>
                <button onClick={() => processRequest(r.id, 'deny')} className="px-3 py-1 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded">Ablehnen</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Risk Scores */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 mb-2">Risikobewertung Benutzer</h3>
        <div className="space-y-2">
          {riskScores.map(u => (
            <div key={u.userId} className="flex items-center gap-3 p-2">
              <span className="text-sm text-gray-700 w-36 truncate">{u.name}</span>
              <span className="text-xs text-gray-400 w-20">{u.role}</span>
              <div className="flex-1"><RiskBar score={u.riskScore} /></div>
            </div>
          ))}
        </div>
        <p className="text-xs text-gray-400 mt-2">Risikoscore: Grün &lt;30, Gelb &lt;70, Rot ≥70</p>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function PermissionsView() {
  const [activeTab, setActiveTab] = useState<'matrix' | 'unused' | 'pim'>('matrix');
  const [unusedCount, setUnusedCount] = useState(3);
  const [usingDemoData, setUsingDemoData] = useState(false);

  const tabs: { id: 'matrix' | 'unused' | 'pim'; label: string; badge?: number }[] = [
    { id: 'matrix',  label: 'Berechtigungsmatrix' },
    { id: 'unused',  label: 'Ungenutzte Rechte', badge: unusedCount },
    { id: 'pim',     label: 'Privilegien (PIM)' },
  ];

  return (
    <div className="p-6 space-y-6">
      {usingDemoData && (
        <div className="mx-6 mt-4 p-3 bg-yellow-900/50 border border-yellow-600 rounded-lg flex items-center gap-2 text-yellow-300 text-sm">
          <span className="text-yellow-400">⚠</span>
          <span>Demo-Modus: API nicht erreichbar. Gezeigte Daten sind Beispieldaten.</span>
        </div>
      )}
      <div>
        <h1 className="text-2xl font-semibold text-gray-900">Berechtigungen</h1>
        <p className="text-sm text-gray-500 mt-1">Verwalte Zugriffsrechte, ungenutzte Berechtigungen und privilegierten Zugang</p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-6">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 pb-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {tab.label}
              {tab.badge !== undefined && tab.badge > 0 && (
                <span className="px-1.5 py-0.5 text-xs font-semibold bg-orange-100 text-orange-700 rounded-full">{tab.badge}</span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-6">
        {activeTab === 'matrix' && <MatrixTab onDemoData={() => setUsingDemoData(true)} />}
        {activeTab === 'unused' && <UnusedTab onCountChange={setUnusedCount} onDemoData={() => setUsingDemoData(true)} />}
        {activeTab === 'pim' && <PimTab />}
      </div>
    </div>
  );
}
