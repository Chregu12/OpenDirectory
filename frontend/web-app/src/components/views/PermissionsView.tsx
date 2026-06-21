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

const LEVEL_BADGE: Record<PermLevel, React.CSSProperties> = {
  none:  { background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' },
  read:  { background: 'var(--accent-light)', color: 'var(--accent)' },
  write: { background: 'var(--warning-light)', color: 'var(--warning)' },
  admin: { background: 'var(--success-light)', color: 'var(--success)' },
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
      className="px-2 py-0.5 text-xs font-medium rounded-full transition-colors"
      style={LEVEL_BADGE[level]}
    >
      {LEVEL_LABEL[level]}
    </button>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? '#f85149' : score >= 30 ? '#d29922' : '#3fb950';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 rounded-full h-2 overflow-hidden" style={{ background: 'var(--bg-surface-raised)' }}>
        <div className="h-2 rounded-full transition-all" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-xs font-semibold w-8 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

// ─── Tab 1: Permission Matrix ─────────────────────────────────────────────────

function MatrixTab({ onDemoData }: { onDemoData: () => void }) {
  const [matrix, setMatrix] = useState<UserPermRow[]>([]);
  const [matrixLoading, setMatrixLoading] = useState(true);
  const [editCell, setEditCell] = useState<{ userId: string; resource: string } | null>(null);

  useEffect(() => {
    fetch('/api/permissions/matrix')
      .then(r => r.json())
      .then(data => { if (Array.isArray(data)) setMatrix(data); else { setMatrix(DEMO_MATRIX); onDemoData(); } })
      .catch(() => {
        setMatrix(DEMO_MATRIX);
        onDemoData();
      })
      .finally(() => setMatrixLoading(false));
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
      {matrixLoading ? (
        <div className="space-y-2 p-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-10 rounded animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />)}
        </div>
      ) : matrix.length === 0 ? (
        <div className="text-center py-8 text-sm" style={{ color: 'var(--text-muted)' }}>Keine Berechtigungen konfiguriert</div>
      ) : (
        <>
          <table className="min-w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3 font-medium w-44" style={{ color: 'var(--text-muted)' }}>Benutzer</th>
                <th className="text-left px-4 py-3 font-medium" style={{ color: 'var(--text-muted)' }}>Rolle</th>
                {RESOURCES.map((r) => (
                  <th key={r} className="text-center px-3 py-3 font-medium whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{r}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matrix.map(row => (
                <tr key={row.userId} className="transition-colors" style={{ borderBottom: '1px solid var(--border)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <td className="px-4 py-3 font-medium whitespace-nowrap" style={{ color: 'var(--text-primary)' }}>{row.name}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 text-xs rounded-full" style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }}>{row.role}</span>
                  </td>
                  {RESOURCE_KEYS.map((key) => {
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
                            className="text-xs rounded px-1 py-0.5"
                            style={{ border: '1px solid var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
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
          <p className="text-xs mt-3 px-4" style={{ color: 'var(--text-muted)' }}>Klick auf eine Berechtigung zum Bearbeiten</p>
        </>
      )}
    </div>
  );
}

// ─── Tab 2: Unused Permissions ────────────────────────────────────────────────

function UnusedTab({ onCountChange, onDemoData }: { onCountChange: (n: number) => void; onDemoData: () => void }) {
  const [unused, setUnused] = useState<UnusedPerm[]>([]);

  useEffect(() => { onCountChange(unused.length); }, [unused, onCountChange]);

  useEffect(() => {
    fetch('/api/permissions/unused')
      .then(r => r.json())
      .then(data => { if (Array.isArray(data)) setUnused(data); else { setUnused(DEMO_UNUSED); onDemoData(); } })
      .catch(() => { setUnused(DEMO_UNUSED); onDemoData(); });
  }, [onDemoData]);

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
    return (
      <div className="text-center py-12" style={{ color: 'var(--text-secondary)' }}>
        <p className="font-medium">Keine ungenutzten Berechtigungen gefunden</p>
        <p className="text-sm mt-1">Alle Berechtigungen wurden kürzlich genutzt.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{unused.length} ungenutzte Berechtigungen (&gt;90 Tage)</p>
        <button
          onClick={revokeAll}
          className="px-3 py-1.5 text-sm font-medium rounded-lg"
          style={{ color: 'var(--danger)', background: 'var(--danger-light)', border: '1px solid var(--danger)' }}
        >
          Alle entziehen
        </button>
      </div>
      <div className="space-y-2">
        {unused.map(u => (
          <div key={`${u.userId}-${u.resource}`} className="flex items-center gap-4 p-3 rounded-lg" style={{ background: 'var(--warning-light)', border: '1px solid var(--border)' }}>
            <div className="flex-1 min-w-0">
              <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{u.userName}</span>
              <span className="mx-2" style={{ color: 'var(--text-muted)' }}>·</span>
              <span style={{ color: 'var(--text-secondary)' }}>{u.resource}</span>
              <span className="ml-2 px-2 py-0.5 text-xs rounded-full" style={{ background: 'var(--warning-light)', color: 'var(--warning)' }}>{u.level}</span>
            </div>
            <span className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>Zuletzt genutzt: {new Date(u.lastUsed).toLocaleDateString('de-DE')}</span>
            <span className="text-xs font-medium whitespace-nowrap" style={{ color: 'var(--warning)' }}>{u.daysIdle} Tage</span>
            <button
              onClick={() => revokeOne(u.userId, u.resource)}
              className="px-3 py-1 text-xs font-medium rounded"
              style={{ color: 'var(--danger)', background: 'var(--bg-surface)', border: '1px solid var(--danger)' }}
            >
              Entziehen
            </button>
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
  const [form, setForm] = useState({ userId: '', resource: 'secrets', duration_hours: 2, reason: '' });
  const [submitting, setSubmitting] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [reqRes, actRes, riskRes] = await Promise.allSettled([
        fetch('/api/pim/requests').then(r => r.json()),
        fetch('/api/pim/active').then(r => r.json()),
        fetch('/api/permissions/risk-scores').then(r => r.json()),
      ]);
      if (reqRes.status === 'fulfilled' && Array.isArray(reqRes.value)) setRequests(reqRes.value);
      if (actRes.status === 'fulfilled' && Array.isArray(actRes.value)) setActive(actRes.value);
      if (riskRes.status === 'fulfilled' && Array.isArray(riskRes.value)) setRiskScores(riskRes.value);
    } catch { /* silently fail, show empty state */ }
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
          <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-secondary)' }}>Aktive Privilegien</h3>
          <div className="space-y-2">
            {active.map(e => (
              <div key={e.id} className="flex items-center gap-4 p-3 rounded-lg text-sm" style={{ background: 'var(--accent-light)', border: '1px solid var(--border)' }}>
                <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{e.userName}</span>
                <span style={{ color: 'var(--text-muted)' }}>→</span>
                <span className="font-medium" style={{ color: 'var(--accent)' }}>{e.resource}</span>
                <span className="ml-auto text-xs" style={{ color: 'var(--text-muted)' }}>Läuft ab in <span className="font-semibold" style={{ color: 'var(--accent)' }}>{e.timeRemainingMinutes} Min.</span></span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Request Form */}
      <div className="rounded-lg p-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
        <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-secondary)' }}>Privilege-Anfrage stellen</h3>
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-muted)' }}>Benutzer</label>
            <select value={form.userId} onChange={e => setForm(f => ({ ...f, userId: e.target.value }))} className="w-full rounded px-2 py-1.5 text-sm" style={{ border: '1px solid var(--border-strong)', background: 'var(--bg-surface)', color: 'var(--text-primary)' }}>
              {riskScores.map(u => <option key={u.userId} value={u.userId}>{u.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-muted)' }}>Ressource</label>
            <select value={form.resource} onChange={e => setForm(f => ({ ...f, resource: e.target.value }))} className="w-full rounded px-2 py-1.5 text-sm" style={{ border: '1px solid var(--border-strong)', background: 'var(--bg-surface)', color: 'var(--text-primary)' }}>
              {RESOURCE_KEYS.map((k, i) => <option key={k} value={k}>{RESOURCES[i]}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-muted)' }}>Dauer</label>
            <select value={form.duration_hours} onChange={e => setForm(f => ({ ...f, duration_hours: Number(e.target.value) }))} className="w-full rounded px-2 py-1.5 text-sm" style={{ border: '1px solid var(--border-strong)', background: 'var(--bg-surface)', color: 'var(--text-primary)' }}>
              {[1, 2, 4, 8].map(h => <option key={h} value={h}>{h} Stunde{h > 1 ? 'n' : ''}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--text-muted)' }}>Begründung</label>
            <input value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} placeholder="Begründung angeben..." className="w-full rounded px-2 py-1.5 text-sm" style={{ border: '1px solid var(--border-strong)', background: 'var(--bg-surface)', color: 'var(--text-primary)' }} />
          </div>
        </div>
        <button onClick={submitRequest} disabled={submitting} className="px-4 py-2 text-sm font-medium text-white rounded-lg disabled:opacity-50" style={{ background: '#7c3aed' }}>
          {submitting ? 'Sende…' : 'Anfragen'}
        </button>
      </div>

      {/* Pending Requests */}
      {requests.filter(r => r.status === 'pending').length > 0 && (
        <div>
          <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-secondary)' }}>Ausstehende Anfragen</h3>
          <div className="space-y-2">
            {requests.filter(r => r.status === 'pending').map(r => (
              <div key={r.id} className="flex items-center gap-3 p-3 rounded-lg text-sm" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                <div className="flex-1 min-w-0">
                  <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{r.userName}</span>
                  <span className="mx-2" style={{ color: 'var(--text-muted)' }}>·</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{r.resource}</span>
                  <span className="ml-2 text-xs" style={{ color: 'var(--text-muted)' }}>{r.duration_hours}h · {r.reason}</span>
                </div>
                <button onClick={() => processRequest(r.id, 'approve')} className="px-3 py-1 text-xs font-medium rounded" style={{ color: 'var(--success)', background: 'var(--success-light)', border: '1px solid var(--success)' }}>Genehmigen</button>
                <button onClick={() => processRequest(r.id, 'deny')} className="px-3 py-1 text-xs font-medium rounded" style={{ color: 'var(--danger)', background: 'var(--danger-light)', border: '1px solid var(--danger)' }}>Ablehnen</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Risk Scores */}
      <div>
        <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-secondary)' }}>Risikobewertung Benutzer</h3>
        <div className="space-y-2">
          {riskScores.map(u => (
            <div key={u.userId} className="flex items-center gap-3 p-2">
              <span className="text-sm w-36 truncate" style={{ color: 'var(--text-secondary)' }}>{u.name}</span>
              <span className="text-xs w-20" style={{ color: 'var(--text-muted)' }}>{u.role}</span>
              <div className="flex-1"><RiskBar score={u.riskScore} /></div>
            </div>
          ))}
        </div>
        <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>Risikoscore: Grün &lt;30, Gelb &lt;70, Rot ≥70</p>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function PermissionsView() {
  const [activeTab, setActiveTab] = useState<'matrix' | 'unused' | 'pim'>('matrix');
  const [unusedCount, setUnusedCount] = useState(0);
  const [usingDemoData, setUsingDemoData] = useState(false);

  const tabs: { id: 'matrix' | 'unused' | 'pim'; label: string; badge?: number }[] = [
    { id: 'matrix',  label: 'Berechtigungsmatrix' },
    { id: 'unused',  label: 'Ungenutzte Rechte', badge: unusedCount },
    { id: 'pim',     label: 'Privilegien (PIM)' },
  ];

  return (
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>
      {usingDemoData && (
        <div className="p-3 rounded-lg flex items-center gap-2 text-sm" style={{ background: 'var(--warning-light)', border: '1px solid var(--warning)', color: 'var(--warning)' }}>
          <span>⚠</span>
          <span>Demo-Modus: API nicht erreichbar. Gezeigte Daten sind Beispieldaten.</span>
        </div>
      )}
      <div>
        <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>Berechtigungen</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>Verwalte Zugriffsrechte, ungenutzte Berechtigungen und privilegierten Zugang</p>
      </div>

      {/* Tabs */}
      <div style={{ borderBottom: '1px solid var(--border)' }}>
        <nav className="flex gap-6">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="flex items-center gap-2 pb-3 text-sm font-medium border-b-2 transition-colors"
              style={activeTab === tab.id
                ? { borderColor: 'var(--accent)', color: 'var(--accent)' }
                : { borderColor: 'transparent', color: 'var(--text-muted)' }
              }
            >
              {tab.label}
              {tab.badge !== undefined && tab.badge > 0 && (
                <span className="px-1.5 py-0.5 text-xs font-semibold rounded-full" style={{ background: 'var(--warning-light)', color: 'var(--warning)' }}>{tab.badge}</span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="rounded-xl p-6" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
        {activeTab === 'matrix' && <MatrixTab onDemoData={() => setUsingDemoData(true)} />}
        {activeTab === 'unused' && <UnusedTab onCountChange={setUnusedCount} onDemoData={() => setUsingDemoData(true)} />}
        {activeTab === 'pim' && <PimTab />}
      </div>
    </div>
  );
}
