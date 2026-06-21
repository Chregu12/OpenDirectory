'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  UserGroupIcon,
  PlusIcon,
  XMarkIcon,
  ArrowPathIcon,
  KeyIcon,
  BoltIcon,
  TrashIcon,
  PencilIcon,
  PlayIcon,
  FireIcon,
} from '@heroicons/react/24/outline';
import { CheckCircleIcon as CheckSolid } from '@heroicons/react/24/solid';
import { api, pimSessionsApi } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface PIMRole {
  id: string;
  name: string;
  description?: string;
  target_group_id: string;
  target_group_name: string;
  max_duration_hours: number;
  requires_approval: boolean;
  approver_group_id?: string;
  created_at: string;
}

interface PIMRequest {
  id: string;
  user_id: string;
  user_name: string;
  user_email?: string;
  role_id: string;
  role_name: string;
  justification?: string;
  requested_duration_hours: number;
  status: 'pending' | 'active' | 'denied' | 'expired' | 'revoked';
  requested_at: string;
  decided_at?: string;
  decided_by?: string;
  activated_at?: string;
  expires_at?: string;
}

interface PIMSession {
  id: string;
  userId?: string;
  user_id?: string;
  userName?: string;
  user_name?: string;
  roleId?: string;
  role_id?: string;
  roleName?: string;
  role_name?: string;
  startedAt?: string;
  started_at?: string;
  endedAt?: string;
  ended_at?: string;
  status?: string;
  riskScore?: number;
  risk_score?: number;
  duration?: number;
}

interface SessionActivity {
  activityType: string;
  activity_type?: string;
  details: Record<string, unknown>;
  riskScore: number;
  risk_score?: number;
  timestamp: string;
}

interface BreakGlassEvent {
  id: string;
  requestedBy?: string;
  requested_by?: string;
  reason: string;
  systemsAffected?: string;
  systems_affected?: string;
  status?: string;
  requestedAt?: string;
  requested_at?: string;
  activatedAt?: string;
  activated_at?: string;
}

type Tab = 'rollen' | 'anfragen' | 'aktiv' | 'anfordern' | 'sessions' | 'breakglass';

// Dark-theme status color map using CSS vars inline
const STATUS_BADGE: Record<string, React.CSSProperties> = {
  pending: { color: 'var(--warning)',  background: 'var(--warning-light)',  border: '1px solid var(--warning)' },
  active:  { color: 'var(--success)',  background: 'var(--success-light)',  border: '1px solid var(--success)' },
  denied:  { color: 'var(--danger)',   background: 'var(--danger-light)',   border: '1px solid var(--danger)' },
  expired: { color: 'var(--text-muted)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' },
  revoked: { color: 'var(--text-muted)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' },
};

function timeLeft(expires_at?: string): string {
  if (!expires_at) return '—';
  const ms = new Date(expires_at).getTime() - Date.now();
  if (ms <= 0) return 'Abgelaufen';
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function fmtDate(s?: string) {
  if (!s) return '—';
  return new Date(s).toLocaleString('de-CH', { dateStyle: 'short', timeStyle: 'short' });
}

function riskBadgeStyle(score: number): React.CSSProperties {
  if (score >= 0.7) return { color: 'var(--danger)',  background: 'var(--danger-light)' };
  if (score >= 0.4) return { color: 'var(--warning)', background: 'var(--warning-light)' };
  return { color: 'var(--success)', background: 'var(--success-light)' };
}

// ─── Role Form Modal ──────────────────────────────────────────────────────────

function RoleFormModal({ role, onClose, onSaved }: {
  role?: PIMRole;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    name:               role?.name ?? '',
    description:        role?.description ?? '',
    target_group_id:    role?.target_group_id ?? '',
    target_group_name:  role?.target_group_name ?? '',
    max_duration_hours: role?.max_duration_hours ?? 4,
    requires_approval:  role?.requires_approval ?? true,
    approver_group_id:  role?.approver_group_id ?? '',
  });
  const [saving, setSaving] = useState(false);

  const inputStyle: React.CSSProperties = {
    padding: '0.5rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border-strong)',
    borderRadius: '0.5rem',
    outline: 'none',
    background: 'var(--bg-surface-raised)',
    color: 'var(--text-primary)',
    width: '100%',
  };

  const save = async () => {
    if (!form.name || !form.target_group_id) {
      toast.error('Name und Ziel-Gruppe sind Pflichtfelder');
      return;
    }
    setSaving(true);
    try {
      if (role) {
        await api.put(`/api/pim/roles/${role.id}`, form);
      } else {
        await api.post('/api/pim/roles', form);
      }
      toast.success(role ? 'Rolle aktualisiert' : 'Rolle erstellt');
      onSaved();
      onClose();
    } catch {
      toast.error('Speichern fehlgeschlagen');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="rounded-2xl shadow-2xl w-full max-w-lg" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)' }} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-0">
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{role ? 'Rolle bearbeiten' : 'Neue PIM-Rolle'}</h2>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} /></button>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Rollenname *</label>
              <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                placeholder="z.B. Server-Administrator" style={inputStyle} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Beschreibung</label>
              <input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
                placeholder="Wofür ist diese Rolle?" style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Ziel-Gruppe ID *</label>
              <input value={form.target_group_id} onChange={e => setForm(p => ({ ...p, target_group_id: e.target.value }))}
                placeholder="grp-servers" style={{ ...inputStyle, fontFamily: 'monospace' }} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Ziel-Gruppe Name</label>
              <input value={form.target_group_name} onChange={e => setForm(p => ({ ...p, target_group_name: e.target.value }))}
                placeholder="Server-Admins" style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Max. Dauer (Stunden)</label>
              <input type="number" min={1} max={72} value={form.max_duration_hours}
                onChange={e => setForm(p => ({ ...p, max_duration_hours: Number(e.target.value) }))}
                style={inputStyle} />
            </div>
            <div className="flex items-center gap-3 mt-5">
              <button type="button"
                onClick={() => setForm(p => ({ ...p, requires_approval: !p.requires_approval }))}
                className={`relative w-11 h-6 rounded-full transition-colors`}
                style={{ background: form.requires_approval ? 'var(--accent)' : 'var(--bg-surface-raised)' }}>
                <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${form.requires_approval ? 'translate-x-5' : ''}`} />
              </button>
              <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Genehmigung erforderlich</span>
            </div>
            {form.requires_approval && (
              <div className="col-span-2">
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Genehmiger-Gruppe ID</label>
                <input value={form.approver_group_id} onChange={e => setForm(p => ({ ...p, approver_group_id: e.target.value }))}
                  placeholder="grp-approvers (leer = alle Admins)" style={{ ...inputStyle, fontFamily: 'monospace' }} />
              </div>
            )}
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>Abbrechen</button>
            <button onClick={save} disabled={saving}
              className="px-4 py-2 text-sm font-medium text-white rounded-lg disabled:opacity-60"
              style={{ background: 'var(--accent)' }}>
              {saving ? 'Speichern...' : 'Speichern'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Request Form Modal ───────────────────────────────────────────────────────

function RequestModal({ roles, onClose, onSubmitted }: {
  roles: PIMRole[];
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const [roleId, setRoleId] = useState(roles[0]?.id ?? '');
  const [hours, setHours] = useState(4);
  const [justification, setJustification] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const selectedRole = roles.find(r => r.id === roleId);

  const inputStyle: React.CSSProperties = {
    padding: '0.5rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border-strong)',
    borderRadius: '0.5rem',
    outline: 'none',
    background: 'var(--bg-surface-raised)',
    color: 'var(--text-primary)',
    width: '100%',
  };

  const submit = async () => {
    if (!roleId || !justification.trim()) {
      toast.error('Rolle und Begründung sind Pflicht');
      return;
    }
    setSubmitting(true);
    try {
      await api.post('/api/pim/requests', {
        role_id: roleId,
        justification,
        requested_duration_hours: hours,
        user_id: 'current-user',
        user_name: 'Aktueller Benutzer',
      });
      toast.success(selectedRole?.requires_approval ? 'Anfrage eingereicht — wartet auf Genehmigung' : 'Zugriff sofort aktiviert');
      onSubmitted();
      onClose();
    } catch {
      toast.error('Anfrage fehlgeschlagen');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="rounded-2xl shadow-2xl w-full max-w-md" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)' }} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-0">
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Erweiterten Zugriff anfordern</h2>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Rolle</label>
            <select value={roleId} onChange={e => { setRoleId(e.target.value); const r = roles.find(x => x.id === e.target.value); setHours(Math.min(hours, r?.max_duration_hours ?? 8)); }}
              style={inputStyle}>
              {roles.map(r => <option key={r.id} value={r.id}>{r.name} ({r.target_group_name})</option>)}
            </select>
          </div>
          {selectedRole && (
            <div className="rounded-xl p-4 space-y-1 text-sm" style={{ background: 'var(--bg-surface-raised)' }}>
              <p style={{ color: 'var(--text-secondary)' }}>{selectedRole.description}</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {selectedRole.requires_approval ? 'Genehmigung erforderlich' : 'Sofortiger Zugriff'}
                {' · '}Max. {selectedRole.max_duration_hours}h
              </p>
            </div>
          )}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Dauer (Stunden)</label>
            <input type="number" min={1} max={selectedRole?.max_duration_hours ?? 8} value={hours}
              onChange={e => setHours(Number(e.target.value))} style={inputStyle} />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Begründung *</label>
            <textarea value={justification} onChange={e => setJustification(e.target.value)} rows={3}
              placeholder="Warum benötigst du diesen Zugriff?" style={{ ...inputStyle, resize: 'none' }} />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>Abbrechen</button>
            <button onClick={submit} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-white rounded-lg disabled:opacity-60"
              style={{ background: 'var(--accent)' }}>
              {submitting ? 'Einreichen...' : 'Zugriff anfordern'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Session Replay Modal ─────────────────────────────────────────────────────

function SessionReplayModal({ session, onClose }: { session: PIMSession; onClose: () => void }) {
  const [activities, setActivities] = useState<SessionActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    pimSessionsApi.getSessionReplay(session.id)
      .then(res => {
        const data = res.data;
        setActivities(data?.activities ?? data ?? []);
      })
      .catch(err => setError(err.message ?? 'Failed to load replay'))
      .finally(() => setLoading(false));
  }, [session.id]);

  const activityRiskStyle = (score: number): React.CSSProperties => {
    if (score >= 0.7) return { background: 'var(--danger-light)',  color: 'var(--danger)' };
    if (score >= 0.4) return { background: 'var(--warning-light)', color: 'var(--warning)' };
    return { background: 'var(--success-light)', color: 'var(--success)' };
  };

  const activityRiskLabel = (score: number) => score >= 0.7 ? 'HIGH' : score >= 0.4 ? 'MED' : 'LOW';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)' }} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>Session Replay</h2>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              {session.userName ?? session.user_name ?? session.userId ?? session.user_id}
              {' — '}
              {session.roleName ?? session.role_name}
            </p>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-muted)' }}>
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <ArrowPathIcon className="w-8 h-8 animate-spin" style={{ color: 'var(--accent)' }} />
            </div>
          )}
          {error && (
            <div className="text-center py-16" style={{ color: 'var(--danger)' }}>
              <ExclamationTriangleIcon className="w-10 h-10 mx-auto mb-3" />
              <p>{error}</p>
            </div>
          )}
          {!loading && !error && activities.length === 0 && (
            <div className="text-center py-16" style={{ color: 'var(--text-muted)' }}>
              <PlayIcon className="w-10 h-10 mx-auto mb-3 opacity-40" />
              <p>No activity recorded for this session</p>
            </div>
          )}
          {!loading && activities.length > 0 && (
            <div className="space-y-2">
              {activities.map((act, i) => {
                const risk = act.riskScore ?? act.risk_score ?? 0;
                const rs = activityRiskStyle(risk);
                const label = activityRiskLabel(risk);
                const type = act.activityType ?? act.activity_type ?? 'UNKNOWN';
                return (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}>
                    <span className="text-xs w-16 flex-shrink-0 pt-0.5 font-mono" style={{ color: 'var(--text-muted)' }}>
                      {new Date(act.timestamp).toLocaleTimeString()}
                    </span>
                    <span
                      className="text-xs font-mono font-semibold px-1.5 py-0.5 rounded flex-shrink-0"
                      style={{ background: 'var(--bg-overlay)', color: 'var(--text-secondary)' }}
                    >
                      {type}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono truncate" style={{ color: 'var(--text-secondary)' }}>
                        {typeof act.details === 'string'
                          ? act.details
                          : (act.details?.command ?? act.details?.path ?? act.details?.target ?? JSON.stringify(act.details))}
                      </p>
                    </div>
                    <span
                      className="text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0"
                      style={rs}
                    >
                      {risk.toFixed(1)} {label}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Break-Glass Request Modal ────────────────────────────────────────────────

function BreakGlassRequestModal({ onClose, onSubmitted }: { onClose: () => void; onSubmitted: (id: string) => void }) {
  const [reason, setReason] = useState('');
  const [systemsAffected, setSystemsAffected] = useState('');
  const [estimatedDuration, setEstimatedDuration] = useState(60);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ id: string } | null>(null);

  const inputStyle: React.CSSProperties = {
    padding: '0.5rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border-strong)',
    borderRadius: '0.5rem',
    outline: 'none',
    background: 'var(--bg-surface-raised)',
    color: 'var(--text-primary)',
    width: '100%',
  };

  const submit = async () => {
    if (!reason.trim()) {
      toast.error('Reason is required');
      return;
    }
    setSubmitting(true);
    try {
      const res = await pimSessionsApi.requestBreakGlass({
        reason,
        systemsAffected,
        estimatedDuration,
      });
      const data = res.data ?? {};
      const id = data.id ?? data.breakGlassId ?? data.breakglass_id ?? `bg-${Date.now()}`;
      setResult({ id });
      onSubmitted(id);
    } catch (err: any) {
      toast.error(err.message ?? 'Break-glass request failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="rounded-2xl shadow-2xl w-full max-w-md" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)' }} onClick={e => e.stopPropagation()}>
        <div className="bg-gradient-to-r from-red-600 to-red-700 rounded-t-2xl p-5 text-white">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <FireIcon className="w-5 h-5" />
              <h2 className="text-base font-bold">Emergency Access Request</h2>
            </div>
            <button onClick={onClose} className="text-white/70 hover:text-white">
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
          <p className="text-xs text-red-200">This action will be logged and requires manager approval.</p>
        </div>

        <div className="p-6 space-y-4">
          {result ? (
            <div className="text-center py-4">
              <CheckCircleIcon className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--success)' }} />
              <h3 className="text-base font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Request Submitted</h3>
              <p className="text-sm mb-3" style={{ color: 'var(--text-muted)' }}>
                Break-glass ID: <span className="font-mono font-semibold" style={{ color: 'var(--text-secondary)' }}>{result.id}</span>
              </p>
              <div className="rounded-lg p-3 text-sm" style={{ background: 'var(--warning-light)', border: '1px solid var(--warning)', color: 'var(--warning)' }}>
                Awaiting second manager approval. You will be notified when access is granted.
              </div>
              <button onClick={onClose} className="mt-4 px-6 py-2 text-white rounded-lg text-sm font-medium" style={{ background: 'var(--bg-surface-raised)' }}>
                Close
              </button>
            </div>
          ) : (
            <>
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Reason *</label>
                <textarea
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  rows={3}
                  placeholder="Why is emergency access needed?"
                  style={{ ...inputStyle, resize: 'none' }}
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Systems Affected</label>
                <input
                  value={systemsAffected}
                  onChange={e => setSystemsAffected(e.target.value)}
                  placeholder="e.g. DC01, FILESERVER-01, Production DB"
                  style={inputStyle}
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Estimated Duration (minutes)</label>
                <input
                  type="number"
                  min={5}
                  max={480}
                  value={estimatedDuration}
                  onChange={e => setEstimatedDuration(Number(e.target.value))}
                  style={inputStyle}
                />
              </div>
              <div className="rounded-lg p-3 text-xs" style={{ background: 'var(--danger-light)', border: '1px solid var(--danger)', color: 'var(--danger)' }}>
                Emergency access bypasses normal approval workflows. All activity will be recorded and audited.
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                  Cancel
                </button>
                <button
                  onClick={submit}
                  disabled={submitting}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-60"
                >
                  {submitting ? 'Submitting...' : 'Request Emergency Access'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export default function PIMView() {
  const [tab, setTab]           = useState<Tab>('anfragen');
  const [roles, setRoles]       = useState<PIMRole[]>([]);
  const [requests, setRequests] = useState<PIMRequest[]>([]);
  const [sessions, setSessions] = useState<PIMSession[]>([]);
  const [breakGlassEvents, setBreakGlassEvents] = useState<BreakGlassEvent[]>([]);
  const [loading, setLoading]   = useState(true);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [bgLoading, setBgLoading] = useState(false);
  const [showRoleForm, setShowRoleForm] = useState(false);
  const [editRole, setEditRole] = useState<PIMRole | undefined>();
  const [showRequest, setShowRequest] = useState(false);
  const [selectedSession, setSelectedSession] = useState<PIMSession | null>(null);
  const [showBGRequest, setShowBGRequest] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rolesRes, reqRes] = await Promise.allSettled([
        api.get('/api/pim/roles'),
        api.get('/api/pim/requests'),
      ]);
      if (rolesRes.status === 'fulfilled') setRoles(rolesRes.value.data?.data ?? rolesRes.value.data ?? []);
      if (reqRes.status === 'fulfilled')   setRequests(reqRes.value.data?.data ?? reqRes.value.data ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    setSessionsLoading(true);
    try {
      const res = await pimSessionsApi.getSessions();
      setSessions(res.data?.sessions ?? res.data ?? []);
    } catch {
      setSessions([]);
    } finally {
      setSessionsLoading(false);
    }
  }, []);

  const loadBreakGlass = useCallback(async () => {
    setBgLoading(true);
    try {
      const res = await pimSessionsApi.getBreakGlassEvents();
      setBreakGlassEvents(res.data?.events ?? res.data ?? []);
    } catch {
      setBreakGlassEvents([]);
    } finally {
      setBgLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (tab === 'sessions') loadSessions();
    if (tab === 'breakglass') loadBreakGlass();
  }, [tab, loadSessions, loadBreakGlass]);

  const approve = async (id: string) => {
    await api.post(`/api/pim/requests/${id}/approve`);
    toast.success('Anfrage genehmigt — Zugriff aktiviert');
    load();
  };
  const deny = async (id: string) => {
    await api.post(`/api/pim/requests/${id}/deny`);
    toast.success('Anfrage abgelehnt');
    load();
  };
  const revoke = async (id: string) => {
    await api.post(`/api/pim/requests/${id}/revoke`);
    toast.success('Zugriff widerrufen');
    load();
  };
  const deleteRole = async (id: string) => {
    await api.delete(`/api/pim/roles/${id}`);
    toast.success('Rolle gelöscht');
    load();
  };

  const terminateSession = async (id: string) => {
    try {
      await pimSessionsApi.terminateBreakGlass(id);
      toast.success('Session terminated');
      loadSessions();
    } catch {
      toast.error('Failed to terminate session');
    }
  };

  const pending = requests.filter(r => r.status === 'pending');
  const active  = requests.filter(r => r.status === 'active');

  const TABS: { key: Tab; label: string; badge?: number }[] = [
    { key: 'anfragen',   label: 'Anfragen',     badge: pending.length },
    { key: 'aktiv',      label: 'Aktiv',         badge: active.length },
    { key: 'rollen',     label: 'Rollen' },
    { key: 'anfordern',  label: 'Zugriff anfordern' },
    { key: 'sessions',   label: 'Sessions' },
    { key: 'breakglass', label: 'Break-Glass' },
  ];

  const tableStyle: React.CSSProperties = {
    background: 'var(--bg-surface)',
    border: '1px solid var(--border)',
    borderRadius: '0.75rem',
    overflow: 'hidden',
  };

  const theadStyle: React.CSSProperties = {
    background: 'var(--bg-surface-raised)',
    borderBottom: '1px solid var(--border)',
  };

  const thStyle: React.CSSProperties = {
    padding: '12px 16px',
    textAlign: 'left',
    fontSize: 12,
    fontWeight: 600,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" style={{ color: 'var(--text-primary)' }}>Privileged Identity Management</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>Zeitbasierter Gruppenzugriff — kein permanenter Admin</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 rounded-lg transition-colors" style={{ background: 'transparent' }}
            onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
          >
            <ArrowPathIcon className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} style={{ color: 'var(--text-muted)' }} />
          </button>
          <button onClick={() => setShowRequest(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white rounded-lg"
            style={{ background: 'var(--accent)' }}>
            <BoltIcon className="w-4 h-4" />
            Zugriff anfordern
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Aktive Sessions', value: active.length, color: 'var(--success)', icon: ShieldCheckIcon },
          { label: 'Ausstehend',      value: pending.length, color: 'var(--warning)', icon: ClockIcon },
          { label: 'PIM-Rollen',      value: roles.length,   color: 'var(--accent)', icon: KeyIcon },
          { label: 'Heute genehmigt', value: requests.filter(r => r.decided_at && new Date(r.decided_at).toDateString() === new Date().toDateString() && r.status === 'active').length, color: 'var(--success)', icon: CheckCircleIcon },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
            <div className="flex items-center gap-2 mb-1">
              <Icon className="w-4 h-4" style={{ color }} />
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</span>
            </div>
            <p className="text-2xl font-semibold" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className="flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap"
            style={tab === t.key
              ? { borderColor: 'var(--accent)', color: 'var(--accent)' }
              : { borderColor: 'transparent', color: 'var(--text-muted)' }
            }>
            {t.label}
            {t.badge != null && t.badge > 0 && (
              <span className="text-white text-xs font-semibold px-1.5 py-0.5 rounded-full" style={{ background: 'var(--warning)' }}>{t.badge}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── Anfragen Tab ── */}
      {tab === 'anfragen' && (
        <div style={tableStyle}>
          {pending.length === 0 ? (
            <div className="text-center py-16">
              <CheckSolid className="w-10 h-10 mx-auto mb-3" style={{ color: 'var(--success)' }} />
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Keine ausstehenden Anfragen</p>
            </div>
          ) : (
            <table className="w-full">
              <thead style={theadStyle}>
                <tr>{['Benutzer', 'Rolle', 'Dauer', 'Begründung', 'Angefragt', 'Aktionen'].map(h => (
                  <th key={h} style={thStyle as any}>{h}</th>
                ))}</tr>
              </thead>
              <tbody>
                {pending.map(r => (
                  <tr key={r.id} style={{ borderTop: '1px solid var(--border)' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{r.user_name}</p>
                      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{r.user_email || r.user_id}</p>
                    </td>
                    <td className="px-4 py-3"><p className="text-sm" style={{ color: 'var(--text-primary)' }}>{r.role_name}</p></td>
                    <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{r.requested_duration_hours}h</td>
                    <td className="px-4 py-3"><p className="text-sm max-w-xs truncate" style={{ color: 'var(--text-secondary)' }}>{r.justification || '—'}</p></td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{fmtDate(r.requested_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button onClick={() => approve(r.id)}
                          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white rounded-lg"
                          style={{ background: 'var(--success)' }}>
                          <CheckCircleIcon className="w-3.5 h-3.5" /> Genehmigen
                        </button>
                        <button onClick={() => deny(r.id)}
                          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg"
                          style={{ color: 'var(--danger)', background: 'var(--danger-light)', border: '1px solid var(--danger)' }}>
                          <XCircleIcon className="w-3.5 h-3.5" /> Ablehnen
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Aktiv Tab ── */}
      {tab === 'aktiv' && (
        <div style={tableStyle}>
          {active.length === 0 ? (
            <div className="text-center py-16">
              <ShieldCheckIcon className="w-10 h-10 mx-auto mb-3 opacity-40" style={{ color: 'var(--text-muted)' }} />
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Keine aktiven PIM-Sessions</p>
            </div>
          ) : (
            <table className="w-full">
              <thead style={theadStyle}>
                <tr>{['Benutzer', 'Rolle / Gruppe', 'Läuft ab in', 'Aktiviert', 'Aktion'].map(h => (
                  <th key={h} style={thStyle as any}>{h}</th>
                ))}</tr>
              </thead>
              <tbody>
                {active.map(r => (
                  <tr key={r.id} style={{ borderTop: '1px solid var(--border)' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    <td className="px-4 py-3"><p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{r.user_name}</p></td>
                    <td className="px-4 py-3"><p className="text-sm" style={{ color: 'var(--text-primary)' }}>{r.role_name}</p></td>
                    <td className="px-4 py-3">
                      <span className="text-sm font-medium" style={{ color: timeLeft(r.expires_at) === 'Abgelaufen' ? 'var(--danger)' : 'var(--warning)' }}>
                        {timeLeft(r.expires_at)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{fmtDate(r.activated_at)}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => revoke(r.id)}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg"
                        style={{ color: 'var(--danger)', background: 'var(--danger-light)', border: '1px solid var(--danger)' }}>
                        <XMarkIcon className="w-3.5 h-3.5" /> Widerrufen
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Rollen Tab ── */}
      {tab === 'rollen' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button onClick={() => { setEditRole(undefined); setShowRoleForm(true); }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white rounded-lg"
              style={{ background: 'var(--accent)' }}>
              <PlusIcon className="w-4 h-4" /> Neue Rolle
            </button>
          </div>
          {loading ? (
            <div className="space-y-3">{[1,2,3].map(i => <div key={i} className="h-20 rounded-xl animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />)}</div>
          ) : roles.length === 0 ? (
            <div className="text-center py-16 rounded-xl" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
              <KeyIcon className="w-10 h-10 mx-auto mb-3 opacity-40" style={{ color: 'var(--text-muted)' }} />
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Noch keine PIM-Rollen definiert</p>
            </div>
          ) : (
            <div className="space-y-3">
              {roles.map(role => (
                <div key={role.id} className="rounded-xl px-5 py-4 flex items-start justify-between gap-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <KeyIcon className="w-4 h-4" style={{ color: 'var(--accent)' }} />
                      <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{role.name}</span>
                      {!role.requires_approval && (
                        <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-muted)' }}>Sofortzugriff</span>
                      )}
                    </div>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{role.description}</p>
                    <div className="flex items-center gap-4 mt-2">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Gruppe:</span> {role.target_group_name || role.target_group_id}
                      </span>
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Max:</span> {role.max_duration_hours}h
                      </span>
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Genehmigung:</span> {role.requires_approval ? 'Ja' : 'Nein'}
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <button onClick={() => { setEditRole(role); setShowRoleForm(true); }}
                      className="p-2 rounded-lg transition-colors"
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                    >
                      <PencilIcon className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                    </button>
                    <button onClick={() => deleteRole(role.id)}
                      className="p-2 rounded-lg transition-colors"
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--danger-light)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                    >
                      <TrashIcon className="w-4 h-4" style={{ color: 'var(--danger)' }} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Anfordern Tab ── */}
      {tab === 'anfordern' && (
        <div className="space-y-3">
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Wähle eine Rolle und begründe deine Anfrage. Der Zugriff läuft automatisch ab.</p>
          {roles.length === 0 ? (
            <div className="text-center py-16 rounded-xl" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
              <ExclamationTriangleIcon className="w-10 h-10 mx-auto mb-3 opacity-40" style={{ color: 'var(--text-muted)' }} />
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Keine PIM-Rollen verfügbar</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {roles.map(role => (
                <div key={role.id} className="rounded-xl p-5 flex items-center justify-between gap-4 transition-colors" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <UserGroupIcon className="w-5 h-5" style={{ color: 'var(--accent)' }} />
                      <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{role.name}</span>
                      {!role.requires_approval
                        ? <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: 'var(--success-light)', color: 'var(--success)', border: '1px solid var(--success)' }}>Sofort</span>
                        : <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid var(--warning)' }}>Genehmigung</span>}
                    </div>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{role.description}</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Gruppe: <span style={{ color: 'var(--text-secondary)' }}>{role.target_group_name}</span> · Max. <span style={{ color: 'var(--text-secondary)' }}>{role.max_duration_hours}h</span></p>
                  </div>
                  <button onClick={() => setShowRequest(true)}
                    className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg flex-shrink-0 transition-colors"
                    style={{ color: 'var(--accent)', border: '1px solid var(--accent)' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-light)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    <BoltIcon className="w-4 h-4" />
                    Anfordern
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Sessions Tab ── */}
      {tab === 'sessions' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Session recordings from the conditional-access service.</p>
            <button onClick={loadSessions} className="p-2 rounded-lg transition-colors"
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              <ArrowPathIcon className={`w-4 h-4 ${sessionsLoading ? 'animate-spin' : ''}`} style={{ color: 'var(--text-muted)' }} />
            </button>
          </div>
          <div style={tableStyle}>
            {sessionsLoading ? (
              <div className="flex items-center justify-center py-16">
                <ArrowPathIcon className="w-8 h-8 animate-spin" style={{ color: 'var(--accent)' }} />
              </div>
            ) : sessions.length === 0 ? (
              <div className="text-center py-16">
                <PlayIcon className="w-10 h-10 mx-auto mb-3 opacity-40" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No session recordings found</p>
              </div>
            ) : (
              <table className="w-full">
                <thead style={theadStyle}>
                  <tr>{['User', 'Role', 'Duration', 'Risk Score', 'Status', 'Actions'].map(h => (
                    <th key={h} style={thStyle as any}>{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {sessions.map(s => {
                    const risk = s.riskScore ?? s.risk_score ?? 0;
                    const rs = riskBadgeStyle(risk);
                    const startTime = s.startedAt ?? s.started_at;
                    const endTime   = s.endedAt   ?? s.ended_at;
                    let durationStr = '—';
                    if (startTime && endTime) {
                      const ms = new Date(endTime).getTime() - new Date(startTime).getTime();
                      const m = Math.round(ms / 60000);
                      durationStr = m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`;
                    }
                    const statusStyle = STATUS_BADGE[s.status ?? 'expired'] ?? STATUS_BADGE.expired;
                    return (
                      <tr key={s.id} style={{ borderTop: '1px solid var(--border)' }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                      >
                        <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-primary)' }}>{s.userName ?? s.user_name ?? s.userId ?? s.user_id ?? '—'}</td>
                        <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-primary)' }}>{s.roleName ?? s.role_name ?? '—'}</td>
                        <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{durationStr}</td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={rs}>
                            {risk.toFixed(2)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs px-2 py-0.5 rounded-full" style={statusStyle}>
                            {s.status ?? 'ended'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedSession(s)}
                            className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg"
                            style={{ color: 'var(--accent)', background: 'var(--accent-light)' }}
                          >
                            <PlayIcon className="w-3.5 h-3.5" /> Replay
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Break-Glass Tab ── */}
      {tab === 'breakglass' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Emergency Access (Break-Glass)</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Use only in critical situations. All access is audited.</p>
            </div>
            <div className="flex gap-2">
              <button onClick={loadBreakGlass} className="p-2 rounded-lg transition-colors"
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <ArrowPathIcon className={`w-4 h-4 ${bgLoading ? 'animate-spin' : ''}`} style={{ color: 'var(--text-muted)' }} />
              </button>
              <button
                onClick={() => setShowBGRequest(true)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
              >
                <FireIcon className="w-4 h-4" />
                Request Emergency Access
              </button>
            </div>
          </div>

          <div style={tableStyle}>
            {bgLoading ? (
              <div className="flex items-center justify-center py-16">
                <ArrowPathIcon className="w-8 h-8 animate-spin text-red-500" />
              </div>
            ) : breakGlassEvents.length === 0 ? (
              <div className="text-center py-16">
                <ShieldCheckIcon className="w-10 h-10 mx-auto mb-3 opacity-60" style={{ color: 'var(--success)' }} />
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No break-glass events recorded</p>
              </div>
            ) : (
              <table className="w-full">
                <thead style={theadStyle}>
                  <tr>{['Requested By', 'Reason', 'Systems', 'Status', 'Requested At'].map(h => (
                    <th key={h} style={thStyle as any}>{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {breakGlassEvents.map(ev => {
                    const statusStyle = STATUS_BADGE[ev.status ?? 'expired'] ?? STATUS_BADGE.expired;
                    return (
                      <tr key={ev.id} style={{ borderTop: '1px solid var(--border)' }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                      >
                        <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-primary)' }}>{ev.requestedBy ?? ev.requested_by ?? '—'}</td>
                        <td className="px-4 py-3">
                          <p className="text-sm max-w-xs truncate" style={{ color: 'var(--text-secondary)' }}>{ev.reason}</p>
                        </td>
                        <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{ev.systemsAffected ?? ev.systems_affected ?? '—'}</td>
                        <td className="px-4 py-3">
                          <span className="text-xs px-2 py-0.5 rounded-full" style={statusStyle}>
                            {ev.status ?? 'unknown'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                          {fmtDate(ev.requestedAt ?? ev.requested_at)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Modals */}
      {showRoleForm && (
        <RoleFormModal role={editRole} onClose={() => setShowRoleForm(false)} onSaved={load} />
      )}
      {showRequest && (
        <RequestModal roles={roles} onClose={() => setShowRequest(false)} onSubmitted={load} />
      )}
      {selectedSession && (
        <SessionReplayModal session={selectedSession} onClose={() => setSelectedSession(null)} />
      )}
      {showBGRequest && (
        <BreakGlassRequestModal
          onClose={() => setShowBGRequest(false)}
          onSubmitted={(_id) => { setShowBGRequest(false); loadBreakGlass(); }}
        />
      )}

      <style jsx global>{`
        .input-apple {
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid var(--border-strong);
          border-radius: 0.5rem;
          outline: none;
          transition: border-color 0.15s, box-shadow 0.15s;
          background: var(--bg-surface-raised);
          color: var(--text-primary);
        }
        .input-apple:focus {
          border-color: var(--accent);
          box-shadow: 0 0 0 3px var(--accent-light);
        }
      `}</style>
    </div>
  );
}
