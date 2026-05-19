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
  EyeIcon,
} from '@heroicons/react/24/outline';
import { CheckCircleIcon as CheckSolid } from '@heroicons/react/24/solid';
import { api } from '@/lib/api';
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

type Tab = 'rollen' | 'anfragen' | 'aktiv' | 'anfordern';

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-yellow-50 text-yellow-700 border-yellow-200',
  active:  'bg-green-50  text-green-700  border-green-200',
  denied:  'bg-red-50    text-red-700    border-red-200',
  expired: 'bg-gray-50   text-gray-600   border-gray-200',
  revoked: 'bg-gray-50   text-gray-500   border-gray-200',
};

const STATUS_LABELS: Record<string, string> = {
  pending: 'Ausstehend',
  active:  'Aktiv',
  denied:  'Abgelehnt',
  expired: 'Abgelaufen',
  revoked: 'Widerrufen',
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
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-0">
          <h2 className="text-base font-semibold text-[#1D1D1F]">{role ? 'Rolle bearbeiten' : 'Neue PIM-Rolle'}</h2>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5 text-[#8E8E93]" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-[#3C3C43] mb-1">Rollenname *</label>
              <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                placeholder="z.B. Server-Administrator" className="input-apple w-full" />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-[#3C3C43] mb-1">Beschreibung</label>
              <input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
                placeholder="Wofür ist diese Rolle?" className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#3C3C43] mb-1">Ziel-Gruppe ID *</label>
              <input value={form.target_group_id} onChange={e => setForm(p => ({ ...p, target_group_id: e.target.value }))}
                placeholder="grp-servers" className="input-apple w-full font-mono" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#3C3C43] mb-1">Ziel-Gruppe Name</label>
              <input value={form.target_group_name} onChange={e => setForm(p => ({ ...p, target_group_name: e.target.value }))}
                placeholder="Server-Admins" className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#3C3C43] mb-1">Max. Dauer (Stunden)</label>
              <input type="number" min={1} max={72} value={form.max_duration_hours}
                onChange={e => setForm(p => ({ ...p, max_duration_hours: Number(e.target.value) }))}
                className="input-apple w-full" />
            </div>
            <div className="flex items-center gap-3 mt-5">
              <button type="button"
                onClick={() => setForm(p => ({ ...p, requires_approval: !p.requires_approval }))}
                className={`relative w-11 h-6 rounded-full transition-colors ${form.requires_approval ? 'bg-[#0071E3]' : 'bg-[#D1D1D6]'}`}>
                <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${form.requires_approval ? 'translate-x-5' : ''}`} />
              </button>
              <span className="text-sm text-[#3C3C43]">Genehmigung erforderlich</span>
            </div>
            {form.requires_approval && (
              <div className="col-span-2">
                <label className="block text-xs font-medium text-[#3C3C43] mb-1">Genehmiger-Gruppe ID</label>
                <input value={form.approver_group_id} onChange={e => setForm(p => ({ ...p, approver_group_id: e.target.value }))}
                  placeholder="grp-approvers (leer = alle Admins)" className="input-apple w-full font-mono" />
              </div>
            )}
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm text-[#3C3C43] bg-[#F2F2F7] rounded-lg hover:bg-[#E5E5EA]">Abbrechen</button>
            <button onClick={save} disabled={saving}
              className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0077ED] disabled:opacity-60">
              {saving ? 'Speichern…' : 'Speichern'}
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
        // In real deployment, user_id/user_name come from JWT
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
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-0">
          <h2 className="text-base font-semibold text-[#1D1D1F]">Erweiterten Zugriff anfordern</h2>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5 text-[#8E8E93]" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium text-[#3C3C43] mb-1">Rolle</label>
            <select value={roleId} onChange={e => { setRoleId(e.target.value); const r = roles.find(x => x.id === e.target.value); setHours(Math.min(hours, r?.max_duration_hours ?? 8)); }}
              className="input-apple w-full">
              {roles.map(r => <option key={r.id} value={r.id}>{r.name} ({r.target_group_name})</option>)}
            </select>
          </div>
          {selectedRole && (
            <div className="bg-[#F2F2F7] rounded-xl p-4 space-y-1 text-sm">
              <p className="text-[#3C3C43]">{selectedRole.description}</p>
              <p className="text-xs text-[#8E8E93]">
                {selectedRole.requires_approval ? '⏳ Genehmigung erforderlich' : '⚡ Sofortiger Zugriff'}
                {' · '}Max. {selectedRole.max_duration_hours}h
              </p>
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-[#3C3C43] mb-1">Dauer (Stunden)</label>
            <input type="number" min={1} max={selectedRole?.max_duration_hours ?? 8} value={hours}
              onChange={e => setHours(Number(e.target.value))} className="input-apple w-full" />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#3C3C43] mb-1">Begründung *</label>
            <textarea value={justification} onChange={e => setJustification(e.target.value)} rows={3}
              placeholder="Warum benötigst du diesen Zugriff?" className="input-apple w-full resize-none" />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm text-[#3C3C43] bg-[#F2F2F7] rounded-lg hover:bg-[#E5E5EA]">Abbrechen</button>
            <button onClick={submit} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0077ED] disabled:opacity-60">
              {submitting ? 'Einreichen…' : 'Zugriff anfordern'}
            </button>
          </div>
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
  const [loading, setLoading]   = useState(true);
  const [showRoleForm, setShowRoleForm] = useState(false);
  const [editRole, setEditRole] = useState<PIMRole | undefined>();
  const [showRequest, setShowRequest] = useState(false);

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

  useEffect(() => { load(); }, [load]);

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

  const pending = requests.filter(r => r.status === 'pending');
  const active  = requests.filter(r => r.status === 'active');

  const TABS: { key: Tab; label: string; badge?: number }[] = [
    { key: 'anfragen', label: 'Anfragen', badge: pending.length },
    { key: 'aktiv',    label: 'Aktiv',    badge: active.length },
    { key: 'rollen',   label: 'Rollen' },
    { key: 'anfordern',label: 'Zugriff anfordern' },
  ];

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#1D1D1F] tracking-tight">Privileged Identity Management</h1>
          <p className="text-sm text-[#8E8E93] mt-0.5">Zeitbasierter Gruppenzugriff — kein permanenter Admin</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 rounded-lg hover:bg-[#F2F2F7] transition-colors">
            <ArrowPathIcon className={`w-5 h-5 text-[#8E8E93] ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button onClick={() => setShowRequest(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0077ED]">
            <BoltIcon className="w-4 h-4" />
            Zugriff anfordern
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Aktive Sessions', value: active.length, color: 'text-[#34C759]', icon: ShieldCheckIcon },
          { label: 'Ausstehend', value: pending.length, color: 'text-[#FF9500]', icon: ClockIcon },
          { label: 'PIM-Rollen', value: roles.length, color: 'text-[#0071E3]', icon: KeyIcon },
          { label: 'Heute genehmigt', value: requests.filter(r => r.decided_at && new Date(r.decided_at).toDateString() === new Date().toDateString() && r.status === 'active').length, color: 'text-[#34C759]', icon: CheckCircleIcon },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-white rounded-xl border border-[#E5E5EA] p-4">
            <div className="flex items-center gap-2 mb-1">
              <Icon className={`w-4 h-4 ${color}`} />
              <span className="text-xs text-[#8E8E93]">{label}</span>
            </div>
            <p className={`text-2xl font-semibold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[#E5E5EA]">
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === t.key ? 'border-[#0071E3] text-[#0071E3]' : 'border-transparent text-[#8E8E93] hover:text-[#3C3C43]'
            }`}>
            {t.label}
            {t.badge != null && t.badge > 0 && (
              <span className="bg-[#FF9500] text-white text-xs font-semibold px-1.5 py-0.5 rounded-full">{t.badge}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── Anfragen Tab ── */}
      {tab === 'anfragen' && (
        <div className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden">
          {pending.length === 0 ? (
            <div className="text-center py-16">
              <CheckSolid className="w-10 h-10 mx-auto mb-3 text-[#34C759]" />
              <p className="text-sm font-medium text-[#1D1D1F]">Keine ausstehenden Anfragen</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-[#F9F9F9] border-b border-[#F2F2F7]">
                <tr>{['Benutzer', 'Rolle', 'Dauer', 'Begründung', 'Angefragt', 'Aktionen'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#8E8E93] uppercase tracking-wider">{h}</th>
                ))}</tr>
              </thead>
              <tbody className="divide-y divide-[#F2F2F7]">
                {pending.map(r => (
                  <tr key={r.id} className="hover:bg-[#F9F9F9]">
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium text-[#1D1D1F]">{r.user_name}</p>
                      <p className="text-xs text-[#8E8E93]">{r.user_email || r.user_id}</p>
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-sm text-[#1D1D1F]">{r.role_name}</p>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#3C3C43]">{r.requested_duration_hours}h</td>
                    <td className="px-4 py-3">
                      <p className="text-sm text-[#3C3C43] max-w-xs truncate">{r.justification || '—'}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#8E8E93] whitespace-nowrap">{fmtDate(r.requested_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button onClick={() => approve(r.id)}
                          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-[#34C759] rounded-lg hover:bg-green-600">
                          <CheckCircleIcon className="w-3.5 h-3.5" /> Genehmigen
                        </button>
                        <button onClick={() => deny(r.id)}
                          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100">
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
        <div className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden">
          {active.length === 0 ? (
            <div className="text-center py-16">
              <ShieldCheckIcon className="w-10 h-10 mx-auto mb-3 text-[#8E8E93] opacity-40" />
              <p className="text-sm text-[#8E8E93]">Keine aktiven PIM-Sessions</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-[#F9F9F9] border-b border-[#F2F2F7]">
                <tr>{['Benutzer', 'Rolle / Gruppe', 'Läuft ab in', 'Aktiviert', 'Aktion'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#8E8E93] uppercase tracking-wider">{h}</th>
                ))}</tr>
              </thead>
              <tbody className="divide-y divide-[#F2F2F7]">
                {active.map(r => (
                  <tr key={r.id} className="hover:bg-[#F9F9F9]">
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium text-[#1D1D1F]">{r.user_name}</p>
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-sm text-[#1D1D1F]">{r.role_name}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-medium ${timeLeft(r.expires_at) === 'Abgelaufen' ? 'text-red-500' : 'text-[#FF9500]'}`}>
                        {timeLeft(r.expires_at)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#8E8E93]">{fmtDate(r.activated_at)}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => revoke(r.id)}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100">
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
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0077ED]">
              <PlusIcon className="w-4 h-4" /> Neue Rolle
            </button>
          </div>
          {loading ? (
            <div className="space-y-3">{[1,2,3].map(i => <div key={i} className="h-20 bg-gray-100 rounded-xl animate-pulse" />)}</div>
          ) : roles.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-xl border border-[#E5E5EA]">
              <KeyIcon className="w-10 h-10 mx-auto mb-3 text-[#8E8E93] opacity-40" />
              <p className="text-sm text-[#8E8E93]">Noch keine PIM-Rollen definiert</p>
            </div>
          ) : (
            <div className="space-y-3">
              {roles.map(role => (
                <div key={role.id} className="bg-white rounded-xl border border-[#E5E5EA] px-5 py-4 flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <KeyIcon className="w-4 h-4 text-[#0071E3]" />
                      <span className="text-sm font-medium text-[#1D1D1F]">{role.name}</span>
                      {!role.requires_approval && (
                        <span className="text-xs bg-[#F2F2F7] text-[#8E8E93] px-2 py-0.5 rounded-full">Sofortzugriff</span>
                      )}
                    </div>
                    <p className="text-xs text-[#8E8E93]">{role.description}</p>
                    <div className="flex items-center gap-4 mt-2">
                      <span className="text-xs text-[#3C3C43]">
                        <span className="text-[#8E8E93]">Gruppe:</span> {role.target_group_name || role.target_group_id}
                      </span>
                      <span className="text-xs text-[#3C3C43]">
                        <span className="text-[#8E8E93]">Max:</span> {role.max_duration_hours}h
                      </span>
                      <span className="text-xs text-[#3C3C43]">
                        <span className="text-[#8E8E93]">Genehmigung:</span> {role.requires_approval ? 'Ja' : 'Nein'}
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <button onClick={() => { setEditRole(role); setShowRoleForm(true); }}
                      className="p-2 rounded-lg hover:bg-[#F2F2F7]">
                      <PencilIcon className="w-4 h-4 text-[#8E8E93]" />
                    </button>
                    <button onClick={() => deleteRole(role.id)}
                      className="p-2 rounded-lg hover:bg-red-50">
                      <TrashIcon className="w-4 h-4 text-red-400" />
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
          <p className="text-sm text-[#8E8E93]">Wähle eine Rolle und begründe deine Anfrage. Der Zugriff läuft automatisch ab.</p>
          {roles.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-xl border border-[#E5E5EA]">
              <ExclamationTriangleIcon className="w-10 h-10 mx-auto mb-3 text-[#8E8E93] opacity-40" />
              <p className="text-sm text-[#8E8E93]">Keine PIM-Rollen verfügbar</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {roles.map(role => (
                <div key={role.id} className="bg-white rounded-xl border border-[#E5E5EA] p-5 flex items-center justify-between gap-4 hover:border-[#0071E3] transition-colors group">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <UserGroupIcon className="w-5 h-5 text-[#0071E3]" />
                      <span className="text-sm font-medium text-[#1D1D1F]">{role.name}</span>
                      {!role.requires_approval
                        ? <span className="text-xs bg-green-50 text-green-700 border border-green-200 px-2 py-0.5 rounded-full">⚡ Sofort</span>
                        : <span className="text-xs bg-yellow-50 text-yellow-700 border border-yellow-200 px-2 py-0.5 rounded-full">⏳ Genehmigung</span>}
                    </div>
                    <p className="text-xs text-[#8E8E93]">{role.description}</p>
                    <p className="text-xs text-[#8E8E93] mt-1">Gruppe: <span className="text-[#3C3C43]">{role.target_group_name}</span> · Max. <span className="text-[#3C3C43]">{role.max_duration_hours}h</span></p>
                  </div>
                  <button onClick={() => { setShowRequest(true); }}
                    className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-[#0071E3] border border-[#0071E3] rounded-lg hover:bg-[#EAF4FF] transition-colors flex-shrink-0">
                    <BoltIcon className="w-4 h-4" />
                    Anfordern
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modals */}
      {showRoleForm && (
        <RoleFormModal role={editRole} onClose={() => setShowRoleForm(false)} onSaved={load} />
      )}
      {showRequest && (
        <RequestModal roles={roles} onClose={() => setShowRequest(false)} onSubmitted={load} />
      )}

      <style jsx global>{`
        .input-apple {
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid #E5E5EA;
          border-radius: 0.5rem;
          outline: none;
          transition: border-color 0.15s, box-shadow 0.15s;
          background: white;
        }
        .input-apple:focus {
          border-color: #0071E3;
          box-shadow: 0 0 0 3px rgba(0,113,227,0.15);
        }
      `}</style>
    </div>
  );
}
