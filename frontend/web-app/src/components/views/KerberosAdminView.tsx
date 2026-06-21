'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';
import {
  ArrowPathIcon,
  PlusIcon,
  XMarkIcon,
  TrashIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  PencilIcon,
} from '@heroicons/react/24/outline';

// ─── Constants ──────────────────────────────────────────────────────────────────

const KDC_URL = process.env.NEXT_PUBLIC_KDC_URL || 'http://kerberos-kdc:3013';

// ─── Types ──────────────────────────────────────────────────────────────────────

type KerberosTab = 'delegation' | 'protected' | 'policies';

interface ConstrainedDelegation {
  servicePrincipal: string;
  protocol: 'Any' | 'Kerberos-only';
  allowedTargets: string[];
}

interface RBCDEntry {
  resourcePrincipal: string;
  allowedDelegators: string[];
}

interface DelegationData {
  constrained: ConstrainedDelegation[];
  rbcd: RBCDEntry[];
  unconstrained: string[];
}

interface ProtectedUser {
  principal: string;
  addedAt?: string;
}

interface TicketPolicy {
  maxTicketLife: number;   // hours
  maxRenewLife: number;    // days
  forwardable: boolean;
  proxiable: boolean;
  renewable: boolean;
}

// ─── Section Header ─────────────────────────────────────────────────────────────

function SectionHeader({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 mb-4">
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {label}
      </span>
      <div className="flex-1 h-px bg-[rgba(255,255,255,0.07)]" />
    </div>
  );
}

// ─── Add Constrained Delegation Modal ──────────────────────────────────────────

function AddConstrainedModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [form, setForm] = useState({ servicePrincipal: '', protocol: 'Any' as 'Any' | 'Kerberos-only', targets: '' });
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!form.servicePrincipal.trim()) { toast.error('Service principal is required'); return; }
    setSubmitting(true);
    try {
      await api.post(`${KDC_URL}/api/delegation/constrained`, {
        servicePrincipal: form.servicePrincipal.trim(),
        allowedTargets: form.targets.split(',').map(t => t.trim()).filter(Boolean),
        protocol: form.protocol,
      });
      toast.success('Constrained delegation configured');
      onAdded();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to configure delegation');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Add Constrained Delegation</h3>
            <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]"><XMarkIcon className="w-5 h-5" /></button>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Service Principal</label>
            <input type="text" placeholder="app/crm@OPENDIRECTORY" value={form.servicePrincipal}
              onChange={e => setForm(p => ({ ...p, servicePrincipal: e.target.value }))}
              className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
              style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Protocol</label>
            <select value={form.protocol} onChange={e => setForm(p => ({ ...p, protocol: e.target.value as 'Any' | 'Kerberos-only' }))}
              className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF]"
              style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }}>
              <option value="Any">Any (NTLM + Kerberos)</option>
              <option value="Kerberos-only">Kerberos-only</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Allowed Targets (comma-separated)</label>
            <input type="text" placeholder="MSSQL/db01, HTTP/web01" value={form.targets}
              onChange={e => setForm(p => ({ ...p, targets: e.target.value }))}
              className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
              style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] bg-[var(--bg-surface-raised,#1c2128)] hover:bg-[rgba(255,255,255,0.08)] rounded-lg disabled:opacity-50">Cancel</button>
            <button onClick={handleSubmit} disabled={submitting}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-60">
              {submitting ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Adding…</> : 'Add Delegation'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Add RBCD Modal ─────────────────────────────────────────────────────────────

function AddRBCDModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [form, setForm] = useState({ resourcePrincipal: '', delegators: '' });
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!form.resourcePrincipal.trim()) { toast.error('Resource principal is required'); return; }
    setSubmitting(true);
    try {
      await api.post(`${KDC_URL}/api/delegation/rbcd`, {
        resourcePrincipal: form.resourcePrincipal.trim(),
        allowedDelegators: form.delegators.split(',').map(d => d.trim()).filter(Boolean),
      });
      toast.success('RBCD entry configured');
      onAdded();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to configure RBCD');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Add RBCD Entry</h3>
            <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]"><XMarkIcon className="w-5 h-5" /></button>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Resource Principal</label>
            <input type="text" placeholder="MSSQL/db01" value={form.resourcePrincipal}
              onChange={e => setForm(p => ({ ...p, resourcePrincipal: e.target.value }))}
              className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
              style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Allowed Delegators (comma-separated)</label>
            <input type="text" placeholder="app/crm, svc/batch" value={form.delegators}
              onChange={e => setForm(p => ({ ...p, delegators: e.target.value }))}
              className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
              style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] bg-[var(--bg-surface-raised,#1c2128)] hover:bg-[rgba(255,255,255,0.08)] rounded-lg disabled:opacity-50">Cancel</button>
            <button onClick={handleSubmit} disabled={submitting}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-60">
              {submitting ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Adding…</> : 'Add RBCD'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Add Protected User Modal ───────────────────────────────────────────────────

function AddProtectedUserModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [principal, setPrincipal] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!principal.trim()) { toast.error('Principal is required'); return; }
    setSubmitting(true);
    try {
      await api.post(`${KDC_URL}/api/protected-users`, { userPrincipal: principal.trim() });
      toast.success(`${principal} added to Protected Users`);
      onAdded();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to add user');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Add to Protected Users</h3>
            <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]"><XMarkIcon className="w-5 h-5" /></button>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">User Principal</label>
            <input type="text" placeholder="admin@OPENDIRECTORY.LOCAL" value={principal}
              onChange={e => setPrincipal(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
              style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
          </div>
          <p className="text-xs text-[var(--text-muted,#6e7681)]">Members of Protected Users cannot use NTLM, RC4, or delegation.</p>
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] bg-[var(--bg-surface-raised,#1c2128)] hover:bg-[rgba(255,255,255,0.08)] rounded-lg disabled:opacity-50">Cancel</button>
            <button onClick={handleSubmit} disabled={submitting}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-60">
              {submitting ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Adding…</> : 'Add Member'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Edit Ticket Policy Modal ───────────────────────────────────────────────────

function EditTicketPolicyModal({ policy, onClose, onSaved }: {
  policy: TicketPolicy;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({ ...policy });
  const [submitting, setSubmitting] = useState(false);

  const handleSave = async () => {
    setSubmitting(true);
    try {
      await api.put(`${KDC_URL}/api/ticket-policy`, form);
      toast.success('Ticket policy updated');
      onSaved();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to update policy');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Edit Ticket Policy</h3>
            <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]"><XMarkIcon className="w-5 h-5" /></button>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Max Ticket Lifetime (hours)</label>
              <input type="number" min={1} max={99999} value={form.maxTicketLife}
                onChange={e => setForm(p => ({ ...p, maxTicketLife: Number(e.target.value) }))}
                className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF]"
                style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Max Renew Lifetime (days)</label>
              <input type="number" min={1} max={99999} value={form.maxRenewLife}
                onChange={e => setForm(p => ({ ...p, maxRenewLife: Number(e.target.value) }))}
                className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF]"
                style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }} />
            </div>
          </div>
          {(['forwardable', 'proxiable', 'renewable'] as (keyof Pick<TicketPolicy, 'forwardable' | 'proxiable' | 'renewable'>)[]).map(key => (
            <label key={key} className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={form[key]} onChange={e => setForm(p => ({ ...p, [key]: e.target.checked }))}
                className="w-4 h-4 text-[#006FFF] rounded border-[rgba(255,255,255,0.07)] focus:ring-[#006FFF]" />
              <span className="text-sm text-[var(--text-secondary,#8b949e)] capitalize">{key}</span>
            </label>
          ))}
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] bg-[var(--bg-surface-raised,#1c2128)] hover:bg-[rgba(255,255,255,0.08)] rounded-lg disabled:opacity-50">Cancel</button>
            <button onClick={handleSave} disabled={submitting}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-60">
              {submitting ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Saving…</> : 'Save Policy'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Delegation Tab ─────────────────────────────────────────────────────────────

function DelegationTab() {
  const [data, setData]                       = useState<DelegationData | null>(null);
  const [loading, setLoading]                 = useState(true);
  const [error, setError]                     = useState<string | null>(null);
  const [showAddConstrained, setShowAddConstrained] = useState(false);
  const [showAddRBCD, setShowAddRBCD]         = useState(false);
  const [simulating, setSimulating]           = useState(false);
  const [s4uForm, setS4uForm]                 = useState({ servicePrincipal: '', userPrincipal: '' });
  const [s4uResult, setS4uResult]             = useState<any>(null);
  const [showS4u, setShowS4u]                 = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get(`${KDC_URL}/api/delegation`);
      setData(res.data?.data || res.data || { constrained: [], rbcd: [], unconstrained: [] });
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to load delegation data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleS4u2Self = async () => {
    if (!s4uForm.servicePrincipal || !s4uForm.userPrincipal) {
      toast.error('Both service and user principals are required');
      return;
    }
    setSimulating(true);
    try {
      const res = await api.post(`${KDC_URL}/api/delegation/simulate/s4u2self`, s4uForm);
      setS4uResult(res.data);
      toast.success('S4U2Self simulation complete');
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  if (loading) return (
    <div className="animate-pulse space-y-4">
      {[...Array(3)].map((_, i) => <div key={i} className="h-20 bg-[var(--bg-surface-raised,#1c2128)] rounded-xl" />)}
    </div>
  );

  if (error) return (
    <div className="bg-[rgba(248,81,73,0.15)] border border-[rgba(248,81,73,0.3)] text-[#f85149] rounded-lg px-4 py-3 text-sm flex items-center gap-2">
      <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" /> {error}
    </div>
  );

  const constrained = data?.constrained ?? [];
  const rbcd        = data?.rbcd ?? [];
  const uncons      = data?.unconstrained ?? [];

  return (
    <div className="space-y-8">
      {/* Constrained Delegation */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <SectionHeader label="Constrained Delegation" />
          <button onClick={() => setShowAddConstrained(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg">
            <PlusIcon className="w-3.5 h-3.5" /> Add
          </button>
        </div>
        {constrained.length === 0 ? (
          <p className="text-sm text-[var(--text-muted,#6e7681)] italic">No constrained delegation configured</p>
        ) : (
          <div className="bg-[var(--bg-surface,#161b22)] rounded-xl border border-[rgba(255,255,255,0.07)] shadow-sm overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-[var(--bg-surface-raised,#1c2128)] border-b border-[rgba(255,255,255,0.07)]">
                <tr>
                  {['Service Principal', 'Protocol', 'Allowed Targets'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-[var(--text-muted,#6e7681)] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[rgba(255,255,255,0.07)]">
                {constrained.map((cd, i) => (
                  <tr key={i} className="hover:bg-[rgba(255,255,255,0.04)]">
                    <td className="px-4 py-2.5 font-mono text-[var(--text-primary,#e4e6ea)]">{cd.servicePrincipal}</td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                        cd.protocol === 'Kerberos-only'
                          ? 'bg-[rgba(63,185,80,0.15)] text-[#3fb950] border border-[rgba(63,185,80,0.3)]'
                          : 'bg-[rgba(0,111,255,0.15)] text-[#006FFF] border border-[rgba(0,111,255,0.3)]'
                      }`}>{cd.protocol}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {cd.allowedTargets.map(t => (
                          <span key={t} className="px-1.5 py-0.5 bg-[rgba(255,255,255,0.08)] text-[var(--text-secondary,#8b949e)] text-xs rounded font-mono">{t}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* RBCD */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <SectionHeader label="Resource-Based Constrained Delegation" />
          <button onClick={() => setShowAddRBCD(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg">
            <PlusIcon className="w-3.5 h-3.5" /> Add
          </button>
        </div>
        {rbcd.length === 0 ? (
          <p className="text-sm text-[var(--text-muted,#6e7681)] italic">No RBCD entries configured</p>
        ) : (
          <div className="bg-[var(--bg-surface,#161b22)] rounded-xl border border-[rgba(255,255,255,0.07)] shadow-sm overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-[var(--bg-surface-raised,#1c2128)] border-b border-[rgba(255,255,255,0.07)]">
                <tr>
                  {['Resource', 'Allowed Delegators'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-[var(--text-muted,#6e7681)] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[rgba(255,255,255,0.07)]">
                {rbcd.map((r, i) => (
                  <tr key={i} className="hover:bg-[rgba(255,255,255,0.04)]">
                    <td className="px-4 py-2.5 font-mono text-[var(--text-primary,#e4e6ea)]">{r.resourcePrincipal}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {r.allowedDelegators.map(d => (
                          <span key={d} className="px-1.5 py-0.5 bg-[rgba(255,255,255,0.08)] text-[var(--text-secondary,#8b949e)] text-xs rounded font-mono">{d}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Unconstrained */}
      <div>
        <SectionHeader label="Unconstrained Delegation" />
        {uncons.length === 0 ? (
          <div className="flex items-center gap-2 bg-[rgba(63,185,80,0.15)] border border-[rgba(63,185,80,0.3)] rounded-lg px-4 py-3">
            <CheckCircleIcon className="w-4 h-4 text-[#3fb950] flex-shrink-0" />
            <span className="text-sm text-[#3fb950]">None configured — this is the secure state.</span>
          </div>
        ) : (
          <div className="bg-[rgba(210,153,34,0.15)] border border-[rgba(210,153,34,0.3)] rounded-lg px-4 py-3">
            <div className="flex items-center gap-2 mb-2">
              <ExclamationTriangleIcon className="w-4 h-4 text-[#d29922] flex-shrink-0" />
              <span className="text-sm font-medium text-[#d29922]">Security Risk: Unconstrained delegation detected</span>
            </div>
            <div className="space-y-1">
              {uncons.map(p => (
                <span key={p} className="block text-xs font-mono text-[#d29922] bg-[rgba(210,153,34,0.1)] px-2 py-1 rounded">{p}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* S4U2Self Simulation */}
      <div>
        <SectionHeader label="Simulate S4U2Self" />
        <div className="bg-[var(--bg-surface-raised,#1c2128)] rounded-xl border border-[rgba(255,255,255,0.07)] p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">Service Principal</label>
              <input type="text" placeholder="app/crm@OPENDIRECTORY" value={s4uForm.servicePrincipal}
                onChange={e => setS4uForm(p => ({ ...p, servicePrincipal: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
                style={{ background: 'var(--bg-surface, #161b22)', color: 'var(--text-primary, #e4e6ea)' }} />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-muted,#6e7681)] mb-1">User Principal</label>
              <input type="text" placeholder="user@OPENDIRECTORY.LOCAL" value={s4uForm.userPrincipal}
                onChange={e => setS4uForm(p => ({ ...p, userPrincipal: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-[rgba(255,255,255,0.07)] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#006FFF] font-mono"
                style={{ background: 'var(--bg-surface, #161b22)', color: 'var(--text-primary, #e4e6ea)' }} />
            </div>
          </div>
          <button onClick={handleS4u2Self} disabled={simulating}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-60">
            <ArrowPathIcon className={`w-4 h-4 ${simulating ? 'animate-spin' : ''}`} />
            {simulating ? 'Simulating…' : 'Simulate S4U2Self'}
          </button>
          {s4uResult && (
            <div className="bg-[var(--bg-surface,#161b22)] rounded-lg p-3 text-xs font-mono text-[var(--text-secondary,#8b949e)] whitespace-pre-wrap">
              {JSON.stringify(s4uResult, null, 2)}
            </div>
          )}
        </div>
      </div>

      {showAddConstrained && <AddConstrainedModal onClose={() => setShowAddConstrained(false)} onAdded={load} />}
      {showAddRBCD        && <AddRBCDModal        onClose={() => setShowAddRBCD(false)}        onAdded={load} />}
    </div>
  );
}

// ─── Protected Users Tab ────────────────────────────────────────────────────────

function ProtectedUsersTab() {
  const [users, setUsers]         = useState<ProtectedUser[]>([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [showAdd, setShowAdd]     = useState(false);
  const [removing, setRemoving]   = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get(`${KDC_URL}/api/protected-users`);
      setUsers(res.data?.members || res.data?.users || res.data || []);
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to load protected users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleRemove = async (principal: string) => {
    if (removing !== principal) { setRemoving(principal); return; }
    try {
      await api.delete(`${KDC_URL}/api/protected-users/${encodeURIComponent(principal)}`);
      setUsers(prev => prev.filter(u => u.principal !== principal));
      toast.success(`${principal} removed from Protected Users`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to remove user');
    } finally {
      setRemoving(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <SectionHeader label="Protected Users Group" />
        <div className="bg-[rgba(0,111,255,0.12)] border border-[rgba(0,111,255,0.25)] rounded-lg px-4 py-3 mb-4">
          <p className="text-sm text-[#006FFF]">
            Members of this group <strong>cannot use NTLM, RC4, or delegation</strong>. Recommended for privileged accounts.
          </p>
        </div>

        <div className="flex justify-end mb-3">
          <button onClick={() => setShowAdd(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg">
            <PlusIcon className="w-3.5 h-3.5" /> Add Member
          </button>
        </div>

        {error && (
          <div className="bg-[rgba(248,81,73,0.15)] border border-[rgba(248,81,73,0.3)] text-[#f85149] rounded-lg px-4 py-3 text-sm flex items-center gap-2 mb-4">
            <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        )}

        {loading ? (
          <div className="animate-pulse space-y-2">
            {[...Array(3)].map((_, i) => <div key={i} className="h-12 bg-[var(--bg-surface-raised,#1c2128)] rounded-lg" />)}
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-10 text-[var(--text-muted,#6e7681)]">
            <p className="text-sm">No members in Protected Users group</p>
          </div>
        ) : (
          <div className="bg-[var(--bg-surface,#161b22)] rounded-xl border border-[rgba(255,255,255,0.07)] shadow-sm overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-[var(--bg-surface-raised,#1c2128)] border-b border-[rgba(255,255,255,0.07)]">
                <tr>
                  {['Principal', 'Added', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-[var(--text-muted,#6e7681)] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[rgba(255,255,255,0.07)]">
                {users.map(u => (
                  <tr key={u.principal} className="hover:bg-[rgba(255,255,255,0.04)]">
                    <td className="px-4 py-2.5 font-mono text-[var(--text-primary,#e4e6ea)]">{u.principal}</td>
                    <td className="px-4 py-2.5 text-[var(--text-muted,#6e7681)]">
                      {u.addedAt ? new Date(u.addedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      {removing === u.principal ? (
                        <div className="flex items-center gap-1">
                          <button onClick={() => handleRemove(u.principal)}
                            className="px-2 py-1 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg">Confirm</button>
                          <button onClick={() => setRemoving(null)}
                            className="px-2 py-1 text-xs font-medium text-[var(--text-secondary,#8b949e)] bg-[var(--bg-surface-raised,#1c2128)] hover:bg-[rgba(255,255,255,0.08)] rounded-lg">Cancel</button>
                        </div>
                      ) : (
                        <button onClick={() => handleRemove(u.principal)}
                          className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-[#f85149] bg-[rgba(248,81,73,0.1)] hover:bg-[rgba(248,81,73,0.2)] rounded-lg">
                          <TrashIcon className="w-3.5 h-3.5" /> Remove
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showAdd && <AddProtectedUserModal onClose={() => setShowAdd(false)} onAdded={load} />}
    </div>
  );
}

// ─── Ticket Policies Tab ────────────────────────────────────────────────────────

function TicketPoliciesTab() {
  const [policy, setPolicy]       = useState<TicketPolicy | null>(null);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [showEdit, setShowEdit]   = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get(`${KDC_URL}/api/ticket-policy`);
      setPolicy(res.data?.policy || res.data || null);
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to load ticket policy');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const defaultPolicy: TicketPolicy = {
    maxTicketLife: 10,
    maxRenewLife: 7,
    forwardable: true,
    proxiable: false,
    renewable: true,
  };
  const p = policy ?? defaultPolicy;

  const rows = [
    { label: 'Max Ticket Lifetime', value: `${p.maxTicketLife} hours` },
    { label: 'Max Renew Lifetime',  value: `${p.maxRenewLife} days` },
    { label: 'Forwardable',         value: p.forwardable ? '✅ Yes' : '❌ No' },
    { label: 'Proxiable',           value: p.proxiable   ? '✅ Yes' : '❌ No' },
    { label: 'Renewable',           value: p.renewable   ? '✅ Yes' : '❌ No' },
  ];

  return (
    <div className="space-y-6">
      <SectionHeader label="Kerberos Ticket Policies" />

      {error && (
        <div className="bg-[rgba(248,81,73,0.15)] border border-[rgba(248,81,73,0.3)] text-[#f85149] rounded-lg px-4 py-3 text-sm flex items-center gap-2">
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      {loading ? (
        <div className="animate-pulse space-y-3">
          {[...Array(5)].map((_, i) => <div key={i} className="h-12 bg-[var(--bg-surface-raised,#1c2128)] rounded-lg" />)}
        </div>
      ) : (
        <>
          <div className="bg-[var(--bg-surface,#161b22)] rounded-xl border border-[rgba(255,255,255,0.07)] shadow-sm overflow-hidden">
            <div className="px-5 py-3 border-b border-[rgba(255,255,255,0.07)] flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted,#6e7681)]">Realm Default Policy</span>
              <button onClick={() => setShowEdit(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#006FFF] bg-[rgba(0,111,255,0.12)] hover:bg-[rgba(0,111,255,0.2)] rounded-lg">
                <PencilIcon className="w-3.5 h-3.5" /> Edit
              </button>
            </div>
            <div className="divide-y divide-[rgba(255,255,255,0.04)]">
              {rows.map(({ label, value }) => (
                <div key={label} className="flex items-center justify-between px-5 py-3">
                  <span className="text-sm text-[var(--text-secondary,#8b949e)]">{label}</span>
                  <span className="text-sm font-medium text-[var(--text-primary,#e4e6ea)]">{value}</span>
                </div>
              ))}
            </div>
          </div>

          <p className="text-xs text-[var(--text-muted,#6e7681)]">
            These settings apply to all Kerberos tickets issued by this KDC. Changes take effect on next ticket renewal.
          </p>
        </>
      )}

      {showEdit && policy && (
        <EditTicketPolicyModal policy={policy} onClose={() => setShowEdit(false)} onSaved={load} />
      )}
    </div>
  );
}

// ─── Main View ──────────────────────────────────────────────────────────────────

export default function KerberosAdminView() {
  const [tab, setTab] = useState<KerberosTab>('delegation');

  const tabs: { key: KerberosTab; label: string }[] = [
    { key: 'delegation', label: 'Delegation' },
    { key: 'protected',  label: 'Protected Users' },
    { key: 'policies',   label: 'Ticket Policies' },
  ];

  return (
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base, #0e1115)', minHeight: '100vh' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary,#e4e6ea)]">Kerberos Administration</h1>
          <p className="text-sm text-[var(--text-muted,#6e7681)] mt-0.5">Delegation, protected accounts, and ticket policies</p>
        </div>
      </div>

      {/* Tab bar */}
      <div className="border-b border-[rgba(255,255,255,0.07)]">
        <nav className="flex gap-1">
          {tabs.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`py-2.5 px-4 text-sm font-medium border-b-2 transition-colors ${
                tab === t.key
                  ? 'border-[#006FFF] text-[#006FFF]'
                  : 'border-transparent text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)] hover:border-[rgba(255,255,255,0.15)]'
              }`}>
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div>
        {tab === 'delegation' && <DelegationTab />}
        {tab === 'protected'  && <ProtectedUsersTab />}
        {tab === 'policies'   && <TicketPoliciesTab />}
      </div>
    </div>
  );
}
