'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShoppingBagIcon,
  CheckCircleIcon,
  ClockIcon,
  XCircleIcon,
  PlusIcon,
  XMarkIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  UserGroupIcon,
  UserIcon,
  ComputerDesktopIcon,
  PencilIcon,
  TrashIcon,
  ExclamationTriangleIcon,
  TagIcon,
  CurrencyDollarIcon,
  CalendarIcon,
} from '@heroicons/react/24/outline';
import { ShoppingBagIcon as ShoppingBagSolid } from '@heroicons/react/24/solid';
import { api } from '@/lib/api';
import LicenseGrantRevokeDialog from './LicenseGrantRevokeDialog';
import LicenseReviewsView from './LicenseReviewsView';
import LicenseDelegationsView from './LicenseDelegationsView';
import LicenseScopeActivationsView from './LicenseScopeActivationsView';
import LicenseScopePoliciesView from './LicenseScopePoliciesView';
import LicenseScopeReviewsView from './LicenseScopeReviewsView';
import LicenseSourceGrantsView from './LicenseSourceGrantsView';
import toast from 'react-hot-toast';
import LicenseFulfillmentView from './LicenseFulfillmentView';

// ─── Types ────────────────────────────────────────────────────────────────────

interface License {
  id: string;
  name: string;
  vendor: string;
  category: string;
  license_type: 'per_user' | 'per_device' | 'concurrent' | 'subscription';
  total_seats: number;
  used_seats: number;
  cost_per_seat?: number | string | null;
  currency?: string;
  renewal_date?: string;
  auto_approve: boolean;
  description?: string;
  notes?: string;
  created_at: string;
}

interface LicenseRequest {
  id: string;
  license_id: string;
  license_name: string;
  requester_id: string;
  requester_name: string;
  assignee_type: 'user' | 'group' | 'device';
  assignee_id?: string;
  assignee_name?: string;
  justification?: string;
  status: 'pending' | 'approved' | 'denied' | 'cancelled';
  allocation_status?: string;
  identity_bound?: boolean;
  requested_at: string;
  decided_at?: string;
  decided_by?: string;
}

type Tab = 'kiosk' | 'verwaltung' | 'anfragen';

interface LicenseAccess {
  subject: string | null;
  identityState: 'active' | 'unlinked' | 'disabled' | 'unavailable';
  permissions: string[];
  demoMode: boolean;
  groupReconciliationEnabled?: boolean;
  userReconciliationEnabled?: boolean;
  groupReconciliationMode?: 'client-credentials'|'static-bearer'|'disabled';
}

interface LicenseUserState {
  user_id: string;
  disabled: boolean;
  directory_revision?: string;
  directory_enabled: boolean | null;
  directory_deleted: boolean | null;
  directory_checked_at?: string;
  directory_error?: string;
}

interface LicenseGroupRule {
  license_id: string;
  grant_id?: string;
  group_id: string;
  group_name?: string;
  license_name: string;
  status: string;
  last_error?: string;
  assigned_users: number;
  desired_users: number;
  source_revision?: string;
  last_synced_at?: string;
  directory_observed_at?: string | null;
  directory_valid_until?: string | null;
  membership_valid_until?: string | null;
  source_authorization_valid_until?: string | null;
}

const GROUP_STATUS: Record<string, string> = {
  active: 'Aktiv', pending: 'Abgleich ausstehend', 'capacity-blocked': 'Kapazität fehlt', revoked: 'Entzogen', deleted: 'Gruppe gelöscht', expired: 'Abgelaufen', 'review-expired': 'Prüffrist abgelaufen',
  'directory-unobserved': 'Verzeichnisnachweis fehlt', 'directory-stale': 'Verzeichnisnachweis abgelaufen', 'membership-expired': 'Mitgliedschaftsfrist abgelaufen',
  'source-consent-expired':'Service-Lesefreigabe abgelaufen',
};

const CATEGORY_COLORS: Record<string, { color: string; background: string }> = {
  'Productivity': { color: 'var(--accent)',   background: 'var(--accent-light)' },
  'Design':       { color: '#a78bfa',         background: 'rgba(167,139,250,0.15)' },
  'Developer':    { color: 'var(--text-secondary)', background: 'var(--bg-overlay)' },
  'Security':     { color: 'var(--danger)',   background: 'var(--danger-light)' },
  'Monitoring':   { color: 'var(--warning)',  background: 'var(--warning-light)' },
  'Network':      { color: 'var(--success)',  background: 'var(--success-light)' },
};

const TYPE_LABELS: Record<string, string> = {
  per_user:     'Pro Benutzer',
  per_device:   'Pro Gerät',
  concurrent:   'Gleichzeitig',
  subscription: 'Abonnement',
};

function fmtDate(s?: string) {
  if (!s) return '—';
  return new Date(s).toLocaleDateString('de-CH');
}

function fmtCHF(amount: number | string | null | undefined, currency = 'CHF') {
  return `${currency} ${Number(amount ?? 0).toFixed(2)}`;
}

function seatsColor(used: number, total: number) {
  if (total === 0) return 'text-[var(--text-muted,#8b949e)] ';
  const pct = used / total;
  if (pct >= 1)   return 'text-red-500';
  if (pct >= 0.8) return 'text-[#FF9500]';
  return 'text-[#34C759]';
}

// ─── Request Modal ────────────────────────────────────────────────────────────

function RequestModal({ license, canRequestForOthers, onClose, onSubmitted }: {
  license: License;
  canRequestForOthers: boolean;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const [form, setForm] = useState({
    assignee_type: 'user' as 'user' | 'group' | 'device',
    assignee_id: '',
    assignee_name: '',
    justification: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const available = license.total_seats - license.used_seats;

  const submit = async () => {
    if (!form.justification.trim() && !license.auto_approve) {
      toast.error('Bitte Begründung angeben');
      return;
    }
    setSubmitting(true);
    try {
      const payload = canRequestForOthers ? form : { justification: form.justification };
      const response = await api.post(`/api/licenses/${license.id}/request`, payload);
      toast.success(response.data?.allocation_status === 'capacity-blocked' ? 'Anfrage genehmigt; Gruppenvergabe wartet auf Kapazität' : response.data?.status === 'approved' ? 'Lizenz sofort zugewiesen!' : 'Anfrage eingereicht — wartet auf Genehmigung');
      onSubmitted();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || 'Anfrage fehlgeschlagen');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="rounded-2xl w-full max-w-md" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-0">
          <div>
            <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{license.name} bestellen</h2>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{license.vendor}</p>
          </div>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} /></button>
        </div>
        <div className="p-6 space-y-4">
          {license.total_seats > 0 && available <= 0 && (
            <div className="flex items-center gap-2 rounded-xl px-4 py-3" style={{ background: 'var(--danger-light)', border: '1px solid var(--danger)' }}>
              <ExclamationTriangleIcon className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--danger)' }} />
              <p className="text-sm" style={{ color: 'var(--danger)' }}>Keine Lizenzen verfügbar — Anfrage trotzdem möglich</p>
            </div>
          )}
          {license.auto_approve && (license.total_seats === 0 || available > 0) && (
            <div className="flex items-center gap-2 rounded-xl px-4 py-3" style={{ background: 'var(--success-light)', border: '1px solid var(--success)' }}>
              <CheckCircleIcon className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--success)' }} />
              <p className="text-sm" style={{ color: 'var(--success)' }}>Wird sofort zugewiesen — keine Genehmigung nötig</p>
            </div>
          )}
          {canRequestForOthers ? <>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Für wen?</label>
            <div className="flex gap-2">
              {(['user', 'group', 'device'] as const).map(t => (
                <button key={t} onClick={() => setForm(p => ({ ...p, assignee_type: t }))}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm rounded-lg border transition-colors"
                  style={form.assignee_type === t
                    ? { border: '1px solid var(--accent)', background: 'var(--accent-light)', color: 'var(--accent)' }
                    : { border: '1px solid var(--border)', color: 'var(--text-secondary)', background: 'transparent' }}>
                  {t === 'user'   && <UserIcon className="w-4 h-4" />}
                  {t === 'group'  && <UserGroupIcon className="w-4 h-4" />}
                  {t === 'device' && <ComputerDesktopIcon className="w-4 h-4" />}
                  {t === 'user' ? 'Benutzer' : t === 'group' ? 'Gruppe' : 'Gerät'}
                </button>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>ID / Username</label>
              <input value={form.assignee_id} onChange={e => setForm(p => ({ ...p, assignee_id: e.target.value }))}
                placeholder="user123" className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Anzeigename</label>
              <input value={form.assignee_name} onChange={e => setForm(p => ({ ...p, assignee_name: e.target.value }))}
                placeholder="Anna Meier" className="input-apple w-full" />
            </div>
          </div>
          </> : <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Die Lizenz wird für dein angemeldetes Benutzerkonto beantragt.</p>}
          {!license.auto_approve && (
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Begründung</label>
              <textarea value={form.justification} onChange={e => setForm(p => ({ ...p, justification: e.target.value }))}
                rows={3} placeholder="Warum wird diese Lizenz benötigt?" className="input-apple w-full resize-none" />
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)' }}>Abbrechen</button>
            <button onClick={submit} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90 disabled:opacity-60">
              {submitting ? 'Einreichen…' : 'Bestellen'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── License Form Modal ───────────────────────────────────────────────────────

function LicenseFormModal({ license, onClose, onSaved }: {
  license?: License;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    name:           license?.name ?? '',
    vendor:         license?.vendor ?? '',
    category:       license?.category ?? 'Software',
    license_type:   license?.license_type ?? 'per_user',
    total_seats:    license?.total_seats ?? 10,
    cost_per_seat:  license?.cost_per_seat ?? 0,
    currency:       license?.currency ?? 'CHF',
    renewal_date:   license?.renewal_date ?? '',
    auto_approve:   license?.auto_approve ?? false,
    description:    license?.description ?? '',
    notes:          license?.notes ?? '',
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.name) { toast.error('Name ist Pflicht'); return; }
    setSaving(true);
    try {
      if (license) {
        await api.put(`/api/licenses/${license.id}`, form);
      } else {
        await api.post('/api/licenses', form);
      }
      toast.success(license ? 'Lizenz aktualisiert' : 'Lizenz hinzugefügt');
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
      <div className="rounded-2xl w-full max-w-lg max-h-[90vh] flex flex-col" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.14)' }} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-0">
          <h2 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)] ">{license ? 'Lizenz bearbeiten' : 'Neue Lizenz'}</h2>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5 text-[var(--text-muted,#8b949e)] " /></button>
        </div>
        <div className="p-6 overflow-y-auto space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Produktname *</label>
              <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="z.B. Microsoft 365 Business" className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Hersteller</label>
              <input value={form.vendor} onChange={e => setForm(p => ({ ...p, vendor: e.target.value }))} placeholder="Microsoft" className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Kategorie</label>
              <select value={form.category} onChange={e => setForm(p => ({ ...p, category: e.target.value }))} className="input-apple w-full">
                {['Productivity', 'Design', 'Developer', 'Security', 'Monitoring', 'Network', 'Software', 'Other'].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Lizenztyp</label>
              <select value={form.license_type} onChange={e => setForm(p => ({ ...p, license_type: e.target.value as any }))} className="input-apple w-full">
                {Object.entries(TYPE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Anzahl Seats</label>
              <input type="number" min={0} value={form.total_seats} onChange={e => setForm(p => ({ ...p, total_seats: Number(e.target.value) }))} className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Kosten / Seat</label>
              <input type="number" min={0} step={0.01} value={form.cost_per_seat} onChange={e => setForm(p => ({ ...p, cost_per_seat: Number(e.target.value) }))} className="input-apple w-full" />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Währung</label>
              <select value={form.currency} onChange={e => setForm(p => ({ ...p, currency: e.target.value }))} className="input-apple w-full">
                {['CHF', 'EUR', 'USD', 'GBP'].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Erneuerungsdatum</label>
              <input type="date" value={form.renewal_date} onChange={e => setForm(p => ({ ...p, renewal_date: e.target.value }))} className="input-apple w-full" />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-[var(--text-secondary,#b1b5bd)]  mb-1">Beschreibung (Kiosk)</label>
              <input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} placeholder="Wird im Kiosk angezeigt" className="input-apple w-full" />
            </div>
            <div className="col-span-2 flex items-center gap-3">
              <button type="button" onClick={() => setForm(p => ({ ...p, auto_approve: !p.auto_approve }))}
                className={`relative w-11 h-6 rounded-full transition-colors ${form.auto_approve ? 'bg-[#006FFF]' : 'bg-gray-600'}`}>
                <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${form.auto_approve ? 'translate-x-5' : ''}`} />
              </button>
              <span className="text-sm text-[var(--text-secondary,#b1b5bd)] ">Sofortzuweisung (ohne Genehmigung)</span>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm text-[var(--text-secondary,#b1b5bd)]  bg-[rgba(255,255,255,0.06)]  rounded-lg">Abbrechen</button>
            <button onClick={save} disabled={saving}
              className="px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90 disabled:opacity-60">
              {saving ? 'Speichern…' : 'Speichern'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export default function LicenseKioskView() {
  const [tab, setTab]             = useState<Tab>('kiosk');
  const [licenses, setLicenses]   = useState<License[]>([]);
  const [requests, setRequests]   = useState<LicenseRequest[]>([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState('');
  const [catFilter, setCatFilter] = useState('');
  const [orderLicense, setOrderLicense]   = useState<License | null>(null);
  const [editLicense, setEditLicense]     = useState<License | undefined>();
  const [showLicForm, setShowLicForm]     = useState(false);
  const [access, setAccess]       = useState<LicenseAccess | null>(null);
  const [loadError, setLoadError] = useState('');
  const [groupRules, setGroupRules] = useState<LicenseGroupRule[]>([]);
  const [grantToRevoke, setGrantToRevoke] = useState<{ licenseId: string; grantId: string } | null>(null);
  const [groupError, setGroupError] = useState('');
  const [userStates, setUserStates] = useState<LicenseUserState[]>([]);
  const [userStateError, setUserStateError] = useState('');
  const canSelfService = access?.identityState === 'active';
  const canReadCatalog = access?.permissions.includes('licenses.catalog.read') ?? false;
  const canManageCatalog = access?.permissions.includes('licenses.catalog.manage') ?? false;
  const canReviewRequests = access?.permissions.includes('licenses.requests.review') ?? false;
  const canRequestForOthers = access?.permissions.includes('licenses.requests.delegate') ?? false;
  const canReadAssignments = access?.permissions.includes('licenses.assignments.read') ?? false;
  const canManageAssignments = access?.permissions.includes('licenses.assignments.manage') ?? false;
  useEffect(() => { if (!canManageAssignments) setGrantToRevoke(null); }, [canManageAssignments]);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    setGroupError('');
    setUserStateError('');
    try {
      const accessResponse = await api.get<LicenseAccess>('/api/licenses/access');
      const nextAccess = { ...accessResponse.data, permissions: accessResponse.data.identityState === 'active' ? accessResponse.data.permissions : [] };
      setAccess(nextAccess);
      if (nextAccess.identityState !== 'active') {
        setOrderLicense(null);
        setShowLicForm(false);
      }
      if (!nextAccess.permissions.includes('licenses.catalog.read')) {
        setTab(current => current === 'verwaltung' ? 'kiosk' : current);
      }
      const [licRes, reqRes, groupRes, userRes] = await Promise.all([
        api.get(nextAccess.permissions.includes('licenses.catalog.read') ? '/api/licenses' : '/api/licenses/kiosk'),
        nextAccess.identityState === 'active' ? api.get('/api/licenses/requests') : Promise.resolve({ data: { requests: [] } }),
        nextAccess.permissions.includes('licenses.assignments.read') ? api.get('/api/licenses/groups').catch(() => {
          setGroupError('Gruppenregeln konnten nicht geladen werden.');
          return { data: { groups: [] } };
        }) : Promise.resolve({ data: { groups: [] } }),
        nextAccess.permissions.includes('licenses.assignments.read') ? api.get('/api/licenses/users').catch(() => {
          setUserStateError('Kontostände konnten nicht geladen werden.');
          return { data: { users: [] } };
        }) : Promise.resolve({ data: { users: [] } }),
      ]);
      setLicenses(licRes.data?.licenses ?? []);
      setRequests(reqRes.data?.requests ?? []);
      setGroupRules(groupRes.data?.groups ?? []);
      setUserStates(userRes.data?.users ?? []);
    } catch {
      setAccess(null);
      setLicenses([]);
      setRequests([]);
      setGroupRules([]);
      setUserStates([]);
      setTab('kiosk');
      setOrderLicense(null);
      setShowLicForm(false);
      setLoadError('Lizenzdaten konnten nicht geladen werden. Bitte erneut versuchen.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const reconcileUser = async (userId: string) => {
    try {
      const result = await api.post(`/api/licenses/users/${userId}/reconcile`);
      toast.success(`Kontostand abgeglichen: ${result.data.assignmentsRevoked || 0} lokale Zuweisungen entzogen`);
      await load();
    } catch { toast.error('Kontostand konnte nicht abgeglichen werden.'); await load(); }
  };

  const approveLicReq = async (id: string) => {
    try {
      const result = await api.post(`/api/licenses/requests/${id}/approve`);
      toast.success(result.data?.allocation_status === 'capacity-blocked' ? 'Anfrage genehmigt; Gruppenvergabe wartet auf Kapazität' : 'Lizenz zugewiesen');
      load();
    } catch {
      toast.error('Anfrage konnte nicht genehmigt werden');
      load();
    }
  };

  const reconcileGroup = async (rule: LicenseGroupRule) => {
    try {
      const result = await api.post(`/api/licenses/${encodeURIComponent(rule.license_id)}/groups/${encodeURIComponent(rule.group_id)}/reconcile`);
      toast.success(result.data?.rule?.status === 'capacity-blocked' ? 'Abgeglichen; für neue Mitglieder fehlt Kapazität' : 'Gruppe abgeglichen');
      load();
    } catch { toast.error('Gruppenabgleich fehlgeschlagen'); }
  };

  const denyLicReq = async (id: string) => {
    try {
      await api.post(`/api/licenses/requests/${id}/deny`);
      toast.success('Anfrage abgelehnt');
      load();
    } catch {
      toast.error('Anfrage konnte nicht abgelehnt werden');
      load();
    }
  };
  const deleteLicense = async (id: string) => {
    try {
      await api.delete(`/api/licenses/${id}`);
      toast.success('Lizenz entfernt');
      load();
    } catch {
      toast.error('Lizenz konnte nicht entfernt werden');
    }
  };

  const categories = Array.from(new Set(licenses.map(l => l.category))).sort();
  const pending = requests.filter(r => r.status === 'pending');

  const filteredLicenses = licenses.filter(l => {
    if (catFilter && l.category !== catFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return l.name.toLowerCase().includes(q) || l.vendor?.toLowerCase().includes(q) || l.description?.toLowerCase().includes(q);
    }
    return true;
  });

  const totalCost = licenses.reduce((sum, license) => sum + Number(license.cost_per_seat ?? 0) * license.used_seats, 0);
  const totalSeats = licenses.reduce((sum, l) => sum + l.total_seats, 0);
  const usedSeats  = licenses.reduce((sum, l) => sum + l.used_seats, 0);

  const TABS: { key: Tab; label: string; badge?: number }[] = [
    { key: 'kiosk',      label: '🛒 Kiosk' },
    ...(canReadCatalog ? [{ key: 'verwaltung' as Tab, label: 'Verwaltung' }] : []),
    { key: 'anfragen',   label: 'Anfragen', badge: pending.length },
  ];

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary,#e4e6ea)]  tracking-tight">Lizenzverwaltung</h1>
          <p className="text-sm text-[var(--text-muted,#8b949e)]  mt-0.5">Software-Lizenzen bestellen, zuweisen und verwalten</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 rounded-lg hover:bg-[rgba(255,255,255,0.06)] ">
            <ArrowPathIcon className={`w-5 h-5 text-[var(--text-muted,#8b949e)]  ${loading ? 'animate-spin' : ''}`} />
          </button>
          {tab === 'verwaltung' && canManageCatalog && (
            <button onClick={() => { setEditLicense(undefined); setShowLicForm(true); }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90">
              <PlusIcon className="w-4 h-4" /> Lizenz hinzufügen
            </button>
          )}
        </div>
      </div>

      {access && <LicenseFulfillmentView permissions={access.permissions} subject={access.subject} />}
      {loadError && <p role="alert" className="text-sm text-red-500">{loadError}</p>}
      {access?.demoMode && <p role="status" className="text-sm text-amber-600">Demo-Modus: Bei Datenbankausfall werden Beispieldaten im Arbeitsspeicher verwendet.</p>}
      {access && !canSelfService && <p role="status" className="text-sm text-amber-600">{access.identityState === 'unlinked'
        ? 'Dein Konto ist noch keiner Verzeichnis-Identität zugeordnet. Bitte die Administration kontaktieren.'
        : access.identityState === 'disabled' ? 'Deine Verzeichnis-Identität ist deaktiviert. Lizenzaktionen sind gesperrt.'
          : 'Die Identitätsquelle ist nicht verfügbar. Lizenzaktionen sind vorübergehend gesperrt.'}</p>}

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Lizenzen total', value: licenses.length,                       sub: 'Produkte' },
          { label: 'Seats vergeben', value: `${usedSeats} / ${totalSeats}`,        sub: 'genutzt / verfügbar' },
          ...(canReadCatalog ? [{ label: 'Kosten der Zuweisungen', value: `CHF ${totalCost.toFixed(0)}`, sub: 'gemäss Katalogpreisen' }] : []),
          { label: 'Offene Anfragen', value: pending.length,                       sub: 'warten auf Genehmigung' },
        ].map(({ label, value, sub }) => (
          <div key={label} className="rounded-xl p-4" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)' }}>
            <p className="text-xs text-[var(--text-muted,#8b949e)]  mb-1">{label}</p>
            <p className="text-xl font-semibold text-[var(--text-primary,#e4e6ea)] ">{value}</p>
            <p className="text-xs text-[var(--text-muted,#8b949e)]  mt-0.5">{sub}</p>
          </div>
        ))}
      </div>

      {access?.subject && access.permissions.some(permission => permission.startsWith('licenses.reviews.')) && <LicenseReviewsView permissions={access.permissions} userId={access.subject} />}
      {access?.subject && access.permissions.some(permission => permission.startsWith('licenses.delegations.')) && <LicenseDelegationsView permissions={access.permissions} userId={access.subject} />}
      {access?.subject && access.permissions.some(permission => permission.startsWith('licenses.delegations.') || permission === 'licenses.scopepim.review') && <LicenseScopeActivationsView permissions={access.permissions} userId={access.subject} />}
      {access?.subject && access.permissions.includes('licenses.scopepolicies.read') && <LicenseScopePoliciesView permissions={access.permissions} userId={access.subject} />}
      {access?.subject && access.permissions.some(permission=>permission.startsWith('licenses.scopereviews.')||permission==='licenses.delegations.self') && <LicenseScopeReviewsView permissions={access.permissions} userId={access.subject} />}
      {access?.subject&&access.permissions.includes('licenses.sources.read')&&<LicenseSourceGrantsView permissions={access.permissions} userId={access.subject}/>}
      {canReadAssignments && <section aria-label="Gruppenbasierte Lizenzvergabe" className="rounded-xl p-4 space-y-3" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        <h3 className="font-semibold">Gruppenbasierte Lizenzvergabe</h3>
        <p className="text-xs">Überlappende Gruppen und Direktzuweisungen verbrauchen zusammen nur einen Sitz je Benutzer. Konfigurierte Hersteller-Connectoren verarbeiten wirksame Änderungen separat; deren Status gesondert prüfen.</p>
        <p className="text-xs">Gruppenrechte gelten höchstens fünf Minuten ab Verzeichnisbestätigung, bei früherer Mitgliedschafts- oder Prüffrist entsprechend kürzer. Ein Ausfall verlängert keine Rechte.</p>
        <p className="text-xs">Der angezeigte Status ist ein Lesestand. Die Fristen wirken auch ohne erneutes Laden.</p>
        {!access?.groupReconciliationEnabled && <p role="status" className="text-xs text-amber-600">Automatischer Gruppenabgleich ist nicht konfiguriert. Ohne rechtzeitigen manuellen Abgleich laufen Gruppenrechte spätestens nach fünf Minuten ab.</p>}
        {access?.groupReconciliationMode==='client-credentials'&&<p className="text-xs">Automatische Token-Erneuerung ist konfiguriert. Nur ausdrücklich freigegebene Gruppen und lebende Client-Fassungen können einen Nachweis erneuern.</p>}
        {access?.groupReconciliationMode==='static-bearer'&&<p role="status" className="text-xs text-amber-600">Älterer statischer Quellen-Bearer: keine automatische Erneuerung. Sein Ablauf kann den Gruppenabgleich unterbrechen.</p>}
        {groupError && <p role="alert">{groupError}</p>}
        {!loading && groupRules.length === 0 && <p className="text-sm">Keine Gruppenregeln vorhanden.</p>}
        {groupRules.map(rule => <div key={`${rule.license_id}:${rule.group_id}`} className="flex flex-wrap gap-3 items-center text-sm">
          <span>{rule.license_name} · {rule.group_name || rule.group_id}</span>
          <span>{GROUP_STATUS[rule.status] || rule.status}</span>
          <span>{rule.assigned_users} / {rule.desired_users} Mitglieder</span>
          <span>Version {rule.source_revision || '—'}</span>
          <span>Letzter Abgleich: {rule.last_synced_at ? new Date(rule.last_synced_at).toLocaleString('de-CH') : '—'}</span>
          <span>Verzeichnis gültig bis: {rule.directory_valid_until ? new Date(rule.directory_valid_until).toLocaleString('de-CH') : 'nicht bestätigt'}</span>
          {rule.membership_valid_until && <span>Früheste Mitgliedschaftsfrist: {new Date(rule.membership_valid_until).toLocaleString('de-CH')}</span>}
          {rule.source_authorization_valid_until&&<span>Service-Lesefreigabe gültig bis: {new Date(rule.source_authorization_valid_until).toLocaleString('de-CH')}</span>}
          {rule.last_error && <span role="alert">{rule.last_error}</span>}
          {canManageAssignments && !['revoked', 'expired', 'deleted', 'review-expired'].includes(rule.status) && <>
            <button onClick={() => reconcileGroup(rule)} className="text-blue-500">Abgleichen</button>
            {rule.grant_id && <button onClick={() => setGrantToRevoke({ licenseId: rule.license_id, grantId: rule.grant_id! })} className="text-red-500">Gruppenquelle entziehen</button>}
          </>}
        </div>)}
      </section>}

      {grantToRevoke && canManageAssignments && <LicenseGrantRevokeDialog key={`${grantToRevoke.licenseId}:${grantToRevoke.grantId}`} {...grantToRevoke}
        onClose={() => setGrantToRevoke(null)} onRevoked={retained => { setGrantToRevoke(null); toast.success(`Quelle lokal entzogen; ${retained} Benutzer behalten andere Vergaben. Herstellerstatus separat prüfen.`); load(); }} />}
      {canReadAssignments && <section aria-label="Kontostände für Lizenzen" className="rounded-xl p-4 space-y-3" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        <h3 className="font-semibold">Kontostände für Lizenzen</h3>
        <p className="text-xs">Letzte bestätigte Verzeichnisstände, maximal 200 Einträge. Sperren und Löschungen entziehen lokale Benutzer-Zuweisungen; eine Reaktivierung stellt Direktlizenzen nicht automatisch wieder her.</p>
        {!access?.userReconciliationEnabled && <p role="status" className="text-xs text-amber-600">Automatischer Kontenabgleich ist nicht konfiguriert. Bestehende Direktlizenzen müssen manuell abgeglichen werden.</p>}
        {userStateError && <p role="alert">{userStateError}</p>}
        {!loading && !userStateError && userStates.length === 0 && <p className="text-sm">Keine geprüften Kontostände vorhanden.</p>}
        {userStates.map(state => <div key={state.user_id} className="flex flex-wrap gap-3 items-center text-sm">
          <span>{state.user_id}</span>
          <span>{state.disabled ? 'Lokal gesperrt' : state.directory_deleted ? 'Im Verzeichnis gelöscht' : state.directory_enabled === false ? 'Im Verzeichnis deaktiviert' : state.directory_enabled ? 'Im Verzeichnis aktiv' : 'Identität ungeklärt'}</span>
          <span>Version {state.directory_revision || '—'}</span>
          <span>Letzte Bestätigung: {state.directory_checked_at ? new Date(state.directory_checked_at).toLocaleString('de-CH') : '—'}</span>
          {state.directory_error && <span role="alert">Abgleichfehler: {state.directory_error}</span>}
          {canManageAssignments && <button onClick={() => reconcileUser(state.user_id)} className="text-blue-500">Kontostand abgleichen</button>}
        </div>)}
      </section>}

      {/* Tabs */}
      <div className="flex" style={{ borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === t.key ? 'border-[#006FFF] text-[#006FFF]' : 'border-transparent text-[var(--text-muted,#8b949e)] hover:text-[var(--text-secondary,#b1b5bd)]'
            }`}>
            {t.label}
            {t.badge != null && t.badge > 0 && (
              <span className="bg-[#FF9500] text-white text-xs font-semibold px-1.5 py-0.5 rounded-full">{t.badge}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── Kiosk Tab ── */}
      {tab === 'kiosk' && (
        <div className="space-y-4">
          {/* Search + category filter */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted,#8b949e)] " />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Software suchen…"
                className="w-full pl-9 pr-3 py-2 text-sm rounded-lg focus:outline-none" style={{ border: '1px solid rgba(255,255,255,0.07)', background: 'var(--bg-surface-raised, #21262d)', color: 'var(--text-primary)' }} />
            </div>
            <div className="flex gap-2 flex-wrap">
              <button onClick={() => setCatFilter('')}
                className={`px-3 py-2 text-xs rounded-lg border transition-colors ${!catFilter ? 'border-[#006FFF] bg-[rgba(0,111,255,0.15)] text-[#006FFF]' : 'text-[var(--text-secondary,#b1b5bd)]'}`} style={{ borderColor: !catFilter ? '#006FFF' : 'rgba(255,255,255,0.07)' }}>
                Alle
              </button>
              {categories.map(cat => (
                <button key={cat} onClick={() => setCatFilter(catFilter === cat ? '' : cat)}
                  className={`px-3 py-2 text-xs rounded-lg border transition-colors ${catFilter === cat ? 'border-[#006FFF] bg-[rgba(0,111,255,0.15)] text-[#006FFF]' : 'text-[var(--text-secondary,#b1b5bd)]'}`} style={{ borderColor: catFilter === cat ? '#006FFF' : 'rgba(255,255,255,0.07)' }}>
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* License cards */}
          {loading ? (
            <div className="grid grid-cols-2 gap-4">
              {[1,2,3,4].map(i => <div key={i} className="h-44 bg-gray-100 rounded-xl animate-pulse" />)}
            </div>
          ) : filteredLicenses.length === 0 ? (
            <div className="text-center py-20">
              <ShoppingBagSolid className="w-12 h-12 mx-auto mb-3 text-[var(--text-muted,#8b949e)]  opacity-30" />
              <p className="text-sm text-[var(--text-muted,#8b949e)] ">Keine Lizenzen gefunden</p>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              {filteredLicenses.map(lic => {
                const avail = lic.total_seats - lic.used_seats;
                const pct = lic.total_seats > 0 ? lic.used_seats / lic.total_seats : 0;
                return (
                  <div key={lic.id} className="rounded-xl p-5 flex flex-col transition-colors group" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)' }}>
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${CATEGORY_COLORS[lic.category] || 'bg-gray-50 text-gray-700'}`}>
                            {lic.category}
                          </span>
                          {lic.auto_approve && (
                            <span className="text-xs bg-green-50 text-green-700 px-2 py-0.5 rounded-full">⚡ Sofort</span>
                          )}
                        </div>
                        <h3 className="text-sm font-semibold text-[var(--text-primary,#e4e6ea)]  truncate">{lic.name}</h3>
                        <p className="text-xs text-[var(--text-muted,#8b949e)] ">{lic.vendor}</p>
                      </div>
                      {lic.cost_per_seat != null && <div className="text-right flex-shrink-0 ml-3">
                        <p className="text-sm font-semibold text-[var(--text-primary,#e4e6ea)] ">{fmtCHF(lic.cost_per_seat, lic.currency)}</p>
                        <p className="text-xs text-[var(--text-muted,#8b949e)] ">pro {TYPE_LABELS[lic.license_type]?.split(' ')[1] ?? 'Seat'}</p>
                      </div>}
                    </div>

                    {lic.description && (
                      <p className="text-xs text-[var(--text-secondary,#b1b5bd)]  mb-3 line-clamp-2">{lic.description}</p>
                    )}

                    {/* Seat bar */}
                    <div className="mb-3">
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-[var(--text-muted,#8b949e)] ">Verfügbar</span>
                        <span className={seatsColor(lic.used_seats, lic.total_seats)}>
                          {lic.total_seats === 0 ? 'Unbegrenzt' : `${avail} / ${lic.total_seats}`}
                        </span>
                      </div>
                      <div className="h-1.5 bg-[rgba(255,255,255,0.06)]  rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all ${pct >= 1 ? 'bg-red-500' : pct >= 0.8 ? 'bg-[#FF9500]' : 'bg-[#34C759]'}`}
                          style={{ width: `${Math.min(pct * 100, 100)}%` }} />
                      </div>
                    </div>

                    <div className="mt-auto">
                      <button disabled={!canSelfService} onClick={() => setOrderLicense(lic)}
                        className="w-full flex items-center justify-center gap-2 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90 transition-colors">
                        <ShoppingBagIcon className="w-4 h-4" />
                        Bestellen
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Verwaltung Tab ── */}
      {tab === 'verwaltung' && (
        <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)' }}>
          {loading ? (
            <div className="p-6 space-y-3">{[1,2,3].map(i => <div key={i} className="h-16 rounded-lg animate-pulse" style={{ background: 'rgba(255,255,255,0.06)' }} />)}</div>
          ) : licenses.length === 0 ? (
            <div className="text-center py-16">
              <TagIcon className="w-10 h-10 mx-auto mb-3 text-[var(--text-muted,#8b949e)]  opacity-40" />
              <p className="text-sm text-[var(--text-muted,#8b949e)] ">Noch keine Lizenzen im Katalog</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-[rgba(255,255,255,0.04)]  border-b border-[rgba(255,255,255,0.07)] ">
                <tr>{['Produkt', 'Typ', 'Seats', 'Kosten/Seat', 'Erneuerung', 'Aktionen'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[var(--text-muted,#8b949e)]  uppercase tracking-wider">{h}</th>
                ))}</tr>
              </thead>
              <tbody className="divide-y divide-[rgba(255,255,255,0.07)] ">
                {licenses.map(lic => (
                  <tr key={lic.id} className="hover:bg-[rgba(255,255,255,0.04)] ">
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium text-[var(--text-primary,#e4e6ea)] ">{lic.name}</p>
                      <p className="text-xs text-[var(--text-muted,#8b949e)] ">{lic.vendor} · {lic.category}</p>
                    </td>
                    <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">{TYPE_LABELS[lic.license_type]}</td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-medium ${seatsColor(lic.used_seats, lic.total_seats)}`}>
                        {lic.used_seats}
                      </span>
                      <span className="text-sm text-[var(--text-muted,#8b949e)] "> / {lic.total_seats}</span>
                    </td>
                    <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">{fmtCHF(lic.cost_per_seat, lic.currency)}</td>
                    <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">{fmtDate(lic.renewal_date)}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        {canManageCatalog && <button aria-label={`Lizenz ${lic.name} bearbeiten`} onClick={() => { setEditLicense(lic); setShowLicForm(true); }}
                          className="p-1.5 rounded-lg hover:bg-[rgba(255,255,255,0.06)] ">
                          <PencilIcon className="w-4 h-4 text-[var(--text-muted,#8b949e)] " />
                        </button>}
                        {canManageCatalog && <button aria-label={`Lizenz ${lic.name} entfernen`} onClick={() => deleteLicense(lic.id)}
                          className="p-1.5 rounded-lg hover:bg-red-50">
                          <TrashIcon className="w-4 h-4 text-red-400" />
                        </button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Anfragen Tab ── */}
      {tab === 'anfragen' && (
        <div className="space-y-4">
          {/* Pending */}
          {pending.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-[var(--text-muted,#8b949e)]  uppercase tracking-wider mb-2">Ausstehend</p>
              <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)' }}>
                <table className="w-full">
                  <thead className="border-b" style={{ background: 'rgba(255,255,255,0.04)', borderColor: 'rgba(255,255,255,0.07)' }}>
                    <tr>{['Benutzer', 'Lizenz', 'Für', 'Begründung', 'Angefragt', 'Aktionen'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[var(--text-muted,#8b949e)]  uppercase tracking-wider">{h}</th>
                    ))}</tr>
                  </thead>
                  <tbody className="divide-y divide-[rgba(255,255,255,0.07)] ">
                    {pending.map(r => (
                      <tr key={r.id} className="hover:bg-[rgba(255,255,255,0.04)] ">
                        <td className="px-4 py-3 text-sm font-medium text-[var(--text-primary,#e4e6ea)] ">{r.requester_name}</td>
                        <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">{r.license_name}</td>
                        <td className="px-4 py-3">
                          <span className="text-xs bg-[rgba(255,255,255,0.06)]  text-[var(--text-secondary,#b1b5bd)]  px-2 py-0.5 rounded-full capitalize">{r.assignee_type}</span>
                          {r.assignee_name && <span className="text-xs text-[var(--text-muted,#8b949e)]  ml-1">{r.assignee_name}</span>}
                        </td>
                        <td className="px-4 py-3">
                          <p className="text-xs text-[var(--text-secondary,#b1b5bd)]  max-w-xs truncate">{r.justification || '—'}</p>
                        </td>
                        <td className="px-4 py-3 text-xs text-[var(--text-muted,#8b949e)]  whitespace-nowrap">{fmtDate(r.requested_at)}</td>
                        <td className="px-4 py-3">
                          {r.identity_bound !== true ? <span className="text-xs text-amber-600">Identität ungeklärt – Anfrage neu erstellen</span> : canReviewRequests && r.requester_id !== access?.subject && !(r.assignee_type === 'user' && r.assignee_id === access?.subject) ? <div className="flex gap-2">
                            <button onClick={() => approveLicReq(r.id)}
                              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-[#34C759] rounded-lg hover:bg-green-600">
                              <CheckCircleIcon className="w-3.5 h-3.5" /> Genehmigen
                            </button>
                            <button onClick={() => denyLicReq(r.id)}
                              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100">
                              <XCircleIcon className="w-3.5 h-3.5" /> Ablehnen
                            </button>
                          </div> : <span className="text-xs text-[var(--text-muted)]">Wartet auf unabhängige Genehmigung</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* History */}
          <div>
            <p className="text-xs font-semibold text-[var(--text-muted,#8b949e)]  uppercase tracking-wider mb-2">Verlauf</p>
            <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)' }}>
              {requests.filter(r => r.status !== 'pending').length === 0 ? (
                <div className="text-center py-12">
                  <ClockIcon className="w-8 h-8 mx-auto mb-2 text-[var(--text-muted,#8b949e)]  opacity-40" />
                  <p className="text-sm text-[var(--text-muted,#8b949e)] ">Noch kein Verlauf</p>
                </div>
              ) : (
                <table className="w-full">
                  <thead className="bg-[rgba(255,255,255,0.04)]  border-b border-[rgba(255,255,255,0.07)] ">
                    <tr>{['Benutzer', 'Lizenz', 'Status', 'Entschieden am', 'Durch'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[var(--text-muted,#8b949e)]  uppercase tracking-wider">{h}</th>
                    ))}</tr>
                  </thead>
                  <tbody className="divide-y divide-[rgba(255,255,255,0.07)] ">
                    {requests.filter(r => r.status !== 'pending').map(r => (
                      <tr key={r.id} className="hover:bg-[rgba(255,255,255,0.04)] ">
                        <td className="px-4 py-3 text-sm text-[var(--text-primary,#e4e6ea)] ">{r.requester_name}</td>
                        <td className="px-4 py-3 text-sm text-[var(--text-secondary,#b1b5bd)] ">{r.license_name}</td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                            r.status === 'approved' ? 'bg-green-50 text-green-700 border-green-200'
                            : 'bg-red-50 text-red-700 border-red-200'}`}>
                            {r.status === 'approved' ? r.assignee_type === 'group' ? `Genehmigt · ${GROUP_STATUS[r.allocation_status || 'pending'] || r.allocation_status}` : 'Genehmigt' : r.status === 'cancelled' ? 'Zurückgezogen' : 'Abgelehnt'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-[var(--text-muted,#8b949e)] ">{fmtDate(r.decided_at)}</td>
                        <td className="px-4 py-3 text-xs text-[var(--text-secondary,#b1b5bd)] ">{r.decided_by || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {orderLicense && (
        <RequestModal license={orderLicense} canRequestForOthers={canRequestForOthers} onClose={() => setOrderLicense(null)} onSubmitted={load} />
      )}
      {showLicForm && canManageCatalog && (
        <LicenseFormModal license={editLicense} onClose={() => setShowLicForm(false)} onSaved={load} />
      )}

      <style jsx global>{`
        .input-apple {
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          border: 1px solid rgba(255,255,255,0.07);
          border-radius: 0.5rem;
          outline: none;
          transition: border-color 0.15s, box-shadow 0.15s;
          background: var(--bg-surface-raised, #21262d);
          color: var(--text-primary, #e4e6ea);
        }
        .input-apple:focus {
          border-color: #006FFF;
          box-shadow: 0 0 0 3px rgba(0,111,255,0.15);
        }
      `}</style>
    </div>
  );
}
