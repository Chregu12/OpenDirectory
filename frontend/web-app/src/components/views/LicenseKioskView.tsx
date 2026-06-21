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
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface License {
  id: string;
  name: string;
  vendor: string;
  category: string;
  license_type: 'per_user' | 'per_device' | 'concurrent' | 'subscription';
  total_seats: number;
  used_seats: number;
  cost_per_seat: number;
  currency: string;
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
  status: 'pending' | 'approved' | 'denied';
  requested_at: string;
  decided_at?: string;
  decided_by?: string;
}

type Tab = 'kiosk' | 'verwaltung' | 'anfragen';

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

function fmtCHF(amount: number, currency = 'CHF') {
  return `${currency} ${amount.toFixed(2)}`;
}

function seatsColor(used: number, total: number) {
  if (total === 0) return 'text-[var(--text-muted,#8b949e)] ';
  const pct = used / total;
  if (pct >= 1)   return 'text-red-500';
  if (pct >= 0.8) return 'text-[#FF9500]';
  return 'text-[#34C759]';
}

// ─── Request Modal ────────────────────────────────────────────────────────────

function RequestModal({ license, onClose, onSubmitted }: {
  license: License;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const [form, setForm] = useState({
    assignee_type: 'user' as 'user' | 'group' | 'device',
    assignee_id: '',
    assignee_name: '',
    justification: '',
    requester_id: 'current-user',
    requester_name: 'Aktueller Benutzer',
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
      await api.post(`/api/licenses/${license.id}/request`, form);
      toast.success(license.auto_approve ? 'Lizenz sofort zugewiesen!' : 'Anfrage eingereicht — wartet auf Genehmigung');
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
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{license.vendor} · {fmtCHF(license.cost_per_seat, license.currency)}/Lizenz</p>
          </div>
          <button onClick={onClose}><XMarkIcon className="w-5 h-5" style={{ color: 'var(--text-muted)' }} /></button>
        </div>
        <div className="p-6 space-y-4">
          {available <= 0 && (
            <div className="flex items-center gap-2 rounded-xl px-4 py-3" style={{ background: 'var(--danger-light)', border: '1px solid var(--danger)' }}>
              <ExclamationTriangleIcon className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--danger)' }} />
              <p className="text-sm" style={{ color: 'var(--danger)' }}>Keine Lizenzen verfügbar — Anfrage trotzdem möglich</p>
            </div>
          )}
          {license.auto_approve && (
            <div className="flex items-center gap-2 rounded-xl px-4 py-3" style={{ background: 'var(--success-light)', border: '1px solid var(--success)' }}>
              <CheckCircleIcon className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--success)' }} />
              <p className="text-sm" style={{ color: 'var(--success)' }}>Wird sofort zugewiesen — keine Genehmigung nötig</p>
            </div>
          )}
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

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [licRes, reqRes] = await Promise.allSettled([
        api.get('/api/licenses'),
        api.get('/api/licenses/requests'),
      ]);
      if (licRes.status === 'fulfilled') setLicenses(licRes.value.data?.data ?? licRes.value.data ?? []);
      if (reqRes.status === 'fulfilled') setRequests(reqRes.value.data?.data ?? reqRes.value.data ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const approveLicReq = async (id: string) => {
    await api.post(`/api/licenses/requests/${id}/approve`);
    toast.success('Lizenz zugewiesen');
    load();
  };
  const denyLicReq = async (id: string) => {
    await api.post(`/api/licenses/requests/${id}/deny`);
    toast.success('Anfrage abgelehnt');
    load();
  };
  const deleteLicense = async (id: string) => {
    await api.delete(`/api/licenses/${id}`);
    toast.success('Lizenz entfernt');
    load();
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

  const totalCost = licenses.reduce((sum, l) => sum + l.cost_per_seat * l.used_seats, 0);
  const totalSeats = licenses.reduce((sum, l) => sum + l.total_seats, 0);
  const usedSeats  = licenses.reduce((sum, l) => sum + l.used_seats, 0);

  const TABS: { key: Tab; label: string; badge?: number }[] = [
    { key: 'kiosk',      label: '🛒 Kiosk' },
    { key: 'verwaltung', label: 'Verwaltung' },
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
          {tab === 'verwaltung' && (
            <button onClick={() => { setEditLicense(undefined); setShowLicForm(true); }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#006FFF]/90">
              <PlusIcon className="w-4 h-4" /> Lizenz hinzufügen
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Lizenzen total', value: licenses.length,                       sub: 'Produkte' },
          { label: 'Seats vergeben', value: `${usedSeats} / ${totalSeats}`,        sub: 'genutzt / verfügbar' },
          { label: 'Monatliche Kosten', value: `CHF ${totalCost.toFixed(0)}`,      sub: 'aktuelle Zuweisung' },
          { label: 'Offene Anfragen', value: pending.length,                       sub: 'warten auf Genehmigung' },
        ].map(({ label, value, sub }) => (
          <div key={label} className="rounded-xl p-4" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid rgba(255,255,255,0.07)' }}>
            <p className="text-xs text-[var(--text-muted,#8b949e)]  mb-1">{label}</p>
            <p className="text-xl font-semibold text-[var(--text-primary,#e4e6ea)] ">{value}</p>
            <p className="text-xs text-[var(--text-muted,#8b949e)]  mt-0.5">{sub}</p>
          </div>
        ))}
      </div>

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
                      <div className="text-right flex-shrink-0 ml-3">
                        <p className="text-sm font-semibold text-[var(--text-primary,#e4e6ea)] ">{fmtCHF(lic.cost_per_seat, lic.currency)}</p>
                        <p className="text-xs text-[var(--text-muted,#8b949e)] ">pro {TYPE_LABELS[lic.license_type]?.split(' ')[1] ?? 'Seat'}</p>
                      </div>
                    </div>

                    {lic.description && (
                      <p className="text-xs text-[var(--text-secondary,#b1b5bd)]  mb-3 line-clamp-2">{lic.description}</p>
                    )}

                    {/* Seat bar */}
                    <div className="mb-3">
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-[var(--text-muted,#8b949e)] ">Verfügbar</span>
                        <span className={seatsColor(lic.used_seats, lic.total_seats)}>
                          {avail} / {lic.total_seats}
                        </span>
                      </div>
                      <div className="h-1.5 bg-[rgba(255,255,255,0.06)]  rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all ${pct >= 1 ? 'bg-red-500' : pct >= 0.8 ? 'bg-[#FF9500]' : 'bg-[#34C759]'}`}
                          style={{ width: `${Math.min(pct * 100, 100)}%` }} />
                      </div>
                    </div>

                    <div className="mt-auto">
                      <button onClick={() => setOrderLicense(lic)}
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
                        <button onClick={() => { setEditLicense(lic); setShowLicForm(true); }}
                          className="p-1.5 rounded-lg hover:bg-[rgba(255,255,255,0.06)] ">
                          <PencilIcon className="w-4 h-4 text-[var(--text-muted,#8b949e)] " />
                        </button>
                        <button onClick={() => deleteLicense(lic.id)}
                          className="p-1.5 rounded-lg hover:bg-red-50">
                          <TrashIcon className="w-4 h-4 text-red-400" />
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
                          <div className="flex gap-2">
                            <button onClick={() => approveLicReq(r.id)}
                              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-[#34C759] rounded-lg hover:bg-green-600">
                              <CheckCircleIcon className="w-3.5 h-3.5" /> Genehmigen
                            </button>
                            <button onClick={() => denyLicReq(r.id)}
                              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100">
                              <XCircleIcon className="w-3.5 h-3.5" /> Ablehnen
                            </button>
                          </div>
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
                            {r.status === 'approved' ? 'Genehmigt' : 'Abgelehnt'}
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
        <RequestModal license={orderLicense} onClose={() => setOrderLicense(null)} onSubmitted={load} />
      )}
      {showLicForm && (
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
