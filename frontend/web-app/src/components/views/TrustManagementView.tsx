'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';
import {
  ArrowPathIcon,
  PlusIcon,
  XMarkIcon,
  TrashIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

// ─── Types ──────────────────────────────────────────────────────────────────────

const SAMBA_URL = process.env.NEXT_PUBLIC_SAMBA_URL || 'http://samba-ad-dc:3010';

type TrustType = 'External' | 'Forest' | 'Shortcut' | 'Kerberos Realm';
type TrustDirection = 'Inbound' | 'Outbound' | 'Bidirectional';
type TrustTransitivity = 'Transitive' | 'Non-Transitive';

interface Trust {
  domain: string;
  trustType: TrustType;
  trustDirection: TrustDirection;
  transitivity: TrustTransitivity;
  status?: 'healthy' | 'degraded' | 'unknown';
  lastVerified?: string;
  latencyMs?: number;
  errors?: string[];
}

interface VerifyResult {
  healthy: boolean;
  latencyMs: number;
  lastVerified: string;
  errors?: string[];
}

// ─── New Trust Modal ────────────────────────────────────────────────────────────

function NewTrustModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    trustedDomain:   '',
    trustType:       'External' as TrustType,
    trustDirection:  'Bidirectional' as TrustDirection,
    transitivity:    'Transitive' as TrustTransitivity,
    trustPassword:   '',
  });
  const [submitting, setSubmitting] = useState(false);

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(prev => ({ ...prev, [k]: e.target.value }));

  const handleCreate = async () => {
    if (!form.trustedDomain.trim()) { toast.error('Trusted domain is required'); return; }
    if (!form.trustPassword.trim()) { toast.error('Trust password is required'); return; }
    setSubmitting(true);
    try {
      await api.post(`${SAMBA_URL}/api/trusts`, form);
      toast.success(`Trust with ${form.trustedDomain} created`);
      onCreated();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to create trust');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-gray-900">New Domain Trust</h3>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-5 h-5" /></button>
          </div>

          {/* Trusted Domain */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Trusted Domain</label>
            <input
              type="text"
              placeholder="partner.corp"
              value={form.trustedDomain}
              onChange={set('trustedDomain')}
              className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Trust Type */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Trust Type</label>
            <select value={form.trustType} onChange={set('trustType')}
              className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
              {(['External', 'Forest', 'Shortcut', 'Kerberos Realm'] as TrustType[]).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Direction */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Direction</label>
            <select value={form.trustDirection} onChange={set('trustDirection')}
              className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
              {(['Inbound', 'Outbound', 'Bidirectional'] as TrustDirection[]).map(d => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </div>

          {/* Transitivity */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Transitivity</label>
            <select value={form.transitivity} onChange={set('transitivity')}
              className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
              {(['Transitive', 'Non-Transitive'] as TrustTransitivity[]).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Trust Password */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Trust Password</label>
            <input
              type="password"
              value={form.trustPassword}
              onChange={set('trustPassword')}
              className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg disabled:opacity-50">
              Cancel
            </button>
            <button onClick={handleCreate} disabled={submitting}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-60">
              {submitting ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Creating…</> : 'Create Trust'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Status Badge ───────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status?: Trust['status'] }) {
  if (status === 'healthy') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-100">
      <CheckCircleIcon className="w-3.5 h-3.5" /> Healthy
    </span>
  );
  if (status === 'degraded') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-50 text-yellow-700 border border-yellow-100">
      <ExclamationTriangleIcon className="w-3.5 h-3.5" /> Degraded
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500">
      Unknown
    </span>
  );
}

function formatRelative(iso?: string): string {
  if (!iso) return '—';
  try {
    const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (diff < 60)   return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  } catch { return '—'; }
}

// ─── Main View ──────────────────────────────────────────────────────────────────

export default function TrustManagementView() {
  const [trusts,       setTrusts]       = useState<Trust[]>([]);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState<string | null>(null);
  const [selected,     setSelected]     = useState<Trust | null>(null);
  const [showNew,      setShowNew]      = useState(false);
  const [verifying,    setVerifying]    = useState<string | null>(null);
  const [rotating,     setRotating]     = useState<string | null>(null);
  const [deleting,     setDeleting]     = useState<string | null>(null);

  const loadTrusts = useCallback(async () => {
    try {
      setError(null);
      const res = await api.get(`${SAMBA_URL}/api/trusts`);
      const data: Trust[] = res.data?.trusts || res.data || [];
      setTrusts(data);
      if (selected) {
        const updated = data.find(t => t.domain === selected.domain);
        if (updated) setSelected(updated);
      }
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to load trusts');
    } finally {
      setLoading(false);
    }
  }, [selected]);

  useEffect(() => {
    loadTrusts();
  }, []);

  const handleVerify = async (domain: string) => {
    setVerifying(domain);
    try {
      const res = await api.get(`${SAMBA_URL}/api/trusts/${encodeURIComponent(domain)}/verify`);
      const result: VerifyResult = res.data;
      const status: Trust['status'] = result.healthy ? 'healthy' : 'degraded';
      setTrusts(prev => prev.map(t => t.domain === domain ? { ...t, status, latencyMs: result.latencyMs, lastVerified: result.lastVerified, errors: result.errors } : t));
      if (selected?.domain === domain) setSelected(prev => prev ? { ...prev, status, latencyMs: result.latencyMs, lastVerified: result.lastVerified, errors: result.errors } : prev);
      toast.success(result.healthy ? `Trust with ${domain} is healthy` : `Trust with ${domain} is degraded`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Verification failed');
    } finally {
      setVerifying(null);
    }
  };

  const handleRotate = async (domain: string) => {
    setRotating(domain);
    try {
      await api.post(`${SAMBA_URL}/api/trusts/${encodeURIComponent(domain)}/rotate-password`);
      toast.success(`Trust credential rotated for ${domain}`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Rotation failed');
    } finally {
      setRotating(null);
    }
  };

  const handleDelete = async (domain: string) => {
    if (deleting !== domain) { setDeleting(domain); return; }
    try {
      await api.delete(`${SAMBA_URL}/api/trusts/${encodeURIComponent(domain)}`);
      setTrusts(prev => prev.filter(t => t.domain !== domain));
      if (selected?.domain === domain) setSelected(null);
      toast.success(`Trust with ${domain} removed`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to remove trust');
    } finally {
      setDeleting(null);
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Forest &amp; Trust Management</h1>
          <p className="text-sm text-gray-500 mt-0.5">Manage domain trusts and forest relationships</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={loadTrusts}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50">
            <ArrowPathIcon className="w-4 h-4" /> Refresh
          </button>
          <button onClick={() => setShowNew(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg">
            <PlusIcon className="w-4 h-4" /> New Trust
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 text-sm flex items-center gap-2">
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trust list */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100">
            <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">Domain Trusts</span>
          </div>

          {loading ? (
            <div className="p-6 space-y-3 animate-pulse">
              {[...Array(3)].map((_, i) => <div key={i} className="h-14 bg-gray-100 rounded-lg" />)}
            </div>
          ) : trusts.length === 0 ? (
            <div className="p-10 text-center text-gray-400">
              <div className="text-4xl mb-2">🌐</div>
              <p className="text-sm">No domain trusts configured</p>
              <button onClick={() => setShowNew(true)} className="mt-3 text-sm text-blue-600 hover:text-blue-700 font-medium">
                + Create your first trust
              </button>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {trusts.map(trust => (
                <button key={trust.domain}
                  onClick={() => setSelected(trust)}
                  className={`w-full flex items-center gap-4 px-5 py-3.5 text-left transition-colors ${
                    selected?.domain === trust.domain ? 'bg-blue-50' : 'hover:bg-gray-50'
                  }`}>
                  <span className="text-xl flex-shrink-0">🌐</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900">{trust.domain}</p>
                    <p className="text-xs text-gray-400">{trust.trustDirection} · {trust.trustType}</p>
                  </div>
                  <StatusBadge status={trust.status} />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Trust detail */}
        {selected ? (
          <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">Trust Details</span>
              <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-gray-600">
                <XMarkIcon className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* Domain */}
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Domain</p>
                <p className="text-sm font-medium text-gray-900 font-mono">{selected.domain}</p>
              </div>

              {/* Properties grid */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Trust Type',    value: selected.trustType },
                  { label: 'Direction',     value: selected.trustDirection },
                  { label: 'Transitivity',  value: selected.transitivity },
                  { label: 'Last Verified', value: formatRelative(selected.lastVerified) },
                  ...(selected.latencyMs !== undefined ? [{ label: 'Latency', value: `${selected.latencyMs} ms` }] : []),
                ].map(({ label, value }) => (
                  <div key={label} className="bg-gray-50 rounded-lg px-3 py-2.5">
                    <p className="text-xs text-gray-400 mb-0.5">{label}</p>
                    <p className="text-sm font-medium text-gray-900">{value}</p>
                  </div>
                ))}
              </div>

              {/* Status */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-gray-500">Status:</span>
                <StatusBadge status={selected.status} />
              </div>

              {/* Errors */}
              {selected.errors && selected.errors.length > 0 && (
                <div className="bg-red-50 border border-red-100 rounded-lg p-3 space-y-1">
                  {selected.errors.map((e, i) => (
                    <p key={i} className="text-xs text-red-700">{e}</p>
                  ))}
                </div>
              )}

              {/* Actions */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-100">
                <button onClick={() => handleVerify(selected.domain)} disabled={verifying === selected.domain}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg disabled:opacity-60">
                  <ArrowPathIcon className={`w-4 h-4 ${verifying === selected.domain ? 'animate-spin' : ''}`} />
                  {verifying === selected.domain ? 'Verifying…' : 'Verify Now'}
                </button>

                <button onClick={() => handleRotate(selected.domain)} disabled={rotating === selected.domain}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg disabled:opacity-60">
                  <ArrowPathIcon className={`w-4 h-4 ${rotating === selected.domain ? 'animate-spin' : ''}`} />
                  {rotating === selected.domain ? 'Rotating…' : 'Rotate Credential'}
                </button>

                {deleting === selected.domain ? (
                  <div className="flex items-center gap-1 ml-auto">
                    <button onClick={() => handleDelete(selected.domain)}
                      className="px-3 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg">
                      Confirm Remove
                    </button>
                    <button onClick={() => setDeleting(null)}
                      className="px-3 py-2 text-sm font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-lg">
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button onClick={() => handleDelete(selected.domain)}
                    className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg ml-auto">
                    <TrashIcon className="w-4 h-4" /> Remove Trust
                  </button>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-100 shadow-sm flex items-center justify-center p-10 text-gray-400">
            <p className="text-sm">Select a trust to view details</p>
          </div>
        )}
      </div>

      {showNew && <NewTrustModal onClose={() => setShowNew(false)} onCreated={loadTrusts} />}
    </div>
  );
}
