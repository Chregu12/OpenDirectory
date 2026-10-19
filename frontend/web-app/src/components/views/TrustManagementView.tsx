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
    <div
      className="fixed inset-0 flex items-center justify-center p-4 z-50"
      style={{ background: 'rgba(0,0,0,0.5)' }}
      onClick={onClose}
    >
      <div
        className="rounded-xl shadow-xl w-full max-w-md"
        style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>New Domain Trust</h3>
            <button
              onClick={onClose}
              style={{ color: 'var(--text-muted)' }}
              className="hover:opacity-80"
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {/* Trusted Domain */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Trusted Domain</label>
            <input
              type="text"
              placeholder="partner.corp"
              value={form.trustedDomain}
              onChange={set('trustedDomain')}
              className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          {/* Trust Type */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Trust Type</label>
            <select
              value={form.trustType}
              onChange={set('trustType')}
              className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-primary)',
              }}
            >
              {(['External', 'Forest', 'Shortcut', 'Kerberos Realm'] as TrustType[]).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Direction */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Direction</label>
            <select
              value={form.trustDirection}
              onChange={set('trustDirection')}
              className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-primary)',
              }}
            >
              {(['Inbound', 'Outbound', 'Bidirectional'] as TrustDirection[]).map(d => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </div>

          {/* Transitivity */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Transitivity</label>
            <select
              value={form.transitivity}
              onChange={set('transitivity')}
              className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-primary)',
              }}
            >
              {(['Transitive', 'Non-Transitive'] as TrustTransitivity[]).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Trust Password */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Trust Password</label>
            <input
              type="password"
              value={form.trustPassword}
              onChange={set('trustPassword')}
              className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={onClose}
              disabled={submitting}
              className="px-4 py-2 text-sm font-medium rounded-lg disabled:opacity-50 hover:opacity-80"
              style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)' }}
            >
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
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
      style={{ background: 'var(--success-light)', color: 'var(--success)', border: '1px solid rgba(63,185,80,0.3)' }}
    >
      <CheckCircleIcon className="w-3.5 h-3.5" /> Healthy
    </span>
  );
  if (status === 'degraded') return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
      style={{ background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid rgba(210,153,34,0.3)' }}
    >
      <ExclamationTriangleIcon className="w-3.5 h-3.5" /> Degraded
    </span>
  );
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
      style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-muted)' }}
    >
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
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>Forest &amp; Trust Management</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>Manage domain trusts and forest relationships</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadTrusts}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg hover:opacity-80"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface)', border: '1px solid var(--border)' }}
          >
            <ArrowPathIcon className="w-4 h-4" /> Refresh
          </button>
          <button onClick={() => setShowNew(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg">
            <PlusIcon className="w-4 h-4" /> New Trust
          </button>
        </div>
      </div>

      {error && (
        <div
          className="rounded-lg px-4 py-3 text-sm flex items-center gap-2"
          style={{ background: 'var(--danger-light)', border: '1px solid rgba(248,81,73,0.3)', color: 'var(--danger)' }}
        >
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trust list */}
        <div
          className="rounded-xl overflow-hidden"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}
        >
          <div className="px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Domain Trusts</span>
          </div>

          {loading ? (
            <div className="p-6 space-y-3 animate-pulse">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-14 rounded-lg" style={{ background: 'var(--bg-surface-raised)' }} />
              ))}
            </div>
          ) : trusts.length === 0 ? (
            <div className="p-10 text-center" style={{ color: 'var(--text-muted)' }}>
              <div className="text-4xl mb-2">🌐</div>
              <p className="text-sm">No domain trusts configured</p>
              <button
                onClick={() => setShowNew(true)}
                className="mt-3 text-sm font-medium hover:opacity-80"
                style={{ color: 'var(--accent)' }}
              >
                + Create your first trust
              </button>
            </div>
          ) : (
            <div className="divide-y divide-[rgba(255,255,255,0.07)]">
              {trusts.map(trust => (
                <button
                  key={trust.domain}
                  onClick={() => setSelected(trust)}
                  className="w-full flex items-center gap-4 px-5 py-3.5 text-left transition-colors"
                  style={
                    selected?.domain === trust.domain
                      ? { background: 'var(--accent-light)' }
                      : undefined
                  }
                  onMouseEnter={e => {
                    if (selected?.domain !== trust.domain) {
                      (e.currentTarget as HTMLElement).style.background = 'var(--bg-surface-raised)';
                    }
                  }}
                  onMouseLeave={e => {
                    if (selected?.domain !== trust.domain) {
                      (e.currentTarget as HTMLElement).style.background = '';
                    }
                  }}
                >
                  <span className="text-xl flex-shrink-0">🌐</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{trust.domain}</p>
                    <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{trust.trustDirection} · {trust.trustType}</p>
                  </div>
                  <StatusBadge status={trust.status} />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Trust detail */}
        {selected ? (
          <div
            className="rounded-xl overflow-hidden"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}
          >
            <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Trust Details</span>
              <button
                onClick={() => setSelected(null)}
                style={{ color: 'var(--text-muted)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
              >
                <XMarkIcon className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* Domain */}
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Domain</p>
                <p className="text-sm font-medium font-mono" style={{ color: 'var(--text-primary)' }}>{selected.domain}</p>
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
                  <div key={label} className="rounded-lg px-3 py-2.5" style={{ background: 'var(--bg-surface-raised)' }}>
                    <p className="text-xs mb-0.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{value}</p>
                  </div>
                ))}
              </div>

              {/* Status */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Status:</span>
                <StatusBadge status={selected.status} />
              </div>

              {/* Errors */}
              {selected.errors && selected.errors.length > 0 && (
                <div
                  className="rounded-lg p-3 space-y-1"
                  style={{ background: 'var(--danger-light)', border: '1px solid rgba(248,81,73,0.3)' }}
                >
                  {selected.errors.map((e, i) => (
                    <p key={i} className="text-xs" style={{ color: 'var(--danger)' }}>{e}</p>
                  ))}
                </div>
              )}

              {/* Actions */}
              <div className="flex flex-wrap gap-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <button
                  onClick={() => handleVerify(selected.domain)}
                  disabled={verifying === selected.domain}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg disabled:opacity-60 hover:opacity-80"
                  style={{ color: 'var(--accent)', background: 'var(--accent-light)' }}
                >
                  <ArrowPathIcon className={`w-4 h-4 ${verifying === selected.domain ? 'animate-spin' : ''}`} />
                  {verifying === selected.domain ? 'Verifying…' : 'Verify Now'}
                </button>

                <button
                  onClick={() => handleRotate(selected.domain)}
                  disabled={rotating === selected.domain}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg disabled:opacity-60 hover:opacity-80"
                  style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)' }}
                >
                  <ArrowPathIcon className={`w-4 h-4 ${rotating === selected.domain ? 'animate-spin' : ''}`} />
                  {rotating === selected.domain ? 'Rotating…' : 'Rotate Credential'}
                </button>

                {deleting === selected.domain ? (
                  <div className="flex items-center gap-1 ml-auto">
                    <button onClick={() => handleDelete(selected.domain)}
                      className="px-3 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg">
                      Confirm Remove
                    </button>
                    <button
                      onClick={() => setDeleting(null)}
                      className="px-3 py-2 text-sm font-medium rounded-lg hover:opacity-80"
                      style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)' }}
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => handleDelete(selected.domain)}
                    className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg ml-auto hover:opacity-80"
                    style={{ color: 'var(--danger)', background: 'var(--danger-light)' }}
                  >
                    <TrashIcon className="w-4 h-4" /> Remove Trust
                  </button>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div
            className="rounded-xl flex items-center justify-center p-10"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}
          >
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Select a trust to view details</p>
          </div>
        )}
      </div>

      {showNew && <NewTrustModal onClose={() => setShowNew(false)} onCreated={loadTrusts} />}
    </div>
  );
}
