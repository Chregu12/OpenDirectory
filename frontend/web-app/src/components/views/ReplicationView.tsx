'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';
import {
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';

// ─── Constants ──────────────────────────────────────────────────────────────────

const SAMBA_URL = process.env.NEXT_PUBLIC_SAMBA_URL || 'http://samba-ad-dc:3010';

// ─── Types ──────────────────────────────────────────────────────────────────────

interface DCReplicationStatus {
  dcName: string;
  lastSuccess?: string;
  lastAttempt?: string;
  consecutiveFailures: number;
  usnGap: number;
}

interface ReplicationHealth {
  overall: 'healthy' | 'degraded' | 'failed';
  namingContexts?: { name: string; status: string }[];
}

type NamingContext = 'Domain' | 'Configuration' | 'Schema';

// ─── Force Sync Modal ───────────────────────────────────────────────────────────

function ForceSyncModal({ dcNames, onClose, onSynced }: {
  dcNames: string[];
  onClose: () => void;
  onSynced: () => void;
}) {
  const [form, setForm] = useState({ sourceDC: dcNames[0] ?? '', namingContext: 'Domain' as NamingContext });
  const [syncing, setSyncing] = useState(false);

  const handleSync = async () => {
    if (!form.sourceDC.trim()) { toast.error('Source DC is required'); return; }
    setSyncing(true);
    try {
      await api.post(`${SAMBA_URL}/api/replication/force-sync`, form);
      toast.success(`Sync triggered from ${form.sourceDC} (${form.namingContext})`);
      onSynced();
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Failed to force sync');
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={onClose}>
      <div className="rounded-xl shadow-xl w-full max-w-md" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Force Replication Sync</h3>
            <button onClick={onClose} style={{ color: 'var(--text-muted)' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}>
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Source DC</label>
            {dcNames.length > 0 ? (
              <select value={form.sourceDC} onChange={e => setForm(p => ({ ...p, sourceDC: e.target.value }))}
                className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-strong)' }}>
                {dcNames.map(dc => <option key={dc} value={dc}>{dc}</option>)}
              </select>
            ) : (
              <input type="text" placeholder="DC01" value={form.sourceDC}
                onChange={e => setForm(p => ({ ...p, sourceDC: e.target.value }))}
                className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-strong)' }} />
            )}
          </div>

          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>Naming Context</label>
            <select value={form.namingContext} onChange={e => setForm(p => ({ ...p, namingContext: e.target.value as NamingContext }))}
              className="w-full px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-strong)' }}>
              {(['Domain', 'Configuration', 'Schema'] as NamingContext[]).map(nc => (
                <option key={nc} value={nc}>{nc}</option>
              ))}
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={syncing}
              className="px-4 py-2 text-sm font-medium rounded-lg disabled:opacity-50"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-strong)' }}>
              Cancel
            </button>
            <button onClick={handleSync} disabled={syncing}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-60">
              {syncing ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Syncing…</> : 'Force Sync'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Helper: format relative time ───────────────────────────────────────────────

function formatRelative(iso?: string): string {
  if (!iso) return '—';
  try {
    const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (diff < 60)    return `${diff}s ago`;
    if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  } catch { return '—'; }
}

// ─── DC Status Row ──────────────────────────────────────────────────────────────

function DCStatusRow({ dc }: { dc: DCReplicationStatus }) {
  const healthy = dc.consecutiveFailures === 0 && dc.usnGap === 0;
  const delayed = dc.usnGap > 0 || (dc.consecutiveFailures > 0 && dc.consecutiveFailures < 3);
  const failed  = dc.consecutiveFailures >= 3;

  return (
    <tr className="hover:bg-[#1c2128]">
      <td className="px-4 py-3 font-mono text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{dc.dcName}</td>
      <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{formatRelative(dc.lastSuccess)}</td>
      <td className="px-4 py-3 text-sm">
        {dc.usnGap === 0 ? (
          <span style={{ color: 'var(--text-muted)' }}>0</span>
        ) : (
          <span className="font-medium" style={{ color: 'var(--warning)' }}>{dc.usnGap.toLocaleString()}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {failed ? (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
            style={{ background: 'var(--danger-light)', color: 'var(--danger)', border: '1px solid rgba(248,81,73,0.3)' }}>
            <XCircleIcon className="w-3.5 h-3.5" /> Failed
          </span>
        ) : delayed ? (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
            style={{ background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid rgba(210,153,34,0.3)' }}>
            <ExclamationTriangleIcon className="w-3.5 h-3.5" /> Delayed
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
            style={{ background: 'var(--success-light)', color: 'var(--success)', border: '1px solid rgba(63,185,80,0.3)' }}>
            <CheckCircleIcon className="w-3.5 h-3.5" /> Healthy
          </span>
        )}
      </td>
    </tr>
  );
}

// ─── Overall Health Badge ───────────────────────────────────────────────────────

function HealthBadge({ overall }: { overall?: 'healthy' | 'degraded' | 'failed' }) {
  if (overall === 'healthy') return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg"
      style={{ background: 'var(--success-light)', border: '1px solid rgba(63,185,80,0.3)' }}>
      <CheckCircleIcon className="w-5 h-5" style={{ color: 'var(--success)' }} />
      <span className="text-sm font-semibold" style={{ color: 'var(--success)' }}>Healthy</span>
    </div>
  );
  if (overall === 'degraded') return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg"
      style={{ background: 'var(--warning-light)', border: '1px solid rgba(210,153,34,0.3)' }}>
      <ExclamationTriangleIcon className="w-5 h-5" style={{ color: 'var(--warning)' }} />
      <span className="text-sm font-semibold" style={{ color: 'var(--warning)' }}>Degraded</span>
    </div>
  );
  if (overall === 'failed') return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg"
      style={{ background: 'var(--danger-light)', border: '1px solid rgba(248,81,73,0.3)' }}>
      <XCircleIcon className="w-5 h-5" style={{ color: 'var(--danger)' }} />
      <span className="text-sm font-semibold" style={{ color: 'var(--danger)' }}>Failed</span>
    </div>
  );
  return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg"
      style={{ background: 'var(--bg-surface-raised)' }}>
      <span className="text-sm font-medium" style={{ color: 'var(--text-muted)' }}>Unknown</span>
    </div>
  );
}

// ─── Main View ──────────────────────────────────────────────────────────────────

export default function ReplicationView() {
  const [dcList,     setDcList]     = useState<DCReplicationStatus[]>([]);
  const [health,     setHealth]     = useState<ReplicationHealth | null>(null);
  const [usn,        setUsn]        = useState<number | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState<string | null>(null);
  const [showSync,   setShowSync]   = useState(false);
  const [checkingLO, setCheckingLO] = useState<string | null>(null);
  const [loResult,   setLoResult]   = useState<any>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statusRes, healthRes, usnRes] = await Promise.allSettled([
        api.get(`${SAMBA_URL}/api/replication/status`),
        api.get(`${SAMBA_URL}/api/replication/health`),
        api.get(`${SAMBA_URL}/api/replication/usn`),
      ]);

      if (statusRes.status === 'fulfilled') {
        setDcList(statusRes.value.data?.dcs || statusRes.value.data || []);
      }
      if (healthRes.status === 'fulfilled') {
        setHealth(healthRes.value.data?.health || healthRes.value.data || null);
      }
      if (usnRes.status === 'fulfilled') {
        setUsn(usnRes.value.data?.usn ?? null);
      }

      if (statusRes.status === 'rejected' && healthRes.status === 'rejected') {
        const err = (statusRes.reason as any)?.response?.data?.error
          || (statusRes.reason as any)?.message
          || 'Failed to load replication status';
        setError(err);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const handleCheckLingeringObjects = async (dcName: string) => {
    setCheckingLO(dcName);
    setLoResult(null);
    try {
      const res = await api.get(`${SAMBA_URL}/api/replication/lingering-objects/${encodeURIComponent(dcName)}`);
      setLoResult({ dc: dcName, data: res.data });
      toast.success(`Lingering object check complete for ${dcName}`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err?.message || 'Check failed');
    } finally {
      setCheckingLO(null);
    }
  };

  return (
    <div className="p-6 space-y-6" style={{ background: 'var(--bg-base)', minHeight: '100vh' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>Active Directory Replication</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>Monitor and manage DC replication health</p>
        </div>
        <button onClick={load}
          className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg"
          style={{ color: 'var(--text-primary)', background: 'var(--bg-surface)', border: '1px solid var(--border-strong)' }}
          onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-surface-raised)')}
          onMouseLeave={e => (e.currentTarget.style.background = 'var(--bg-surface)')}>
          <ArrowPathIcon className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg px-4 py-3 text-sm flex items-center gap-2"
          style={{ background: 'var(--danger-light)', border: '1px solid rgba(248,81,73,0.3)', color: 'var(--danger)' }}>
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      {/* Overall health + USN */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }} className="mb-2">
            Overall Health
          </p>
          {loading ? (
            <div className="h-10 rounded-lg animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />
          ) : (
            <HealthBadge overall={health?.overall} />
          )}
        </div>

        <div className="rounded-xl p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }} className="mb-2">
            Current USN
          </p>
          {loading ? (
            <div className="h-8 w-24 rounded-lg animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />
          ) : (
            <p className="text-2xl font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>
              {usn !== null ? usn.toLocaleString() : '—'}
            </p>
          )}
        </div>
      </div>

      {/* Naming contexts */}
      {health?.namingContexts && health.namingContexts.length > 0 && (
        <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Naming Contexts
            </span>
          </div>
          <div>
            {health.namingContexts.map((nc, idx) => (
              <div key={nc.name} className="flex items-center justify-between px-5 py-3"
                style={{ borderBottom: idx < (health.namingContexts?.length ?? 0) - 1 ? '1px solid var(--border)' : 'none' }}>
                <span className="text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{nc.name}</span>
                <span className="px-2 py-0.5 rounded-full text-xs font-medium" style={
                  nc.status === 'healthy'
                    ? { background: 'var(--success-light)', color: 'var(--success)', border: '1px solid rgba(63,185,80,0.3)' }
                    : { background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid rgba(210,153,34,0.3)' }
                }>{nc.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* DC table */}
      <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
        <div className="px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Domain Controllers
          </span>
        </div>

        {loading ? (
          <div className="p-6 space-y-3 animate-pulse">
            {[...Array(3)].map((_, i) => <div key={i} className="h-12 rounded-lg" style={{ background: 'var(--bg-surface-raised)' }} />)}
          </div>
        ) : dcList.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No domain controller data available</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead style={{ background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }}>
                <tr>
                  {['DC Name', 'Last Success', 'USN Gap', 'Status'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dcList.map((dc, idx) => (
                  <React.Fragment key={dc.dcName}>
                    {idx > 0 && (
                      <tr style={{ height: 0 }}>
                        <td colSpan={4} style={{ padding: 0, borderTop: '1px solid var(--border)' }} />
                      </tr>
                    )}
                    <DCStatusRow dc={dc} />
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={() => setShowSync(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg">
          <ArrowPathIcon className="w-4 h-4" /> Force Sync
        </button>

        {dcList.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>Check lingering objects on:</span>
            <select
              onChange={e => e.target.value && handleCheckLingeringObjects(e.target.value)}
              value=""
              className="px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-strong)' }}
              disabled={!!checkingLO}>
              <option value="">Select DC…</option>
              {dcList.map(dc => <option key={dc.dcName} value={dc.dcName}>{dc.dcName}</option>)}
            </select>
            {checkingLO && (
              <ArrowPathIcon className="w-4 h-4 text-blue-500 animate-spin" />
            )}
          </div>
        )}
      </div>

      {/* Lingering objects result */}
      {loResult && (
        <div className="rounded-xl p-5" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)' }}>
          <div className="flex items-center justify-between mb-3">
            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Lingering Objects — {loResult.dc}
            </p>
            <button onClick={() => setLoResult(null)}
              style={{ color: 'var(--text-muted)' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}>
              <XMarkIcon className="w-4 h-4" />
            </button>
          </div>
          {loResult.data?.count === 0 || (Array.isArray(loResult.data) && loResult.data.length === 0) ? (
            <div className="flex items-center gap-2" style={{ color: 'var(--success)' }}>
              <CheckCircleIcon className="w-5 h-5" />
              <span className="text-sm font-medium">No lingering objects found.</span>
            </div>
          ) : (
            <pre className="text-xs font-mono rounded-lg p-3 overflow-x-auto whitespace-pre-wrap"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }}>
              {JSON.stringify(loResult.data, null, 2)}
            </pre>
          )}
        </div>
      )}

      {showSync && (
        <ForceSyncModal
          dcNames={dcList.map(d => d.dcName)}
          onClose={() => setShowSync(false)}
          onSynced={load}
        />
      )}
    </div>
  );
}
