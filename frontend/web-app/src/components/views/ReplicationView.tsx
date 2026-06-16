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
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-gray-900">Force Replication Sync</h3>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="w-5 h-5" /></button>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Source DC</label>
            {dcNames.length > 0 ? (
              <select value={form.sourceDC} onChange={e => setForm(p => ({ ...p, sourceDC: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
                {dcNames.map(dc => <option key={dc} value={dc}>{dc}</option>)}
              </select>
            ) : (
              <input type="text" placeholder="DC01" value={form.sourceDC}
                onChange={e => setForm(p => ({ ...p, sourceDC: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono" />
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Naming Context</label>
            <select value={form.namingContext} onChange={e => setForm(p => ({ ...p, namingContext: e.target.value as NamingContext }))}
              className="w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
              {(['Domain', 'Configuration', 'Schema'] as NamingContext[]).map(nc => (
                <option key={nc} value={nc}>{nc}</option>
              ))}
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} disabled={syncing}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg disabled:opacity-50">Cancel</button>
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
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-3 font-mono text-sm font-medium text-gray-900">{dc.dcName}</td>
      <td className="px-4 py-3 text-sm text-gray-600">{formatRelative(dc.lastSuccess)}</td>
      <td className="px-4 py-3 text-sm">
        {dc.usnGap === 0 ? (
          <span className="text-gray-500">0</span>
        ) : (
          <span className="font-medium text-yellow-700">{dc.usnGap.toLocaleString()}</span>
        )}
      </td>
      <td className="px-4 py-3">
        {failed ? (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-100">
            <XCircleIcon className="w-3.5 h-3.5" /> Failed
          </span>
        ) : delayed ? (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-50 text-yellow-700 border border-yellow-100">
            <ExclamationTriangleIcon className="w-3.5 h-3.5" /> Delayed
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-100">
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
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-green-50 border border-green-100">
      <CheckCircleIcon className="w-5 h-5 text-green-600" />
      <span className="text-sm font-semibold text-green-800">Healthy</span>
    </div>
  );
  if (overall === 'degraded') return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-yellow-50 border border-yellow-200">
      <ExclamationTriangleIcon className="w-5 h-5 text-yellow-600" />
      <span className="text-sm font-semibold text-yellow-800">Degraded</span>
    </div>
  );
  if (overall === 'failed') return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-red-50 border border-red-200">
      <XCircleIcon className="w-5 h-5 text-red-600" />
      <span className="text-sm font-semibold text-red-800">Failed</span>
    </div>
  );
  return (
    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100">
      <span className="text-sm font-medium text-gray-500">Unknown</span>
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
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Active Directory Replication</h1>
          <p className="text-sm text-gray-500 mt-0.5">Monitor and manage DC replication health</p>
        </div>
        <button onClick={load}
          className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50">
          <ArrowPathIcon className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 text-sm flex items-center gap-2">
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      {/* Overall health + USN */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-4">
          <p style={{ fontSize: 11, fontWeight: 600, color: '#86868b', textTransform: 'uppercase', letterSpacing: '0.05em' }} className="mb-2">
            Overall Health
          </p>
          {loading ? (
            <div className="h-10 bg-gray-100 rounded-lg animate-pulse" />
          ) : (
            <HealthBadge overall={health?.overall} />
          )}
        </div>

        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-4">
          <p style={{ fontSize: 11, fontWeight: 600, color: '#86868b', textTransform: 'uppercase', letterSpacing: '0.05em' }} className="mb-2">
            Current USN
          </p>
          {loading ? (
            <div className="h-8 w-24 bg-gray-100 rounded-lg animate-pulse" />
          ) : (
            <p className="text-2xl font-semibold text-gray-900 font-mono">
              {usn !== null ? usn.toLocaleString() : '—'}
            </p>
          )}
        </div>
      </div>

      {/* Naming contexts */}
      {health?.namingContexts && health.namingContexts.length > 0 && (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100">
            <span style={{ fontSize: 11, fontWeight: 600, color: '#86868b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Naming Contexts
            </span>
          </div>
          <div className="divide-y divide-gray-50">
            {health.namingContexts.map(nc => (
              <div key={nc.name} className="flex items-center justify-between px-5 py-3">
                <span className="text-sm font-mono text-gray-700">{nc.name}</span>
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                  nc.status === 'healthy'
                    ? 'bg-green-50 text-green-700 border border-green-100'
                    : 'bg-yellow-50 text-yellow-700 border border-yellow-100'
                }`}>{nc.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* DC table */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-100">
          <span style={{ fontSize: 11, fontWeight: 600, color: '#86868b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Domain Controllers
          </span>
        </div>

        {loading ? (
          <div className="p-6 space-y-3 animate-pulse">
            {[...Array(3)].map((_, i) => <div key={i} className="h-12 bg-gray-100 rounded-lg" />)}
          </div>
        ) : dcList.length === 0 ? (
          <div className="p-10 text-center text-gray-400">
            <p className="text-sm">No domain controller data available</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-100">
                <tr>
                  {['DC Name', 'Last Success', 'USN Gap', 'Status'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {dcList.map(dc => <DCStatusRow key={dc.dcName} dc={dc} />)}
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
            <span className="text-sm text-gray-500">Check lingering objects on:</span>
            <select
              onChange={e => e.target.value && handleCheckLingeringObjects(e.target.value)}
              value=""
              className="px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
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
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
          <div className="flex items-center justify-between mb-3">
            <p style={{ fontSize: 11, fontWeight: 600, color: '#86868b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Lingering Objects — {loResult.dc}
            </p>
            <button onClick={() => setLoResult(null)} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-4 h-4" />
            </button>
          </div>
          {loResult.data?.count === 0 || (Array.isArray(loResult.data) && loResult.data.length === 0) ? (
            <div className="flex items-center gap-2 text-green-700">
              <CheckCircleIcon className="w-5 h-5" />
              <span className="text-sm font-medium">No lingering objects found.</span>
            </div>
          ) : (
            <pre className="text-xs font-mono text-gray-700 bg-gray-50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
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
