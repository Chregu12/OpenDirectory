'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  XMarkIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ArrowTopRightOnSquareIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ComplianceSnapshotProps {
  onClose: () => void;
  onViewChange?: (view: string) => void;
}

interface TopViolation {
  name?: string;
  policy?: string;
  count: number;
  severity: 'high' | 'medium' | 'low' | 'critical' | 'warning' | 'info';
}

interface DeviceAttention {
  deviceId?: string;
  id?: string;
  name: string;
  issues?: string[];
  issue?: string;
  os?: string;
}

interface ComplianceData {
  compliant: number;
  warning: number;
  nonCompliant: number;
  totalDevices?: number;
  lastScan: string;
  topViolations: TopViolation[];
  devicesNeedingAttention: DeviceAttention[];
}

// ─── Fallback data ─────────────────────────────────────────────────────────────

const FALLBACK_DATA: ComplianceData = {
  compliant: 0,
  warning: 0,
  nonCompliant: 0,
  lastScan: new Date().toISOString(),
  topViolations: [],
  devicesNeedingAttention: [],
};

// ─── Donut chart (pure SVG) ───────────────────────────────────────────────────

function DonutChart({ compliant, warning, nonCompliant }: { compliant: number; warning: number; nonCompliant: number }) {
  const total = compliant + warning + nonCompliant;
  if (total === 0) return null;

  const r = 54;
  const cx = 70;
  const cy = 70;
  const strokeW = 20;
  const circumference = 2 * Math.PI * r;

  const segments = [
    { value: compliant,    color: '#22c55e', label: 'Compliant' },
    { value: warning,      color: '#eab308', label: 'Warning' },
    { value: nonCompliant, color: '#ef4444', label: 'Non-Compliant' },
  ];

  let offset = 0;
  const arcs = segments.map(seg => {
    const dash = (seg.value / total) * circumference;
    const gap  = circumference - dash;
    const gap2 = circumference * (offset / total);
    const arc = { dash, gap, gap2, ...seg };
    offset += seg.value;
    return arc;
  });

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
      <svg width={140} height={140} viewBox="0 0 140 140">
        {arcs.map((arc, i) => (
          <circle
            key={i}
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={arc.color}
            strokeWidth={strokeW}
            strokeDasharray={`${arc.dash} ${arc.gap}`}
            strokeDashoffset={-arc.gap2}
            transform={`rotate(-90 ${cx} ${cy})`}
          />
        ))}
        <text x={cx} y={cy - 6} textAnchor="middle" fontSize={22} fontWeight={700} fill="#1D1D1F">{total}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fontSize={11} fill="#6E6E73">devices</text>
      </svg>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {segments.map(seg => (
          <div key={seg.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: seg.color, flexShrink: 0 }} />
            <span style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>{seg.label}</span>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginLeft: 4 }}>{seg.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ComplianceSnapshot({ onClose, onViewChange }: ComplianceSnapshotProps) {
  const [data, setData]         = useState<ComplianceData>(FALLBACK_DATA);
  const [loading, setLoading]   = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const timeAgo = (iso: string) => {
    const ms = Date.now() - new Date(iso).getTime();
    const m = Math.round(ms / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m} min ago`;
    return `${Math.round(m / 60)} hr ago`;
  };

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/quick/compliance/snapshot');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();
      setData({
        compliant:    d.compliant    ?? 0,
        warning:      d.warning      ?? 0,
        nonCompliant: d.nonCompliant ?? d.non_compliant ?? 0,
        totalDevices: d.totalDevices ?? d.total_devices,
        lastScan:     d.lastScan     ?? d.last_scan ?? new Date().toISOString(),
        topViolations:           (d.topViolations ?? d.top_violations ?? []).map((v: any) => ({
          name:     v.name     ?? v.policy,
          policy:   v.policy   ?? v.name,
          count:    v.count,
          severity: normaliseSeverity(v.severity),
        })),
        devicesNeedingAttention: (d.devicesNeedingAttention ?? d.devices_needing_attention ?? []).map((dev: any) => ({
          deviceId: dev.deviceId ?? dev.device_id ?? dev.id,
          id:       dev.id       ?? dev.deviceId,
          name:     dev.name,
          issues:   dev.issues   ?? (dev.issue ? [dev.issue] : []),
          issue:    dev.issue    ?? (dev.issues?.[0]),
          os:       dev.os,
        })),
      });
    } catch (err: any) {
      setError(err.message ?? 'Failed to load compliance data');
      // keep existing data or fallback
    } finally {
      setLoading(false);
    }
  }, [refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { fetchData(); }, [fetchData]);

  const runScan = async () => {
    setScanning(true);
    try {
      await fetch('/api/quick/policies/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetType: 'all', dryRun: false }),
      });
      toast.success('Compliance scan started');
      // Reload snapshot after brief delay to let the scan complete
      setTimeout(() => {
        setRefreshKey(k => k + 1);
        setScanning(false);
      }, 2000);
    } catch {
      toast.error('Scan request failed');
      setScanning(false);
    }
  };

  const sevColor = (s: string) => {
    switch (s) {
      case 'high':    case 'critical': return { bg: '#FEE2E2', color: '#991B1B' };
      case 'medium':  case 'warning':  return { bg: '#FEF3C7', color: '#92400E' };
      default:                         return { bg: '#DBEAFE', color: '#1E40AF' };
    }
  };

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 60, display: 'flex', justifyContent: 'flex-end' }}
      onClick={onClose}
    >
      {/* Backdrop */}
      <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.35)', backdropFilter: 'blur(2px)' }} />

      {/* Panel */}
      <div
        style={{
          position: 'relative',
          background: 'white',
          width: '100%',
          maxWidth: 420,
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '-8px 0 40px rgba(0,0,0,0.15)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            background: 'linear-gradient(135deg, #EF4444 0%, #B91C1C 100%)',
            padding: '22px 20px 20px',
            color: 'white',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <CheckCircleIcon style={{ width: 22, height: 22, color: 'rgba(255,255,255,0.9)' }} />
              <h2 style={{ fontSize: 17, fontWeight: 700, color: 'white' }}>Compliance Snapshot</h2>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.7)', padding: 2 }}>
              <XMarkIcon style={{ width: 20, height: 20 }} />
            </button>
          </div>
          <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)' }}>
            {loading ? 'Loading...' : error ? 'Data unavailable' : `Last scan: ${timeAgo(data.lastScan)}`}
          </p>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {/* Error banner */}
          {error && (
            <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: 13, color: '#991B1B', display: 'flex', alignItems: 'center', gap: 8 }}>
              <ExclamationTriangleIcon style={{ width: 16, height: 16, flexShrink: 0 }} />
              {error} — showing cached data
            </div>
          )}

          {/* Donut chart */}
          <div
            style={{
              background: 'var(--apple-gray-1)',
              borderRadius: 12,
              padding: '16px 20px',
              marginBottom: 20,
            }}
          >
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 14 }}>
              Device Compliance Overview
            </div>
            {loading ? (
              <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <ArrowPathIcon style={{ width: 28, height: 28, color: '#6B7280', animation: 'spin 1s linear infinite' }} />
              </div>
            ) : (
              <DonutChart
                compliant={data.compliant}
                warning={data.warning}
                nonCompliant={data.nonCompliant}
              />
            )}
          </div>

          {/* Top violations */}
          {data.topViolations.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 10 }}>
                Top Policy Violations
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {data.topViolations.slice(0, 5).map((v, i) => {
                  const sc = sevColor(v.severity);
                  return (
                    <div
                      key={i}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '9px 12px',
                        background: 'white',
                        border: '1px solid var(--apple-gray-2)',
                        borderRadius: 8,
                      }}
                    >
                      <ExclamationTriangleIcon style={{ width: 15, height: 15, color: sc.color, flexShrink: 0 }} />
                      <span style={{ flex: 1, fontSize: 13, color: 'var(--apple-text-primary)' }}>{v.name ?? v.policy}</span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>{v.count}</span>
                        <span style={{ fontSize: 11, padding: '2px 6px', borderRadius: 4, background: sc.bg, color: sc.color, fontWeight: 500 }}>
                          {v.severity}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Devices needing attention */}
          {data.devicesNeedingAttention.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 10 }}>
                Devices Needing Attention
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {data.devicesNeedingAttention.map((d, i) => (
                  <div
                    key={d.deviceId ?? d.id ?? i}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '9px 12px',
                      background: 'white',
                      border: '1px solid var(--apple-gray-2)',
                      borderRadius: 8,
                    }}
                  >
                    {d.os && <span style={{ fontSize: 18, flexShrink: 0 }}>{d.os}</span>}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {d.name}
                      </div>
                      <div style={{ fontSize: 11, color: '#DC2626', marginTop: 1 }}>
                        {d.issue ?? d.issues?.join(', ')}
                      </div>
                    </div>
                    <button
                      onClick={() => { onViewChange?.('fleet'); onClose(); }}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--apple-gray-5)', padding: 2, flexShrink: 0 }}
                      title="View device"
                    >
                      <ArrowTopRightOnSquareIcon style={{ width: 14, height: 14 }} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Empty state */}
          {!loading && !error && data.compliant === 0 && data.warning === 0 && data.nonCompliant === 0 && (
            <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--apple-text-secondary)', fontSize: 13 }}>
              No compliance data available. Run a scan to populate.
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '14px 20px',
            borderTop: '1px solid var(--apple-gray-2)',
            display: 'flex',
            gap: 10,
            flexShrink: 0,
          }}
        >
          <button
            onClick={runScan}
            disabled={scanning || loading}
            style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
              padding: '9px 16px',
              background: '#EF4444',
              color: 'white',
              border: 'none',
              borderRadius: 8,
              fontSize: 13,
              fontWeight: 500,
              cursor: (scanning || loading) ? 'not-allowed' : 'pointer',
              opacity: (scanning || loading) ? 0.7 : 1,
            }}
          >
            <ArrowPathIcon style={{ width: 14, height: 14, animation: scanning ? 'spin 1s linear infinite' : 'none' }} />
            {scanning ? 'Scanning...' : 'Run Scan Now'}
          </button>
          <button
            onClick={() => { onViewChange?.('compliance'); onClose(); }}
            style={{
              padding: '9px 16px',
              border: '1px solid var(--apple-gray-2)',
              borderRadius: 8,
              background: 'white',
              fontSize: 13,
              color: 'var(--apple-text-primary)',
              cursor: 'pointer',
            }}
          >
            Full Report
          </button>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normaliseSeverity(s: string): 'high' | 'medium' | 'low' | 'critical' | 'warning' | 'info' {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high':     return 'high';
    case 'warning':  case 'medium': return 'medium';
    case 'low':      case 'info':   return 'low';
    default:         return 'medium';
  }
}
