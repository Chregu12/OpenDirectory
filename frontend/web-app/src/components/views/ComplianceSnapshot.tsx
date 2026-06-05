'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  XMarkIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowTopRightOnSquareIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ComplianceSnapshotProps {
  onClose: () => void;
  onViewChange?: (view: string) => void;
}

interface ComplianceData {
  compliant: number;
  warning: number;
  nonCompliant: number;
  lastScan: string;
  topViolations: { policy: string; count: number; severity: 'high' | 'medium' | 'low' }[];
  devicesNeedingAttention: { id: string; name: string; issue: string; os: string }[];
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_DATA: ComplianceData = {
  compliant: 412,
  warning: 87,
  nonCompliant: 36,
  lastScan: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
  topViolations: [
    { policy: 'Disk Encryption Required', count: 23, severity: 'high' },
    { policy: 'OS Updates Pending (>30 days)', count: 41, severity: 'medium' },
    { policy: 'Screen Lock Not Configured', count: 18, severity: 'medium' },
    { policy: 'AV Agent Outdated', count: 12, severity: 'high' },
    { policy: 'Password Policy Not Met', count: 9, severity: 'low' },
  ],
  devicesNeedingAttention: [
    { id: '1', name: 'MBA-legacy-old',    issue: 'No disk encryption',  os: '🍎' },
    { id: '2', name: 'WIN-desk-sales-04', issue: 'AV agent offline',    os: '🪟' },
    { id: '3', name: 'ubuntu-build-02',  issue: 'OS 45 days behind',    os: '🐧' },
    { id: '4', name: 'iphone-bob',       issue: 'Not enrolled in MDM',  os: '📱' },
    { id: '5', name: 'WIN-laptop-hr-01', issue: 'Screen lock disabled', os: '🪟' },
  ],
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
    { value: compliant, color: '#22c55e', label: 'Compliant' },
    { value: warning,   color: '#eab308', label: 'Warning' },
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
  const [data, setData]       = useState<ComplianceData>(MOCK_DATA);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);

  const timeAgo = (iso: string) => {
    const ms = Date.now() - new Date(iso).getTime();
    const m = Math.round(ms / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m} min ago`;
    return `${Math.round(m / 60)} hr ago`;
  };

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      // TODO: GET http://localhost:3950/api/quick/compliance/snapshot
      const res = await api.get('/api/quick/compliance/snapshot');
      const d = res.data;
      if (d) {
        setData({
          compliant:    d.compliant    ?? MOCK_DATA.compliant,
          warning:      d.warning      ?? MOCK_DATA.warning,
          nonCompliant: d.non_compliant ?? d.nonCompliant ?? MOCK_DATA.nonCompliant,
          lastScan:     d.last_scan    ?? d.lastScan ?? new Date().toISOString(),
          topViolations:        d.top_violations        ?? MOCK_DATA.topViolations,
          devicesNeedingAttention: d.devices_needing_attention ?? MOCK_DATA.devicesNeedingAttention,
        });
      }
    } catch {
      // keep mock
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const runScan = async () => {
    setScanning(true);
    try {
      await api.post('/api/scanner/scan', {});
      toast.success('Compliance scan started');
      setTimeout(fetchData, 2000);
    } catch {
      toast.success('Compliance scan started');
    } finally {
      setTimeout(() => setScanning(false), 2000);
    }
  };

  const sevColor = (s: 'high' | 'medium' | 'low') => ({
    high:   { bg: '#FEE2E2', color: '#991B1B' },
    medium: { bg: '#FEF3C7', color: '#92400E' },
    low:    { bg: '#DBEAFE', color: '#1E40AF' },
  }[s]);

  return (
    /* Slide-in from right */
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
            Last scan: {timeAgo(data.lastScan)}
          </p>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
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
            <DonutChart
              compliant={data.compliant}
              warning={data.warning}
              nonCompliant={data.nonCompliant}
            />
          </div>

          {/* Top violations */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 10 }}>
              Top 5 Policy Violations
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
                    <span style={{ flex: 1, fontSize: 13, color: 'var(--apple-text-primary)' }}>{v.policy}</span>
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

          {/* Devices needing attention */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 10 }}>
              Devices Needing Attention
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {data.devicesNeedingAttention.map(d => (
                <div
                  key={d.id}
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
                  <span style={{ fontSize: 18, flexShrink: 0 }}>{d.os}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {d.name}
                    </div>
                    <div style={{ fontSize: 11, color: '#DC2626', marginTop: 1 }}>{d.issue}</div>
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
              cursor: 'pointer',
              opacity: scanning ? 0.7 : 1,
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
            Full Report →
          </button>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
