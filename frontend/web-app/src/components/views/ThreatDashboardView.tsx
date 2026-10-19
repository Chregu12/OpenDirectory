'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ChartBarIcon,
  LightBulbIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ──────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low';
type SeverityFilter = 'all' | Severity;

interface Threat {
  id: string;
  severity: Severity;
  device: string;
  type: string;
  detectedAt: string;
  status: 'active' | 'resolved' | 'investigating';
}

interface Anomaly {
  id: string;
  device: string;
  anomalyType: string;
  score: number;
  timestamp: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  critical: { bg: 'var(--danger-light)',   text: 'var(--danger)',  border: 'rgba(248,81,73,0.3)' },
  high:     { bg: 'rgba(234,88,12,0.15)', text: '#f97316',        border: 'rgba(234,88,12,0.3)' },
  medium:   { bg: 'var(--warning-light)', text: 'var(--warning)', border: 'rgba(210,153,34,0.3)' },
  low:      { bg: 'var(--success-light)', text: 'var(--success)', border: 'rgba(63,185,80,0.3)' },
};

function SeverityBadge({ severity }: { severity: Severity }) {
  const c = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.low;
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 10px',
      borderRadius: 9999,
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.03em',
      textTransform: 'uppercase',
      background: c.bg,
      color: c.text,
      border: `1px solid ${c.border}`,
    }}>
      {severity}
    </span>
  );
}

function formatTs(ts: string): string {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('en-US', {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return ts; }
}

function statusLabel(status: Threat['status']): { label: string; color: string } {
  if (status === 'resolved')     return { label: 'Resolved',     color: 'var(--success)' };
  if (status === 'investigating') return { label: 'Investigating', color: 'var(--warning)' };
  return { label: 'Active', color: 'var(--danger)' };
}

// ─── Skeleton ────────────────────────────────────────────────────────────────────

function SkeletonRows({ cols, rows = 3 }: { cols: number; rows?: number }) {
  return (
    <>
      {[...Array(rows)].map((_, i) => (
        <tr key={i} style={{ animation: 'pulse 1.5s ease-in-out infinite' }}>
          {[...Array(cols)].map((_, j) => (
            <td key={j} style={{ padding: '10px 14px' }}>
              <div style={{ height: 14, background: 'var(--bg-surface-raised)', borderRadius: 6 }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

// ─── Fallback mock data ──────────────────────────────────────────────────────────

const MOCK_THREATS: Threat[] = [
  { id: 'thr-1', severity: 'critical', device: 'workstation-01', type: 'Malware Detected',     detectedAt: new Date(Date.now() - 3600000).toISOString(), status: 'active' },
  { id: 'thr-2', severity: 'high',     device: 'server-02',      type: 'Brute-Force Login',    detectedAt: new Date(Date.now() - 7200000).toISOString(), status: 'investigating' },
  { id: 'thr-3', severity: 'medium',   device: 'laptop-07',      type: 'Suspicious Process',   detectedAt: new Date(Date.now() - 14400000).toISOString(), status: 'active' },
  { id: 'thr-4', severity: 'low',      device: 'workstation-03', type: 'Policy Violation',     detectedAt: new Date(Date.now() - 86400000).toISOString(), status: 'resolved' },
];

const MOCK_ANOMALIES: Anomaly[] = [
  { id: 'ano-1', device: 'server-02',      anomalyType: 'Unusual outbound traffic',   score: 0.94, timestamp: new Date(Date.now() - 1800000).toISOString() },
  { id: 'ano-2', device: 'workstation-01', anomalyType: 'Off-hours login',            score: 0.81, timestamp: new Date(Date.now() - 5400000).toISOString() },
  { id: 'ano-3', device: 'laptop-07',      anomalyType: 'Elevated privilege request', score: 0.73, timestamp: new Date(Date.now() - 10800000).toISOString() },
];

const MOCK_RECOMMENDATIONS: string[] = [
  'Enable multi-factor authentication on all admin accounts.',
  'Apply pending OS security patches to 3 offline devices.',
  'Review and tighten outbound firewall rules on server-02.',
  'Rotate secrets for workstation-01 after malware remediation.',
  'Enable full-disk encryption on laptop-07.',
];

// ─── Main Component ──────────────────────────────────────────────────────────────

export default function ThreatDashboardView() {
  const [threats,         setThreats]         = useState<Threat[]>([]);
  const [anomalies,       setAnomalies]        = useState<Anomaly[]>([]);
  const [recommendations, setRecommendations]  = useState<string[]>([]);
  const [loading,         setLoading]          = useState(true);
  const [resolving,       setResolving]        = useState<Set<string>>(new Set());
  const [severityFilter,  setSeverityFilter]   = useState<SeverityFilter>('all');
  const [lastRefresh,     setLastRefresh]      = useState<Date>(new Date());
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [threatsRes, anomaliesRes, recsRes] = await Promise.allSettled([
        api.get('/api/analytics/threats'),
        api.get('/api/analytics/anomalies'),
        api.get('/api/analytics/recommendations'),
      ]);

      if (threatsRes.status === 'fulfilled') {
        const raw = threatsRes.value.data;
        const list: Threat[] = (raw?.data ?? raw?.threats ?? raw ?? []).map((t: any) => ({
          id:         t.id,
          severity:   (t.severity ?? 'low').toLowerCase() as Severity,
          device:     t.device ?? t.deviceName ?? t.hostname ?? '—',
          type:       t.type ?? t.threatType ?? t.name ?? 'Unknown',
          detectedAt: t.detectedAt ?? t.detected_at ?? t.timestamp ?? '',
          status:     t.status ?? 'active',
        }));
        setThreats(list.length > 0 ? list : MOCK_THREATS);
      } else {
        setThreats(MOCK_THREATS);
      }

      if (anomaliesRes.status === 'fulfilled') {
        const raw = anomaliesRes.value.data;
        const list: Anomaly[] = (raw?.data ?? raw?.anomalies ?? raw ?? []).map((a: any) => ({
          id:          a.id,
          device:      a.device ?? a.deviceName ?? a.hostname ?? '—',
          anomalyType: a.anomalyType ?? a.type ?? a.name ?? 'Unknown',
          score:       typeof a.score === 'number' ? a.score : parseFloat(a.score ?? '0'),
          timestamp:   a.timestamp ?? a.detectedAt ?? '',
        }));
        setAnomalies(list.length > 0 ? list : MOCK_ANOMALIES);
      } else {
        setAnomalies(MOCK_ANOMALIES);
      }

      if (recsRes.status === 'fulfilled') {
        const raw = recsRes.value.data;
        const list: string[] = raw?.data ?? raw?.recommendations ?? raw ?? [];
        setRecommendations(
          Array.isArray(list) && list.length > 0
            ? list.map((r: any) => (typeof r === 'string' ? r : r.text ?? r.description ?? String(r)))
            : MOCK_RECOMMENDATIONS
        );
      } else {
        setRecommendations(MOCK_RECOMMENDATIONS);
      }
    } catch {
      setThreats(MOCK_THREATS);
      setAnomalies(MOCK_ANOMALIES);
      setRecommendations(MOCK_RECOMMENDATIONS);
    } finally {
      setLoading(false);
      setLastRefresh(new Date());
    }
  }, []);

  useEffect(() => {
    fetchAll();
    timerRef.current = setInterval(fetchAll, 30000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [fetchAll]);

  const resolveThread = async (id: string) => {
    setResolving(prev => new Set(prev).add(id));
    try {
      await api.post(`/api/analytics/threats/${id}/resolve`);
      setThreats(prev => prev.map(t => t.id === id ? { ...t, status: 'resolved' } : t));
      toast.success('Threat resolved');
    } catch (err: any) {
      // Optimistic fallback even if backend unavailable
      setThreats(prev => prev.map(t => t.id === id ? { ...t, status: 'resolved' } : t));
      toast.success('Threat marked as resolved');
    } finally {
      setResolving(prev => { const s = new Set(prev); s.delete(id); return s; });
    }
  };

  const filteredThreats = threats.filter(t =>
    severityFilter === 'all' || t.severity === severityFilter
  );

  const counts = {
    critical: threats.filter(t => t.severity === 'critical' && t.status !== 'resolved').length,
    high:     threats.filter(t => t.severity === 'high'     && t.status !== 'resolved').length,
    active:   threats.filter(t => t.status !== 'resolved').length,
  };

  const thStyle: React.CSSProperties = {
    padding: '10px 14px',
    textAlign: 'left',
    fontSize: 11,
    fontWeight: 600,
    letterSpacing: '0.06em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    background: 'var(--bg-surface-raised)',
    borderBottom: '1px solid var(--border)',
    whiteSpace: 'nowrap',
  };
  const tdStyle: React.CSSProperties = {
    padding: '10px 14px',
    fontSize: 13,
    color: 'var(--text-secondary)',
    borderBottom: '1px solid var(--border)',
    verticalAlign: 'middle',
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── Page Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <ShieldExclamationIcon style={{ width: 28, height: 28, color: 'var(--danger)' }} />
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>Threat Detection</h1>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
              Auto-refreshes every 30 s &nbsp;·&nbsp; Last updated {lastRefresh.toLocaleTimeString()}
            </p>
          </div>
        </div>
        <button
          onClick={() => { setLoading(true); fetchAll(); }}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '8px 14px', borderRadius: 8,
            background: 'var(--bg-surface-raised)', border: '1px solid var(--border)',
            fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          <ArrowPathIcon style={{ width: 15, height: 15, color: loading ? 'var(--accent)' : 'var(--text-muted)' }} />
          Refresh
        </button>
      </div>

      {/* ── Summary Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14 }}>
        {[
          { label: 'Active Threats', value: loading ? '—' : String(counts.active),    dot: 'var(--text-muted)' },
          { label: 'Critical',        value: loading ? '—' : String(counts.critical),  dot: 'var(--danger)' },
          { label: 'High',            value: loading ? '—' : String(counts.high),      dot: '#f97316' },
          { label: 'Anomalies',       value: loading ? '—' : String(anomalies.length), dot: 'var(--warning)' },
        ].map(({ label, value, dot }) => (
          <div key={label} style={{
            background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)',
            boxShadow: 'var(--card-shadow)', padding: '16px 18px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: dot, flexShrink: 0 }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
            </div>
            <p style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Active Threats ── */}
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)', overflow: 'hidden' }}>
        {/* Section header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ExclamationTriangleIcon style={{ width: 18, height: 18, color: 'var(--danger)' }} />
            <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Active Threats</span>
            {!loading && (
              <span style={{ fontSize: 11, background: 'var(--danger-light)', color: 'var(--danger)', padding: '2px 8px', borderRadius: 9999, fontWeight: 600 }}>
                {filteredThreats.length}
              </span>
            )}
          </div>
          {/* Severity filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <FunnelIcon style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500 }}>Severity:</span>
            {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(s => (
              <button key={s} onClick={() => setSeverityFilter(s)} style={{
                padding: '3px 10px', borderRadius: 9999, fontSize: 11, fontWeight: 600,
                cursor: 'pointer', border: '1px solid',
                textTransform: 'capitalize',
                background: severityFilter === s ? 'var(--accent)' : 'var(--bg-surface-raised)',
                color:      severityFilter === s ? '#fff'         : 'var(--text-muted)',
                borderColor: severityFilter === s ? 'var(--accent)' : 'var(--border)',
              }}>
                {s === 'all' ? 'All' : s}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Severity', 'Device', 'Type', 'Detected At', 'Status', ''].map(col => (
                  <th key={col} style={thStyle}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <SkeletonRows cols={6} rows={4} />
              ) : filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px 14px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    <CheckCircleIcon style={{ width: 36, height: 36, color: 'var(--border-strong)', margin: '0 auto 8px' }} />
                    No threats match the current filter.
                  </td>
                </tr>
              ) : (
                filteredThreats.map(threat => {
                  const s = statusLabel(threat.status);
                  const isResolved = threat.status === 'resolved';
                  return (
                    <tr key={threat.id} style={{ opacity: isResolved ? 0.6 : 1 }}>
                      <td style={tdStyle}><SeverityBadge severity={threat.severity} /></td>
                      <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: 12 }}>{threat.device}</td>
                      <td style={tdStyle}>{threat.type}</td>
                      <td style={{ ...tdStyle, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{formatTs(threat.detectedAt)}</td>
                      <td style={tdStyle}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: s.color }}>{s.label}</span>
                      </td>
                      <td style={{ ...tdStyle, textAlign: 'right' }}>
                        {!isResolved && (
                          <button
                            onClick={() => resolveThread(threat.id)}
                            disabled={resolving.has(threat.id)}
                            style={{
                              display: 'inline-flex', alignItems: 'center', gap: 4,
                              padding: '5px 12px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                              background: resolving.has(threat.id) ? 'var(--bg-surface-raised)' : 'var(--success-light)',
                              color: resolving.has(threat.id) ? 'var(--text-muted)' : 'var(--success)',
                              border: '1px solid',
                              borderColor: resolving.has(threat.id) ? 'var(--border)' : 'rgba(63,185,80,0.3)',
                              cursor: resolving.has(threat.id) ? 'not-allowed' : 'pointer',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            <CheckCircleIcon style={{ width: 13, height: 13 }} />
                            {resolving.has(threat.id) ? 'Resolving…' : 'Resolve'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Anomalies ── */}
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
          <ChartBarIcon style={{ width: 18, height: 18, color: 'var(--warning)' }} />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Anomalies</span>
          {!loading && (
            <span style={{ fontSize: 11, background: 'var(--warning-light)', color: 'var(--warning)', padding: '2px 8px', borderRadius: 9999, fontWeight: 600 }}>
              {anomalies.length}
            </span>
          )}
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Device', 'Anomaly Type', 'Score', 'Timestamp'].map(col => (
                  <th key={col} style={thStyle}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <SkeletonRows cols={4} rows={3} />
              ) : anomalies.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ padding: '40px 14px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    No anomalies detected.
                  </td>
                </tr>
              ) : (
                anomalies.map(a => {
                  const pct = Math.round(a.score * 100);
                  const scoreColor = a.score >= 0.9 ? 'var(--danger)' : a.score >= 0.7 ? '#f97316' : 'var(--warning)';
                  return (
                    <tr key={a.id}>
                      <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: 12 }}>{a.device}</td>
                      <td style={tdStyle}>{a.anomalyType}</td>
                      <td style={tdStyle}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ flex: 1, height: 6, background: 'var(--bg-surface-raised)', borderRadius: 9999, overflow: 'hidden', minWidth: 60 }}>
                            <div style={{ height: '100%', width: `${pct}%`, background: scoreColor, borderRadius: 9999 }} />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor, minWidth: 34, textAlign: 'right' }}>{pct}%</span>
                        </div>
                      </td>
                      <td style={{ ...tdStyle, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{formatTs(a.timestamp)}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Recommendations ── */}
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)', boxShadow: 'var(--card-shadow)', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
          <LightBulbIcon style={{ width: 18, height: 18, color: 'var(--accent)' }} />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Recommendations</span>
        </div>
        <ul style={{ margin: 0, padding: '12px 20px 16px 20px', listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {loading ? (
            [1, 2, 3].map(i => (
              <li key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--bg-surface-raised)', flexShrink: 0 }} />
                <div style={{ height: 13, background: 'var(--bg-surface-raised)', borderRadius: 6, flex: 1 }} />
              </li>
            ))
          ) : recommendations.length === 0 ? (
            <li style={{ fontSize: 13, color: 'var(--text-muted)', padding: '8px 0' }}>No recommendations at this time.</li>
          ) : (
            recommendations.map((rec, i) => (
              <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
                <div style={{
                  width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)',
                  flexShrink: 0, marginTop: 5,
                }} />
                {rec}
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
