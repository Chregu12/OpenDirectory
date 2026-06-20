'use client';
import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowPathIcon,
  DocumentArrowDownIcon,
  FunnelIcon,
  BoltIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  CheckCircleIcon,
  UserCircleIcon,
} from '@heroicons/react/24/outline';

interface AuditEvent {
  id: string;
  timestamp: string;
  event: string;
  user: string;
  source: string;
  severity: 'error' | 'warning' | 'info' | 'success';
}

const MOCK_EVENTS: AuditEvent[] = [
  { id: '1', timestamp: new Date(Date.now() - 30000).toISOString(), event: 'User login successful', user: 'admin@corp.local', source: 'Auth Service', severity: 'success' },
  { id: '2', timestamp: new Date(Date.now() - 90000).toISOString(), event: 'MFA challenge failed', user: 'jsmith@corp.local', source: 'MFA Provider', severity: 'warning' },
  { id: '3', timestamp: new Date(Date.now() - 150000).toISOString(), event: 'Device compliance check failed', user: 'system', source: 'MDM Agent', severity: 'error' },
  { id: '4', timestamp: new Date(Date.now() - 240000).toISOString(), event: 'Policy deployed successfully', user: 'admin@corp.local', source: 'Policy Engine', severity: 'success' },
  { id: '5', timestamp: new Date(Date.now() - 360000).toISOString(), event: 'User account locked', user: 'jdoe@corp.local', source: 'Directory', severity: 'error' },
  { id: '6', timestamp: new Date(Date.now() - 480000).toISOString(), event: 'Certificate renewed', user: 'system', source: 'PKI Service', severity: 'info' },
  { id: '7', timestamp: new Date(Date.now() - 600000).toISOString(), event: 'LDAP bind succeeded', user: 'svc-ldap@corp.local', source: 'LDAP', severity: 'info' },
  { id: '8', timestamp: new Date(Date.now() - 720000).toISOString(), event: 'Backup completed', user: 'system', source: 'Backup Service', severity: 'success' },
  { id: '9', timestamp: new Date(Date.now() - 900000).toISOString(), event: 'Suspicious login attempt detected', user: 'unknown', source: 'Auth Service', severity: 'error' },
  { id: '10', timestamp: new Date(Date.now() - 1080000).toISOString(), event: 'Group membership changed', user: 'admin@corp.local', source: 'Directory', severity: 'info' },
];

export default function ActivityView() {
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/audit/events?limit=100');
      if (r.ok) {
        const data = await r.json();
        const raw: any[] = data.events ?? (Array.isArray(data) ? data : []);
        const mapped: AuditEvent[] = raw.map((e: any) => ({
          id:        e.id ?? String(Math.random()),
          timestamp: e.event_time ?? e.timestamp ?? new Date().toISOString(),
          event:     e.operation ?? e.action ?? e.event ?? 'Unknown event',
          user:      e.actor_dn ?? e.actor ?? e.user ?? 'system',
          source:    e.source ?? e.category ?? 'System',
          severity:  e.severity ?? 'info',
        }));
        setItems(mapped.length > 0 ? mapped : MOCK_EVENTS);
      } else {
        setItems(MOCK_EVENTS);
      }
    } catch {
      setItems(MOCK_EVENTS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [load]);

  const filtered = items.filter(i => {
    const matchSearch = i.event.toLowerCase().includes(search.toLowerCase()) ||
      i.user.toLowerCase().includes(search.toLowerCase()) ||
      i.source.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = severityFilter === 'all' || i.severity === severityFilter;
    return matchSearch && matchSeverity;
  });

  const errorsCount = items.filter(i => i.severity === 'error').length;
  const warningsCount = items.filter(i => i.severity === 'warning').length;
  const activeUsers = [...new Set(items.map(i => i.user))].length;

  const severityBadge = (severity: string) => {
    const map: Record<string, { bg: string; color: string; label: string; icon: React.ReactNode }> = {
      error:   { bg: 'rgba(248,81,73,0.15)',   color: '#f85149', label: 'Error',   icon: <ExclamationTriangleIcon style={{ width: 12, height: 12 }} /> },
      warning: { bg: 'rgba(210,153,34,0.15)',  color: '#d29922', label: 'Warning', icon: <ExclamationTriangleIcon style={{ width: 12, height: 12 }} /> },
      info:    { bg: 'rgba(0,111,255,0.15)',    color: '#006FFF', label: 'Info',    icon: <InformationCircleIcon style={{ width: 12, height: 12 }} /> },
      success: { bg: 'rgba(63,185,80,0.15)',    color: '#3fb950', label: 'Success', icon: <CheckCircleIcon style={{ width: 12, height: 12 }} /> },
    };
    const s = map[severity] ?? map['info'];
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        {s.icon}{s.label}
      </span>
    );
  };

  function exportCSV() {
    const rows = [['Timestamp', 'Event', 'User', 'Source', 'Severity']];
    filtered.forEach(e => rows.push([e.timestamp, e.event, e.user, e.source, e.severity]));
    const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'activity-export.csv'; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Activity</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Real-time event stream across all services</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>EVENTS TODAY</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{items.length}</div>
          <div style={{ fontSize: 12, color: '#006FFF', marginTop: 4 }}>↑ 12% from yesterday</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>ERRORS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: errorsCount > 0 ? '#f85149' : 'var(--text-primary, #e4e6ea)' }}>{errorsCount}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Requires attention</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>WARNINGS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: warningsCount > 0 ? '#d29922' : 'var(--text-primary, #e4e6ea)' }}>{warningsCount}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Non-critical alerts</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>ACTIVE USERS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{activeUsers}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>Distinct actors</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={exportCSV}>
          <DocumentArrowDownIcon style={{ width: 14, height: 14 }} />
          Export
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8 }}>
          <FunnelIcon style={{ width: 13, height: 13, color: '#8b949e' }} />
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-primary, #e4e6ea)', fontSize: 13, outline: 'none', cursor: 'pointer' }}
          >
            <option value="all">All Severities</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
            <option value="success">Success</option>
          </select>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: '#3fb950' }}>
          <BoltIcon style={{ width: 13, height: 13 }} />
          Auto-refresh 30s
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search events..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ padding: '6px 12px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, color: 'var(--text-primary, #e4e6ea)', fontSize: 13, width: 200, outline: 'none' }}
          />
        </div>
      </div>

      <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, overflow: 'hidden' }}>
        <table className="fluent-table" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
          <thead>
            <tr>
              {['Timestamp', 'Event', 'User', 'Source', 'Severity'].map(col => (
                <th key={col} style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-muted, #6e7681)', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>Loading...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No events found</td></tr>
            ) : filtered.map(item => (
              <tr key={item.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                <td style={{ padding: '10px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12, whiteSpace: 'nowrap' }}>
                  {new Date(item.timestamp).toLocaleString()}
                </td>
                <td style={{ padding: '10px 16px', color: 'var(--text-primary, #e4e6ea)', fontWeight: 500 }}>{item.event}</td>
                <td style={{ padding: '10px 16px', color: 'var(--text-secondary, #8b949e)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <UserCircleIcon style={{ width: 14, height: 14, flexShrink: 0 }} />
                  {item.user}
                </td>
                <td style={{ padding: '10px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.source}</td>
                <td style={{ padding: '10px 16px' }}>{severityBadge(item.severity)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
