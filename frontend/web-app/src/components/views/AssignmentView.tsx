'use client';
import React, { useState, useEffect } from 'react';
import {
  ArrowPathIcon,
  DocumentArrowDownIcon,
  FunnelIcon,
  ComputerDesktopIcon,
  UserIcon,
} from '@heroicons/react/24/outline';

interface Assignment {
  id: string;
  item: string;
  assignedTo: string;
  from: string;
  to: string;
  action: 'Assigned' | 'Returned' | 'Transferred' | 'Revoked';
  admin: string;
}

const MOCK_ASSIGNMENTS: Assignment[] = [
  { id: '1', item: 'MacBook Pro 14" (MBP-001)', assignedTo: 'jane.doe@corp.local', from: '2024-12-01', to: '—', action: 'Assigned', admin: 'admin@corp.local' },
  { id: '2', item: 'Dell XPS 15 (DXP-042)', assignedTo: 'john.smith@corp.local', from: '2024-11-15', to: '2024-12-20', action: 'Returned', admin: 'admin@corp.local' },
  { id: '3', item: 'Microsoft 365 License', assignedTo: 'marketing@corp.local', from: '2024-10-01', to: '—', action: 'Assigned', admin: 'it-admin@corp.local' },
  { id: '4', item: 'iPhone 15 Pro (IP15-007)', assignedTo: 'ceo@corp.local', from: '2024-09-01', to: '—', action: 'Transferred', admin: 'admin@corp.local' },
  { id: '5', item: 'Adobe Creative Suite', assignedTo: 'designer@corp.local', from: '2024-08-15', to: '2024-12-01', action: 'Revoked', admin: 'billing@corp.local' },
  { id: '6', item: 'iPad Pro 12.9" (IPD-023)', assignedTo: 'sales@corp.local', from: '2024-11-01', to: '—', action: 'Assigned', admin: 'it-admin@corp.local' },
  { id: '7', item: 'Surface Pro 9 (SP9-011)', assignedTo: 'hr@corp.local', from: '2024-07-01', to: '2024-10-15', action: 'Returned', admin: 'admin@corp.local' },
  { id: '8', item: 'Slack Business License', assignedTo: 'engineering@corp.local', from: '2024-06-01', to: '—', action: 'Assigned', admin: 'admin@corp.local' },
];

export default function AssignmentView() {
  const [items, setItems] = useState<Assignment[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch('/api/devices?limit=50');
      if (r.ok) {
        const data = await r.json();
        const raw: any[] = Array.isArray(data) ? data : (data.devices ?? data.items ?? []);
        const mapped: Assignment[] = raw.map((d: any) => ({
          id:         d.id ?? String(Math.random()),
          item:       d.name ?? d.hostname ?? d.model ?? 'Unknown Device',
          assignedTo: d.owner ?? d.assignedTo ?? d.email ?? 'Unassigned',
          from:       d.enrolledAt ?? d.assignedDate ?? '—',
          to:         d.returnedAt ?? '—',
          action:     'Assigned' as const,
          admin:      d.enrolledBy ?? 'admin@corp.local',
        }));
        setItems(mapped.length > 0 ? mapped : MOCK_ASSIGNMENTS);
      } else {
        setItems(MOCK_ASSIGNMENTS);
      }
    } catch {
      setItems(MOCK_ASSIGNMENTS);
    } finally {
      setLoading(false);
    }
  }

  const filtered = items.filter(i => {
    const matchSearch = i.item.toLowerCase().includes(search.toLowerCase()) ||
      i.assignedTo.toLowerCase().includes(search.toLowerCase()) ||
      i.admin.toLowerCase().includes(search.toLowerCase());
    const matchType = typeFilter === 'all' || i.action.toLowerCase() === typeFilter.toLowerCase();
    return matchSearch && matchType;
  });

  const thisMonth = items.filter(i => {
    const d = new Date(i.from);
    const now = new Date();
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  }).length;
  const pendingReturns = items.filter(i => i.action === 'Assigned' && i.to === '—').length;
  const reassignments = items.filter(i => i.action === 'Transferred').length;

  const actionBadge = (action: string) => {
    const map: Record<string, { bg: string; color: string }> = {
      Assigned:    { bg: 'rgba(63,185,80,0.15)',   color: '#3fb950' },
      Returned:    { bg: 'rgba(210,153,34,0.15)',  color: '#d29922' },
      Transferred: { bg: 'rgba(0,111,255,0.15)',   color: '#006FFF' },
      Revoked:     { bg: 'rgba(248,81,73,0.15)',   color: '#f85149' },
    };
    const s = map[action] ?? { bg: 'rgba(110,118,129,0.15)', color: '#6e7681' };
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
        {action}
      </span>
    );
  };

  function exportCSV() {
    const rows = [['Device/License', 'Assigned To', 'From', 'To', 'Action', 'Admin']];
    filtered.forEach(e => rows.push([e.item, e.assignedTo, e.from, e.to, e.action, e.admin]));
    const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'assignments.csv'; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Assignment History</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Device and license assignment audit trail</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>TOTAL ASSIGNMENTS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{items.length}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>All time</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>THIS MONTH</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{thisMonth}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>↑ new this period</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>PENDING RETURNS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: pendingReturns > 0 ? '#d29922' : 'var(--text-primary, #e4e6ea)' }}>{pendingReturns}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Active assignments</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>REASSIGNMENTS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{reassignments}</div>
          <div style={{ fontSize: 12, color: '#006FFF', marginTop: 4 }}>Transferred items</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={exportCSV}>
          <DocumentArrowDownIcon style={{ width: 14, height: 14 }} />
          Export CSV
        </button>
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8 }}>
          <FunnelIcon style={{ width: 13, height: 13, color: '#8b949e' }} />
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-primary, #e4e6ea)', fontSize: 13, outline: 'none', cursor: 'pointer' }}
          >
            <option value="all">All Types</option>
            <option value="assigned">Assigned</option>
            <option value="returned">Returned</option>
            <option value="transferred">Transferred</option>
            <option value="revoked">Revoked</option>
          </select>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search assignments..."
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
              {['Device / License', 'Assigned To', 'From', 'To', 'Action', 'Admin'].map(col => (
                <th key={col} style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-muted, #6e7681)', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>Loading...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No assignments found</td></tr>
            ) : filtered.map(item => (
              <tr key={item.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                <td style={{ padding: '11px 16px', fontWeight: 500, color: 'var(--text-primary, #e4e6ea)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ComputerDesktopIcon style={{ width: 14, height: 14, color: '#8b949e', flexShrink: 0 }} />
                    {item.item}
                  </div>
                </td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <UserIcon style={{ width: 13, height: 13, flexShrink: 0 }} />
                    {item.assignedTo}
                  </div>
                </td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.from}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.to}</td>
                <td style={{ padding: '11px 16px' }}>{actionBadge(item.action)}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.admin}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
