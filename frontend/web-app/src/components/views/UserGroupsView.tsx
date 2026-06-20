'use client';
import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  ArrowPathIcon,
  TrashIcon,
  UserGroupIcon,
  ChevronDownIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';

interface Group {
  id: string;
  name: string;
  type: 'security' | 'distribution' | 'dynamic';
  members: number;
  description: string;
  created: string;
  memberList?: string[];
}

const MOCK_GROUPS: Group[] = [
  { id: '1', name: 'Domain Admins', type: 'security', members: 3, description: 'Full administrative access to the domain', created: '2024-01-01', memberList: ['admin@corp.local', 'superuser@corp.local', 'root@corp.local'] },
  { id: '2', name: 'IT Support', type: 'security', members: 8, description: 'Helpdesk and IT support team', created: '2024-01-15', memberList: ['helpdesk1@corp.local', 'helpdesk2@corp.local', 'it-lead@corp.local'] },
  { id: '3', name: 'All Employees', type: 'distribution', members: 87, description: 'Company-wide distribution list', created: '2024-01-01', memberList: [] },
  { id: '4', name: 'Engineering', type: 'security', members: 24, description: 'Engineering department access group', created: '2024-02-10', memberList: ['eng1@corp.local', 'eng2@corp.local', 'eng3@corp.local'] },
  { id: '5', name: 'Remote Workers', type: 'dynamic', members: 31, description: 'Auto-populated from device compliance status', created: '2024-03-01', memberList: [] },
  { id: '6', name: 'Executive Team', type: 'distribution', members: 6, description: 'Leadership distribution list', created: '2024-01-01', memberList: ['ceo@corp.local', 'cto@corp.local', 'cfo@corp.local'] },
];

export default function UserGroupsView() {
  const [items, setItems] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch('/api/auth/groups');
      if (r.ok) {
        const data = await r.json();
        const raw: any[] = Array.isArray(data) ? data : (data.groups ?? []);
        const mapped: Group[] = raw.map((g: any) => ({
          id:          g.id ?? g.dn ?? String(Math.random()),
          name:        g.name ?? g.cn ?? g.displayName ?? 'Unknown',
          type:        g.groupType === 'dist' ? 'distribution' : g.dynamic ? 'dynamic' : 'security',
          members:     g.memberCount ?? g.members?.length ?? 0,
          description: g.description ?? '',
          created:     g.created ?? g.whenCreated ?? '—',
          memberList:  g.members ?? [],
        }));
        setItems(mapped.length > 0 ? mapped : MOCK_GROUPS);
      } else {
        setItems(MOCK_GROUPS);
      }
    } catch {
      setItems(MOCK_GROUPS);
    } finally {
      setLoading(false);
    }
  }

  const filtered = items.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase()) ||
    i.description.toLowerCase().includes(search.toLowerCase())
  );

  const securityCount = items.filter(i => i.type === 'security').length;
  const distributionCount = items.filter(i => i.type === 'distribution').length;
  const withMembers = items.filter(i => i.members > 0).length;

  const typeBadge = (type: string) => {
    const map: Record<string, { bg: string; color: string; label: string }> = {
      security:     { bg: 'rgba(0,111,255,0.15)',   color: '#006FFF', label: 'Security' },
      distribution: { bg: 'rgba(139,73,229,0.15)',  color: '#a371f7', label: 'Distribution' },
      dynamic:      { bg: 'rgba(210,153,34,0.15)',  color: '#d29922', label: 'Dynamic' },
    };
    const s = map[type] ?? map['security'];
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
        {s.label}
      </span>
    );
  };

  const toggleExpanded = (id: string) => setExpanded(prev => prev === id ? null : id);

  const toggleSelected = (id: string) => {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>User Groups</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Manage directory groups and memberships</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>TOTAL GROUPS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{items.length}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>All group types</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>SECURITY GROUPS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{securityCount}</div>
          <div style={{ fontSize: 12, color: '#006FFF', marginTop: 4 }}>Access control</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>DISTRIBUTION LISTS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{distributionCount}</div>
          <div style={{ fontSize: 12, color: '#a371f7', marginTop: 4 }}>Mail-enabled</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>WITH MEMBERS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{withMembers}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>Non-empty groups</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <PlusIcon style={{ width: 14, height: 14 }} />
          New Group
        </button>
        {selected.length > 0 && (
          <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#f85149' }} onClick={() => setSelected([])}>
            <TrashIcon style={{ width: 14, height: 14 }} />
            Delete ({selected.length})
          </button>
        )}
        <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={load} disabled={loading}>
          <ArrowPathIcon style={{ width: 14, height: 14 }} />
          Refresh
        </button>
        <div style={{ marginLeft: 'auto' }}>
          <input
            type="search"
            placeholder="Search groups..."
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
              <th style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-muted, #6e7681)', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', padding: '10px 16px', width: 36 }}></th>
              {['Name', 'Type', 'Members', 'Description', 'Created'].map(col => (
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
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No groups found</td></tr>
            ) : filtered.map(item => (
              <React.Fragment key={item.id}>
                <tr
                  style={{ borderBottom: expanded === item.id ? 'none' : '1px solid var(--border, rgba(255,255,255,0.07))', cursor: 'pointer', background: selected.includes(item.id) ? 'rgba(0,111,255,0.06)' : undefined }}
                  onClick={() => toggleExpanded(item.id)}
                >
                  <td style={{ padding: '11px 16px' }} onClick={e => { e.stopPropagation(); toggleSelected(item.id); }}>
                    <input type="checkbox" checked={selected.includes(item.id)} onChange={() => toggleSelected(item.id)} style={{ cursor: 'pointer', accentColor: '#006FFF' }} />
                  </td>
                  <td style={{ padding: '11px 16px', fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <UserGroupIcon style={{ width: 15, height: 15, color: '#006FFF', flexShrink: 0 }} />
                      {item.name}
                      {expanded === item.id
                        ? <ChevronDownIcon style={{ width: 13, height: 13, color: '#8b949e', marginLeft: 2 }} />
                        : <ChevronRightIcon style={{ width: 13, height: 13, color: '#8b949e', marginLeft: 2 }} />}
                    </div>
                  </td>
                  <td style={{ padding: '11px 16px' }}>{typeBadge(item.type)}</td>
                  <td style={{ padding: '11px 16px' }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', padding: '2px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600, background: 'rgba(0,111,255,0.1)', color: '#006FFF' }}>
                      {item.members}
                    </span>
                  </td>
                  <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)', fontSize: 13 }}>{item.description}</td>
                  <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.created}</td>
                </tr>
                {expanded === item.id && (
                  <tr style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                    <td colSpan={6} style={{ padding: '0 16px 14px 52px', background: 'var(--bg-overlay, #252c37)' }}>
                      <div style={{ paddingTop: 12 }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>Group Members</div>
                        {item.memberList && item.memberList.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {item.memberList.map(m => (
                              <span key={m} style={{ padding: '3px 10px', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 20, fontSize: 12, color: 'var(--text-secondary, #8b949e)' }}>
                                {m}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ fontSize: 13, color: 'var(--text-muted, #6e7681)' }}>
                            {item.members > 0 ? `${item.members} members (list not loaded)` : 'No members'}
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
