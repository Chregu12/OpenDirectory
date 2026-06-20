'use client';
import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  ArrowPathIcon,
  PencilIcon,
  TrashIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';

interface Role {
  id: string;
  name: string;
  type: 'system' | 'custom';
  users: number;
  permissions: number;
  created: string;
}

const MOCK_ROLES: Role[] = [
  { id: '1', name: 'Global Administrator', type: 'system', users: 2, permissions: 48, created: '2024-01-01' },
  { id: '2', name: 'User Administrator', type: 'system', users: 5, permissions: 24, created: '2024-01-01' },
  { id: '3', name: 'Device Manager', type: 'custom', users: 8, permissions: 12, created: '2024-03-15' },
  { id: '4', name: 'Helpdesk', type: 'custom', users: 15, permissions: 8, created: '2024-02-10' },
  { id: '5', name: 'Read Only', type: 'system', users: 30, permissions: 3, created: '2024-01-01' },
];

export default function RolesView() {
  const [items, setItems] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string[]>([]);
  const [search, setSearch] = useState('');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch('/api/auth/roles');
      if (r.ok) {
        const data = await r.json();
        const raw: any[] = Array.isArray(data) ? data : (data.roles ?? []);
        const mapped: Role[] = raw.map((role: any) => ({
          id:          role.id ?? String(Math.random()),
          name:        role.name ?? role.displayName ?? 'Unknown Role',
          type:        role.type ?? (role.isBuiltIn ? 'system' : 'custom'),
          users:       role.userCount ?? role.assignments ?? 0,
          permissions: role.permissionCount ?? role.permissions?.length ?? 0,
          created:     role.created ?? role.createdDateTime ?? '—',
        }));
        setItems(mapped.length > 0 ? mapped : MOCK_ROLES);
      } else {
        setItems(MOCK_ROLES);
      }
    } catch {
      setItems(MOCK_ROLES);
    } finally {
      setLoading(false);
    }
  }

  const filtered = items.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase())
  );

  const systemRoles = items.filter(i => i.type === 'system').length;
  const customRoles = items.filter(i => i.type === 'custom').length;
  const totalAssignments = items.reduce((s, i) => s + i.users, 0);

  const typeBadge = (type: string) => {
    const map: Record<string, { bg: string; color: string; label: string }> = {
      system: { bg: 'rgba(0,111,255,0.15)',  color: '#006FFF', label: 'System' },
      custom: { bg: 'rgba(139,73,229,0.15)', color: '#a371f7', label: 'Custom' },
    };
    const s = map[type] ?? map['system'];
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
        {s.label}
      </span>
    );
  };

  const toggleSelected = (id: string) => {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', background: 'var(--bg-base, #0e1115)' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Roles & Permissions</h1>
        <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 4, marginBottom: 0 }}>Role-based access control definitions</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>TOTAL ROLES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{items.length}</div>
          <div style={{ fontSize: 12, color: '#8b949e', marginTop: 4 }}>Across all types</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>SYSTEM ROLES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{systemRoles}</div>
          <div style={{ fontSize: 12, color: '#006FFF', marginTop: 4 }}>Built-in roles</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>CUSTOM ROLES</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{customRoles}</div>
          <div style={{ fontSize: 12, color: '#a371f7', marginTop: 4 }}>User-defined</div>
        </div>
        <div style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>ASSIGNMENTS</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>{totalAssignments}</div>
          <div style={{ fontSize: 12, color: '#3fb950', marginTop: 4 }}>Total user assignments</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="fluent-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <PlusIcon style={{ width: 14, height: 14 }} />
          New Role
        </button>
        {selected.length === 1 && (
          <button className="fluent-btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <PencilIcon style={{ width: 14, height: 14 }} />
            Edit
          </button>
        )}
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
            placeholder="Search roles..."
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
              {['Role Name', 'Type', 'Users Assigned', 'Permissions Count', 'Created'].map(col => (
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
              <tr><td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-secondary, #8b949e)' }}>No roles found</td></tr>
            ) : filtered.map(item => (
              <tr key={item.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', background: selected.includes(item.id) ? 'rgba(0,111,255,0.06)' : undefined }}>
                <td style={{ padding: '11px 16px' }}>
                  <input type="checkbox" checked={selected.includes(item.id)} onChange={() => toggleSelected(item.id)} style={{ cursor: 'pointer', accentColor: '#006FFF' }} />
                </td>
                <td style={{ padding: '11px 16px', fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ShieldCheckIcon style={{ width: 15, height: 15, color: item.type === 'system' ? '#006FFF' : '#a371f7', flexShrink: 0 }} />
                    {item.name}
                  </div>
                </td>
                <td style={{ padding: '11px 16px' }}>{typeBadge(item.type)}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.users}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-secondary, #8b949e)' }}>{item.permissions}</td>
                <td style={{ padding: '11px 16px', color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{item.created}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
