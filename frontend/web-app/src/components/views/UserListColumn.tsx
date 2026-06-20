'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DirectoryUser {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user' | 'read-only' | 'service-account';
  department?: string;
  status: 'active' | 'inactive';
  lastActive?: string;
  mfa: boolean;
  groups?: string[];
  devices?: string[];
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_USERS: DirectoryUser[] = [
  { id: '1', name: 'Alice Mueller',   email: 'alice@company.local',   role: 'admin',           department: 'IT',          status: 'active',   lastActive: '2 hours ago',   mfa: true,  groups: ['IT', 'Admins'],    devices: ['MacBook Pro'] },
  { id: '2', name: 'Bob Schneider',   email: 'bob@company.local',     role: 'user',            department: 'Engineering', status: 'active',   lastActive: '1 day ago',     mfa: true,  groups: ['Engineering'],     devices: ['Windows 11 Laptop'] },
  { id: '3', name: 'Carol Weber',     email: 'carol@company.local',   role: 'user',            department: 'Marketing',   status: 'active',   lastActive: '3 days ago',    mfa: false, groups: ['Marketing'],       devices: [] },
  { id: '4', name: 'David Koch',      email: 'david@company.local',   role: 'read-only',       department: 'Engineering', status: 'inactive', lastActive: '45 days ago',   mfa: false, groups: ['Engineering'],     devices: [] },
  { id: '5', name: 'Eva Fischer',     email: 'eva@company.local',     role: 'service-account', department: 'IT',          status: 'active',   lastActive: '5 minutes ago', mfa: false, groups: ['IT'],              devices: [] },
  { id: '6', name: 'Frank Meyer',     email: 'frank@company.local',   role: 'user',            department: 'Marketing',   status: 'active',   lastActive: '2 days ago',    mfa: true,  groups: ['Marketing'],       devices: ['Ubuntu Workstation'] },
  { id: '7', name: 'Grace Hoffmann',  email: 'grace@company.local',   role: 'admin',           department: 'IT',          status: 'active',   lastActive: '1 hour ago',    mfa: true,  groups: ['IT', 'Admins'],    devices: ['MacBook Air'] },
  { id: '8', name: 'Hans Bauer',      email: 'hans@company.local',    role: 'user',            department: 'Finance',     status: 'active',   lastActive: '4 hours ago',   mfa: true,  groups: ['Finance'],         devices: ['Windows Laptop'] },
];

// ─── Avatar initials ──────────────────────────────────────────────────────────

function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

const AVATAR_COLORS = ['#0071e3', '#34c759', '#ff9500', '#af52de', '#ff3b30', '#5ac8fa', '#30b0c7'];

function avatarColor(id: string): string {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0;
  return AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length];
}

interface UserListColumnProps {
  selectedId: string | null;
  onSelect: (user: DirectoryUser) => void;
  onCreateNew?: () => void;
}

export default function UserListColumn({ selectedId, onSelect, onCreateNew }: UserListColumnProps) {
  const [users,    setUsers]    = useState<DirectoryUser[]>(MOCK_USERS);
  const [search,   setSearch]   = useState('');
  const [filter,   setFilter]   = useState<'all' | 'active' | 'inactive' | 'admin'>('all');
  const [filterOpen, setFilterOpen] = useState(false);

  const loadUsers = useCallback(async () => {
    try {
      const res = await api.get('/api/users').catch(() => api.get('/api/lldap/users'));
      const raw = Array.isArray(res.data) ? res.data : res.data?.users ?? [];
      if (raw.length > 0) {
        setUsers(raw.map((u: any) => ({
          id: u.id ?? u.username,
          name: u.displayName ?? u.name ?? u.username ?? u.id,
          email: u.email ?? '',
          role: u.role ?? 'user',
          department: u.department ?? u.ou,
          status: u.status === 'inaktiv' ? 'inactive' : 'active',
          lastActive: u.lastActive ?? u.last_active,
          mfa: u.mfa ?? false,
          groups: u.groups ?? [],
          devices: u.devices ?? [],
        })));
      }
    } catch {}
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  useEffect(() => {
    const handler = () => setFilterOpen(false);
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const filtered = users.filter(u => {
    if (filter === 'active' && u.status !== 'active') return false;
    if (filter === 'inactive' && u.status !== 'inactive') return false;
    if (filter === 'admin' && u.role !== 'admin') return false;
    const q = search.toLowerCase();
    return !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
  });

  const FILTER_LABELS: Record<typeof filter, string> = { all: 'All', active: 'Active', inactive: 'Inactive', admin: 'Admins' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{ padding: '16px 16px 10px 16px', borderBottom: '1px solid var(--apple-gray-2)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--apple-text-primary)', margin: 0 }}>Users</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--apple-text-secondary)' }}>{filtered.length}</span>
            {onCreateNew && (
              <button
                onClick={onCreateNew}
                style={{
                  width: 24, height: 24, borderRadius: '50%',
                  background: 'var(--apple-blue)', color: 'white',
                  border: 'none', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 16, flexShrink: 0,
                }}
                title="New User"
              >
                +
              </button>
            )}
          </div>
        </div>

        {/* Search + Filter */}
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            type="text"
            placeholder="Search users..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              flex: 1, padding: '5px 10px', border: '1px solid var(--apple-gray-2)',
              borderRadius: 6, fontSize: 12, outline: 'none', background: 'var(--apple-gray-1)',
              color: 'var(--apple-text-primary)',
            }}
          />
          <div style={{ position: 'relative' }}>
            <button
              onClick={e => { e.stopPropagation(); setFilterOpen(o => !o); }}
              style={{
                padding: '5px 10px', border: '1px solid var(--apple-gray-2)',
                borderRadius: 6, background: filter !== 'all' ? 'var(--apple-blue-light)' : '#fff',
                fontSize: 12, color: filter !== 'all' ? 'var(--apple-blue)' : 'var(--apple-text-secondary)',
                cursor: 'pointer', fontWeight: 500,
              }}
            >
              {FILTER_LABELS[filter]}
            </button>
            {filterOpen && (
              <div
                style={{
                  position: 'absolute', top: 'calc(100% + 4px)', right: 0, zIndex: 20,
                  background: 'white', border: '1px solid var(--apple-gray-2)',
                  borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,0.1)', overflow: 'hidden', minWidth: 120,
                }}
                onClick={e => e.stopPropagation()}
              >
                {(Object.keys(FILTER_LABELS) as Array<typeof filter>).map(key => (
                  <button
                    key={key}
                    onClick={() => { setFilter(key); setFilterOpen(false); }}
                    style={{
                      display: 'block', width: '100%', padding: '7px 12px', fontSize: 13,
                      background: filter === key ? 'var(--apple-blue-light)' : 'none',
                      color: filter === key ? 'var(--apple-blue)' : 'var(--apple-text-primary)',
                      border: 'none', cursor: 'pointer', textAlign: 'left',
                    }}
                    onMouseEnter={e => { if (filter !== key) (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                    onMouseLeave={e => { if (filter !== key) (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    {FILTER_LABELS[key]}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* User list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.map(user => {
          const isSelected = user.id === selectedId;
          const color = avatarColor(user.id);
          return (
            <button
              key={user.id}
              onClick={() => onSelect(user)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                width: '100%', padding: '11px 16px',
                borderBottom: '1px solid var(--apple-gray-2)',
                background: isSelected ? 'var(--apple-blue)' : 'transparent',
                border: 'none',
                borderBottomColor: 'var(--apple-gray-2)',
                borderBottomWidth: 1, borderBottomStyle: 'solid',
                cursor: 'pointer', textAlign: 'left',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => { if (!isSelected) (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
              onMouseLeave={e => { if (!isSelected) (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
            >
              {/* Avatar */}
              <div style={{
                width: 34, height: 34, borderRadius: '50%',
                background: isSelected ? 'rgba(255,255,255,0.25)' : color,
                color: 'white', fontSize: 13, fontWeight: 700,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                {getInitials(user.name)}
              </div>

              {/* Text */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 13, fontWeight: 600,
                  color: isSelected ? '#ffffff' : 'var(--apple-text-primary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {user.name}
                </div>
                <div style={{
                  fontSize: 11, marginTop: 2,
                  color: isSelected ? 'rgba(255,255,255,0.75)' : 'var(--apple-text-secondary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {user.email}
                </div>
              </div>

              {/* Status dot */}
              {!isSelected && (
                <span style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: user.status === 'active' ? '#22c55e' : '#9CA3AF',
                  flexShrink: 0,
                }} />
              )}
            </button>
          );
        })}

        {filtered.length === 0 && (
          <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--apple-text-tertiary)', fontSize: 13 }}>
            No users found.
          </div>
        )}
      </div>
    </div>
  );
}
