'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';
import { DataTable, Column, CommandBar } from '@/components/ui';
import { PlusIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';

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

  const columns: Column<DirectoryUser>[] = [
    {
      key: 'name',
      header: 'Name',
      sortable: true,
      render: (u) => (
        <div>
          <div style={{ fontWeight: 500 }}>{u.name}</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{u.email}</div>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      sortable: true,
    },
    {
      key: 'status',
      header: 'Status',
      width: 90,
      render: (u) => (
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 4,
          fontSize: 12, fontWeight: 600,
          color: u.status === 'active' ? 'var(--success)' : 'var(--danger)',
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
          {u.status === 'active' ? 'Active' : 'Disabled'}
        </span>
      ),
    },
    {
      key: 'groups',
      header: 'Groups',
      width: 80,
      render: (u) => (
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          {Array.isArray(u.groups) ? u.groups.length : 0}
        </span>
      ),
    },
  ];

  return (
    <div style={{ background: 'var(--bg-primary)', height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* CommandBar */}
      <CommandBar
        primary={{ label: 'New User', icon: PlusIcon, onClick: () => onCreateNew?.() }}
        actions={[
          { label: 'Export', icon: ArrowDownTrayIcon, onClick: () => {} },
        ]}
        onRefresh={loadUsers}
        rightContent={
          <input
            type="search"
            placeholder="Search users…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              padding: '4px 10px', border: '1px solid var(--border-color)',
              borderRadius: 'var(--border-radius)', fontSize: 13,
              background: 'var(--input-bg)', color: 'var(--text-primary)',
              width: 200,
            }}
          />
        }
      />

      {/* Filter bar */}
      <div style={{ padding: '0 16px 8px 16px', display: 'flex', gap: 6, flexShrink: 0 }}>
        {(Object.keys(FILTER_LABELS) as Array<typeof filter>).map(key => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 6, cursor: 'pointer',
              border: '1px solid var(--border-color)',
              background: filter === key ? 'var(--accent-blue)' : 'var(--bg-primary)',
              color: filter === key ? '#fff' : 'var(--text-secondary)',
              fontWeight: filter === key ? 600 : 400,
            }}
          >
            {FILTER_LABELS[key]}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-secondary)', alignSelf: 'center' }}>
          {filtered.length} user{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* DataTable */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <DataTable
          columns={columns}
          rows={filtered}
          getRowId={(u) => u.id}
          onRowClick={onSelect}
          activeRowId={selectedId ?? undefined}
          emptyMessage="No users found."
        />
      </div>
    </div>
  );
}
