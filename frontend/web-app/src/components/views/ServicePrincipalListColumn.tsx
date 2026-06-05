'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ServicePrincipal {
  id: string;
  name: string;
  clientId: string;
  spn: string;
  createdAt: string;
  permissions: string[];
  status: 'active' | 'disabled';
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_SPS: ServicePrincipal[] = [
  { id: '1', name: 'inventory-service',    clientId: 'a3f8c2d1-e4b5-4c6d-8e9f-0a1b2c3d4e5f', spn: 'app/inventory-service@opendirectory.local',   createdAt: '2024-01-15', permissions: ['read_users', 'read_devices'],              status: 'active' },
  { id: '2', name: 'ci-pipeline',          clientId: 'b5c7d9e1-f2a3-4b5c-6d7e-8f9a0b1c2d3e', spn: 'app/ci-pipeline@opendirectory.local',         createdAt: '2024-02-20', permissions: ['read_users', 'api_gateway'],               status: 'active' },
  { id: '3', name: 'legacy-erp-connector', clientId: 'c1d2e3f4-a5b6-7c8d-9e0f-1a2b3c4d5e6f', spn: 'app/legacy-erp@opendirectory.local',          createdAt: '2023-08-01', permissions: ['read_users', 'write_policies', 'admin_access'], status: 'disabled' },
  { id: '4', name: 'monitoring-agent',     clientId: 'd4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a', spn: 'app/monitoring@opendirectory.local',          createdAt: '2024-03-10', permissions: ['read_devices', 'audit_logs'],              status: 'active' },
  { id: '5', name: 'backup-service',       clientId: 'e5f6a7b8-c9d0-1e2f-3a4b-5c6d7e8f9a0b', spn: 'app/backup@opendirectory.local',              createdAt: '2024-04-05', permissions: ['read_devices', 'write_backups'],           status: 'active' },
];

interface ServicePrincipalListColumnProps {
  selectedId: string | null;
  onSelect: (sp: ServicePrincipal) => void;
  onCreateNew?: () => void;
}

export default function ServicePrincipalListColumn({ selectedId, onSelect, onCreateNew }: ServicePrincipalListColumnProps) {
  const [sps,        setSps]        = useState<ServicePrincipal[]>(MOCK_SPS);
  const [search,     setSearch]     = useState('');
  const [sortOpen,   setSortOpen]   = useState(false);
  const [sortKey,    setSortKey]    = useState<'name' | 'createdAt' | 'status'>('name');

  const loadSPs = useCallback(async () => {
    try {
      const res = await api.get('/api/quick/service-principals');
      const data = Array.isArray(res.data) ? res.data : res.data?.items ?? [];
      if (data.length > 0) {
        setSps(data.map((sp: any) => ({
          id: sp.id,
          name: sp.name ?? sp.app_name,
          clientId: sp.client_id ?? sp.clientId,
          spn: sp.spn,
          createdAt: sp.created_at ?? sp.createdAt,
          permissions: sp.permissions ?? [],
          status: sp.status ?? 'active',
        })));
      }
    } catch {}
  }, []);

  useEffect(() => { loadSPs(); }, [loadSPs]);

  useEffect(() => {
    const handler = () => setSortOpen(false);
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const filtered = sps
    .filter(sp =>
      sp.name.toLowerCase().includes(search.toLowerCase()) ||
      sp.clientId.toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) => {
      if (sortKey === 'name') return a.name.localeCompare(b.name);
      if (sortKey === 'createdAt') return b.createdAt.localeCompare(a.createdAt);
      if (sortKey === 'status') return a.status.localeCompare(b.status);
      return 0;
    });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{ padding: '16px 16px 10px 16px', borderBottom: '1px solid var(--apple-gray-2)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--apple-text-primary)', margin: 0 }}>
            Service Principals
          </h2>
          {onCreateNew && (
            <button
              onClick={onCreateNew}
              style={{
                width: 24, height: 24, borderRadius: '50%',
                background: 'var(--apple-blue)', color: 'white',
                border: 'none', cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 16, fontWeight: 400, flexShrink: 0,
              }}
              title="New Service Principal"
            >
              +
            </button>
          )}
        </div>

        {/* Search + Sort row */}
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            type="text"
            placeholder="Search..."
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
              onClick={e => { e.stopPropagation(); setSortOpen(o => !o); }}
              style={{
                padding: '5px 10px', border: '1px solid var(--apple-gray-2)',
                borderRadius: 6, background: '#fff', fontSize: 12,
                color: 'var(--apple-text-secondary)', cursor: 'pointer', fontWeight: 500,
              }}
            >
              Sort ↕
            </button>
            {sortOpen && (
              <div
                style={{
                  position: 'absolute', top: 'calc(100% + 4px)', right: 0, zIndex: 20,
                  background: 'white', border: '1px solid var(--apple-gray-2)',
                  borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,0.1)', overflow: 'hidden', minWidth: 130,
                }}
                onClick={e => e.stopPropagation()}
              >
                {([['name', 'Name'], ['createdAt', 'Date Created'], ['status', 'Status']] as const).map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => { setSortKey(key); setSortOpen(false); }}
                    style={{
                      display: 'block', width: '100%', padding: '7px 12px', fontSize: 13,
                      background: sortKey === key ? 'var(--apple-blue-light)' : 'none',
                      color: sortKey === key ? 'var(--apple-blue)' : 'var(--apple-text-primary)',
                      border: 'none', cursor: 'pointer', textAlign: 'left',
                    }}
                    onMouseEnter={e => { if (sortKey !== key) (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
                    onMouseLeave={e => { if (sortKey !== key) (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* List */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.map(sp => {
          const isSelected = sp.id === selectedId;
          return (
            <button
              key={sp.id}
              onClick={() => onSelect(sp)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                width: '100%', padding: '12px 16px',
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
              {/* Key icon */}
              <div style={{
                width: 32, height: 32, borderRadius: 8,
                background: isSelected ? 'rgba(255,255,255,0.2)' : '#F3E8FF',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                <span style={{ fontSize: 16 }}>🔑</span>
              </div>

              {/* Text */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 13, fontWeight: 600,
                  color: isSelected ? '#ffffff' : 'var(--apple-text-primary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {sp.name}
                </div>
                <div style={{
                  fontSize: 11, marginTop: 2,
                  color: isSelected ? 'rgba(255,255,255,0.75)' : 'var(--apple-text-secondary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                  fontFamily: 'monospace',
                }}>
                  {sp.clientId.slice(0, 18)}…
                </div>
              </div>

              {/* Status dot */}
              {!isSelected && (
                <span style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: sp.status === 'active' ? '#22c55e' : '#9CA3AF',
                  flexShrink: 0,
                }} />
              )}
            </button>
          );
        })}

        {filtered.length === 0 && (
          <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--apple-text-tertiary)', fontSize: 13 }}>
            No service principals found.
          </div>
        )}
      </div>
    </div>
  );
}
