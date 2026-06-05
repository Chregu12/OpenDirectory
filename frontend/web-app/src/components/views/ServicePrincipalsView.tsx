'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  PlusIcon,
  EllipsisHorizontalIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  KeyIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ServicePrincipal {
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
  {
    id: '1',
    name: 'inventory-service',
    clientId: 'a3f8c2d1-e4b5-4c6d-8e9f-0a1b2c3d4e5f',
    spn: 'app/inventory-service@opendirectory.local',
    createdAt: '2024-01-15',
    permissions: ['read_users', 'read_devices'],
    status: 'active',
  },
  {
    id: '2',
    name: 'ci-pipeline',
    clientId: 'b5c7d9e1-f2a3-4b5c-6d7e-8f9a0b1c2d3e',
    spn: 'app/ci-pipeline@opendirectory.local',
    createdAt: '2024-02-20',
    permissions: ['read_users', 'api_gateway'],
    status: 'active',
  },
  {
    id: '3',
    name: 'legacy-erp-connector',
    clientId: 'c1d2e3f4-a5b6-7c8d-9e0f-1a2b3c4d5e6f',
    spn: 'app/legacy-erp@opendirectory.local',
    createdAt: '2023-08-01',
    permissions: ['read_users', 'write_policies', 'admin_access'],
    status: 'disabled',
  },
  {
    id: '4',
    name: 'monitoring-agent',
    clientId: 'd4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a',
    spn: 'app/monitoring@opendirectory.local',
    createdAt: '2024-03-10',
    permissions: ['read_devices', 'audit_logs'],
    status: 'active',
  },
];

// ─── Status pill ──────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: 'active' | 'disabled' }) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '2px 10px',
        borderRadius: 999,
        background: status === 'active' ? '#D1FAE5' : '#F3F4F6',
        color: status === 'active' ? '#065F46' : '#6B7280',
        fontSize: 12,
        fontWeight: 500,
      }}
    >
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: status === 'active' ? '#22c55e' : '#9CA3AF', flexShrink: 0 }} />
      {status === 'active' ? 'Active' : 'Disabled'}
    </span>
  );
}

// ─── Actions menu ─────────────────────────────────────────────────────────────

function ActionsMenu({ spId, spName, onClose, onDelete }: {
  spId: string;
  spName: string;
  onClose: () => void;
  onDelete: (id: string) => void;
}) {
  const actions = [
    { label: 'View Details', icon: '👁', danger: false },
    { label: 'Rotate Secret', icon: '🔄', danger: false },
    { label: 'Disable', icon: '⏸', danger: false },
    { label: 'Delete', icon: '🗑', danger: true },
  ];

  return (
    <div
      style={{
        position: 'absolute',
        right: 0,
        top: '100%',
        zIndex: 50,
        background: 'white',
        border: '1px solid var(--apple-gray-2)',
        borderRadius: 10,
        boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
        overflow: 'hidden',
        minWidth: 160,
      }}
      onClick={e => e.stopPropagation()}
    >
      {actions.map(a => (
        <button
          key={a.label}
          onClick={() => {
            if (a.label === 'Delete') {
              if (confirm(`Delete service principal "${spName}"?`)) {
                onDelete(spId);
              }
            } else if (a.label === 'Rotate Secret') {
              toast.success(`Secret rotation initiated for ${spName}`);
            } else {
              toast.success(`${a.label}: ${spName}`);
            }
            onClose();
          }}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            width: '100%',
            padding: '8px 14px',
            fontSize: 13,
            color: a.danger ? '#DC2626' : 'var(--apple-text-primary)',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            textAlign: 'left',
          }}
          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
        >
          <span>{a.icon}</span>
          {a.label}
        </button>
      ))}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

interface ServicePrincipalsViewProps {
  onCreateNew?: () => void;
}

export default function ServicePrincipalsView({ onCreateNew }: ServicePrincipalsViewProps) {
  const [sps, setSps]         = useState<ServicePrincipal[]>(MOCK_SPS);
  const [loading, setLoading] = useState(false);
  const [search, setSearch]   = useState('');
  const [openMenu, setOpenMenu] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      // TODO: GET http://localhost:3950/api/quick/service-principals
      const res = await api.get('/api/quick/service-principals');
      const data = Array.isArray(res.data) ? res.data : res.data?.items ?? [];
      if (data.length > 0) {
        setSps(data.map((sp: any) => ({
          id:          sp.id,
          name:        sp.name ?? sp.app_name,
          clientId:    sp.client_id ?? sp.clientId,
          spn:         sp.spn,
          createdAt:   sp.created_at ?? sp.createdAt,
          permissions: sp.permissions ?? [],
          status:      sp.status ?? 'active',
        })));
      }
    } catch {
      // keep mock
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  useEffect(() => {
    const handler = () => setOpenMenu(null);
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const filtered = sps.filter(sp =>
    sp.name.toLowerCase().includes(search.toLowerCase()) ||
    sp.clientId.toLowerCase().includes(search.toLowerCase()) ||
    sp.spn.toLowerCase().includes(search.toLowerCase())
  );

  const handleDelete = (id: string) => {
    setSps(prev => prev.filter(sp => sp.id !== id));
    api.delete(`/api/quick/service-principals/${id}`).catch(() => {});
    toast.success('Service principal deleted');
  };

  const truncate = (s: string, n: number) => s.length > n ? s.slice(0, n) + '...' : s;

  return (
    <div>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--apple-text-primary)', marginBottom: 2 }}>
            Service Principals
          </h1>
          <p style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>
            App identities for service-to-service authentication
          </p>
        </div>
        <button
          onClick={onCreateNew}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '8px 16px',
            background: '#AF52DE',
            color: 'white',
            border: 'none',
            borderRadius: 8,
            fontSize: 13,
            fontWeight: 500,
            cursor: 'pointer',
          }}
        >
          <PlusIcon style={{ width: 15, height: 15 }} />
          New Service Principal
        </button>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total', value: sps.length, color: 'var(--apple-text-primary)' },
          { label: 'Active', value: sps.filter(s => s.status === 'active').length, color: '#22c55e' },
          { label: 'Disabled', value: sps.filter(s => s.status === 'disabled').length, color: '#6B7280' },
        ].map(stat => (
          <div
            key={stat.label}
            style={{
              flex: 1,
              background: 'white',
              border: '1px solid var(--apple-gray-2)',
              borderRadius: 10,
              padding: '12px 16px',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: 24, fontWeight: 700, color: stat.color }}>{stat.value}</div>
            <div style={{ fontSize: 12, color: 'var(--apple-text-secondary)' }}>{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Table card */}
      <div style={{ background: 'white', border: '1px solid var(--apple-gray-2)', borderRadius: 12, overflow: 'hidden' }}>
        {/* Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 16px', borderBottom: '1px solid var(--apple-gray-2)', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
            <MagnifyingGlassIcon style={{ width: 15, height: 15, position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--apple-gray-5)', pointerEvents: 'none' }} />
            <input
              type="text"
              placeholder="Search service principals..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ width: '100%', paddingLeft: 32, paddingRight: 12, paddingTop: 7, paddingBottom: 7, border: '1px solid var(--apple-gray-2)', borderRadius: 8, fontSize: 13, background: 'var(--apple-gray-1)', outline: 'none', boxSizing: 'border-box' }}
            />
          </div>
          <button
            onClick={fetch}
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', border: '1px solid var(--apple-gray-2)', borderRadius: 8, background: 'white', fontSize: 13, color: 'var(--apple-text-secondary)', cursor: 'pointer' }}
          >
            <ArrowPathIcon style={{ width: 14, height: 14, animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>

        {/* Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--apple-gray-1)' }}>
                {['App Name', 'Client ID', 'SPN', 'Created', 'Permissions', 'Status', 'Actions'].map(col => (
                  <th key={col} style={{ padding: '9px 16px', fontSize: 12, fontWeight: 600, color: 'var(--apple-text-secondary)', textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.04em', borderBottom: '1px solid var(--apple-gray-2)', whiteSpace: 'nowrap' }}>
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((sp, idx) => (
                <tr
                  key={sp.id}
                  style={{ borderBottom: idx < filtered.length - 1 ? '1px solid var(--apple-gray-1)' : 'none', background: 'white', transition: 'background 0.1s' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'var(--apple-gray-1)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'white'; }}
                >
                  {/* Name */}
                  <td style={{ padding: '11px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 28, height: 28, borderRadius: 6, background: '#F3E8FF', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                        <KeyIcon style={{ width: 14, height: 14, color: '#AF52DE' }} />
                      </div>
                      <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)' }}>{sp.name}</span>
                    </div>
                  </td>

                  {/* Client ID */}
                  <td style={{ padding: '11px 16px' }}>
                    <code style={{ fontSize: 12, color: 'var(--apple-text-secondary)', fontFamily: 'monospace' }}>
                      {truncate(sp.clientId, 20)}
                    </code>
                  </td>

                  {/* SPN */}
                  <td style={{ padding: '11px 16px' }}>
                    <code style={{ fontSize: 12, color: 'var(--apple-text-secondary)', fontFamily: 'monospace' }}>
                      {truncate(sp.spn, 30)}
                    </code>
                  </td>

                  {/* Created */}
                  <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--apple-text-secondary)', whiteSpace: 'nowrap' }}>
                    {sp.createdAt ? new Date(sp.createdAt).toLocaleDateString() : '—'}
                  </td>

                  {/* Permissions */}
                  <td style={{ padding: '11px 16px' }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {sp.permissions.slice(0, 2).map(p => (
                        <span
                          key={p}
                          style={{
                            fontSize: 11,
                            padding: '2px 7px',
                            borderRadius: 4,
                            background: 'var(--apple-gray-1)',
                            color: 'var(--apple-text-secondary)',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {p.replace(/_/g, ' ')}
                        </span>
                      ))}
                      {sp.permissions.length > 2 && (
                        <span style={{ fontSize: 11, color: 'var(--apple-text-tertiary)' }}>
                          +{sp.permissions.length - 2}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Status */}
                  <td style={{ padding: '11px 16px' }}>
                    <StatusPill status={sp.status} />
                  </td>

                  {/* Actions */}
                  <td style={{ padding: '11px 16px' }}>
                    <div style={{ position: 'relative', display: 'inline-block' }}>
                      <button
                        onClick={e => { e.stopPropagation(); setOpenMenu(prev => prev === sp.id ? null : sp.id); }}
                        style={{ display: 'flex', alignItems: 'center', padding: '4px 8px', border: '1px solid var(--apple-gray-2)', borderRadius: 6, background: 'white', cursor: 'pointer', color: 'var(--apple-gray-5)' }}
                      >
                        <EllipsisHorizontalIcon style={{ width: 16, height: 16 }} />
                      </button>
                      {openMenu === sp.id && (
                        <ActionsMenu
                          spId={sp.id}
                          spName={sp.name}
                          onClose={() => setOpenMenu(null)}
                          onDelete={handleDelete}
                        />
                      )}
                    </div>
                  </td>
                </tr>
              ))}

              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--apple-text-tertiary)', fontSize: 13 }}>
                    No service principals found.
                    {onCreateNew && (
                      <button onClick={onCreateNew} style={{ marginLeft: 8, color: '#AF52DE', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 500 }}>
                        Create one →
                      </button>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div style={{ padding: '10px 16px', borderTop: '1px solid var(--apple-gray-2)', fontSize: 12, color: 'var(--apple-text-tertiary)' }}>
          {filtered.length} of {sps.length} service principals
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
