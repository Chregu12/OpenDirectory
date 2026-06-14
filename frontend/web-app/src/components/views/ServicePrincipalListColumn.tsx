'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { qaGet, qaDelete, qaPost, RotateSecretResult } from '@/lib/quickActionsApi';

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


interface ServicePrincipalListColumnProps {
  selectedId: string | null;
  onSelect: (sp: ServicePrincipal) => void;
  onCreateNew?: () => void;
}

export default function ServicePrincipalListColumn({ selectedId, onSelect, onCreateNew }: ServicePrincipalListColumnProps) {
  const [sps,          setSps]          = useState<ServicePrincipal[]>([]);
  const [search,       setSearch]       = useState('');
  const [sortOpen,     setSortOpen]     = useState(false);
  const [sortKey,      setSortKey]      = useState<'name' | 'createdAt' | 'status'>('name');
  const [refreshKey,   setRefreshKey]   = useState(0);
  const [deletingId,   setDeletingId]   = useState<string | null>(null);
  const [rotatingId,   setRotatingId]   = useState<string | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState<RotateSecretResult | null>(null);

  const loadSPs = useCallback(async () => {
    try {
      const data = await qaGet<ServicePrincipal[] | { items?: ServicePrincipal[] }>('/api/quick/service-principals');
      const list = Array.isArray(data) ? data : (data.items ?? []);
      setSps(list.map((sp: any) => ({
        id:          sp.id          ?? sp.clientId ?? sp.client_id,
        name:        sp.name        ?? sp.appName  ?? sp.app_name  ?? sp.clientId,
        clientId:    sp.clientId    ?? sp.client_id,
        spn:         sp.spn         ?? '',
        createdAt:   sp.createdAt   ?? sp.created_at ?? '',
        permissions: sp.permissions ?? [],
        status:      sp.status      ?? 'active',
      })));
    } catch {}
  }, []);

  useEffect(() => { loadSPs(); }, [loadSPs, refreshKey]);

  const handleDelete = async (sp: ServicePrincipal) => {
    if (!confirm(`Delete service principal "${sp.name}"? This cannot be undone.`)) return;
    setDeletingId(sp.id);
    try {
      await qaDelete(`/api/quick/service-principals/${encodeURIComponent(sp.clientId || sp.id)}`);
      setRefreshKey(k => k + 1);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete');
    } finally {
      setDeletingId(null);
    }
  };

  const handleRotateSecret = async (sp: ServicePrincipal) => {
    setRotatingId(sp.id);
    try {
      const result = await qaPost<RotateSecretResult>(
        `/api/quick/service-principals/${encodeURIComponent(sp.clientId || sp.id)}/rotate-secret`
      );
      setRotatedSecret(result);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to rotate secret');
    } finally {
      setRotatingId(null);
    }
  };

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

              {/* Status dot + actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                {!isSelected && (
                  <span style={{
                    width: 7, height: 7, borderRadius: '50%',
                    background: sp.status === 'active' ? '#22c55e' : '#9CA3AF',
                  }} />
                )}
                <button
                  onClick={e => { e.stopPropagation(); handleRotateSecret(sp); }}
                  disabled={rotatingId === sp.id}
                  title="Rotate secret"
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer', padding: 2,
                    color: isSelected ? 'rgba(255,255,255,0.7)' : 'var(--apple-gray-5)',
                    fontSize: 12, opacity: rotatingId === sp.id ? 0.5 : 1,
                  }}
                >
                  ↻
                </button>
                <button
                  onClick={e => { e.stopPropagation(); handleDelete(sp); }}
                  disabled={deletingId === sp.id}
                  title="Delete"
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer', padding: 2,
                    color: isSelected ? 'rgba(255,255,255,0.7)' : '#ef4444',
                    fontSize: 12, opacity: deletingId === sp.id ? 0.5 : 1,
                  }}
                >
                  ✕
                </button>
              </div>
            </button>
          );
        })}

        {filtered.length === 0 && (
          <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--apple-text-tertiary)', fontSize: 13 }}>
            No service principals found.
          </div>
        )}
      </div>

      {/* Rotated secret modal */}
      {rotatedSecret && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 70, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
          <div style={{ background: 'white', borderRadius: 14, padding: 24, maxWidth: 420, width: '100%', boxShadow: '0 16px 48px rgba(0,0,0,0.18)' }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 8 }}>New Client Secret</h3>
            <p style={{ fontSize: 13, color: '#92400E', background: '#FEF3C7', borderRadius: 8, padding: '8px 12px', marginBottom: 16 }}>
              Save this secret now — it will not be shown again.
            </p>
            <div style={{ fontFamily: 'monospace', fontSize: 13, background: '#F3F4F6', borderRadius: 8, padding: '10px 14px', wordBreak: 'break-all', marginBottom: 16 }}>
              {rotatedSecret.newClientSecret}
            </div>
            {rotatedSecret.rotatedAt && (
              <p style={{ fontSize: 11, color: '#9CA3AF', marginBottom: 16 }}>
                Rotated at: {new Date(rotatedSecret.rotatedAt).toLocaleString()}
              </p>
            )}
            <button
              onClick={() => setRotatedSecret(null)}
              style={{ width: '100%', padding: '9px', background: '#AF52DE', color: 'white', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 500, cursor: 'pointer' }}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
