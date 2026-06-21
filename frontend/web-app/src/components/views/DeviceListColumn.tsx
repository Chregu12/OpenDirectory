'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

export type OSType = 'all' | 'macos' | 'windows' | 'linux' | 'ios' | 'android';

export interface FleetDevice {
  id: string;
  name: string;
  os: Exclude<OSType, 'all'>;
  osVersion?: string;
  assignedUser?: string;
  lastSeen: string;
  compliance: 'compliant' | 'warning' | 'non-compliant';
  enrolledAt?: string;
  serial?: string;
  model?: string;
  mdmServer?: string;
  orderNumber?: string;
  partNumber?: string;
  storage?: string;
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_DEVICES: FleetDevice[] = [
  { id: '1',  name: 'MacBook Pro 14"',  os: 'macos',   model: 'MacBook Pro 14"',  assignedUser: 'John Doe',    lastSeen: '2 min ago',  compliance: 'compliant',     enrolledAt: '2024-01-15', serial: 'XYX1234YYY00', mdmServer: 'OpenDirectory MDM', orderNumber: 'XYZ123456', partNumber: 'MKGP3LL/A', storage: '512 GB' },
  { id: '2',  name: 'MacBook Air M2',   os: 'macos',   model: 'MacBook Air M2',   assignedUser: 'Jane Smith',  lastSeen: '1 hr ago',   compliance: 'compliant',     enrolledAt: '2024-02-01', serial: 'C02XN1234567', mdmServer: 'OpenDirectory MDM', storage: '256 GB' },
  { id: '3',  name: 'WIN-desk-01',      os: 'windows', model: 'Dell OptiPlex',    assignedUser: 'Bob Wilson',  lastSeen: '30 min ago', compliance: 'warning',       enrolledAt: '2024-01-20', serial: 'DELLWIN01234' },
  { id: '4',  name: 'WIN-laptop-03',    os: 'windows', model: 'ThinkPad X1',      assignedUser: 'Alice Chen',  lastSeen: '5 min ago',  compliance: 'compliant',     enrolledAt: '2024-03-10', serial: 'LNV001234567' },
  { id: '5',  name: 'ubuntu-dev-01',    os: 'linux',   model: 'System76 Lemur',   assignedUser: 'Dev Team',    lastSeen: '10 min ago', compliance: 'compliant',     enrolledAt: '2024-01-05', serial: 'S76LMR00001' },
  { id: '6',  name: 'iPhone 13 Pro',    os: 'ios',     model: 'iPhone 13 Pro',    assignedUser: 'Sarah Park',  lastSeen: '1 min ago',  compliance: 'compliant',     enrolledAt: '2024-04-01', serial: 'F2LXCG123456' },
  { id: '7',  name: 'Galaxy S24 Ultra', os: 'android', model: 'Galaxy S24 Ultra', assignedUser: 'Mike Brown',  lastSeen: '20 min ago', compliance: 'warning',       enrolledAt: '2024-03-25', serial: 'R5CW7XX1234' },
  { id: '8',  name: 'MacBook Air M1',   os: 'macos',   model: 'MacBook Air M1',   assignedUser: 'Legacy User', lastSeen: '3 days ago', compliance: 'non-compliant', enrolledAt: '2023-06-01', serial: 'C02XN7654321', mdmServer: 'OpenDirectory MDM', storage: '256 GB' },
  { id: '9',  name: 'WIN-server-02',    os: 'windows', model: 'HP ProLiant',      assignedUser: 'IT Team',     lastSeen: '1 min ago',  compliance: 'compliant',     enrolledAt: '2024-01-10', serial: 'HPPRL002345' },
  { id: '10', name: 'iPad 10th Gen',    os: 'ios',     model: 'iPad 10th Gen',    assignedUser: 'Reception',   lastSeen: '5 hr ago',   compliance: 'warning',       enrolledAt: '2024-02-14', serial: 'DLXH9A0012AB' },
];

// ─── OS icons & labels ────────────────────────────────────────────────────────

const OS_META: Record<Exclude<OSType, 'all'>, { icon: string; label: string }> = {
  macos:   { icon: '💻', label: 'macOS' },
  windows: { icon: '🖥', label: 'Windows' },
  linux:   { icon: '🐧', label: 'Linux' },
  ios:     { icon: '📱', label: 'iOS/iPadOS' },
  android: { icon: '🤖', label: 'Android' },
};

type SortKey = 'name' | 'serial' | 'enrolledAt' | 'compliance';

const SORT_LABELS: Record<SortKey, string> = {
  name:       'Name',
  serial:     'Serial',
  enrolledAt: 'Date Added',
  compliance: 'Compliance',
};

interface DeviceListColumnProps {
  selectedId: string | null;
  onSelect: (device: FleetDevice) => void;
}

export default function DeviceListColumn({ selectedId, onSelect }: DeviceListColumnProps) {
  const [devices,    setDevices]    = useState<FleetDevice[]>(MOCK_DEVICES);
  const [osFilter,   setOsFilter]   = useState<OSType>('all');
  const [sortKey,    setSortKey]    = useState<SortKey>('name');
  const [filterOpen, setFilterOpen] = useState(false);
  const [sortOpen,   setSortOpen]   = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const loadDevices = useCallback(async () => {
    try {
      const res = await api.get('/api/devices');
      const raw = Array.isArray(res.data) ? res.data : res.data?.devices ?? [];
      if (raw.length > 0) {
        const mapped: FleetDevice[] = raw.map((d: any) => ({
          id: d.id,
          name: d.hostname ?? d.name ?? d.id,
          os: (d.platform ?? d.os ?? 'linux') as Exclude<OSType, 'all'>,
          osVersion: d.osVersion ?? d.os_version,
          assignedUser: d.assigned_user ?? d.owner,
          lastSeen: d.lastSeen ?? d.last_seen ?? 'Unknown',
          compliance: d.complianceScore != null
            ? d.complianceScore >= 90 ? 'compliant' : d.complianceScore >= 70 ? 'warning' : 'non-compliant'
            : 'compliant',
          enrolledAt: d.registeredAt ?? d.enrolled_at,
          serial: d.serial ?? d.serial_number,
          model: d.model,
          mdmServer: d.mdm_server,
        }));
        setDevices(mapped);
      }
    } catch {}
  }, []);

  useEffect(() => { loadDevices(); }, [loadDevices, refreshKey]);

  // Refresh when a new device is enrolled via EnrollmentWizard
  useEffect(() => {
    const handler = () => setRefreshKey(k => k + 1);
    window.addEventListener('device-enrolled', handler);
    return () => window.removeEventListener('device-enrolled', handler);
  }, []);

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = () => { setFilterOpen(false); setSortOpen(false); };
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const filtered = devices
    .filter(d => osFilter === 'all' || d.os === osFilter)
    .sort((a, b) => {
      if (sortKey === 'name') return a.name.localeCompare(b.name);
      if (sortKey === 'serial') return (a.serial ?? '').localeCompare(b.serial ?? '');
      if (sortKey === 'enrolledAt') return (b.enrolledAt ?? '').localeCompare(a.enrolledAt ?? '');
      if (sortKey === 'compliance') {
        const order = { 'non-compliant': 0, 'warning': 1, 'compliant': 2 };
        return order[a.compliance] - order[b.compliance];
      }
      return 0;
    });

  const complianceDot = (c: FleetDevice['compliance']) => {
    const colors = { compliant: '#22c55e', warning: '#f59e0b', 'non-compliant': '#ef4444' };
    return (
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: colors[c], flexShrink: 0, display: 'inline-block' }} />
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-surface, #161b22)', borderRight: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
      {/* Column header */}
      <div style={{ padding: '16px 16px 10px 16px', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: 0 }}>Your Devices</h2>
          <span style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)' }}>{filtered.length}</span>
        </div>

        {/* Filter + Sort row */}
        <div style={{ display: 'flex', gap: 6 }}>
          {/* Filter button */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={e => { e.stopPropagation(); setFilterOpen(o => !o); setSortOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '5px 10px', border: '1px solid var(--border, rgba(255,255,255,0.07))',
                borderRadius: 6,
                background: osFilter !== 'all' ? 'rgba(0,111,255,0.15)' : 'var(--bg-surface-raised, #1c2128)',
                fontSize: 12, color: osFilter !== 'all' ? '#006FFF' : 'var(--text-secondary, #8b949e)',
                cursor: 'pointer', fontWeight: 500,
              }}
            >
              Filter {osFilter !== 'all' && `· ${OS_META[osFilter as Exclude<OSType, 'all'>]?.label}`}
            </button>
            {filterOpen && (
              <div
                style={{
                  position: 'absolute', top: 'calc(100% + 4px)', left: 0, zIndex: 20,
                  background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))',
                  borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,0.4)', overflow: 'hidden', minWidth: 140,
                }}
                onClick={e => e.stopPropagation()}
              >
                {(['all', 'macos', 'windows', 'linux', 'ios', 'android'] as const).map(os => (
                  <button
                    key={os}
                    onClick={() => { setOsFilter(os); setFilterOpen(false); }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                      padding: '7px 12px', fontSize: 13,
                      background: osFilter === os ? 'rgba(0,111,255,0.15)' : 'none',
                      color: osFilter === os ? '#006FFF' : 'var(--text-primary, #e4e6ea)',
                      border: 'none', cursor: 'pointer', textAlign: 'left',
                    }}
                    onMouseEnter={e => { if (osFilter !== os) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)'; }}
                    onMouseLeave={e => { if (osFilter !== os) (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    {os === 'all' ? '💻' : OS_META[os].icon}
                    {os === 'all' ? 'All Platforms' : OS_META[os].label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Sort button */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={e => { e.stopPropagation(); setSortOpen(o => !o); setFilterOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '5px 10px', border: '1px solid var(--border, rgba(255,255,255,0.07))',
                borderRadius: 6, background: 'var(--bg-surface-raised, #1c2128)',
                fontSize: 12, color: 'var(--text-secondary, #8b949e)', cursor: 'pointer', fontWeight: 500,
              }}
            >
              Sort ↕
            </button>
            {sortOpen && (
              <div
                style={{
                  position: 'absolute', top: 'calc(100% + 4px)', left: 0, zIndex: 20,
                  background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))',
                  borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,0.4)', overflow: 'hidden', minWidth: 140,
                }}
                onClick={e => e.stopPropagation()}
              >
                {(Object.keys(SORT_LABELS) as SortKey[]).map(key => (
                  <button
                    key={key}
                    onClick={() => { setSortKey(key); setSortOpen(false); }}
                    style={{
                      display: 'block', width: '100%', padding: '7px 12px', fontSize: 13,
                      background: sortKey === key ? 'rgba(0,111,255,0.15)' : 'none',
                      color: sortKey === key ? '#006FFF' : 'var(--text-primary, #e4e6ea)',
                      border: 'none', cursor: 'pointer', textAlign: 'left',
                    }}
                    onMouseEnter={e => { if (sortKey !== key) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)'; }}
                    onMouseLeave={e => { if (sortKey !== key) (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                  >
                    {SORT_LABELS[key]}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Device list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.map(device => {
          const meta = OS_META[device.os];
          const isSelected = device.id === selectedId;
          return (
            <button
              key={device.id}
              onClick={() => onSelect(device)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                width: '100%',
                padding: '12px 16px',
                background: isSelected ? '#006FFF' : 'transparent',
                border: 'none',
                borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => { if (!isSelected) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)'; }}
              onMouseLeave={e => { if (!isSelected) (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
            >
              {/* OS icon */}
              <span style={{ fontSize: 22, flexShrink: 0 }}>{meta?.icon ?? '💻'}</span>

              {/* Text */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 13, fontWeight: 600,
                  color: isSelected ? '#ffffff' : 'var(--text-primary, #e4e6ea)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {device.name}
                </div>
                <div style={{
                  fontSize: 11, marginTop: 2,
                  color: isSelected ? 'rgba(255,255,255,0.75)' : 'var(--text-secondary, #8b949e)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {device.mdmServer ?? meta?.label ?? ''}
                  {device.serial && ` · ${device.serial}`}
                </div>
              </div>

              {/* Compliance dot (hide when selected — blue bg makes it hard to see) */}
              {!isSelected && complianceDot(device.compliance)}
            </button>
          );
        })}

        {filtered.length === 0 && (
          <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted, #6e7681)', fontSize: 13 }}>
            No devices match the filter.
          </div>
        )}
      </div>
    </div>
  );
}
