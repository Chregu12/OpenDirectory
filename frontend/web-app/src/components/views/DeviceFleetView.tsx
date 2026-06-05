'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  MagnifyingGlassIcon,
  EllipsisHorizontalIcon,
  ArrowPathIcon,
  FunnelIcon,
  ComputerDesktopIcon,
  DevicePhoneMobileIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

type OSType = 'all' | 'macos' | 'windows' | 'linux' | 'ios' | 'android';
type ComplianceStatus = 'all' | 'compliant' | 'warning' | 'non-compliant';

interface FleetDevice {
  id: string;
  name: string;
  os: OSType;
  osVersion?: string;
  assignedUser?: string;
  lastSeen: string;
  compliance: 'compliant' | 'warning' | 'non-compliant';
  enrolledAt?: string;
  serial?: string;
}

interface OSSummary {
  os: OSType;
  label: string;
  icon: string;
  total: number;
  compliant: number;
  warning: number;
}

// ─── Mock data (TODO: replace with real API calls) ────────────────────────────

const MOCK_DEVICES: FleetDevice[] = [
  { id: '1',  name: 'MBA-johndoe',     os: 'macos',   assignedUser: 'John Doe',    lastSeen: '2 min ago',  compliance: 'compliant',     enrolledAt: '2024-01-15' },
  { id: '2',  name: 'MBP-janesmith',   os: 'macos',   assignedUser: 'Jane Smith',  lastSeen: '1 hr ago',   compliance: 'compliant',     enrolledAt: '2024-02-01' },
  { id: '3',  name: 'WIN-desk-01',     os: 'windows', assignedUser: 'Bob Wilson',  lastSeen: '30 min ago', compliance: 'warning',       enrolledAt: '2024-01-20' },
  { id: '4',  name: 'WIN-laptop-03',   os: 'windows', assignedUser: 'Alice Chen',  lastSeen: '5 min ago',  compliance: 'compliant',     enrolledAt: '2024-03-10' },
  { id: '5',  name: 'ubuntu-dev-01',   os: 'linux',   assignedUser: 'Dev Team',    lastSeen: '10 min ago', compliance: 'compliant',     enrolledAt: '2024-01-05' },
  { id: '6',  name: 'iphone-sarah',    os: 'ios',     assignedUser: 'Sarah Park',  lastSeen: '1 min ago',  compliance: 'compliant',     enrolledAt: '2024-04-01' },
  { id: '7',  name: 'galaxy-s24-mike', os: 'android', assignedUser: 'Mike Brown',  lastSeen: '20 min ago', compliance: 'warning',       enrolledAt: '2024-03-25' },
  { id: '8',  name: 'MBA-legacy-old',  os: 'macos',   assignedUser: 'Legacy User', lastSeen: '3 days ago', compliance: 'non-compliant', enrolledAt: '2023-06-01' },
  { id: '9',  name: 'WIN-server-02',   os: 'windows', assignedUser: 'IT Team',     lastSeen: '1 min ago',  compliance: 'compliant',     enrolledAt: '2024-01-10' },
  { id: '10', name: 'ipad-reception',  os: 'ios',     assignedUser: 'Reception',   lastSeen: '5 hr ago',   compliance: 'warning',       enrolledAt: '2024-02-14' },
];

// ─── OS Icons & Labels ─────────────────────────────────────────────────────────

const OS_META: Record<OSType, { icon: string; label: string; color: string }> = {
  all:     { icon: '💻', label: 'All',     color: '#6E6E73' },
  macos:   { icon: '🍎', label: 'macOS',   color: '#1D1D1F' },
  windows: { icon: '🪟', label: 'Windows', color: '#0078D4' },
  linux:   { icon: '🐧', label: 'Linux',   color: '#E95420' },
  ios:     { icon: '📱', label: 'iOS',     color: '#0071E3' },
  android: { icon: '🤖', label: 'Android', color: '#34A853' },
};

// ─── Status Pill ──────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: 'compliant' | 'warning' | 'non-compliant' }) {
  const map = {
    compliant:     { bg: '#D1FAE5', color: '#065F46', label: 'Compliant' },
    warning:       { bg: '#FEF3C7', color: '#92400E', label: 'Warning' },
    'non-compliant': { bg: '#FEE2E2', color: '#991B1B', label: 'Non-Compliant' },
  };
  const s = map[status];
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '2px 10px',
        borderRadius: 999,
        background: s.bg,
        color: s.color,
        fontSize: 12,
        fontWeight: 500,
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: s.color,
          flexShrink: 0,
        }}
      />
      {s.label}
    </span>
  );
}

// ─── OS Summary Card ──────────────────────────────────────────────────────────

function OSSummaryCard({
  summary,
  isActive,
  onClick,
}: {
  summary: OSSummary;
  isActive: boolean;
  onClick: () => void;
}) {
  const meta = OS_META[summary.os];
  const nonCompliant = summary.total - summary.compliant - summary.warning;

  return (
    <button
      onClick={onClick}
      style={{
        flex: 1,
        minWidth: 120,
        background: isActive ? 'var(--apple-blue-light)' : '#FFFFFF',
        border: isActive ? '1.5px solid var(--apple-blue)' : '1px solid var(--apple-gray-2)',
        borderRadius: 12,
        padding: '14px 16px',
        cursor: 'pointer',
        textAlign: 'left',
        transition: 'border 0.15s, background 0.15s',
      }}
      onMouseEnter={e => {
        if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)';
      }}
      onMouseLeave={e => {
        if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = '#FFFFFF';
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 20 }}>{meta.icon}</span>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)' }}>{meta.label}</span>
      </div>
      <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--apple-text-primary)', lineHeight: 1.1, marginBottom: 4 }}>
        {summary.total}
      </div>
      <div style={{ fontSize: 11, color: 'var(--apple-text-secondary)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ color: '#059669' }}>{summary.compliant} compliant</span>
        {summary.warning > 0 && <span style={{ color: '#D97706' }}>{summary.warning} warning</span>}
        {nonCompliant > 0 && <span style={{ color: '#DC2626' }}>{nonCompliant} issues</span>}
      </div>
    </button>
  );
}

// ─── Actions Menu ─────────────────────────────────────────────────────────────

function ActionsMenu({
  deviceId,
  deviceName,
  onClose,
}: {
  deviceId: string;
  deviceName: string;
  onClose: () => void;
}) {
  const actions = [
    { label: 'View Details', icon: '👁' },
    { label: 'Push Policy', icon: '📋' },
    { label: 'Remote Lock', icon: '🔒' },
    { label: 'Unenroll', icon: '❌', danger: true },
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
            toast.success(`${a.label}: ${deviceName}`);
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

// ─── Main Component ───────────────────────────────────────────────────────────

export default function DeviceFleetView() {
  const [devices, setDevices] = useState<FleetDevice[]>(MOCK_DEVICES);
  const [loading, setLoading] = useState(false);
  const [osFilter, setOsFilter] = useState<OSType>('all');
  const [complianceFilter, setComplianceFilter] = useState<ComplianceStatus>('all');
  const [search, setSearch] = useState('');
  const [openMenu, setOpenMenu] = useState<string | null>(null);

  const fetchDevices = useCallback(async () => {
    setLoading(true);
    try {
      // TODO: replace with quick-actions endpoint GET /api/quick/devices
      const res = await api.get('/api/devices');
      const raw = Array.isArray(res.data) ? res.data : res.data?.devices ?? [];
      if (raw.length > 0) {
        const mapped: FleetDevice[] = raw.map((d: any) => ({
          id: d.id,
          name: d.hostname ?? d.name ?? d.id,
          os: (d.platform ?? d.os ?? 'linux') as OSType,
          osVersion: d.osVersion ?? d.os_version,
          assignedUser: d.assigned_user ?? d.owner,
          lastSeen: d.lastSeen ?? d.last_seen ?? 'Unknown',
          compliance: d.complianceScore != null
            ? d.complianceScore >= 90 ? 'compliant' : d.complianceScore >= 70 ? 'warning' : 'non-compliant'
            : 'compliant',
          enrolledAt: d.registeredAt ?? d.enrolled_at,
        }));
        setDevices(mapped);
      }
    } catch {
      // keep mock data
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  // Close menu on outside click
  useEffect(() => {
    const handler = () => setOpenMenu(null);
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  // OS summary cards
  const osList: OSType[] = ['macos', 'windows', 'linux', 'ios', 'android'];
  const summaries: OSSummary[] = osList.map(os => {
    const devs = devices.filter(d => d.os === os);
    return {
      os,
      label: OS_META[os].label,
      icon: OS_META[os].icon,
      total: devs.length,
      compliant: devs.filter(d => d.compliance === 'compliant').length,
      warning: devs.filter(d => d.compliance === 'warning').length,
    };
  });

  // Filtered devices
  const filtered = devices.filter(d => {
    if (osFilter !== 'all' && d.os !== osFilter) return false;
    if (complianceFilter !== 'all' && d.compliance !== complianceFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return d.name.toLowerCase().includes(q) || (d.assignedUser ?? '').toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div style={{ padding: 0 }}>
      {/* OS Summary Cards */}
      <div
        style={{
          display: 'flex',
          gap: 10,
          marginBottom: 20,
          flexWrap: 'wrap',
        }}
      >
        {summaries.map(s => (
          <OSSummaryCard
            key={s.os}
            summary={s}
            isActive={osFilter === s.os}
            onClick={() => setOsFilter(prev => prev === s.os ? 'all' : s.os)}
          />
        ))}
      </div>

      {/* Table card */}
      <div
        style={{
          background: '#FFFFFF',
          border: '1px solid var(--apple-gray-2)',
          borderRadius: 12,
          overflow: 'hidden',
        }}
      >
        {/* Table header controls */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '14px 16px',
            borderBottom: '1px solid var(--apple-gray-2)',
            flexWrap: 'wrap',
          }}
        >
          {/* Search */}
          <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
            <MagnifyingGlassIcon
              style={{
                width: 15,
                height: 15,
                position: 'absolute',
                left: 10,
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--apple-gray-5)',
                pointerEvents: 'none',
              }}
            />
            <input
              type="text"
              placeholder="Search devices or users..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{
                width: '100%',
                paddingLeft: 32,
                paddingRight: 12,
                paddingTop: 7,
                paddingBottom: 7,
                border: '1px solid var(--apple-gray-2)',
                borderRadius: 8,
                fontSize: 13,
                color: 'var(--apple-text-primary)',
                background: 'var(--apple-gray-1)',
                outline: 'none',
              }}
            />
          </div>

          {/* OS filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <FunnelIcon style={{ width: 14, height: 14, color: 'var(--apple-gray-5)' }} />
            <select
              value={osFilter}
              onChange={e => setOsFilter(e.target.value as OSType)}
              style={{
                border: '1px solid var(--apple-gray-2)',
                borderRadius: 8,
                padding: '6px 10px',
                fontSize: 13,
                color: 'var(--apple-text-primary)',
                background: 'white',
                cursor: 'pointer',
                outline: 'none',
              }}
            >
              <option value="all">All OS</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="ios">iOS</option>
              <option value="android">Android</option>
            </select>
          </div>

          {/* Compliance filter */}
          <select
            value={complianceFilter}
            onChange={e => setComplianceFilter(e.target.value as ComplianceStatus)}
            style={{
              border: '1px solid var(--apple-gray-2)',
              borderRadius: 8,
              padding: '6px 10px',
              fontSize: 13,
              color: 'var(--apple-text-primary)',
              background: 'white',
              cursor: 'pointer',
              outline: 'none',
            }}
          >
            <option value="all">All Status</option>
            <option value="compliant">Compliant</option>
            <option value="warning">Warning</option>
            <option value="non-compliant">Non-Compliant</option>
          </select>

          {/* Refresh */}
          <button
            onClick={fetchDevices}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              padding: '6px 12px',
              border: '1px solid var(--apple-gray-2)',
              borderRadius: 8,
              background: 'white',
              fontSize: 13,
              color: 'var(--apple-text-secondary)',
              cursor: 'pointer',
            }}
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
                {['Device', 'User', 'Last Seen', 'Compliance', 'Enrolled', 'Actions'].map(col => (
                  <th
                    key={col}
                    style={{
                      padding: '9px 16px',
                      fontSize: 12,
                      fontWeight: 600,
                      color: 'var(--apple-text-secondary)',
                      textAlign: 'left',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      borderBottom: '1px solid var(--apple-gray-2)',
                    }}
                  >
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((device, idx) => {
                const meta = OS_META[device.os];
                return (
                  <tr
                    key={device.id}
                    style={{
                      borderBottom: idx < filtered.length - 1 ? '1px solid var(--apple-gray-1)' : 'none',
                      background: 'white',
                      transition: 'background 0.1s',
                    }}
                    onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'var(--apple-gray-1)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'white'; }}
                  >
                    {/* Device name */}
                    <td style={{ padding: '11px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                        <span style={{ fontSize: 18, flexShrink: 0 }}>{meta.icon}</span>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)' }}>
                            {device.name}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--apple-text-tertiary)' }}>
                            {meta.label}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* User */}
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--apple-text-secondary)' }}>
                      {device.assignedUser ?? '—'}
                    </td>

                    {/* Last seen */}
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--apple-text-secondary)' }}>
                      {device.lastSeen}
                    </td>

                    {/* Compliance */}
                    <td style={{ padding: '11px 16px' }}>
                      <StatusPill status={device.compliance} />
                    </td>

                    {/* Enrolled */}
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--apple-text-tertiary)' }}>
                      {device.enrolledAt
                        ? new Date(device.enrolledAt).toLocaleDateString()
                        : '—'}
                    </td>

                    {/* Actions */}
                    <td style={{ padding: '11px 16px' }}>
                      <div style={{ position: 'relative', display: 'inline-block' }}>
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            setOpenMenu(prev => prev === device.id ? null : device.id);
                          }}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            padding: '4px 8px',
                            border: '1px solid var(--apple-gray-2)',
                            borderRadius: 6,
                            background: 'white',
                            cursor: 'pointer',
                            color: 'var(--apple-gray-5)',
                          }}
                        >
                          <EllipsisHorizontalIcon style={{ width: 16, height: 16 }} />
                        </button>
                        {openMenu === device.id && (
                          <ActionsMenu
                            deviceId={device.id}
                            deviceName={device.name}
                            onClose={() => setOpenMenu(null)}
                          />
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={6}
                    style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--apple-text-tertiary)', fontSize: 13 }}
                  >
                    No devices match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Footer count */}
        <div
          style={{
            padding: '10px 16px',
            borderTop: '1px solid var(--apple-gray-2)',
            fontSize: 12,
            color: 'var(--apple-text-tertiary)',
          }}
        >
          Showing {filtered.length} of {devices.length} devices
        </div>
      </div>

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
