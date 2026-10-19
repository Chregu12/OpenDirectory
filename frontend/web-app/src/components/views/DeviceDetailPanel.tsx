'use client';

import React from 'react';
import { FleetDevice } from './DeviceListColumn';
import toast from 'react-hot-toast';

// ─── OS icons ─────────────────────────────────────────────────────────────────

const OS_ICON: Record<string, string> = {
  macos:   '💻',
  windows: '🖥',
  linux:   '🐧',
  ios:     '📱',
  android: '🤖',
};

// ─── Action button (icon above label) ─────────────────────────────────────────

function ActionBtn({ icon, label, onClick, danger }: { icon: string; label: string; onClick?: () => void; danger?: boolean }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
        padding: '8px 14px', minWidth: 100,
        border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8,
        background: 'var(--bg-surface, #161b22)', cursor: 'pointer',
        transition: 'background 0.12s',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-surface, #161b22)'; }}
    >
      <span style={{ fontSize: 18 }}>{icon}</span>
      <span style={{ fontSize: 11, color: danger ? '#DC2626' : 'var(--text-secondary, #8b949e)', textAlign: 'center', lineHeight: 1.2 }}>
        {label}
      </span>
    </button>
  );
}

// ─── Section heading ──────────────────────────────────────────────────────────

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3
      style={{
        fontSize: 11, fontWeight: 600,
        color: 'var(--text-muted, #6e7681)',
        textTransform: 'uppercase', letterSpacing: '0.07em',
        margin: '0 0 10px 0',
      }}
    >
      {children}
    </h3>
  );
}

// ─── Detail grid item ─────────────────────────────────────────────────────────

function DetailItem({ label, value }: { label: string; value?: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)', fontWeight: 500 }}>{label}</span>
      <span style={{ fontSize: 13, color: 'var(--text-primary, #e4e6ea)' }}>{value ?? '—'}</span>
    </div>
  );
}

// ─── Compliance badge ─────────────────────────────────────────────────────────

function ComplianceBadge({ status }: { status: FleetDevice['compliance'] }) {
  const map = {
    compliant:       { bg: 'rgba(34,197,94,0.15)',   color: '#22c55e', label: 'Compliant' },
    warning:         { bg: 'rgba(234,179,8,0.15)',   color: '#eab308', label: 'Warning' },
    'non-compliant': { bg: 'rgba(239,68,68,0.15)',   color: '#ef4444', label: 'Non-Compliant' },
  };
  const s = map[status];
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 999, background: s.bg, color: s.color, fontSize: 12, fontWeight: 500 }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color }} />
      {s.label}
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

interface DeviceDetailPanelProps {
  device: FleetDevice | null;
}

export default function DeviceDetailPanel({ device }: DeviceDetailPanelProps) {
  if (!device) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16, color: 'var(--text-muted, #6e7681)', background: 'var(--bg-base, #0e1115)' }}>
        <span style={{ fontSize: 48 }}>💻</span>
        <p style={{ fontSize: 14, margin: 0 }}>Select a device to view details</p>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', background: 'var(--bg-base, #0e1115)' }}>
      {/* Action buttons row */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 28 }}>
        <ActionBtn icon="✏️" label="Edit MDM Server" onClick={() => toast.success('Edit MDM Server')} />
        <ActionBtn icon="🔒" label="Remote Lock"     onClick={() => toast.success('Remote Lock sent')} />
        <ActionBtn icon="📋" label="Push Policy"     onClick={() => toast.success('Policy pushed')} />
        <ActionBtn icon="↩️" label="Release from Org" onClick={() => { if (confirm('Release this device from the organization?')) toast.success('Device released'); }} danger />
      </div>

      {/* Device icon + name */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 32 }}>
        <div style={{
          width: 128, height: 128, borderRadius: 24,
          background: 'var(--bg-surface, #161b22)',
          border: '1px solid var(--border, rgba(255,255,255,0.07))',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          marginBottom: 14,
        }}>
          <span style={{ fontSize: 72 }}>{OS_ICON[device.os] ?? '💻'}</span>
        </div>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: '0 0 8px 0', textAlign: 'center' }}>
          {device.name}
        </h1>
        <ComplianceBadge status={device.compliance} />
      </div>

      {/* Overview section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Overview</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <DetailItem label="MDM Server"    value={device.mdmServer ?? 'Not enrolled'} />
          <DetailItem label="Device Model"  value={device.model ?? device.name} />
          <DetailItem label="Serial Number" value={device.serial} />
        </div>
      </section>

      {/* Divider */}
      <div style={{ height: 1, background: 'var(--border, rgba(255,255,255,0.07))', marginBottom: 24 }} />

      {/* Details section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Details</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <DetailItem label="Platform"      value={device.os.charAt(0).toUpperCase() + device.os.slice(1)} />
          <DetailItem label="Assigned User" value={device.assignedUser} />
          <DetailItem label="Last Seen"     value={device.lastSeen} />
          <DetailItem label="Order Number"  value={device.orderNumber} />
          <DetailItem label="Part Number"   value={device.partNumber} />
          <DetailItem label="Storage"       value={device.storage} />
        </div>
      </section>

      {/* Divider */}
      <div style={{ height: 1, background: 'var(--border, rgba(255,255,255,0.07))', marginBottom: 24 }} />

      {/* Activity section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Activity</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <DetailItem
            label="Date Added"
            value={device.enrolledAt ? new Date(device.enrolledAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : undefined}
          />
          <DetailItem label="OS Version" value={device.osVersion} />
        </div>
      </section>
    </div>
  );
}
