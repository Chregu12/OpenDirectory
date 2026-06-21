'use client';

import React from 'react';
import { ServicePrincipal } from './ServicePrincipalListColumn';
import toast from 'react-hot-toast';

// ─── Action button ────────────────────────────────────────────────────────────

function ActionBtn({ icon, label, onClick, danger }: { icon: string; label: string; onClick?: () => void; danger?: boolean }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
        padding: '8px 14px', minWidth: 100,
        border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8,
        background: 'var(--bg-surface, #161b22)', cursor: 'pointer', transition: 'background 0.12s',
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

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3 style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', letterSpacing: '0.07em', margin: '0 0 10px 0' }}>
      {children}
    </h3>
  );
}

function DetailItem({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)', fontWeight: 500 }}>{label}</span>
      <span style={{ fontSize: 13, color: 'var(--text-primary, #e4e6ea)', fontFamily: mono ? 'monospace' : undefined, wordBreak: 'break-all' }}>
        {value ?? '—'}
      </span>
    </div>
  );
}

interface ServicePrincipalDetailPanelProps {
  sp: ServicePrincipal | null;
}

export default function ServicePrincipalDetailPanel({ sp }: ServicePrincipalDetailPanelProps) {
  if (!sp) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16, color: 'var(--text-muted, #6e7681)', background: 'var(--bg-base, #0e1115)' }}>
        <span style={{ fontSize: 48 }}>🔑</span>
        <p style={{ fontSize: 14, margin: 0 }}>Select a service principal to view details</p>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', background: 'var(--bg-base, #0e1115)' }}>
      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 28 }}>
        <ActionBtn icon="🔄" label="Rotate Secret"    onClick={() => toast.success(`Secret rotation initiated for ${sp.name}`)} />
        <ActionBtn icon="✏️" label="Edit Principal"   onClick={() => toast.success('Edit principal')} />
        <ActionBtn icon="⏸"  label="Disable"          onClick={() => toast.success(`${sp.name} disabled`)} />
        <ActionBtn icon="🗑"  label="Delete"           onClick={() => { if (confirm(`Delete "${sp.name}"?`)) toast.success('Deleted'); }} danger />
      </div>

      {/* Icon + name */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 32 }}>
        <div style={{
          width: 96, height: 96, borderRadius: 20,
          background: 'rgba(175,82,222,0.15)',
          border: '1px solid rgba(175,82,222,0.3)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          marginBottom: 14,
        }}>
          <span style={{ fontSize: 52 }}>🔑</span>
        </div>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', margin: '0 0 8px 0', textAlign: 'center' }}>
          {sp.name}
        </h1>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          padding: '3px 10px', borderRadius: 999,
          background: sp.status === 'active' ? 'rgba(34,197,94,0.15)' : 'rgba(255,255,255,0.06)',
          color: sp.status === 'active' ? '#22c55e' : 'var(--text-secondary, #8b949e)',
          fontSize: 12, fontWeight: 500,
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: sp.status === 'active' ? '#22c55e' : '#6e7681' }} />
          {sp.status === 'active' ? 'Active' : 'Disabled'}
        </span>
      </div>

      {/* Identity section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Identity</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 20 }}>
          <DetailItem label="Client ID"  value={sp.clientId}  mono />
          <DetailItem label="SPN"        value={sp.spn}        mono />
        </div>
      </section>

      <div style={{ height: 1, background: 'var(--border, rgba(255,255,255,0.07))', marginBottom: 24 }} />

      {/* Permissions section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Permissions</SectionHeading>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {sp.permissions.length === 0
            ? <span style={{ fontSize: 13, color: 'var(--text-muted, #6e7681)' }}>No permissions assigned</span>
            : sp.permissions.map(p => (
              <span key={p} style={{
                padding: '4px 10px', borderRadius: 6,
                background: 'rgba(255,255,255,0.06)',
                color: 'var(--text-secondary, #8b949e)',
                fontSize: 12, fontWeight: 500,
              }}>
                {p.replace(/_/g, ' ')}
              </span>
            ))
          }
        </div>
      </section>

      <div style={{ height: 1, background: 'var(--border, rgba(255,255,255,0.07))', marginBottom: 24 }} />

      {/* Activity section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Activity</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <DetailItem
            label="Date Created"
            value={sp.createdAt ? new Date(sp.createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : undefined}
          />
          <DetailItem label="Secret Rotation" value="Never" />
        </div>
      </section>
    </div>
  );
}
