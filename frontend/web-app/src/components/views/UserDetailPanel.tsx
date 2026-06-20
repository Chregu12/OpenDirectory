'use client';

import React from 'react';
import { DirectoryUser } from './UserListColumn';
import toast from 'react-hot-toast';

// ─── Avatar ───────────────────────────────────────────────────────────────────

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

// ─── Action button ────────────────────────────────────────────────────────────

function ActionBtn({ icon, label, onClick, danger }: { icon: string; label: string; onClick?: () => void; danger?: boolean }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
        padding: '8px 14px', minWidth: 100,
        border: '1px solid var(--apple-gray-2)', borderRadius: 8,
        background: '#FFFFFF', cursor: 'pointer', transition: 'background 0.12s',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--apple-gray-1)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = '#FFFFFF'; }}
    >
      <span style={{ fontSize: 18 }}>{icon}</span>
      <span style={{ fontSize: 11, color: danger ? '#DC2626' : 'var(--apple-text-secondary)', textAlign: 'center', lineHeight: 1.2 }}>
        {label}
      </span>
    </button>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3 style={{ fontSize: 11, fontWeight: 600, color: '#86868b', textTransform: 'uppercase', letterSpacing: '0.07em', margin: '0 0 10px 0' }}>
      {children}
    </h3>
  );
}

function DetailItem({ label, value }: { label: string; value?: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{ fontSize: 11, color: '#86868b', fontWeight: 500 }}>{label}</span>
      <span style={{ fontSize: 13, color: 'var(--apple-text-primary)' }}>{value ?? '—'}</span>
    </div>
  );
}

const ROLE_LABELS: Record<DirectoryUser['role'], string> = {
  admin:           'Administrator',
  user:            'Standard User',
  'read-only':     'Read-Only',
  'service-account': 'Service Account',
};

interface UserDetailPanelProps {
  user: DirectoryUser | null;
}

export default function UserDetailPanel({ user }: UserDetailPanelProps) {
  if (!user) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16, color: 'var(--apple-text-tertiary)' }}>
        <span style={{ fontSize: 48 }}>👤</span>
        <p style={{ fontSize: 14, margin: 0 }}>Select a user to view details</p>
      </div>
    );
  }

  const color = avatarColor(user.id);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px' }}>
      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 28 }}>
        <ActionBtn icon="✏️" label="Edit User"       onClick={() => toast.success('Edit user')} />
        <ActionBtn icon="🔒" label="Reset Password"  onClick={() => toast.success('Password reset link sent')} />
        <ActionBtn icon="📱" label="Manage MFA"      onClick={() => toast.success('MFA management')} />
        <ActionBtn icon="🚫" label="Disable Account" onClick={() => { if (confirm(`Disable ${user.name}?`)) toast.success('Account disabled'); }} danger />
      </div>

      {/* Avatar + name */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 32 }}>
        <div style={{
          width: 96, height: 96, borderRadius: '50%',
          background: color,
          color: 'white', fontSize: 36, fontWeight: 700,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          marginBottom: 14,
        }}>
          {getInitials(user.name)}
        </div>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--apple-text-primary)', margin: '0 0 4px 0', textAlign: 'center' }}>
          {user.name}
        </h1>
        <p style={{ fontSize: 14, color: 'var(--apple-text-secondary)', margin: '0 0 8px 0' }}>{user.email}</p>
        <div style={{ display: 'flex', gap: 6 }}>
          <span style={{
            padding: '3px 10px', borderRadius: 999,
            background: user.status === 'active' ? '#D1FAE5' : '#F3F4F6',
            color: user.status === 'active' ? '#065F46' : '#6B7280',
            fontSize: 12, fontWeight: 500,
            display: 'inline-flex', alignItems: 'center', gap: 5,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: user.status === 'active' ? '#22c55e' : '#9CA3AF' }} />
            {user.status === 'active' ? 'Active' : 'Inactive'}
          </span>
          <span style={{
            padding: '3px 10px', borderRadius: 999,
            background: 'var(--apple-gray-1)',
            color: 'var(--apple-text-secondary)',
            fontSize: 12, fontWeight: 500,
          }}>
            {ROLE_LABELS[user.role]}
          </span>
        </div>
      </div>

      {/* Overview section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Overview</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <DetailItem label="Department"   value={user.department} />
          <DetailItem label="Role"         value={ROLE_LABELS[user.role]} />
          <DetailItem label="MFA Enabled"  value={user.mfa ? 'Yes' : 'No'} />
        </div>
      </section>

      <div style={{ height: 1, background: 'var(--apple-gray-2)', marginBottom: 24 }} />

      {/* Groups section */}
      {user.groups && user.groups.length > 0 && (
        <>
          <section style={{ marginBottom: 28 }}>
            <SectionHeading>Groups</SectionHeading>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {user.groups.map(g => (
                <span key={g} style={{ padding: '4px 10px', borderRadius: 6, background: 'var(--apple-gray-1)', color: 'var(--apple-text-secondary)', fontSize: 12, fontWeight: 500 }}>
                  {g}
                </span>
              ))}
            </div>
          </section>
          <div style={{ height: 1, background: 'var(--apple-gray-2)', marginBottom: 24 }} />
        </>
      )}

      {/* Devices section */}
      {user.devices && user.devices.length > 0 && (
        <>
          <section style={{ marginBottom: 28 }}>
            <SectionHeading>Assigned Devices</SectionHeading>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {user.devices.map(d => (
                <div key={d} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderRadius: 8, background: 'var(--apple-gray-1)' }}>
                  <span>💻</span>
                  <span style={{ fontSize: 13, color: 'var(--apple-text-primary)' }}>{d}</span>
                </div>
              ))}
            </div>
          </section>
          <div style={{ height: 1, background: 'var(--apple-gray-2)', marginBottom: 24 }} />
        </>
      )}

      {/* Activity section */}
      <section style={{ marginBottom: 28 }}>
        <SectionHeading>Activity</SectionHeading>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <DetailItem label="Last Sign-in" value={user.lastActive} />
        </div>
      </section>
    </div>
  );
}
