'use client';

import React from 'react';
import {
  PlusIcon,
  UserPlusIcon,
  KeyIcon,
  DocumentCheckIcon,
  ClipboardDocumentListIcon,
} from '@heroicons/react/24/outline';

interface QuickActionsBarProps {
  onEnrollDevice: () => void;
  onNewUser: () => void;
  onServicePrincipal: () => void;
  onDeployPolicy: () => void;
  onComplianceSnapshot: () => void;
}

interface ActionButtonProps {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
  accent?: boolean;
}

function ActionButton({ icon, label, onClick, accent }: ActionButtonProps) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 7,
        padding: '7px 14px',
        borderRadius: 8,
        border: accent ? 'none' : '1px solid var(--apple-gray-2)',
        background: accent ? 'var(--apple-blue)' : '#FFFFFF',
        color: accent ? '#FFFFFF' : 'var(--apple-text-primary)',
        fontSize: 13,
        fontWeight: 500,
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        transition: 'background 0.15s, box-shadow 0.15s',
        boxShadow: accent ? '0 1px 4px rgba(0,113,227,0.25)' : '0 1px 2px rgba(0,0,0,0.06)',
      }}
      onMouseEnter={e => {
        const btn = e.currentTarget as HTMLButtonElement;
        btn.style.background = accent ? 'var(--apple-blue-hover)' : 'var(--apple-gray-1)';
      }}
      onMouseLeave={e => {
        const btn = e.currentTarget as HTMLButtonElement;
        btn.style.background = accent ? 'var(--apple-blue)' : '#FFFFFF';
      }}
    >
      <span style={{ width: 16, height: 16, display: 'flex', alignItems: 'center', flexShrink: 0 }}>
        {icon}
      </span>
      {label}
    </button>
  );
}

export default function QuickActionsBar({
  onEnrollDevice,
  onNewUser,
  onServicePrincipal,
  onDeployPolicy,
  onComplianceSnapshot,
}: QuickActionsBarProps) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '10px 0 14px 0',
        flexWrap: 'wrap',
      }}
    >
      <ActionButton
        accent
        icon={<PlusIcon style={{ width: 15, height: 15 }} />}
        label="Enroll Device"
        onClick={onEnrollDevice}
      />
      <ActionButton
        icon={<UserPlusIcon style={{ width: 15, height: 15 }} />}
        label="New User"
        onClick={onNewUser}
      />
      <ActionButton
        icon={<KeyIcon style={{ width: 15, height: 15 }} />}
        label="Service Principal"
        onClick={onServicePrincipal}
      />
      <ActionButton
        icon={<DocumentCheckIcon style={{ width: 15, height: 15 }} />}
        label="Deploy Policy"
        onClick={onDeployPolicy}
      />
      <ActionButton
        icon={<ClipboardDocumentListIcon style={{ width: 15, height: 15 }} />}
        label="Compliance Snapshot"
        onClick={onComplianceSnapshot}
      />
    </div>
  );
}
