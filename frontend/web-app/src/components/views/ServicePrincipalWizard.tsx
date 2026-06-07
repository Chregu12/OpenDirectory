'use client';

import React, { useState } from 'react';
import {
  XMarkIcon,
  CheckCircleIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  EyeIcon,
  EyeSlashIcon,
  ArrowDownTrayIcon,
} from '@heroicons/react/24/outline';
import { qaPost } from '@/lib/quickActionsApi';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ServicePrincipalWizardProps {
  onClose: () => void;
}

interface Permission {
  id: string;
  label: string;
  desc: string;
  default: boolean;
}

interface CreatedSP {
  clientId: string;
  clientSecret: string;
  spn: string;
  name: string;
}

// ─── Permission list ──────────────────────────────────────────────────────────

const PERMISSIONS: Permission[] = [
  { id: 'read_users',    label: 'Read Users',     desc: 'List and read user objects',          default: true  },
  { id: 'read_devices',  label: 'Read Devices',   desc: 'List and read managed devices',       default: true  },
  { id: 'write_policies',label: 'Write Policies', desc: 'Create and update policies',          default: false },
  { id: 'admin_access',  label: 'Admin Access',   desc: 'Full administrative control',         default: false },
  { id: 'api_gateway',   label: 'API Gateway',    desc: 'Access all API gateway endpoints',    default: false },
  { id: 'audit_logs',    label: 'Audit Logs',     desc: 'Read security and access audit logs', default: false },
];

// ─── CopyField ────────────────────────────────────────────────────────────────

function CopyField({ label, value, secret }: { label: string; value: string; secret?: boolean }) {
  const [copied, setCopied] = useState(false);
  const [visible, setVisible] = useState(!secret);

  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      toast.success(`${label} copied`);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const display = secret && !visible ? '●'.repeat(Math.min(value.length, 24)) : value;

  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--apple-text-secondary)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
        {label}
      </div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          background: 'var(--apple-gray-1)',
          border: '1px solid var(--apple-gray-2)',
          borderRadius: 8,
          padding: '8px 12px',
        }}
      >
        <code
          style={{
            flex: 1,
            fontSize: 13,
            fontFamily: 'monospace',
            color: 'var(--apple-text-primary)',
            wordBreak: 'break-all',
            letterSpacing: secret && !visible ? '0.1em' : 'normal',
          }}
        >
          {display}
        </code>
        {secret && (
          <button
            onClick={() => setVisible(v => !v)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--apple-gray-5)', padding: 2, flexShrink: 0 }}
          >
            {visible
              ? <EyeSlashIcon style={{ width: 15, height: 15 }} />
              : <EyeIcon style={{ width: 15, height: 15 }} />}
          </button>
        )}
        <button
          onClick={copy}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#22c55e' : 'var(--apple-gray-5)', padding: 2, flexShrink: 0 }}
        >
          {copied
            ? <CheckIcon style={{ width: 15, height: 15 }} />
            : <ClipboardDocumentIcon style={{ width: 15, height: 15 }} />}
        </button>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ServicePrincipalWizard({ onClose }: ServicePrincipalWizardProps) {
  const [name, setName]         = useState('');
  const [desc, setDesc]         = useState('');
  const [permissions, setPerms] = useState<Record<string, boolean>>(
    Object.fromEntries(PERMISSIONS.map(p => [p.id, p.default]))
  );
  const [loading, setLoading]   = useState(false);
  const [created, setCreated]   = useState<CreatedSP | null>(null);

  const togglePerm = (id: string) => setPerms(prev => ({ ...prev, [id]: !prev[id] }));

  const downloadEnv = () => {
    if (!created) return;
    const content = `CLIENT_ID=${created.clientId}\nCLIENT_SECRET=${created.clientSecret}\nAUTHORITY=https://opendirectory.local\nSPN=${created.spn}\n`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name.toLowerCase().replace(/\s+/g, '-')}.env`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCreate = async () => {
    if (!name.trim()) { toast.error('Application name is required'); return; }
    setLoading(true);
    try {
      const data = await qaPost<{
        clientId?: string; client_id?: string;
        clientSecret?: string; client_secret?: string;
        spn?: string;
      }>('/api/quick/service-principals', {
        appName:     name.trim(),
        description: desc.trim(),
        permissions: Object.entries(permissions).filter(([, v]) => v).map(([k]) => k),
      });
      setCreated({
        clientId:     data.clientId     ?? data.client_id     ?? '',
        clientSecret: data.clientSecret ?? data.client_secret ?? '',
        spn:          data.spn          ?? `app/${name.toLowerCase().replace(/\s+/g, '-')}@opendirectory.local`,
        name:         name.trim(),
      });
      toast.success('Service Principal created');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create service principal');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        backdropFilter: 'blur(4px)',
        zIndex: 60,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'white',
          borderRadius: 16,
          boxShadow: '0 24px 64px rgba(0,0,0,0.18)',
          width: '100%',
          maxWidth: 520,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            background: 'linear-gradient(135deg, #AF52DE 0%, #8B44BE 100%)',
            padding: '22px 24px 20px',
            color: 'white',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: 'white' }}>
              {created ? 'Service Principal Created' : 'Create Service Principal'}
            </h2>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.7)', padding: 2 }}
            >
              <XMarkIcon style={{ width: 20, height: 20 }} />
            </button>
          </div>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)' }}>
            {created ? 'Save the credentials before closing.' : 'Generate app identity and credentials for service-to-service auth.'}
          </p>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
          {created ? (
            /* Success view */
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <CheckCircleIcon style={{ width: 28, height: 28, color: '#22c55e', flexShrink: 0 }} />
                <div>
                  <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--apple-text-primary)' }}>{created.name}</div>
                  <div style={{ fontSize: 13, color: 'var(--apple-text-secondary)' }}>Service Principal ready</div>
                </div>
              </div>

              <CopyField label="Client ID" value={created.clientId} />
              <CopyField label="Client Secret" value={created.clientSecret} secret />
              <CopyField label="SPN" value={created.spn} />

              <div
                style={{
                  background: '#FEF3C7',
                  border: '1px solid #FDE68A',
                  borderRadius: 8,
                  padding: '10px 14px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 8,
                  marginTop: 16,
                  marginBottom: 16,
                }}
              >
                <span style={{ fontSize: 16, flexShrink: 0 }}>⚠️</span>
                <div style={{ fontSize: 13, color: '#92400E', lineHeight: 1.4 }}>
                  Save the Client Secret now — it won't be shown again.
                </div>
              </div>

              {/* .env snippet */}
              <div
                style={{
                  background: '#1D1D1F',
                  borderRadius: 10,
                  padding: '14px 16px',
                  marginBottom: 16,
                }}
              >
                <div style={{ fontSize: 11, color: '#AEAEB2', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  .env snippet
                </div>
                <pre style={{ margin: 0, fontSize: 12, color: '#E5E5EA', fontFamily: 'monospace', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
{`CLIENT_ID=${created.clientId}
CLIENT_SECRET=${created.clientSecret}
AUTHORITY=https://opendirectory.local`}
                </pre>
              </div>
            </div>
          ) : (
            /* Form view */
            <div>
              {/* Name */}
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
                  Application Name <span style={{ color: '#DC2626' }}>*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. inventory-service"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    border: '1px solid var(--apple-gray-2)',
                    borderRadius: 8,
                    fontSize: 14,
                    outline: 'none',
                    color: 'var(--apple-text-primary)',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* Description */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)', marginBottom: 6 }}>
                  Description <span style={{ color: 'var(--apple-text-tertiary)', fontWeight: 400 }}>(optional)</span>
                </label>
                <input
                  type="text"
                  placeholder="What does this service do?"
                  value={desc}
                  onChange={e => setDesc(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    border: '1px solid var(--apple-gray-2)',
                    borderRadius: 8,
                    fontSize: 14,
                    outline: 'none',
                    color: 'var(--apple-text-primary)',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* Permissions */}
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--apple-text-primary)', marginBottom: 10 }}>
                  Permissions
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  {PERMISSIONS.map(p => (
                    <label
                      key={p.id}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: 10,
                        padding: '10px 12px',
                        border: permissions[p.id] ? '1.5px solid #0071E3' : '1px solid var(--apple-gray-2)',
                        borderRadius: 8,
                        background: permissions[p.id] ? 'var(--apple-blue-light)' : 'white',
                        cursor: 'pointer',
                        transition: 'all 0.15s',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={permissions[p.id] ?? false}
                        onChange={() => togglePerm(p.id)}
                        style={{ marginTop: 2, accentColor: '#0071E3', flexShrink: 0 }}
                      />
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--apple-text-primary)' }}>{p.label}</div>
                        <div style={{ fontSize: 11, color: 'var(--apple-text-tertiary)', marginTop: 1, lineHeight: 1.3 }}>{p.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '16px 24px',
            borderTop: '1px solid var(--apple-gray-2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexShrink: 0,
            background: 'white',
          }}
        >
          {created ? (
            <>
              <button
                onClick={downloadEnv}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  border: '1px solid var(--apple-gray-2)',
                  borderRadius: 8,
                  background: 'white',
                  fontSize: 13,
                  color: 'var(--apple-text-primary)',
                  cursor: 'pointer',
                }}
              >
                <ArrowDownTrayIcon style={{ width: 15, height: 15 }} />
                Download .env
              </button>
              <button
                onClick={onClose}
                style={{
                  padding: '9px 20px',
                  background: '#AF52DE',
                  color: 'white',
                  border: 'none',
                  borderRadius: 8,
                  fontSize: 14,
                  fontWeight: 500,
                  cursor: 'pointer',
                }}
              >
                Done
              </button>
            </>
          ) : (
            <>
              <button
                onClick={onClose}
                style={{
                  padding: '8px 16px',
                  border: 'none',
                  background: 'none',
                  fontSize: 14,
                  color: 'var(--apple-text-secondary)',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={loading || !name.trim()}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '9px 20px',
                  background: name.trim() ? '#AF52DE' : 'var(--apple-gray-3)',
                  color: 'white',
                  border: 'none',
                  borderRadius: 8,
                  fontSize: 14,
                  fontWeight: 500,
                  cursor: name.trim() ? 'pointer' : 'not-allowed',
                  opacity: loading ? 0.7 : 1,
                }}
              >
                {loading ? 'Creating...' : 'Create →'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
