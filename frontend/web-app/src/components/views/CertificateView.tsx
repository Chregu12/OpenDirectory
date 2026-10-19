'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  PlusIcon,
  ArrowPathIcon,
  XCircleIcon,
  ArrowDownTrayIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

// ─── Types ───────────────────────────────────────────────────────────────────

type CertStatus = 'valid' | 'expired' | 'revoked';

interface Certificate {
  id: string;
  cn: string;
  issuer: string;
  notAfter: string;
  status: CertStatus;
  san?: string[];
  keyUsage?: string[];
  serialNumber?: string;
}

interface IssueFormData {
  cn: string;
  san: string;
  keyUsage: {
    serverAuth: boolean;
    clientAuth: boolean;
    codeSigning: boolean;
  };
  validityDays: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function daysUntil(dateStr: string): number {
  const diff = new Date(dateStr).getTime() - Date.now();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

function fmtDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

// ─── Status Badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status, days }: { status: CertStatus; days: number }) {
  if (status === 'revoked') {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
        background: '#fee2e2', color: '#b91c1c', border: '1px solid #fecaca',
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#b91c1c' }} />
        Revoked
      </span>
    );
  }
  if (status === 'expired') {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
        background: '#f3f4f6', color: '#6b7280', border: '1px solid #e5e7eb',
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#9ca3af' }} />
        Expired
      </span>
    );
  }
  // valid — colour by days remaining
  if (days < 30) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
        background: '#fee2e2', color: '#b91c1c', border: '1px solid #fecaca',
      }}>
        <ExclamationTriangleIcon style={{ width: 12, height: 12 }} />
        {days}d left
      </span>
    );
  }
  if (days < 90) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
        background: '#fef9c3', color: '#854d0e', border: '1px solid #fde68a',
      }}>
        <ClockIcon style={{ width: 12, height: 12 }} />
        {days}d left
      </span>
    );
  }
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 10px', borderRadius: 9999, fontSize: 12, fontWeight: 500,
      background: '#dcfce7', color: '#166534', border: '1px solid #bbf7d0',
    }}>
      <CheckCircleIcon style={{ width: 12, height: 12 }} />
      Valid
    </span>
  );
}

// ─── Issue Certificate Modal ──────────────────────────────────────────────────

function IssueModal({ onClose, onIssued }: { onClose: () => void; onIssued: () => void }) {
  const [form, setForm] = useState<IssueFormData>({
    cn: '',
    san: '',
    keyUsage: { serverAuth: false, clientAuth: false, codeSigning: false },
    validityDays: 365,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.cn.trim()) { setError('Common Name is required.'); return; }
    setSubmitting(true);
    setError('');
    try {
      const san = form.san ? form.san.split(',').map(s => s.trim()).filter(Boolean) : [];
      const keyUsage = Object.entries(form.keyUsage)
        .filter(([, v]) => v)
        .map(([k]) => k);
      await api.post('/api/certificates', {
        cn: form.cn.trim(),
        san,
        keyUsage,
        validityDays: form.validityDays,
      });
      onIssued();
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to issue certificate.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 12px', border: '1px solid #d1d5db',
    borderRadius: 8, fontSize: 14, outline: 'none', boxSizing: 'border-box',
  };
  const labelStyle: React.CSSProperties = {
    display: 'block', fontSize: 13, fontWeight: 500, color: '#374151', marginBottom: 4,
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 50,
      background: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: '#fff', borderRadius: 12, padding: 28, width: 480, maxWidth: '95vw',
        boxShadow: '0 20px 60px rgba(0,0,0,0.18)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, color: '#111827', margin: 0 }}>Issue Certificate</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af' }}>
            <XCircleIcon style={{ width: 22, height: 22 }} />
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={labelStyle}>Common Name (CN) *</label>
            <input
              style={inputStyle}
              placeholder="e.g. server.example.com"
              value={form.cn}
              onChange={e => setForm(f => ({ ...f, cn: e.target.value }))}
            />
          </div>

          <div>
            <label style={labelStyle}>Subject Alternative Names (SAN)</label>
            <input
              style={inputStyle}
              placeholder="Comma-separated, e.g. www.example.com, api.example.com"
              value={form.san}
              onChange={e => setForm(f => ({ ...f, san: e.target.value }))}
            />
          </div>

          <div>
            <label style={labelStyle}>Key Usage</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
              {(['serverAuth', 'clientAuth', 'codeSigning'] as const).map(ku => (
                <label key={ku} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 14, color: '#374151' }}>
                  <input
                    type="checkbox"
                    checked={form.keyUsage[ku]}
                    onChange={e => setForm(f => ({
                      ...f, keyUsage: { ...f.keyUsage, [ku]: e.target.checked },
                    }))}
                    style={{ width: 16, height: 16, accentColor: '#0066CC' }}
                  />
                  {ku === 'serverAuth' ? 'Server Authentication' :
                   ku === 'clientAuth' ? 'Client Authentication' : 'Code Signing'}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label style={labelStyle}>Validity (days)</label>
            <input
              type="number"
              min={1}
              max={3650}
              style={inputStyle}
              value={form.validityDays}
              onChange={e => setForm(f => ({ ...f, validityDays: Number(e.target.value) }))}
            />
          </div>

          {error && (
            <div style={{ background: '#fee2e2', border: '1px solid #fecaca', borderRadius: 8, padding: '10px 12px', color: '#b91c1c', fontSize: 13 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 4 }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 18px', borderRadius: 8, border: '1px solid #d1d5db',
                background: '#fff', color: '#374151', fontSize: 14, fontWeight: 500, cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              style={{
                padding: '8px 18px', borderRadius: 8, border: 'none',
                background: submitting ? '#93c5fd' : '#0066CC', color: '#fff',
                fontSize: 14, fontWeight: 500, cursor: submitting ? 'not-allowed' : 'pointer',
              }}
            >
              {submitting ? 'Issuing…' : 'Issue Certificate'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Revoke Confirm Modal ─────────────────────────────────────────────────────

function RevokeModal({ cert, onClose, onRevoked }: {
  cert: Certificate; onClose: () => void; onRevoked: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const confirm = async () => {
    setSubmitting(true);
    setError('');
    try {
      await api.post(`/api/certificates/${cert.id}/revoke`);
      onRevoked();
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Revoke failed.');
      setSubmitting(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 50,
      background: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: '#fff', borderRadius: 12, padding: 28, width: 420, maxWidth: '95vw',
        boxShadow: '0 20px 60px rgba(0,0,0,0.18)',
      }}>
        <h2 style={{ fontSize: 18, fontWeight: 600, color: '#111827', margin: '0 0 12px' }}>Revoke Certificate</h2>
        <p style={{ fontSize: 14, color: '#6b7280', marginBottom: 20 }}>
          Are you sure you want to revoke <strong>{cert.cn}</strong>? This action cannot be undone.
        </p>
        {error && (
          <div style={{ background: '#fee2e2', border: '1px solid #fecaca', borderRadius: 8, padding: '8px 12px', color: '#b91c1c', fontSize: 13, marginBottom: 16 }}>
            {error}
          </div>
        )}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            style={{ padding: '8px 18px', borderRadius: 8, border: '1px solid #d1d5db', background: '#fff', color: '#374151', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}
          >
            Cancel
          </button>
          <button
            onClick={confirm}
            disabled={submitting}
            style={{ padding: '8px 18px', borderRadius: 8, border: 'none', background: submitting ? '#fca5a5' : '#dc2626', color: '#fff', fontSize: 14, fontWeight: 500, cursor: submitting ? 'not-allowed' : 'pointer' }}
          >
            {submitting ? 'Revoking…' : 'Revoke'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function CertificateView() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showIssue, setShowIssue] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<Certificate | null>(null);
  const [renewingId, setRenewingId] = useState<string | null>(null);

  const fetchCerts = useCallback(async () => {
    try {
      const res = await api.get('/api/certificates');
      const raw = res.data;
      const list: any[] = raw.certificates ?? raw.data ?? (Array.isArray(raw) ? raw : []);
      const normalized: Certificate[] = list.map((c: any) => ({
        id: c.id || c.serialNumber || String(Math.random()),
        cn: c.cn || c.commonName || c.subject?.commonName || 'Unknown',
        issuer: c.issuer || c.issuerDN || 'Unknown CA',
        notAfter: c.notAfter || c.expiresAt || c.expires || new Date().toISOString(),
        status: c.status === 'revoked' ? 'revoked' : c.status === 'expired' ? 'expired' : 'valid',
        san: c.san || c.subjectAltName || [],
        keyUsage: c.keyUsage || [],
        serialNumber: c.serialNumber,
      }));
      setCerts(normalized);
      setError('');
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || 'Failed to load certificates.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchCerts();
    const timer = setInterval(fetchCerts, 60000);
    return () => clearInterval(timer);
  }, [fetchCerts]);

  const handleRenew = async (cert: Certificate) => {
    setRenewingId(cert.id);
    try {
      await api.post(`/api/certificates/${cert.id}/renew`);
      await fetchCerts();
    } catch (err: any) {
      alert(err?.response?.data?.error || err?.message || 'Renewal failed.');
    } finally {
      setRenewingId(null);
    }
  };

  const handleDownload = (cert: Certificate) => {
    window.open(`/api/certificates/${cert.id}/download`, '_blank');
  };

  const validCount   = certs.filter(c => c.status === 'valid').length;
  const expiredCount = certs.filter(c => c.status === 'expired').length;
  const revokedCount = certs.filter(c => c.status === 'revoked').length;
  const warnCount    = certs.filter(c => c.status === 'valid' && daysUntil(c.notAfter) < 30).length;

  return (
    <div style={{ padding: 24, fontFamily: 'inherit' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 36, height: 36, background: '#eff6ff', border: '1px solid #dbeafe',
            borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ShieldCheckIcon style={{ width: 20, height: 20, color: '#0066CC' }} />
          </div>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 600, color: '#111827', margin: 0 }}>Certificate Lifecycle</h1>
            <p style={{ fontSize: 13, color: '#6b7280', margin: 0 }}>
              {certs.length} certificate{certs.length !== 1 ? 's' : ''}
              {warnCount > 0 && (
                <span style={{ marginLeft: 8, color: '#b91c1c', fontWeight: 500 }}>· {warnCount} expiring soon</span>
              )}
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowIssue(true)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '8px 16px', background: '#0066CC', color: '#fff',
            border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 500, cursor: 'pointer',
          }}
        >
          <PlusIcon style={{ width: 16, height: 16 }} />
          Issue Certificate
        </button>
      </div>

      {/* KPI cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Valid', value: validCount, bg: '#f0fdf4', color: '#166534' },
          { label: 'Expiring < 30d', value: warnCount, bg: '#fef2f2', color: '#b91c1c' },
          { label: 'Expired', value: expiredCount, bg: '#f9fafb', color: '#374151' },
          { label: 'Revoked', value: revokedCount, bg: '#fef2f2', color: '#7f1d1d' },
        ].map(k => (
          <div key={k.label} style={{ background: k.bg, borderRadius: 10, padding: '16px 20px' }}>
            <p style={{ fontSize: 12, fontWeight: 500, color: k.color, margin: '0 0 4px' }}>{k.label}</p>
            <p style={{ fontSize: 26, fontWeight: 700, color: k.color, margin: 0 }}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div style={{ background: '#fff', borderRadius: 10, border: '1px solid #e5e7eb', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#9ca3af', fontSize: 14 }}>Loading certificates…</div>
        ) : error ? (
          <div style={{ padding: 40, textAlign: 'center' }}>
            <p style={{ color: '#b91c1c', fontSize: 14, margin: 0 }}>{error}</p>
            <button
              onClick={() => { setLoading(true); fetchCerts(); }}
              style={{ marginTop: 12, padding: '6px 14px', border: '1px solid #d1d5db', borderRadius: 6, background: '#fff', fontSize: 13, cursor: 'pointer' }}
            >
              Retry
            </button>
          </div>
        ) : certs.length === 0 ? (
          <div style={{ padding: 60, textAlign: 'center', color: '#9ca3af', fontSize: 14 }}>
            No certificates found. Issue your first certificate to get started.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }}>
                {['Common Name', 'Issuer', 'Expires', 'Status', 'Actions'].map(h => (
                  <th key={h} style={{
                    padding: '10px 16px', textAlign: 'left',
                    fontSize: 12, fontWeight: 500, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {certs.map((cert, idx) => {
                const days = daysUntil(cert.notAfter);
                return (
                  <tr
                    key={cert.id}
                    style={{
                      borderBottom: idx < certs.length - 1 ? '1px solid #f3f4f6' : 'none',
                      background: '#fff',
                    }}
                  >
                    <td style={{ padding: '12px 16px' }}>
                      <p style={{ fontSize: 14, fontWeight: 500, color: '#111827', margin: 0 }}>{cert.cn}</p>
                      {cert.serialNumber && (
                        <p style={{ fontSize: 11, color: '#9ca3af', fontFamily: 'monospace', margin: '2px 0 0' }}>
                          {cert.serialNumber}
                        </p>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: 13, color: '#6b7280' }}>{cert.issuer}</td>
                    <td style={{ padding: '12px 16px', fontSize: 13, color: '#6b7280', whiteSpace: 'nowrap' }}>
                      {fmtDate(cert.notAfter)}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <StatusBadge status={cert.status} days={days} />
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        {/* Renew */}
                        <button
                          onClick={() => handleRenew(cert)}
                          disabled={renewingId === cert.id || cert.status === 'revoked'}
                          title="Renew"
                          style={{
                            display: 'flex', alignItems: 'center', gap: 4,
                            padding: '4px 10px', borderRadius: 6, border: '1px solid #d1d5db',
                            background: '#fff', fontSize: 12, fontWeight: 500,
                            color: cert.status === 'revoked' ? '#d1d5db' : '#374151',
                            cursor: cert.status === 'revoked' ? 'not-allowed' : 'pointer',
                          }}
                        >
                          <ArrowPathIcon style={{ width: 13, height: 13, animation: renewingId === cert.id ? 'spin 1s linear infinite' : undefined }} />
                          {renewingId === cert.id ? 'Renewing…' : 'Renew'}
                        </button>

                        {/* Download */}
                        <button
                          onClick={() => handleDownload(cert)}
                          title="Download PEM"
                          style={{
                            display: 'flex', alignItems: 'center', gap: 4,
                            padding: '4px 10px', borderRadius: 6, border: '1px solid #d1d5db',
                            background: '#fff', fontSize: 12, fontWeight: 500, color: '#374151', cursor: 'pointer',
                          }}
                        >
                          <ArrowDownTrayIcon style={{ width: 13, height: 13 }} />
                          PEM
                        </button>

                        {/* Revoke */}
                        {cert.status !== 'revoked' && (
                          <button
                            onClick={() => setRevokeTarget(cert)}
                            title="Revoke"
                            style={{
                              display: 'flex', alignItems: 'center', gap: 4,
                              padding: '4px 10px', borderRadius: 6, border: '1px solid #fecaca',
                              background: '#fef2f2', fontSize: 12, fontWeight: 500, color: '#dc2626', cursor: 'pointer',
                            }}
                          >
                            <XCircleIcon style={{ width: 13, height: 13 }} />
                            Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Modals */}
      {showIssue && (
        <IssueModal onClose={() => setShowIssue(false)} onIssued={fetchCerts} />
      )}
      {revokeTarget && (
        <RevokeModal
          cert={revokeTarget}
          onClose={() => setRevokeTarget(null)}
          onRevoked={fetchCerts}
        />
      )}

      {/* CSS keyframe for spinner (injected inline) */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
