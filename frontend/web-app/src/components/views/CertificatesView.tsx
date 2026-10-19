'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  PlusIcon,
  ArrowDownTrayIcon,
  InformationCircleIcon,
  XMarkIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ClipboardDocumentIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  KeyIcon,
  BuildingLibraryIcon,
  BellAlertIcon,
  NoSymbolIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ── Types ──────────────────────────────────────────────────────────────────────

type CertType = 'Gerät' | 'Benutzer' | 'Server' | 'CA';
type CertStatus = 'Aktiv' | 'Abgelaufen' | 'Widerrufen';
type TabId = 'zertifikate' | 'cas' | 'scep' | 'crl' | 'ablauf';
type KeyLength = '2048' | '4096' | 'P-256 EC';
type Validity = '90d' | '1y' | '2y' | '5y';
type CertIssueType = 'Benutzer' | 'Gerät' | 'Server' | 'Code-Signierung';
type CAType = 'self-signed' | 'intermediate';
type RevocationReason = 'keyCompromise' | 'affiliationChanged' | 'superseded' | 'cessationOfOperation' | 'unspecified';

interface Certificate {
  id: string;
  cn: string;
  type: CertType;
  issuer: string;
  validUntil: string;
  status: CertStatus;
  serial: string;
  keyType: string;
  sans?: string[];
}

interface CertificateAuthority {
  id: string;
  name: string;
  validUntil: string;
  keyType: string;
  status: 'Aktiv' | 'Abgelaufen';
  isRoot: boolean;
  subject: string;
}

interface RevokedCert {
  cn: string;
  serial: string;
  reason: string;
  date: string;
}

interface ScepConfig {
  enabled: boolean;
  challengePassword: string;
  url: string;
  allowedDevices: string[];
  autoEnrollment: boolean;
}

interface CrlInfo {
  url: string;
  lastUpdated: string;
  revokedCerts: RevokedCert[];
}

// ── Demo Data ──────────────────────────────────────────────────────────────────

const DEMO_CERTS: Certificate[] = [
  { id: '1', cn: 'alice.mueller@firma.local', type: 'Benutzer', issuer: 'Firma Intermediate CA', validUntil: new Date(Date.now() + 86400000 * 180).toISOString(), status: 'Aktiv', serial: '0A:1B:2C:3D', keyType: 'RSA 2048' },
  { id: '2', cn: 'macbook-pro-alice', type: 'Gerät', issuer: 'Firma Intermediate CA', validUntil: new Date(Date.now() + 86400000 * 20).toISOString(), status: 'Aktiv', serial: '0A:1B:2C:3E', keyType: 'P-256 EC' },
  { id: '3', cn: 'vpn.firma.local', type: 'Server', issuer: 'Firma Intermediate CA', validUntil: new Date(Date.now() - 86400000 * 10).toISOString(), status: 'Abgelaufen', serial: '0A:1B:2C:3F', keyType: 'RSA 4096' },
  { id: '4', cn: 'bob.schneider@firma.local', type: 'Benutzer', issuer: 'Firma Intermediate CA', validUntil: new Date(Date.now() + 86400000 * 300).toISOString(), status: 'Aktiv', serial: '0A:1B:2C:40', keyType: 'RSA 2048' },
  { id: '5', cn: 'old-laptop-david', type: 'Gerät', issuer: 'Firma Root CA', validUntil: new Date(Date.now() - 86400000 * 60).toISOString(), status: 'Widerrufen', serial: '0A:1B:2C:41', keyType: 'RSA 2048' },
  { id: '6', cn: 'mail.firma.local', type: 'Server', issuer: 'Firma Intermediate CA', validUntil: new Date(Date.now() + 86400000 * 25).toISOString(), status: 'Aktiv', serial: '0A:1B:2C:42', keyType: 'RSA 4096' },
];

const DEMO_CAS: CertificateAuthority[] = [
  { id: 'ca1', name: 'Firma Root CA', validUntil: new Date(Date.now() + 86400000 * 3650).toISOString(), keyType: 'RSA 4096', status: 'Aktiv', isRoot: true, subject: 'CN=Firma Root CA, O=Firma GmbH, C=CH' },
  { id: 'ca2', name: 'Firma Intermediate CA', validUntil: new Date(Date.now() + 86400000 * 1825).toISOString(), keyType: 'RSA 4096', status: 'Aktiv', isRoot: false, subject: 'CN=Firma Intermediate CA, O=Firma GmbH, C=CH' },
];

const DEMO_SCEP: ScepConfig = {
  enabled: true,
  challengePassword: 'SCEP-7xK9mN2pQ4wR',
  url: 'https://od.firma.local/scep',
  allowedDevices: ['iOS', 'macOS'],
  autoEnrollment: true,
};

const DEMO_CRL: CrlInfo = {
  url: 'https://od.firma.local/crl/firma.crl',
  lastUpdated: new Date(Date.now() - 3600000 * 2).toISOString(),
  revokedCerts: [
    { cn: 'old-laptop-david', serial: '0A:1B:2C:41', reason: 'keyCompromise', date: new Date(Date.now() - 86400000 * 60).toISOString() },
    { cn: 'test-device-2023', serial: '0A:1B:2C:38', reason: 'affiliationChanged', date: new Date(Date.now() - 86400000 * 120).toISOString() },
  ],
};

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString('de-CH', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function fmtDateTime(iso: string): string {
  return new Date(iso).toLocaleString('de-CH', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function daysUntil(iso: string): number {
  return Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success('In Zwischenablage kopiert'),
    () => toast.error('Kopieren fehlgeschlagen'),
  );
}

// ── Status Badge ───────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: CertStatus }) {
  const map: Record<CertStatus, string> = {
    Aktiv: 'bg-green-900/40 text-green-400 border border-green-700/50',
    Abgelaufen: 'bg-red-900/40 text-red-400 border border-red-700/50',
    Widerrufen: 'bg-white/5 text-[#8b949e] border border-white/10',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${map[status]}`}>
      {status}
    </span>
  );
}

// ── Type Badge ─────────────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: CertType }) {
  const map: Record<CertType, string> = {
    Benutzer: 'bg-blue-900/40 text-blue-400',
    Gerät: 'bg-purple-900/40 text-purple-400',
    Server: 'bg-orange-900/40 text-orange-400',
    CA: 'bg-indigo-900/40 text-indigo-400',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${map[type]}`}>
      {type}
    </span>
  );
}

// ── Stats Card ─────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color?: string;
}

function StatCard({ label, value, icon, color = '#006FFF' }: StatCardProps) {
  return (
    <div className="od-card rounded-xl px-5 py-4 flex items-center gap-4">
      <div className="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'var(--bg-surface-raised, #1c2128)', color }}>
        {icon}
      </div>
      <div>
        <p className="text-xs font-medium" style={{ color: 'var(--text-secondary, #8b949e)' }}>{label}</p>
        <p className="text-2xl font-bold leading-tight" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{value}</p>
      </div>
    </div>
  );
}

// ── Issue Certificate Modal ────────────────────────────────────────────────────

interface IssueCertModalProps {
  onClose: () => void;
  onIssued: () => void;
}

function IssueCertModal({ onClose, onIssued }: IssueCertModalProps) {
  const [type, setType] = useState<CertIssueType>('Benutzer');
  const [cn, setCn] = useState('');
  const [ou, setOu] = useState('');
  const [o, setO] = useState('Firma GmbH');
  const [c, setC] = useState('CH');
  const [keyLength, setKeyLength] = useState<KeyLength>('2048');
  const [validity, setValidity] = useState<Validity>('1y');
  const [sans, setSans] = useState('');
  const [usages, setUsages] = useState<string[]>(['TLS-Client']);
  const [saving, setSaving] = useState(false);

  const USAGE_OPTIONS = ['TLS-Client', 'TLS-Server', 'Code-Signing', 'Email'];
  const VALIDITY_LABELS: Record<Validity, string> = { '90d': '90 Tage', '1y': '1 Jahr', '2y': '2 Jahre', '5y': '5 Jahre' };

  const toggleUsage = (u: string) => {
    setUsages(prev => prev.includes(u) ? prev.filter(x => x !== u) : [...prev, u]);
  };

  const handleSubmit = async () => {
    if (!cn.trim()) { toast.error('CN ist erforderlich'); return; }
    setSaving(true);
    try {
      await api.post('/api/pki/certificates', { type, subject: { cn, ou, o, c }, keyLength, validity, sans, usages });
      toast.success('Zertifikat erfolgreich ausgestellt');
      onIssued();
      onClose();
    } catch {
      toast.error('Fehler beim Ausstellen des Zertifikats');
    } finally {
      setSaving(false);
    }
  };

  const inputCls = 'flex-1 rounded-lg px-3 py-2 text-sm focus:outline-none';
  const inputStyle = { border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' };

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
        <div className="flex items-center justify-between px-6 py-5" style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Zertifikat ausstellen</h2>
          <button onClick={onClose} style={{ color: 'var(--text-secondary, #8b949e)' }} className="hover:opacity-80 transition-opacity">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Type */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>Typ</label>
            <div className="grid grid-cols-4 gap-2">
              {(['Benutzer', 'Gerät', 'Server', 'Code-Signierung'] as CertIssueType[]).map(t => (
                <button
                  key={t}
                  onClick={() => setType(t)}
                  className="px-3 py-2 rounded-lg text-xs font-medium border transition-all"
                  style={{
                    background: type === t ? '#006FFF' : 'var(--bg-surface-raised, #1c2128)',
                    color: type === t ? 'white' : 'var(--text-primary, #e4e6ea)',
                    borderColor: type === t ? '#006FFF' : 'var(--border, rgba(255,255,255,0.07))',
                  }}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Subject */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>Subject</label>
            <div className="space-y-2">
              {[
                { label: 'CN (Common Name)*', value: cn, setter: setCn, placeholder: 'z.B. alice@firma.local' },
                { label: 'OU (Organizational Unit)', value: ou, setter: setOu, placeholder: 'z.B. IT' },
                { label: 'O (Organization)', value: o, setter: setO, placeholder: 'z.B. Firma GmbH' },
                { label: 'C (Country)', value: c, setter: setC, placeholder: 'z.B. CH' },
              ].map(({ label, value, setter, placeholder }) => (
                <div key={label} className="flex items-center gap-3">
                  <label className="w-40 text-xs shrink-0" style={{ color: 'var(--text-secondary, #8b949e)' }}>{label}</label>
                  <input
                    type="text"
                    value={value}
                    onChange={e => setter(e.target.value)}
                    placeholder={placeholder}
                    className={inputCls}
                    style={{ ...inputStyle, width: '100%', boxSizing: 'border-box' }}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Key & Validity */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>Schlüssellänge</label>
              <select
                value={keyLength}
                onChange={e => setKeyLength(e.target.value as KeyLength)}
                className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none cursor-pointer"
                style={inputStyle}
              >
                <option value="2048">RSA 2048</option>
                <option value="4096">RSA 4096</option>
                <option value="P-256 EC">P-256 EC</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>Gültigkeit</label>
              <select
                value={validity}
                onChange={e => setValidity(e.target.value as Validity)}
                className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none cursor-pointer"
                style={inputStyle}
              >
                {Object.entries(VALIDITY_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
          </div>

          {/* SANs */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>Subject Alternative Names (SAN)</label>
            <textarea
              value={sans}
              onChange={e => setSans(e.target.value)}
              rows={3}
              placeholder={'DNS:vpn.firma.local\nIP:192.168.1.10\nemail:alice@firma.local'}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none resize-none font-mono"
              style={inputStyle}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted, #6e7681)' }}>Ein Eintrag pro Zeile (DNS:, IP:, email:)</p>
          </div>

          {/* Usage */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>Verwendungszweck</label>
            <div className="flex flex-wrap gap-3">
              {USAGE_OPTIONS.map(u => (
                <label key={u} className="flex items-center gap-2 text-sm cursor-pointer select-none" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
                  <input
                    type="checkbox"
                    checked={usages.includes(u)}
                    onChange={() => toggleUsage(u)}
                    className="w-4 h-4 rounded"
                  />
                  {u}
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="px-6 py-4 flex justify-end gap-3" style={{ borderTop: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium rounded-lg transition-colors" style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
            Abbrechen
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50"
            style={{ background: '#006FFF' }}
          >
            {saving ? 'Ausstellen…' : 'Zertifikat ausstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── New CA Modal ───────────────────────────────────────────────────────────────

interface NewCAModalProps {
  onClose: () => void;
  onCreated: () => void;
  existingCAs: CertificateAuthority[];
}

function NewCAModal({ onClose, onCreated, existingCAs }: NewCAModalProps) {
  const [caType, setCaType] = useState<CAType>('self-signed');
  const [name, setCaName] = useState('');
  const [keyType, setKeyType] = useState<KeyLength>('4096');
  const [validity, setValidity] = useState<Validity>('5y');
  const [parentCA, setParentCA] = useState('');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    if (caType === 'intermediate' && !parentCA) { toast.error('Bitte übergeordnete CA auswählen'); return; }
    setSaving(true);
    try {
      await api.post('/api/pki/cas', { name, caType, keyType, validity, parentCA: caType === 'intermediate' ? parentCA : undefined });
      toast.success('Zertifizierungsstelle erstellt');
      onCreated();
      onClose();
    } catch {
      toast.error('Fehler beim Erstellen der CA');
    } finally {
      setSaving(false);
    }
  };

  const inputStyle = { border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' };

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="rounded-2xl shadow-2xl w-full max-w-md" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
        <div className="flex items-center justify-between px-6 py-5" style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Neue CA erstellen</h2>
          <button onClick={onClose} style={{ color: 'var(--text-secondary, #8b949e)' }} className="hover:opacity-80 transition-opacity">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary, #8b949e)' }}>CA-Typ</label>
            <div className="grid grid-cols-2 gap-2">
              {([
                { value: 'self-signed', label: 'Self-Signed Root' },
                { value: 'intermediate', label: 'Intermediate CA' },
              ] as { value: CAType; label: string }[]).map(t => (
                <button
                  key={t.value}
                  onClick={() => setCaType(t.value)}
                  className="px-3 py-2 rounded-lg text-sm font-medium border transition-all"
                  style={{
                    background: caType === t.value ? '#006FFF' : 'var(--bg-surface-raised, #1c2128)',
                    color: caType === t.value ? 'white' : 'var(--text-primary, #e4e6ea)',
                    borderColor: caType === t.value ? '#006FFF' : 'var(--border, rgba(255,255,255,0.07))',
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setCaName(e.target.value)}
              placeholder="z.B. Firma Root CA"
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none"
              style={inputStyle}
            />
          </div>

          {caType === 'intermediate' && (
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Übergeordnete CA</label>
              <select
                value={parentCA}
                onChange={e => setParentCA(e.target.value)}
                className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none cursor-pointer"
                style={inputStyle}
              >
                <option value="">CA auswählen…</option>
                {existingCAs.filter(ca => ca.isRoot).map(ca => (
                  <option key={ca.id} value={ca.id}>{ca.name}</option>
                ))}
              </select>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Schlüssellänge</label>
              <select
                value={keyType}
                onChange={e => setKeyType(e.target.value as KeyLength)}
                className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none cursor-pointer"
                style={inputStyle}
              >
                <option value="2048">RSA 2048</option>
                <option value="4096">RSA 4096</option>
                <option value="P-256 EC">P-256 EC</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Gültigkeit</label>
              <select
                value={validity}
                onChange={e => setValidity(e.target.value as Validity)}
                className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none cursor-pointer"
                style={inputStyle}
              >
                <option value="1y">1 Jahr</option>
                <option value="2y">2 Jahre</option>
                <option value="5y">5 Jahre</option>
              </select>
            </div>
          </div>
        </div>

        <div className="px-6 py-4 flex justify-end gap-3" style={{ borderTop: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium rounded-lg transition-colors" style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
            Abbrechen
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50"
            style={{ background: '#006FFF' }}
          >
            {saving ? 'Erstellen…' : 'CA erstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Certificate Details Modal ──────────────────────────────────────────────────

function CertDetailsModal({ cert, onClose }: { cert: Certificate; onClose: () => void }) {
  const days = daysUntil(cert.validUntil);
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="rounded-2xl shadow-2xl w-full max-w-md" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
        <div className="flex items-center justify-between px-6 py-5" style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Zertifikat-Details</h2>
          <button onClick={onClose} style={{ color: 'var(--text-secondary, #8b949e)' }} className="hover:opacity-80 transition-opacity">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          {[
            { label: 'CN (Common Name)', value: cert.cn },
            { label: 'Typ', value: cert.type },
            { label: 'Seriennummer', value: cert.serial },
            { label: 'Aussteller', value: cert.issuer },
            { label: 'Schlüsseltyp', value: cert.keyType },
            { label: 'Gültig bis', value: `${fmtDate(cert.validUntil)} (${days > 0 ? `${days} Tage` : 'abgelaufen'})` },
            { label: 'Status', value: cert.status },
          ].map(({ label, value }) => (
            <div key={label} className="flex justify-between items-start gap-4">
              <span className="text-sm shrink-0" style={{ color: 'var(--text-secondary, #8b949e)' }}>{label}</span>
              <span className="text-sm font-medium text-right" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{value}</span>
            </div>
          ))}
          {cert.sans && cert.sans.length > 0 && (
            <div>
              <span className="text-sm" style={{ color: 'var(--text-secondary, #8b949e)' }}>SANs</span>
              <div className="mt-1 space-y-0.5">
                {cert.sans.map(s => (
                  <div key={s} className="text-sm font-mono rounded px-2 py-0.5" style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }}>{s}</div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="px-6 py-4 flex justify-end" style={{ borderTop: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium rounded-lg transition-colors" style={{ background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
            Schließen
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Zertifikate ───────────────────────────────────────────────────────────

function ZertifikateTab({
  certs,
  onIssue,
  onRevoke,
  onDownload,
}: {
  certs: Certificate[];
  onIssue: () => void;
  onRevoke: (id: string) => void;
  onDownload: (id: string) => void;
}) {
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null);

  return (
    <div>
      {selectedCert && <CertDetailsModal cert={selectedCert} onClose={() => setSelectedCert(null)} />}

      <div className="flex items-center justify-between mb-4">
        <p className="text-sm" style={{ color: 'var(--text-secondary, #8b949e)' }}>{certs.length} Zertifikate gefunden</p>
        <button
          onClick={onIssue}
          className="inline-flex items-center gap-2 px-4 py-2 text-white text-sm font-medium rounded-lg transition-colors"
          style={{ background: '#006FFF' }}
        >
          <PlusIcon className="w-4 h-4" />
          Zertifikat ausstellen
        </button>
      </div>

      <div className="od-card rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)', background: 'var(--bg-surface-raised, #1c2128)' }}>Subject CN</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)', background: 'var(--bg-surface-raised, #1c2128)' }}>Typ</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)', background: 'var(--bg-surface-raised, #1c2128)' }}>Aussteller</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)', background: 'var(--bg-surface-raised, #1c2128)' }}>Gültig bis</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)', background: 'var(--bg-surface-raised, #1c2128)' }}>Status</th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)', background: 'var(--bg-surface-raised, #1c2128)' }}>Aktionen</th>
            </tr>
          </thead>
          <tbody>
            {certs.map(cert => {
              const days = daysUntil(cert.validUntil);
              const soonExpiring = days > 0 && days <= 30;
              return (
                <tr key={cert.id} className="transition-colors" style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{cert.cn}</span>
                      {soonExpiring && (
                        <ExclamationTriangleIcon className="w-3.5 h-3.5 text-amber-400 shrink-0" title="Läuft bald ab" />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3"><TypeBadge type={cert.type} /></td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>{cert.issuer}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs ${soonExpiring ? 'text-amber-400 font-medium' : ''}`} style={!soonExpiring ? { color: 'var(--text-secondary, #8b949e)' } : {}}>
                      {fmtDate(cert.validUntil)}
                    </span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={cert.status} /></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onDownload(cert.id)}
                        title="Download (.pem)"
                        className="p-1.5 rounded-lg transition-colors"
                        style={{ color: 'var(--text-muted, #6e7681)' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#006FFF')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted, #6e7681)')}
                      >
                        <ArrowDownTrayIcon className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setSelectedCert(cert)}
                        title="Details"
                        className="p-1.5 rounded-lg transition-colors"
                        style={{ color: 'var(--text-muted, #6e7681)' }}
                        onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-primary, #e4e6ea)')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted, #6e7681)')}
                      >
                        <InformationCircleIcon className="w-4 h-4" />
                      </button>
                      {cert.status === 'Aktiv' && (
                        <button
                          onClick={() => onRevoke(cert.id)}
                          title="Widerrufen"
                          className="p-1.5 rounded-lg transition-colors"
                          style={{ color: 'var(--text-muted, #6e7681)' }}
                          onMouseEnter={e => (e.currentTarget.style.color = '#f85149')}
                          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted, #6e7681)')}
                        >
                          <NoSymbolIcon className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {certs.length === 0 && (
          <div className="text-center py-12" style={{ color: 'var(--text-muted, #6e7681)' }}>
            <KeyIcon className="w-10 h-10 mx-auto mb-2 opacity-40" />
            <p className="text-sm">Keine Zertifikate vorhanden</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Zertifizierungsstellen ────────────────────────────────────────────────

function CATab({
  cas,
  onNewCA,
  onDownloadCA,
}: {
  cas: CertificateAuthority[];
  onNewCA: () => void;
  onDownloadCA: (id: string) => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm" style={{ color: 'var(--text-secondary, #8b949e)' }}>{cas.length} Zertifizierungsstellen</p>
        <button
          onClick={onNewCA}
          className="inline-flex items-center gap-2 px-4 py-2 text-white text-sm font-medium rounded-lg transition-colors"
          style={{ background: '#006FFF' }}
        >
          <PlusIcon className="w-4 h-4" />
          Neue CA erstellen
        </button>
      </div>

      <div className="space-y-3">
        {cas.map(ca => (
          <div key={ca.id} className="od-card rounded-xl p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-4">
                <div className="mt-0.5 w-10 h-10 rounded-lg flex items-center justify-center shrink-0" style={{ background: ca.isRoot ? 'rgba(99,102,241,0.12)' : 'rgba(0,111,255,0.12)' }}>
                  <BuildingLibraryIcon className="w-5 h-5" style={{ color: ca.isRoot ? '#818cf8' : '#006FFF' }} />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{ca.name}</span>
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium" style={{ background: ca.isRoot ? 'rgba(99,102,241,0.12)' : 'rgba(0,111,255,0.12)', color: ca.isRoot ? '#818cf8' : '#006FFF' }}>
                      {ca.isRoot ? 'Root CA' : 'Intermediate CA'}
                    </span>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${ca.status === 'Aktiv' ? 'bg-green-900/40 text-green-400 border-green-700/50' : 'bg-red-900/40 text-red-400 border-red-700/50'}`}>
                      {ca.status}
                    </span>
                  </div>
                  <p className="text-xs font-mono" style={{ color: 'var(--text-secondary, #8b949e)' }}>{ca.subject}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>
                    <span>Schlüssel: <span className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{ca.keyType}</span></span>
                    <span>Gültig bis: <span className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{fmtDate(ca.validUntil)}</span></span>
                    <span>({daysUntil(ca.validUntil)} Tage)</span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => onDownloadCA(ca.id)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors shrink-0"
                style={{ color: 'var(--text-primary, #e4e6ea)', border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)' }}
              >
                <ArrowDownTrayIcon className="w-3.5 h-3.5" />
                Download
              </button>
            </div>
          </div>
        ))}
        {cas.length === 0 && (
          <div className="od-card rounded-xl text-center py-12" style={{ color: 'var(--text-muted, #6e7681)' }}>
            <BuildingLibraryIcon className="w-10 h-10 mx-auto mb-2 opacity-40" />
            <p className="text-sm">Keine Zertifizierungsstellen konfiguriert</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: SCEP ──────────────────────────────────────────────────────────────────

function ScepTab({ config, onChange }: { config: ScepConfig; onChange: (c: ScepConfig) => void }) {
  const [showPassword, setShowPassword] = useState(false);
  const [saving, setSaving] = useState(false);

  const DEVICE_TYPES = ['iOS', 'macOS', 'Windows', 'Android'];

  const toggleDevice = (d: string) => {
    const next = config.allowedDevices.includes(d)
      ? config.allowedDevices.filter(x => x !== d)
      : [...config.allowedDevices, d];
    onChange({ ...config, allowedDevices: next });
  };

  const regeneratePassword = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789-';
    const pwd = 'SCEP-' + Array.from({ length: 12 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    onChange({ ...config, challengePassword: pwd });
    toast.success('Challenge-Passwort erneuert');
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.put('/api/pki/scep', config);
      toast.success('SCEP-Konfiguration gespeichert');
    } catch {
      toast.error('Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  };

  const iconBtnStyle = { color: 'var(--text-muted, #6e7681)', border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', borderRadius: 8, padding: 8, cursor: 'pointer' };

  return (
    <div className="max-w-2xl space-y-6">
      {/* Enable toggle */}
      <div className="od-card rounded-xl px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>SCEP aktivieren</p>
            <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Simple Certificate Enrollment Protocol für automatische Zertifikatsvergabe</p>
          </div>
          <button
            onClick={() => onChange({ ...config, enabled: !config.enabled })}
            className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors"
            style={{ background: config.enabled ? '#006FFF' : 'rgba(255,255,255,0.15)' }}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${config.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>
      </div>

      {config.enabled && (
        <>
          {/* URL */}
          <div className="od-card rounded-xl px-6 py-5 space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>SCEP URL</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={config.url}
                  className="flex-1 rounded-lg px-3 py-2 text-sm font-mono cursor-default"
                  style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }}
                />
                <button onClick={() => copyToClipboard(config.url)} style={iconBtnStyle}>
                  <ClipboardDocumentIcon className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Challenge Password */}
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Challenge Passwort</label>
              <div className="flex items-center gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    readOnly
                    value={config.challengePassword}
                    className="w-full rounded-lg px-3 py-2 text-sm font-mono cursor-default pr-10"
                    style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }}
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2"
                    style={{ color: 'var(--text-muted, #6e7681)' }}
                  >
                    <EyeIcon className="w-4 h-4" />
                  </button>
                </div>
                <button onClick={() => copyToClipboard(config.challengePassword)} style={iconBtnStyle}>
                  <ClipboardDocumentIcon className="w-4 h-4" />
                </button>
                <button onClick={regeneratePassword} style={iconBtnStyle} title="Neu generieren">
                  <ArrowPathIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Allowed devices */}
          <div className="od-card rounded-xl px-6 py-5">
            <p className="font-medium mb-3" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Erlaubte Geräteplattformen</p>
            <div className="flex flex-wrap gap-3">
              {DEVICE_TYPES.map(d => (
                <label key={d} className="flex items-center gap-2 text-sm cursor-pointer select-none" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
                  <input
                    type="checkbox"
                    checked={config.allowedDevices.includes(d)}
                    onChange={() => toggleDevice(d)}
                    className="w-4 h-4 rounded"
                  />
                  {d}
                </label>
              ))}
            </div>
          </div>

          {/* Auto-enrollment */}
          <div className="od-card rounded-xl px-6 py-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Auto-Enrollment für MDM-Geräte</p>
                <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Zertifikat automatisch bei MDM-Einschreibung ausstellen</p>
              </div>
              <button
                onClick={() => onChange({ ...config, autoEnrollment: !config.autoEnrollment })}
                className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors"
                style={{ background: config.autoEnrollment ? '#006FFF' : 'rgba(255,255,255,0.15)' }}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${config.autoEnrollment ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-5 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50"
              style={{ background: '#006FFF' }}
            >
              {saving ? 'Speichern…' : 'SCEP-Konfiguration speichern'}
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// ── Tab: CRL ───────────────────────────────────────────────────────────────────

function CrlTab({ crl, onUpdate }: { crl: CrlInfo; onUpdate: () => void }) {
  const REASON_LABELS: Record<string, string> = {
    keyCompromise: 'Schlüssel kompromittiert',
    affiliationChanged: 'Zugehörigkeit geändert',
    superseded: 'Ersetzt',
    cessationOfOperation: 'Betrieb eingestellt',
    unspecified: 'Nicht angegeben',
  };

  return (
    <div className="max-w-3xl space-y-5">
      <div className="od-card rounded-xl px-6 py-5 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>CRL URL</label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={crl.url}
              className="flex-1 rounded-lg px-3 py-2 text-sm font-mono cursor-default"
              style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }}
            />
            <button
              onClick={() => copyToClipboard(crl.url)}
              className="p-2 rounded-lg transition-colors"
              style={{ color: 'var(--text-muted, #6e7681)', border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)' }}
            >
              <ClipboardDocumentIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary, #8b949e)' }}>
            <ClockIcon className="w-4 h-4" />
            <span>Zuletzt aktualisiert: <span className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{fmtDateTime(crl.lastUpdated)}</span></span>
          </div>
          <button
            onClick={onUpdate}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white rounded-lg transition-colors"
            style={{ background: '#006FFF' }}
          >
            <ArrowPathIcon className="w-4 h-4" />
            CRL aktualisieren
          </button>
        </div>
      </div>

      <div className="od-card rounded-xl overflow-hidden">
        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <h3 className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Widerrufene Zertifikate ({crl.revokedCerts.length})</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)' }}>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>CN</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>Seriennummer</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>Grund</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>Datum</th>
            </tr>
          </thead>
          <tbody>
            {crl.revokedCerts.map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{r.cn}</td>
                <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>{r.serial}</td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>{REASON_LABELS[r.reason] ?? r.reason}</td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>{fmtDate(r.date)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {crl.revokedCerts.length === 0 && (
          <div className="text-center py-10 text-sm" style={{ color: 'var(--text-muted, #6e7681)' }}>Keine widerrufenen Zertifikate</div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Ablauf-Warnungen ──────────────────────────────────────────────────────

function AblaufTab({ certs }: { certs: Certificate[] }) {
  const [warnDays, setWarnDays] = useState(30);
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [saving, setSaving] = useState(false);
  const [renewing, setRenewing] = useState(false);

  const expiring = certs.filter(c => {
    const d = daysUntil(c.validUntil);
    return d >= 0 && d <= warnDays && c.status === 'Aktiv';
  });

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.put('/api/pki/expiry-warnings', { warnDays, emailEnabled });
      toast.success('Einstellungen gespeichert');
    } catch {
      toast.error('Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  };

  const handleRenewAll = async () => {
    setRenewing(true);
    try {
      await api.post('/api/pki/certificates/renew-expiring', { warnDays });
      toast.success(`${expiring.length} Zertifikate zur Erneuerung vorgemerkt`);
    } catch {
      toast.error('Fehler bei der Erneuerung');
    } finally {
      setRenewing(false);
    }
  };

  return (
    <div className="max-w-3xl space-y-5">
      {/* Config */}
      <div className="od-card rounded-xl px-6 py-5 space-y-4">
        <h3 className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Warnungs-Konfiguration</h3>
        <div className="flex items-center gap-3">
          <label className="text-sm shrink-0" style={{ color: 'var(--text-secondary, #8b949e)' }}>Warnung bei</label>
          <input
            type="number"
            min={1}
            max={365}
            value={warnDays}
            onChange={e => setWarnDays(Number(e.target.value))}
            className="w-20 rounded-lg px-3 py-1.5 text-sm text-center focus:outline-none"
            style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)' }}
          />
          <label className="text-sm shrink-0" style={{ color: 'var(--text-secondary, #8b949e)' }}>Tagen vor Ablauf</label>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Email-Benachrichtigung</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary, #8b949e)' }}>Automatische Benachrichtigung bei ablaufenden Zertifikaten</p>
          </div>
          <button
            onClick={() => setEmailEnabled(!emailEnabled)}
            className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors"
            style={{ background: emailEnabled ? '#006FFF' : 'rgba(255,255,255,0.15)' }}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${emailEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>
        <div className="flex justify-end">
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50"
            style={{ background: '#006FFF' }}
          >
            {saving ? 'Speichern…' : 'Einstellungen speichern'}
          </button>
        </div>
      </div>

      {/* Expiring list */}
      <div className="od-card rounded-xl overflow-hidden">
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          <h3 className="font-medium" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
            Bald ablaufend
            {expiring.length > 0 && (
              <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium" style={{ background: 'rgba(210,153,34,0.15)', color: '#d29922' }}>
                {expiring.length}
              </span>
            )}
          </h3>
          {expiring.length > 0 && (
            <button
              onClick={handleRenewAll}
              disabled={renewing}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50"
              style={{ background: '#d29922' }}
            >
              <ArrowPathIcon className="w-4 h-4" />
              {renewing ? 'Erneuern…' : 'Alle erneuern'}
            </button>
          )}
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)' }}>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>CN</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>Typ</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>Gültig bis</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary, #8b949e)' }}>Verbleibend</th>
            </tr>
          </thead>
          <tbody>
            {expiring.map(cert => {
              const days = daysUntil(cert.validUntil);
              return (
                <tr key={cert.id} style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                  <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-primary, #e4e6ea)' }}>{cert.cn}</td>
                  <td className="px-4 py-3"><TypeBadge type={cert.type} /></td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>{fmtDate(cert.validUntil)}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-semibold" style={{ color: days <= 7 ? '#f85149' : '#d29922' }}>
                      {days} Tage
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {expiring.length === 0 && (
          <div className="text-center py-10">
            <CheckCircleIcon className="w-10 h-10 mx-auto mb-2" style={{ color: '#3fb950' }} />
            <p className="text-sm" style={{ color: 'var(--text-muted, #6e7681)' }}>Keine Zertifikate laufen in {warnDays} Tagen ab</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function CertificatesView() {
  const [activeTab, setActiveTab] = useState<TabId>('zertifikate');
  const [certs, setCerts] = useState<Certificate[]>(DEMO_CERTS);
  const [cas, setCas] = useState<CertificateAuthority[]>(DEMO_CAS);
  const [scep, setScep] = useState<ScepConfig>(DEMO_SCEP);
  const [crl, setCrl] = useState<CrlInfo>(DEMO_CRL);
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [showNewCAModal, setShowNewCAModal] = useState(false);
  const [loading, setLoading] = useState(false);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [certsRes, casRes, scepRes, crlRes] = await Promise.all([
        api.get('/api/pki/certificates').catch(() => null),
        api.get('/api/pki/cas').catch(() => null),
        api.get('/api/pki/scep').catch(() => null),
        api.get('/api/pki/crl').catch(() => null),
      ]);
      if (certsRes?.data) setCerts(certsRes.data.certificates ?? certsRes.data);
      if (casRes?.data) setCas(casRes.data.cas ?? casRes.data);
      if (scepRes?.data) setScep(scepRes.data);
      if (crlRes?.data) setCrl(crlRes.data);
    } catch {
      // Fall back to demo data already set
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleRevoke = async (id: string) => {
    if (!window.confirm('Zertifikat wirklich widerrufen? Diese Aktion kann nicht rückgängig gemacht werden.')) return;
    try {
      await api.post(`/api/pki/certificates/${id}/revoke`, { reason: 'unspecified' });
      setCerts(prev => prev.map(c => c.id === id ? { ...c, status: 'Widerrufen' as CertStatus } : c));
      toast.success('Zertifikat widerrufen');
    } catch {
      toast.error('Fehler beim Widerrufen');
    }
  };

  const handleDownload = async (id: string) => {
    try {
      const res = await api.get(`/api/pki/certificates/${id}/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = `certificate-${id}.pem`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error('Download fehlgeschlagen');
    }
  };

  const handleDownloadCA = async (id: string) => {
    try {
      const res = await api.get(`/api/pki/cas/${id}/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = `ca-${id}.pem`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error('Download fehlgeschlagen');
    }
  };

  const handleUpdateCrl = async () => {
    try {
      await api.post('/api/pki/crl/update');
      setCrl(prev => ({ ...prev, lastUpdated: new Date().toISOString() }));
      toast.success('CRL aktualisiert');
    } catch {
      toast.error('Fehler beim Aktualisieren der CRL');
    }
  };

  // Stats
  const total = certs.length;
  const active = certs.filter(c => c.status === 'Aktiv').length;
  const expired = certs.filter(c => c.status === 'Abgelaufen').length;
  const expiringSoon = certs.filter(c => { const d = daysUntil(c.validUntil); return d >= 0 && d <= 30 && c.status === 'Aktiv'; }).length;

  const TABS: { id: TabId; label: string }[] = [
    { id: 'zertifikate', label: 'Zertifikate' },
    { id: 'cas', label: 'Zertifizierungsstellen' },
    { id: 'scep', label: 'SCEP' },
    { id: 'crl', label: 'Widerrufsliste (CRL)' },
    { id: 'ablauf', label: 'Ablauf-Warnungen' },
  ];

  return (
    <div className="min-h-screen" style={{ background: 'var(--bg-base, #0e1115)' }}>
      {/* Modals */}
      {showIssueModal && (
        <IssueCertModal
          onClose={() => setShowIssueModal(false)}
          onIssued={loadData}
        />
      )}
      {showNewCAModal && (
        <NewCAModal
          onClose={() => setShowNewCAModal(false)}
          onCreated={loadData}
          existingCAs={cas}
        />
      )}

      {/* Header */}
      <div className="px-8 py-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: 'rgba(0,111,255,0.1)' }}>
            <ShieldCheckIcon className="w-5 h-5" style={{ color: '#006FFF' }} />
          </div>
          <div>
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary, #e4e6ea)' }}>Zertifikatsverwaltung</h1>
            <p className="text-sm" style={{ color: 'var(--text-secondary, #8b949e)' }}>Interne Zertifizierungsstelle und PKI-Verwaltung</p>
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <StatCard
            label="Gesamt Zertifikate"
            value={loading ? '…' : total}
            icon={<KeyIcon className="w-5 h-5" />}
          />
          <StatCard
            label="Aktiv"
            value={loading ? '…' : active}
            icon={<CheckCircleIcon className="w-5 h-5" />}
            color="#3fb950"
          />
          <StatCard
            label="Abgelaufen"
            value={loading ? '…' : expired}
            icon={<XCircleIcon className="w-5 h-5" />}
            color="#f85149"
          />
          <StatCard
            label="Läuft bald ab (< 30 Tage)"
            value={loading ? '…' : expiringSoon}
            icon={<BellAlertIcon className="w-5 h-5" />}
            color="#d29922"
          />
        </div>

        {/* Tabs */}
        <div className="flex gap-1 rounded-xl p-1 mb-6 w-fit" style={{ background: 'var(--bg-surface, #161b22)', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="px-4 py-2 rounded-lg text-sm font-medium transition-all"
              style={activeTab === tab.id
                ? { background: '#006FFF', color: '#ffffff' }
                : { color: 'var(--text-secondary, #8b949e)' }
              }
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'zertifikate' && (
          <ZertifikateTab
            certs={certs}
            onIssue={() => setShowIssueModal(true)}
            onRevoke={handleRevoke}
            onDownload={handleDownload}
          />
        )}
        {activeTab === 'cas' && (
          <CATab
            cas={cas}
            onNewCA={() => setShowNewCAModal(true)}
            onDownloadCA={handleDownloadCA}
          />
        )}
        {activeTab === 'scep' && <ScepTab config={scep} onChange={setScep} />}
        {activeTab === 'crl' && <CrlTab crl={crl} onUpdate={handleUpdateCrl} />}
        {activeTab === 'ablauf' && <AblaufTab certs={certs} />}
      </div>
    </div>
  );
}
