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
    Aktiv: 'bg-green-100 text-green-800 border border-green-200',
    Abgelaufen: 'bg-red-100 text-red-800 border border-red-200',
    Widerrufen: 'bg-gray-100 text-gray-600 border border-gray-200',
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
    Benutzer: 'bg-blue-50 text-blue-700',
    Gerät: 'bg-purple-50 text-purple-700',
    Server: 'bg-orange-50 text-orange-700',
    CA: 'bg-indigo-50 text-indigo-700',
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

function StatCard({ label, value, icon, color = 'text-[#0071E3]' }: StatCardProps) {
  return (
    <div className="bg-white rounded-xl shadow-sm px-5 py-4 flex items-center gap-4">
      <div className={`flex-shrink-0 w-10 h-10 rounded-lg bg-gray-50 flex items-center justify-center ${color}`}>
        {icon}
      </div>
      <div>
        <p className="text-xs text-gray-500 font-medium">{label}</p>
        <p className="text-2xl font-bold text-gray-900 leading-tight">{value}</p>
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

  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-5 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">Zertifikat ausstellen</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Typ</label>
            <div className="grid grid-cols-4 gap-2">
              {(['Benutzer', 'Gerät', 'Server', 'Code-Signierung'] as CertIssueType[]).map(t => (
                <button
                  key={t}
                  onClick={() => setType(t)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium border transition-all ${
                    type === t ? 'bg-[#0071E3] text-white border-[#0071E3]' : 'bg-gray-50 text-gray-700 border-gray-200 hover:border-[#0071E3]'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Subject */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Subject</label>
            <div className="space-y-2">
              {[
                { label: 'CN (Common Name)*', value: cn, setter: setCn, placeholder: 'z.B. alice@firma.local' },
                { label: 'OU (Organizational Unit)', value: ou, setter: setOu, placeholder: 'z.B. IT' },
                { label: 'O (Organization)', value: o, setter: setO, placeholder: 'z.B. Firma GmbH' },
                { label: 'C (Country)', value: c, setter: setC, placeholder: 'z.B. CH' },
              ].map(({ label, value, setter, placeholder }) => (
                <div key={label} className="flex items-center gap-3">
                  <label className="w-40 text-xs text-gray-500 shrink-0">{label}</label>
                  <input
                    type="text"
                    value={value}
                    onChange={e => setter(e.target.value)}
                    placeholder={placeholder}
                    className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Key & Validity */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Schlüssellänge</label>
              <select
                value={keyLength}
                onChange={e => setKeyLength(e.target.value as KeyLength)}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
              >
                <option value="2048">RSA 2048</option>
                <option value="4096">RSA 4096</option>
                <option value="P-256 EC">P-256 EC</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Gültigkeit</label>
              <select
                value={validity}
                onChange={e => setValidity(e.target.value as Validity)}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
              >
                {Object.entries(VALIDITY_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
          </div>

          {/* SANs */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Subject Alternative Names (SAN)</label>
            <textarea
              value={sans}
              onChange={e => setSans(e.target.value)}
              rows={3}
              placeholder={'DNS:vpn.firma.local\nIP:192.168.1.10\nemail:alice@firma.local'}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3] resize-none font-mono"
            />
            <p className="text-xs text-gray-400 mt-1">Ein Eintrag pro Zeile (DNS:, IP:, email:)</p>
          </div>

          {/* Usage */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Verwendungszweck</label>
            <div className="flex flex-wrap gap-3">
              {USAGE_OPTIONS.map(u => (
                <label key={u} className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={usages.includes(u)}
                    onChange={() => toggleUsage(u)}
                    className="w-4 h-4 rounded border-gray-300 text-[#0071E3] focus:ring-[#0071E3]"
                  />
                  {u}
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-gray-100 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors">
            Abbrechen
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0060C7] transition-colors disabled:opacity-50"
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

  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-5 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">Neue CA erstellen</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">CA-Typ</label>
            <div className="grid grid-cols-2 gap-2">
              {([
                { value: 'self-signed', label: 'Self-Signed Root' },
                { value: 'intermediate', label: 'Intermediate CA' },
              ] as { value: CAType; label: string }[]).map(t => (
                <button
                  key={t.value}
                  onClick={() => setCaType(t.value)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium border transition-all ${
                    caType === t.value ? 'bg-[#0071E3] text-white border-[#0071E3]' : 'bg-gray-50 text-gray-700 border-gray-200 hover:border-[#0071E3]'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setCaName(e.target.value)}
              placeholder="z.B. Firma Root CA"
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
            />
          </div>

          {caType === 'intermediate' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Übergeordnete CA</label>
              <select
                value={parentCA}
                onChange={e => setParentCA(e.target.value)}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
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
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Schlüssellänge</label>
              <select
                value={keyType}
                onChange={e => setKeyType(e.target.value as KeyLength)}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
              >
                <option value="2048">RSA 2048</option>
                <option value="4096">RSA 4096</option>
                <option value="P-256 EC">P-256 EC</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Gültigkeit</label>
              <select
                value={validity}
                onChange={e => setValidity(e.target.value as Validity)}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
              >
                <option value="1y">1 Jahr</option>
                <option value="2y">2 Jahre</option>
                <option value="5y">5 Jahre</option>
              </select>
            </div>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-gray-100 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors">
            Abbrechen
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0060C7] transition-colors disabled:opacity-50"
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
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-5 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">Zertifikat-Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
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
              <span className="text-sm text-gray-500 shrink-0">{label}</span>
              <span className="text-sm font-medium text-gray-900 text-right">{value}</span>
            </div>
          ))}
          {cert.sans && cert.sans.length > 0 && (
            <div>
              <span className="text-sm text-gray-500">SANs</span>
              <div className="mt-1 space-y-0.5">
                {cert.sans.map(s => (
                  <div key={s} className="text-sm font-mono text-gray-800 bg-gray-50 rounded px-2 py-0.5">{s}</div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="px-6 py-4 border-t border-gray-100 flex justify-end">
          <button onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors">
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
        <p className="text-sm text-gray-500">{certs.length} Zertifikate gefunden</p>
        <button
          onClick={onIssue}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#0060C7] transition-colors"
        >
          <PlusIcon className="w-4 h-4" />
          Zertifikat ausstellen
        </button>
      </div>

      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50">
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Subject CN</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Typ</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Aussteller</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Gültig bis</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
              <th className="px-4 py-3 text-right text-xs font-semibold text-gray-500 uppercase tracking-wide">Aktionen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {certs.map(cert => {
              const days = daysUntil(cert.validUntil);
              const soonExpiring = days > 0 && days <= 30;
              return (
                <tr key={cert.id} className="hover:bg-gray-50/50 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-gray-900 text-xs">{cert.cn}</span>
                      {soonExpiring && (
                        <ExclamationTriangleIcon className="w-3.5 h-3.5 text-amber-500 shrink-0" title="Läuft bald ab" />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3"><TypeBadge type={cert.type} /></td>
                  <td className="px-4 py-3 text-gray-600 text-xs">{cert.issuer}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs ${soonExpiring ? 'text-amber-600 font-medium' : 'text-gray-600'}`}>
                      {fmtDate(cert.validUntil)}
                    </span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={cert.status} /></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onDownload(cert.id)}
                        title="Download (.pem)"
                        className="p-1.5 text-gray-400 hover:text-[#0071E3] rounded-lg hover:bg-blue-50 transition-colors"
                      >
                        <ArrowDownTrayIcon className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setSelectedCert(cert)}
                        title="Details"
                        className="p-1.5 text-gray-400 hover:text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
                      >
                        <InformationCircleIcon className="w-4 h-4" />
                      </button>
                      {cert.status === 'Aktiv' && (
                        <button
                          onClick={() => onRevoke(cert.id)}
                          title="Widerrufen"
                          className="p-1.5 text-gray-400 hover:text-red-600 rounded-lg hover:bg-red-50 transition-colors"
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
          <div className="text-center py-12 text-gray-400">
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
        <p className="text-sm text-gray-500">{cas.length} Zertifizierungsstellen</p>
        <button
          onClick={onNewCA}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#0071E3] text-white text-sm font-medium rounded-lg hover:bg-[#0060C7] transition-colors"
        >
          <PlusIcon className="w-4 h-4" />
          Neue CA erstellen
        </button>
      </div>

      <div className="space-y-3">
        {cas.map(ca => (
          <div key={ca.id} className="bg-white rounded-xl shadow-sm p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-4">
                <div className={`mt-0.5 w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${ca.isRoot ? 'bg-indigo-50' : 'bg-blue-50'}`}>
                  <BuildingLibraryIcon className={`w-5 h-5 ${ca.isRoot ? 'text-indigo-600' : 'text-blue-600'}`} />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-gray-900">{ca.name}</span>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${ca.isRoot ? 'bg-indigo-50 text-indigo-700' : 'bg-blue-50 text-blue-700'}`}>
                      {ca.isRoot ? 'Root CA' : 'Intermediate CA'}
                    </span>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${ca.status === 'Aktiv' ? 'bg-green-100 text-green-800 border-green-200' : 'bg-red-100 text-red-800 border-red-200'}`}>
                      {ca.status}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 font-mono">{ca.subject}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                    <span>Schlüssel: <span className="text-gray-700 font-medium">{ca.keyType}</span></span>
                    <span>Gültig bis: <span className="text-gray-700 font-medium">{fmtDate(ca.validUntil)}</span></span>
                    <span>({daysUntil(ca.validUntil)} Tage)</span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => onDownloadCA(ca.id)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors shrink-0"
              >
                <ArrowDownTrayIcon className="w-3.5 h-3.5" />
                Download
              </button>
            </div>
          </div>
        ))}
        {cas.length === 0 && (
          <div className="bg-white rounded-xl shadow-sm text-center py-12 text-gray-400">
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

  return (
    <div className="max-w-2xl space-y-6">
      {/* Enable toggle */}
      <div className="bg-white rounded-xl shadow-sm px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium text-gray-900">SCEP aktivieren</p>
            <p className="text-sm text-gray-500 mt-0.5">Simple Certificate Enrollment Protocol für automatische Zertifikatsvergabe</p>
          </div>
          <button
            onClick={() => onChange({ ...config, enabled: !config.enabled })}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${config.enabled ? 'bg-[#0071E3]' : 'bg-gray-200'}`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${config.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>
      </div>

      {config.enabled && (
        <>
          {/* URL */}
          <div className="bg-white rounded-xl shadow-sm px-6 py-5 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">SCEP URL</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={config.url}
                  className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm bg-gray-50 text-gray-700 font-mono cursor-default"
                />
                <button
                  onClick={() => copyToClipboard(config.url)}
                  className="p-2 text-gray-400 hover:text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  <ClipboardDocumentIcon className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Challenge Password */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Challenge Passwort</label>
              <div className="flex items-center gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    readOnly
                    value={config.challengePassword}
                    className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm bg-gray-50 text-gray-700 font-mono cursor-default pr-10"
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    <EyeIcon className="w-4 h-4" />
                  </button>
                </div>
                <button
                  onClick={() => copyToClipboard(config.challengePassword)}
                  className="p-2 text-gray-400 hover:text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  <ClipboardDocumentIcon className="w-4 h-4" />
                </button>
                <button
                  onClick={regeneratePassword}
                  className="p-2 text-gray-400 hover:text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                  title="Neu generieren"
                >
                  <ArrowPathIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Allowed devices */}
          <div className="bg-white rounded-xl shadow-sm px-6 py-5">
            <p className="font-medium text-gray-900 mb-3">Erlaubte Geräteplattformen</p>
            <div className="flex flex-wrap gap-3">
              {DEVICE_TYPES.map(d => (
                <label key={d} className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={config.allowedDevices.includes(d)}
                    onChange={() => toggleDevice(d)}
                    className="w-4 h-4 rounded border-gray-300 text-[#0071E3] focus:ring-[#0071E3]"
                  />
                  {d}
                </label>
              ))}
            </div>
          </div>

          {/* Auto-enrollment */}
          <div className="bg-white rounded-xl shadow-sm px-6 py-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Auto-Enrollment für MDM-Geräte</p>
                <p className="text-sm text-gray-500 mt-0.5">Zertifikat automatisch bei MDM-Einschreibung ausstellen</p>
              </div>
              <button
                onClick={() => onChange({ ...config, autoEnrollment: !config.autoEnrollment })}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${config.autoEnrollment ? 'bg-[#0071E3]' : 'bg-gray-200'}`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${config.autoEnrollment ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-5 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0060C7] transition-colors disabled:opacity-50"
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
      <div className="bg-white rounded-xl shadow-sm px-6 py-5 space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1.5">CRL URL</label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={crl.url}
              className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm bg-gray-50 text-gray-700 font-mono cursor-default"
            />
            <button
              onClick={() => copyToClipboard(crl.url)}
              className="p-2 text-gray-400 hover:text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <ClipboardDocumentIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <ClockIcon className="w-4 h-4" />
            <span>Zuletzt aktualisiert: <span className="text-gray-800 font-medium">{fmtDateTime(crl.lastUpdated)}</span></span>
          </div>
          <button
            onClick={onUpdate}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0060C7] transition-colors"
          >
            <ArrowPathIcon className="w-4 h-4" />
            CRL aktualisieren
          </button>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100">
          <h3 className="font-medium text-gray-900">Widerrufene Zertifikate ({crl.revokedCerts.length})</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50">
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">CN</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Seriennummer</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Grund</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Datum</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {crl.revokedCerts.map((r, i) => (
              <tr key={i} className="hover:bg-gray-50/50">
                <td className="px-4 py-3 font-mono text-xs text-gray-900">{r.cn}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-600">{r.serial}</td>
                <td className="px-4 py-3 text-xs text-gray-600">{REASON_LABELS[r.reason] ?? r.reason}</td>
                <td className="px-4 py-3 text-xs text-gray-600">{fmtDate(r.date)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {crl.revokedCerts.length === 0 && (
          <div className="text-center py-10 text-gray-400 text-sm">Keine widerrufenen Zertifikate</div>
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
      <div className="bg-white rounded-xl shadow-sm px-6 py-5 space-y-4">
        <h3 className="font-medium text-gray-900">Warnungs-Konfiguration</h3>
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-700 shrink-0">Warnung bei</label>
          <input
            type="number"
            min={1}
            max={365}
            value={warnDays}
            onChange={e => setWarnDays(Number(e.target.value))}
            className="w-20 border border-gray-200 rounded-lg px-3 py-1.5 text-sm text-center focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30 focus:border-[#0071E3]"
          />
          <label className="text-sm text-gray-700 shrink-0">Tagen vor Ablauf</label>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-900">Email-Benachrichtigung</p>
            <p className="text-xs text-gray-500 mt-0.5">Automatische Benachrichtigung bei ablaufenden Zertifikaten</p>
          </div>
          <button
            onClick={() => setEmailEnabled(!emailEnabled)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${emailEnabled ? 'bg-[#0071E3]' : 'bg-gray-200'}`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${emailEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>
        <div className="flex justify-end">
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white bg-[#0071E3] rounded-lg hover:bg-[#0060C7] transition-colors disabled:opacity-50"
          >
            {saving ? 'Speichern…' : 'Einstellungen speichern'}
          </button>
        </div>
      </div>

      {/* Expiring list */}
      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <h3 className="font-medium text-gray-900">
            Bald ablaufend
            {expiring.length > 0 && (
              <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800">
                {expiring.length}
              </span>
            )}
          </h3>
          {expiring.length > 0 && (
            <button
              onClick={handleRenewAll}
              disabled={renewing}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-amber-500 rounded-lg hover:bg-amber-600 transition-colors disabled:opacity-50"
            >
              <ArrowPathIcon className="w-4 h-4" />
              {renewing ? 'Erneuern…' : 'Alle erneuern'}
            </button>
          )}
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50">
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">CN</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Typ</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Gültig bis</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Verbleibend</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {expiring.map(cert => {
              const days = daysUntil(cert.validUntil);
              return (
                <tr key={cert.id} className="hover:bg-gray-50/50">
                  <td className="px-4 py-3 font-mono text-xs text-gray-900">{cert.cn}</td>
                  <td className="px-4 py-3"><TypeBadge type={cert.type} /></td>
                  <td className="px-4 py-3 text-xs text-gray-600">{fmtDate(cert.validUntil)}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-semibold ${days <= 7 ? 'text-red-600' : 'text-amber-600'}`}>
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
            <CheckCircleIcon className="w-10 h-10 mx-auto mb-2 text-green-400" />
            <p className="text-sm text-gray-400">Keine Zertifikate laufen in {warnDays} Tagen ab</p>
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
    <div className="min-h-screen bg-[#F2F2F7]">
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
          <div className="w-10 h-10 rounded-xl bg-[#0071E3]/10 flex items-center justify-center">
            <ShieldCheckIcon className="w-5 h-5 text-[#0071E3]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">Zertifikatsverwaltung</h1>
            <p className="text-sm text-gray-500">Interne Zertifizierungsstelle und PKI-Verwaltung</p>
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
            color="text-green-600"
          />
          <StatCard
            label="Abgelaufen"
            value={loading ? '…' : expired}
            icon={<XCircleIcon className="w-5 h-5" />}
            color="text-red-500"
          />
          <StatCard
            label="Läuft bald ab (< 30 Tage)"
            value={loading ? '…' : expiringSoon}
            icon={<BellAlertIcon className="w-5 h-5" />}
            color="text-amber-500"
          />
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-white rounded-xl shadow-sm p-1 mb-6 w-fit">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-[#0071E3] text-white shadow-sm'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
              }`}
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
