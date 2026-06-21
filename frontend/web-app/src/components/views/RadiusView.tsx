'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  WifiIcon,
  PlusIcon,
  XMarkIcon,
  EyeIcon,
  EyeSlashIcon,
  ArrowPathIcon,
  DocumentArrowDownIcon,
  FunnelIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ServerIcon,
  ShieldCheckIcon,
  ClockIcon,
  UserIcon,
  ChevronDownIcon,
  TrashIcon,
  PencilIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ── Types ──────────────────────────────────────────────────────────────────────

type TabId = 'clients' | 'policies' | 'log' | 'config';
type NasType = 'Switch' | 'WiFi AP' | 'VPN' | 'Other';
type AuthMethod = 'EAP-TLS' | 'PEAP' | 'PAP' | 'CHAP' | 'EAP-TTLS';
type AuthResult = 'Accept' | 'Reject' | 'Challenge';
type PolicyAction = 'Accept' | 'Reject' | 'Challenge';

interface RadiusClient {
  id: string;
  name: string;
  ipSubnet: string;
  secret: string;
  nasType: NasType;
  status: 'Aktiv' | 'Inaktiv';
}

interface AuthPolicy {
  id: string;
  name: string;
  userGroup: string;
  deviceType: string;
  timeOfDay: string;
  action: PolicyAction;
  vlan?: string;
  enabled: boolean;
}

interface AuthLogEntry {
  id: string;
  timestamp: string;
  user: string;
  clientIp: string;
  nasIp: string;
  method: AuthMethod;
  result: AuthResult;
  vlan?: string;
}

interface RadiusConfig {
  authPort: number;
  accountingPort: number;
  maxRetry: number;
  sessionTimeout: number;
  eapTls: boolean;
  peapMschapv2: boolean;
  eapTtls: boolean;
  caCertId: string;
  accountingEnabled: boolean;
  accountingDest: 'syslog' | 'database';
}

// ── Demo Data ──────────────────────────────────────────────────────────────────

const DEMO_CLIENTS: RadiusClient[] = [
  { id: 'c1', name: 'Core-Switch-01', ipSubnet: '192.168.1.10/32', secret: 'SecretKey$2024!', nasType: 'Switch', status: 'Aktiv' },
  { id: 'c2', name: 'WiFi-AP-Floor2', ipSubnet: '192.168.1.20/32', secret: 'WifiSecret#9x', nasType: 'WiFi AP', status: 'Aktiv' },
  { id: 'c3', name: 'VPN-Gateway', ipSubnet: '10.0.0.1/32', secret: 'VpnRadius!77', nasType: 'VPN', status: 'Aktiv' },
  { id: 'c4', name: 'Legacy-Switch-B2', ipSubnet: '192.168.2.5/32', secret: 'OldSecret123', nasType: 'Switch', status: 'Inaktiv' },
];

const DEMO_POLICIES: AuthPolicy[] = [
  { id: 'p1', name: 'IT-Mitarbeiter (VLAN 10)', userGroup: 'IT', deviceType: 'Alle', timeOfDay: 'Immer', action: 'Accept', vlan: '10', enabled: true },
  { id: 'p2', name: 'Engineering (VLAN 20)', userGroup: 'Engineering', deviceType: 'Alle', timeOfDay: 'Immer', action: 'Accept', vlan: '20', enabled: true },
  { id: 'p3', name: 'Gäste – MFA erforderlich', userGroup: 'Gäste', deviceType: 'Alle', timeOfDay: 'Immer', action: 'Challenge', vlan: '100', enabled: true },
  { id: 'p4', name: 'Nach Feierabend ablehnen', userGroup: 'Marketing', deviceType: 'Alle', timeOfDay: '18:00–08:00', action: 'Reject', enabled: false },
];

const DEMO_LOG: AuthLogEntry[] = [
  { id: 'l1', timestamp: new Date(Date.now() - 60000).toISOString(), user: 'alice.mueller', clientIp: '192.168.1.20', nasIp: '192.168.1.20', method: 'EAP-TLS', result: 'Accept', vlan: '10' },
  { id: 'l2', timestamp: new Date(Date.now() - 180000).toISOString(), user: 'bob.schneider', clientIp: '192.168.1.10', nasIp: '192.168.1.10', method: 'PEAP', result: 'Accept', vlan: '20' },
  { id: 'l3', timestamp: new Date(Date.now() - 300000).toISOString(), user: 'unknown_user', clientIp: '192.168.1.20', nasIp: '192.168.1.20', method: 'PAP', result: 'Reject' },
  { id: 'l4', timestamp: new Date(Date.now() - 600000).toISOString(), user: 'carol.weber', clientIp: '192.168.2.5', nasIp: '192.168.2.5', method: 'PEAP', result: 'Accept', vlan: '30' },
  { id: 'l5', timestamp: new Date(Date.now() - 900000).toISOString(), user: 'guest01', clientIp: '192.168.1.20', nasIp: '192.168.1.20', method: 'EAP-TTLS', result: 'Challenge', vlan: '100' },
  { id: 'l6', timestamp: new Date(Date.now() - 1200000).toISOString(), user: 'david.koch', clientIp: '10.0.0.1', nasIp: '10.0.0.1', method: 'PAP', result: 'Reject' },
];

const DEMO_CONFIG: RadiusConfig = {
  authPort: 1812,
  accountingPort: 1813,
  maxRetry: 3,
  sessionTimeout: 3600,
  eapTls: true,
  peapMschapv2: true,
  eapTtls: false,
  caCertId: '',
  accountingEnabled: true,
  accountingDest: 'syslog',
};

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDateTime(iso: string): string {
  return new Date(iso).toLocaleString('de-CH', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function generateSecret(length = 16): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ── Stat Card ──────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color?: string;
}

function StatCard({ label, value, icon, color = 'text-[#006FFF]' }: StatCardProps) {
  return (
    <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl px-5 py-4 flex items-center gap-4">
      <div style={{ background: 'var(--bg-surface-raised)' }} className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
        {icon}
      </div>
      <div>
        <p style={{ color: 'var(--text-muted)' }} className="text-xs font-medium">{label}</p>
        <p style={{ color: 'var(--text-primary)' }} className="text-2xl font-bold leading-tight">{value}</p>
      </div>
    </div>
  );
}

// ── Result Badge ───────────────────────────────────────────────────────────────

function ResultBadge({ result }: { result: AuthResult }) {
  const styleMap: Record<AuthResult, React.CSSProperties> = {
    Accept:    { background: 'var(--success-light)', color: 'var(--success)', border: '1px solid var(--success)' },
    Reject:    { background: 'var(--danger-light)',  color: 'var(--danger)',  border: '1px solid var(--danger)' },
    Challenge: { background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid var(--warning)' },
  };
  return (
    <span style={styleMap[result]} className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium">
      {result}
    </span>
  );
}

// ── NAS Type Badge ─────────────────────────────────────────────────────────────

function NasTypeBadge({ type }: { type: NasType }) {
  const styleMap: Record<NasType, React.CSSProperties> = {
    Switch:    { background: 'var(--accent-light)',           color: 'var(--accent)' },
    'WiFi AP': { background: 'rgba(139,92,246,0.15)',         color: '#a78bfa' },
    VPN:       { background: 'rgba(99,102,241,0.15)',         color: '#818cf8' },
    Other:     { background: 'var(--bg-surface-raised)',      color: 'var(--text-secondary)' },
  };
  return (
    <span style={styleMap[type]} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium">
      {type}
    </span>
  );
}

// ── Toggle ─────────────────────────────────────────────────────────────────────

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${checked ? 'bg-[#006FFF]' : 'bg-gray-200'}`}
    >
      <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-6' : 'translate-x-1'}`} />
    </button>
  );
}

// ── New Client Modal ───────────────────────────────────────────────────────────

interface NewClientModalProps {
  onClose: () => void;
  onCreated: (client: RadiusClient) => void;
}

function NewClientModal({ onClose, onCreated }: NewClientModalProps) {
  const [name, setName] = useState('');
  const [ipSubnet, setIpSubnet] = useState('');
  const [secret, setSecret] = useState(generateSecret());
  const [nasType, setNasType] = useState<NasType>('Switch');
  const [showSecret, setShowSecret] = useState(true);
  const [saving, setSaving] = useState(false);

  const handleSubmit = async () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    if (!ipSubnet.trim()) { toast.error('IP-Adresse/CIDR ist erforderlich'); return; }
    if (!secret.trim()) { toast.error('Shared Secret ist erforderlich'); return; }
    setSaving(true);
    try {
      const res = await api.post('/api/radius/clients', { name, ipSubnet, secret, nasType });
      const newClient: RadiusClient = {
        id: res.data?.id ?? String(Date.now()),
        name, ipSubnet, secret, nasType,
        status: 'Aktiv',
      };
      toast.success('RADIUS-Client erstellt');
      onCreated(newClient);
      onClose();
    } catch {
      toast.error('Fehler beim Erstellen des Clients');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
      <div style={{ background: 'var(--bg-surface)' }} className="rounded-2xl shadow-2xl w-full max-w-md">
        <div style={{ borderBottom: '1px solid var(--border)' }} className="flex items-center justify-between px-6 py-5">
          <h2 style={{ color: 'var(--text-primary)' }} className="text-base font-semibold">Neuer RADIUS-Client</h2>
          <button onClick={onClose} style={{ color: 'var(--text-muted)' }} className="hover:text-[var(--text-secondary)] transition-colors">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="z.B. Core-Switch-01"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
            />
          </div>

          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">IP-Adresse / CIDR</label>
            <input
              type="text"
              value={ipSubnet}
              onChange={e => setIpSubnet(e.target.value)}
              placeholder="z.B. 192.168.1.10/32"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
            />
          </div>

          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">Shared Secret</label>
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={secret}
                  onChange={e => setSecret(e.target.value)}
                  style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
                  className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF] pr-10 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  style={{ color: 'var(--text-muted)' }}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 hover:text-[var(--text-secondary)]"
                >
                  {showSecret ? <EyeSlashIcon className="w-4 h-4" /> : <EyeIcon className="w-4 h-4" />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => setSecret(generateSecret())}
                title="Neu generieren"
                style={{ color: 'var(--text-muted)', borderColor: 'var(--border-strong)', background: 'var(--bg-surface-raised)' }}
                className="p-2 border rounded-lg hover:text-[var(--text-secondary)] transition-colors"
              >
                <ArrowPathIcon className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">NAS-Typ</label>
            <select
              value={nasType}
              onChange={e => setNasType(e.target.value as NasType)}
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
            >
              {(['Switch', 'WiFi AP', 'VPN', 'Other'] as NasType[]).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ borderTop: '1px solid var(--border)' }} className="px-6 py-4 flex justify-end gap-3">
          <button onClick={onClose} style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }} className="px-4 py-2 text-sm font-medium rounded-lg hover:bg-[#252c37] transition-colors">
            Abbrechen
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#0060E0] transition-colors disabled:opacity-50"
          >
            {saving ? 'Erstellen…' : 'Client erstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── New Policy Modal ───────────────────────────────────────────────────────────

interface NewPolicyModalProps {
  onClose: () => void;
  onCreated: (policy: AuthPolicy) => void;
}

function NewPolicyModal({ onClose, onCreated }: NewPolicyModalProps) {
  const [name, setName] = useState('');
  const [userGroup, setUserGroup] = useState('');
  const [deviceType, setDeviceType] = useState('Alle');
  const [timeOfDay, setTimeOfDay] = useState('Immer');
  const [action, setAction] = useState<PolicyAction>('Accept');
  const [vlan, setVlan] = useState('');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    setSaving(true);
    try {
      const res = await api.post('/api/radius/policies', { name, userGroup, deviceType, timeOfDay, action, vlan: vlan || undefined });
      const newPolicy: AuthPolicy = {
        id: res.data?.id ?? String(Date.now()),
        name, userGroup, deviceType, timeOfDay, action, vlan: vlan || undefined, enabled: true,
      };
      toast.success('Richtlinie erstellt');
      onCreated(newPolicy);
      onClose();
    } catch {
      toast.error('Fehler beim Erstellen der Richtlinie');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
      <div style={{ background: 'var(--bg-surface)' }} className="rounded-2xl shadow-2xl w-full max-w-md">
        <div style={{ borderBottom: '1px solid var(--border)' }} className="flex items-center justify-between px-6 py-5">
          <h2 style={{ color: 'var(--text-primary)' }} className="text-base font-semibold">Neue Richtlinie</h2>
          <button onClick={onClose} style={{ color: 'var(--text-muted)' }} className="hover:text-[var(--text-secondary)] transition-colors">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="z.B. IT-Mitarbeiter VLAN 10"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
            />
          </div>

          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">Benutzergruppe</label>
            <input
              type="text"
              value={userGroup}
              onChange={e => setUserGroup(e.target.value)}
              placeholder="z.B. IT, Engineering (leer = alle)"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">Gerätetyp</label>
              <input
                type="text"
                value={deviceType}
                onChange={e => setDeviceType(e.target.value)}
                placeholder="Alle"
                style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
              />
            </div>
            <div>
              <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">Tageszeit</label>
              <input
                type="text"
                value={timeOfDay}
                onChange={e => setTimeOfDay(e.target.value)}
                placeholder="Immer"
                style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
              />
            </div>
          </div>

          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-2">Aktion</label>
            <div className="grid grid-cols-3 gap-2">
              {(['Accept', 'Reject', 'Challenge'] as PolicyAction[]).map(a => (
                <button
                  key={a}
                  onClick={() => setAction(a)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium border transition-all ${
                    action === a
                      ? a === 'Accept' ? 'bg-green-600 text-white border-green-600'
                        : a === 'Reject' ? 'bg-red-600 text-white border-red-600'
                        : 'bg-amber-500 text-white border-amber-500'
                      : ''
                  }`}
                  style={action !== a ? { background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)', borderColor: 'var(--border-strong)' } : {}}
                >
                  {a}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">VLAN (optional)</label>
            <input
              type="text"
              value={vlan}
              onChange={e => setVlan(e.target.value)}
              placeholder="z.B. 10"
              style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
            />
          </div>
        </div>

        <div style={{ borderTop: '1px solid var(--border)' }} className="px-6 py-4 flex justify-end gap-3">
          <button onClick={onClose} style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }} className="px-4 py-2 text-sm font-medium rounded-lg hover:bg-[#252c37] transition-colors">
            Abbrechen
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#0060E0] transition-colors disabled:opacity-50"
          >
            {saving ? 'Erstellen…' : 'Richtlinie erstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Tab: RADIUS Clients ────────────────────────────────────────────────────────

function ClientsTab({
  clients,
  onNewClient,
  onDelete,
}: {
  clients: RadiusClient[];
  onNewClient: () => void;
  onDelete: (id: string) => void;
}) {
  const [visibleSecrets, setVisibleSecrets] = useState<Set<string>>(new Set());

  const toggleSecret = (id: string) => {
    setVisibleSecrets(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p style={{ color: 'var(--text-muted)' }} className="text-sm">{clients.length} Clients konfiguriert</p>
        <button
          onClick={onNewClient}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#006FFF] text-white text-sm font-medium rounded-lg hover:bg-[#0060E0] transition-colors"
        >
          <PlusIcon className="w-4 h-4" />
          Neuer Client
        </button>
      </div>

      <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Client Name</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">IP / Subnetz</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Shared Secret</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">NAS-Typ</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Status</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wide">Aktionen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[rgba(255,255,255,0.07)]">
            {clients.map(client => (
              <tr key={client.id} className="hover:bg-[#1c2128] transition-colors">
                <td style={{ color: 'var(--text-primary)' }} className="px-4 py-3 font-medium">{client.name}</td>
                <td style={{ color: 'var(--text-secondary)' }} className="px-4 py-3 font-mono text-xs">{client.ipSubnet}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <span style={{ color: 'var(--text-secondary)' }} className="font-mono text-xs">
                      {visibleSecrets.has(client.id) ? client.secret : '••••••••••••'}
                    </span>
                    <button
                      onClick={() => toggleSecret(client.id)}
                      style={{ color: 'var(--text-muted)' }}
                      className="hover:text-[var(--text-secondary)] transition-colors"
                    >
                      {visibleSecrets.has(client.id)
                        ? <EyeSlashIcon className="w-3.5 h-3.5" />
                        : <EyeIcon className="w-3.5 h-3.5" />
                      }
                    </button>
                  </div>
                </td>
                <td className="px-4 py-3"><NasTypeBadge type={client.nasType} /></td>
                <td className="px-4 py-3">
                  <span
                    className={`inline-flex items-center gap-1 text-xs font-medium ${client.status === 'Aktiv' ? 'text-green-400' : ''}`}
                    style={client.status !== 'Aktiv' ? { color: 'var(--text-muted)' } : {}}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${client.status === 'Aktiv' ? 'bg-green-500' : 'bg-gray-400'}`} />
                    {client.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      onClick={() => toast('Bearbeiten noch nicht implementiert', { icon: 'ℹ️' })}
                      style={{ color: 'var(--text-muted)' }}
                      className="p-1.5 hover:text-[var(--text-primary)] rounded-lg hover:bg-[#252c37] transition-colors"
                    >
                      <PencilIcon className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => onDelete(client.id)}
                      style={{ color: 'var(--text-muted)' }}
                      className="p-1.5 hover:text-red-400 rounded-lg hover:bg-red-500/10 transition-colors"
                    >
                      <TrashIcon className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {clients.length === 0 && (
          <div style={{ color: 'var(--text-muted)' }} className="text-center py-12">
            <ServerIcon className="w-10 h-10 mx-auto mb-2 opacity-40" />
            <p className="text-sm">Keine RADIUS-Clients konfiguriert</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Policies ──────────────────────────────────────────────────────────────

function PoliciesTab({
  policies,
  onNewPolicy,
  onToggle,
  onDelete,
}: {
  policies: AuthPolicy[];
  onNewPolicy: () => void;
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  const ACTION_STYLES: Record<PolicyAction, React.CSSProperties> = {
    Accept:    { background: 'var(--success-light)', color: 'var(--success)', border: '1px solid var(--success)' },
    Reject:    { background: 'var(--danger-light)',  color: 'var(--danger)',  border: '1px solid var(--danger)' },
    Challenge: { background: 'var(--warning-light)', color: 'var(--warning)', border: '1px solid var(--warning)' },
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p style={{ color: 'var(--text-muted)' }} className="text-sm">{policies.length} Richtlinien definiert</p>
        <button
          onClick={onNewPolicy}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#006FFF] text-white text-sm font-medium rounded-lg hover:bg-[#0060E0] transition-colors"
        >
          <PlusIcon className="w-4 h-4" />
          Neue Richtlinie
        </button>
      </div>

      <div className="space-y-3">
        {policies.map(policy => (
          <div key={policy.id} style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className={`rounded-xl px-5 py-4 ${!policy.enabled ? 'opacity-60' : ''}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <span style={{ color: 'var(--text-primary)' }} className="font-semibold">{policy.name}</span>
                  <span style={ACTION_STYLES[policy.action]} className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium">
                    {policy.action}
                  </span>
                  {policy.vlan && (
                    <span style={{ background: 'var(--accent-light)', color: 'var(--accent)' }} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium">
                      VLAN {policy.vlan}
                    </span>
                  )}
                  {!policy.enabled && (
                    <span style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-muted)' }} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium">
                      Deaktiviert
                    </span>
                  )}
                </div>
                <div style={{ color: 'var(--text-muted)' }} className="flex items-center gap-5 text-xs">
                  <span>Gruppe: <span style={{ color: 'var(--text-secondary)' }} className="font-medium">{policy.userGroup || 'Alle'}</span></span>
                  <span>Gerät: <span style={{ color: 'var(--text-secondary)' }} className="font-medium">{policy.deviceType}</span></span>
                  <span>Zeit: <span style={{ color: 'var(--text-secondary)' }} className="font-medium">{policy.timeOfDay}</span></span>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Toggle checked={policy.enabled} onChange={() => onToggle(policy.id)} />
                <button
                  onClick={() => onDelete(policy.id)}
                  style={{ color: 'var(--text-muted)' }}
                  className="p-1.5 hover:text-red-400 rounded-lg hover:bg-red-500/10 transition-colors"
                >
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
        {policies.length === 0 && (
          <div style={{ background: 'var(--bg-surface)', color: 'var(--text-muted)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl text-center py-12">
            <ShieldCheckIcon className="w-10 h-10 mx-auto mb-2 opacity-40" />
            <p className="text-sm">Keine Richtlinien definiert</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Auth Log ──────────────────────────────────────────────────────────────

function AuthLogTab({ entries }: { entries: AuthLogEntry[] }) {
  const [filterResult, setFilterResult] = useState<AuthResult | 'Alle'>('Alle');
  const [filterUser, setFilterUser] = useState('');
  const [filterClient, setFilterClient] = useState('');

  const filtered = entries.filter(e => {
    if (filterResult !== 'Alle' && e.result !== filterResult) return false;
    if (filterUser && !e.user.toLowerCase().includes(filterUser.toLowerCase())) return false;
    if (filterClient && !e.clientIp.includes(filterClient)) return false;
    return true;
  });

  const METHOD_STYLES: Record<AuthMethod, React.CSSProperties> = {
    'EAP-TLS':  { background: 'var(--accent-light)',        color: 'var(--accent)' },
    PEAP:       { background: 'rgba(139,92,246,0.15)',       color: '#a78bfa' },
    PAP:        { background: 'var(--bg-surface-raised)',    color: 'var(--text-secondary)' },
    CHAP:       { background: 'var(--bg-surface-raised)',    color: 'var(--text-secondary)' },
    'EAP-TTLS': { background: 'rgba(99,102,241,0.15)',       color: '#818cf8' },
  };

  const handleExport = () => {
    const header = 'Timestamp,User,Client IP,NAS IP,Method,Result,VLAN\n';
    const rows = filtered.map(e =>
      `${e.timestamp},${e.user},${e.clientIp},${e.nasIp},${e.method},${e.result},${e.vlan ?? ''}`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `radius-log-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('CSV exportiert');
  };

  return (
    <div>
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex items-center gap-2">
          <FunnelIcon style={{ color: 'var(--text-muted)' }} className="w-4 h-4" />
          <span style={{ color: 'var(--text-muted)' }} className="text-sm">Filter:</span>
        </div>
        <select
          value={filterResult}
          onChange={e => setFilterResult(e.target.value as AuthResult | 'Alle')}
          style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
          className="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
        >
          <option value="Alle">Alle Ergebnisse</option>
          <option value="Accept">Accept</option>
          <option value="Reject">Reject</option>
          <option value="Challenge">Challenge</option>
        </select>
        <input
          type="text"
          value={filterUser}
          onChange={e => setFilterUser(e.target.value)}
          placeholder="Benutzer filtern…"
          style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
          className="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF] w-44"
        />
        <input
          type="text"
          value={filterClient}
          onChange={e => setFilterClient(e.target.value)}
          placeholder="Client-IP filtern…"
          style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
          className="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF] w-40"
        />
        <div className="ml-auto">
          <button
            onClick={handleExport}
            style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-strong)' }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium border rounded-lg hover:bg-[#1c2128] transition-colors"
          >
            <DocumentArrowDownIcon className="w-4 h-4" />
            CSV exportieren
          </button>
        </div>
      </div>

      <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Zeitstempel</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Benutzer</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Client IP</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">NAS IP</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Methode</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">Ergebnis</th>
              <th style={{ color: 'var(--text-muted)' }} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide">VLAN</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[rgba(255,255,255,0.07)]">
            {filtered.map(entry => (
              <tr key={entry.id} className="hover:bg-[#1c2128] transition-colors">
                <td style={{ color: 'var(--text-secondary)' }} className="px-4 py-3 text-xs whitespace-nowrap">{fmtDateTime(entry.timestamp)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <UserIcon style={{ color: 'var(--text-muted)' }} className="w-3.5 h-3.5" />
                    <span style={{ color: 'var(--text-primary)' }} className="text-xs font-medium">{entry.user}</span>
                  </div>
                </td>
                <td style={{ color: 'var(--text-secondary)' }} className="px-4 py-3 font-mono text-xs">{entry.clientIp}</td>
                <td style={{ color: 'var(--text-secondary)' }} className="px-4 py-3 font-mono text-xs">{entry.nasIp}</td>
                <td className="px-4 py-3">
                  <span style={METHOD_STYLES[entry.method] ?? { background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)' }} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium">
                    {entry.method}
                  </span>
                </td>
                <td className="px-4 py-3"><ResultBadge result={entry.result} /></td>
                <td style={{ color: 'var(--text-secondary)' }} className="px-4 py-3 text-xs">{entry.vlan ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div style={{ color: 'var(--text-muted)' }} className="text-center py-10 text-sm">
            Keine Log-Einträge gefunden
          </div>
        )}
      </div>
      <p style={{ color: 'var(--text-muted)' }} className="text-xs mt-2">{filtered.length} von {entries.length} Einträgen</p>
    </div>
  );
}

// ── Tab: Konfiguration ─────────────────────────────────────────────────────────

function KonfigTab({ config, onChange }: { config: RadiusConfig; onChange: (c: RadiusConfig) => void }) {
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.put('/api/radius/config', config);
      toast.success('Konfiguration gespeichert');
    } catch {
      toast.error('Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  };

  const numberInput = (label: string, value: number, setter: (v: number) => void, min?: number, max?: number, suffix?: string) => (
    <div className="flex items-center justify-between">
      <label style={{ color: 'var(--text-secondary)' }} className="text-sm">{label}</label>
      <div className="flex items-center gap-2">
        <input
          type="number"
          min={min}
          max={max}
          value={value}
          onChange={e => setter(Number(e.target.value))}
          style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
          className="w-24 border rounded-lg px-3 py-1.5 text-sm text-right focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
        />
        {suffix && <span style={{ color: 'var(--text-muted)' }} className="text-sm">{suffix}</span>}
      </div>
    </div>
  );

  const toggleRow = (label: string, description: string, value: boolean, setter: (v: boolean) => void) => (
    <div className="flex items-center justify-between">
      <div>
        <p style={{ color: 'var(--text-primary)' }} className="text-sm font-medium">{label}</p>
        {description && <p style={{ color: 'var(--text-muted)' }} className="text-xs mt-0.5">{description}</p>}
      </div>
      <Toggle checked={value} onChange={setter} />
    </div>
  );

  return (
    <div className="max-w-2xl space-y-5">
      {/* Server settings */}
      <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl px-6 py-5 space-y-4">
        <h3 style={{ color: 'var(--text-primary)' }} className="font-semibold">Server-Einstellungen</h3>
        <div className="space-y-3">
          {numberInput('Authentication Port', config.authPort, v => onChange({ ...config, authPort: v }), 1, 65535)}
          {numberInput('Accounting Port', config.accountingPort, v => onChange({ ...config, accountingPort: v }), 1, 65535)}
          {numberInput('Max. Wiederholungsversuche', config.maxRetry, v => onChange({ ...config, maxRetry: v }), 1, 10)}
          {numberInput('Session Timeout', config.sessionTimeout, v => onChange({ ...config, sessionTimeout: v }), 60, 86400, 'Sek.')}
        </div>
      </div>

      {/* EAP settings */}
      <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl px-6 py-5 space-y-4">
        <h3 style={{ color: 'var(--text-primary)' }} className="font-semibold">EAP-Einstellungen</h3>
        <div className="space-y-4">
          {toggleRow(
            'EAP-TLS aktivieren',
            'Zertifikatsbasierte Authentifizierung (empfohlen)',
            config.eapTls,
            v => onChange({ ...config, eapTls: v }),
          )}
          {toggleRow(
            'PEAP/MSCHAPv2 aktivieren',
            'Passwortbasierte Authentifizierung über TLS-Tunnel',
            config.peapMschapv2,
            v => onChange({ ...config, peapMschapv2: v }),
          )}
          {toggleRow(
            'EAP-TTLS aktivieren',
            'Flexible Authentifizierung über TLS-Tunnel',
            config.eapTtls,
            v => onChange({ ...config, eapTtls: v }),
          )}
        </div>
        <div>
          <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-1.5">CA-Zertifikat</label>
          <select
            value={config.caCertId}
            onChange={e => onChange({ ...config, caCertId: e.target.value })}
            style={{ background: 'var(--bg-surface-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
            className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#006FFF]/30 focus:border-[#006FFF]"
          >
            <option value="">CA-Zertifikat auswählen…</option>
            <option value="ca1">Firma Root CA</option>
            <option value="ca2">Firma Intermediate CA</option>
          </select>
          <p style={{ color: 'var(--text-muted)' }} className="text-xs mt-1">CA aus der Zertifikatsverwaltung auswählen</p>
        </div>
      </div>

      {/* Accounting */}
      <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="rounded-xl px-6 py-5 space-y-4">
        <h3 style={{ color: 'var(--text-primary)' }} className="font-semibold">Accounting</h3>
        <div className="space-y-4">
          {toggleRow(
            'RADIUS Accounting aktivieren',
            'Sitzungsdaten für Abrechnung und Audit aufzeichnen',
            config.accountingEnabled,
            v => onChange({ ...config, accountingEnabled: v }),
          )}
          {config.accountingEnabled && (
            <div className="flex items-center justify-between">
              <label style={{ color: 'var(--text-secondary)' }} className="text-sm">Accounting-Ziel</label>
              <div className="flex gap-2">
                {(['syslog', 'database'] as const).map(d => (
                  <button
                    key={d}
                    onClick={() => onChange({ ...config, accountingDest: d })}
                    className={`px-3 py-1.5 text-sm font-medium rounded-lg border transition-all ${
                      config.accountingDest === d
                        ? 'bg-[#006FFF] text-white border-[#006FFF]'
                        : ''
                    }`}
                    style={config.accountingDest !== d ? { background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)', borderColor: 'var(--border-strong)' } : {}}
                  >
                    {d === 'syslog' ? 'Syslog' : 'Datenbank'}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-5 py-2 text-sm font-medium text-white bg-[#006FFF] rounded-lg hover:bg-[#0060E0] transition-colors disabled:opacity-50"
        >
          {saving ? 'Speichern…' : 'Konfiguration speichern'}
        </button>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function RadiusView() {
  const [activeTab, setActiveTab] = useState<TabId>('clients');
  const [clients, setClients] = useState<RadiusClient[]>(DEMO_CLIENTS);
  const [policies, setPolicies] = useState<AuthPolicy[]>(DEMO_POLICIES);
  const [logEntries, setLogEntries] = useState<AuthLogEntry[]>(DEMO_LOG);
  const [config, setConfig] = useState<RadiusConfig>(DEMO_CONFIG);
  const [showNewClientModal, setShowNewClientModal] = useState(false);
  const [showNewPolicyModal, setShowNewPolicyModal] = useState(false);
  const [loading, setLoading] = useState(false);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [clientsRes, policiesRes, logRes, configRes] = await Promise.all([
        api.get('/api/radius/clients').catch(() => null),
        api.get('/api/radius/policies').catch(() => null),
        api.get('/api/radius/log').catch(() => null),
        api.get('/api/radius/config').catch(() => null),
      ]);
      if (clientsRes?.data) setClients(clientsRes.data.clients ?? clientsRes.data);
      if (policiesRes?.data) setPolicies(policiesRes.data.policies ?? policiesRes.data);
      if (logRes?.data) setLogEntries(logRes.data.entries ?? logRes.data);
      if (configRes?.data) setConfig(configRes.data);
    } catch {
      // Fall back to demo data
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleDeleteClient = async (id: string) => {
    if (!window.confirm('RADIUS-Client wirklich löschen?')) return;
    try {
      await api.delete(`/api/radius/clients/${id}`);
      setClients(prev => prev.filter(c => c.id !== id));
      toast.success('Client gelöscht');
    } catch {
      toast.error('Fehler beim Löschen');
    }
  };

  const handleTogglePolicy = async (id: string) => {
    const policy = policies.find(p => p.id === id);
    if (!policy) return;
    try {
      await api.patch(`/api/radius/policies/${id}`, { enabled: !policy.enabled });
      setPolicies(prev => prev.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));
    } catch {
      toast.error('Fehler beim Ändern der Richtlinie');
    }
  };

  const handleDeletePolicy = async (id: string) => {
    if (!window.confirm('Richtlinie wirklich löschen?')) return;
    try {
      await api.delete(`/api/radius/policies/${id}`);
      setPolicies(prev => prev.filter(p => p.id !== id));
      toast.success('Richtlinie gelöscht');
    } catch {
      toast.error('Fehler beim Löschen');
    }
  };

  // Stats
  const activeClients = clients.filter(c => c.status === 'Aktiv').length;
  const activeSessions = logEntries.filter(e => e.result === 'Accept').length;
  const failedToday = logEntries.filter(e => e.result === 'Reject').length;
  const successToday = logEntries.filter(e => e.result === 'Accept').length;

  const TABS: { id: TabId; label: string }[] = [
    { id: 'clients', label: 'RADIUS Clients' },
    { id: 'policies', label: 'Richtlinien' },
    { id: 'log', label: 'Authentifizierungs-Log' },
    { id: 'config', label: 'Konfiguration' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-base)' }}>
      {/* Modals */}
      {showNewClientModal && (
        <NewClientModal
          onClose={() => setShowNewClientModal(false)}
          onCreated={client => setClients(prev => [...prev, client])}
        />
      )}
      {showNewPolicyModal && (
        <NewPolicyModal
          onClose={() => setShowNewPolicyModal(false)}
          onCreated={policy => setPolicies(prev => [...prev, policy])}
        />
      )}

      {/* Header */}
      <div className="px-8 py-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-[#006FFF]/10 flex items-center justify-center">
            <WifiIcon className="w-5 h-5 text-[#006FFF]" />
          </div>
          <div>
            <h1 style={{ color: 'var(--text-primary)' }} className="text-xl font-bold">RADIUS / 802.1X</h1>
            <p style={{ color: 'var(--text-muted)' }} className="text-sm">Netzwerk-Authentifizierung und Zugriffskontrolle</p>
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <StatCard
            label="RADIUS Clients"
            value={loading ? '…' : activeClients}
            icon={<ServerIcon className="w-5 h-5" />}
          />
          <StatCard
            label="Aktive Sitzungen"
            value={loading ? '…' : activeSessions}
            icon={<CheckCircleIcon className="w-5 h-5" />}
            color="text-green-400"
          />
          <StatCard
            label="Fehlgeschlagene Auth heute"
            value={loading ? '…' : failedToday}
            icon={<XCircleIcon className="w-5 h-5" />}
            color="text-red-400"
          />
          <StatCard
            label="Erfolgreiche Auth heute"
            value={loading ? '…' : successToday}
            icon={<ShieldCheckIcon className="w-5 h-5" />}
            color="text-[#006FFF]"
          />
        </div>

        {/* Tabs */}
        <div style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }} className="flex gap-1 rounded-xl p-1 mb-6 w-fit">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-[#006FFF] text-white shadow-sm'
                  : 'hover:bg-[#1c2128]'
              }`}
              style={activeTab !== tab.id ? { color: 'var(--text-secondary)' } : {}}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'clients' && (
          <ClientsTab
            clients={clients}
            onNewClient={() => setShowNewClientModal(true)}
            onDelete={handleDeleteClient}
          />
        )}
        {activeTab === 'policies' && (
          <PoliciesTab
            policies={policies}
            onNewPolicy={() => setShowNewPolicyModal(true)}
            onToggle={handleTogglePolicy}
            onDelete={handleDeletePolicy}
          />
        )}
        {activeTab === 'log' && <AuthLogTab entries={logEntries} />}
        {activeTab === 'config' && <KonfigTab config={config} onChange={setConfig} />}
      </div>
    </div>
  );
}
