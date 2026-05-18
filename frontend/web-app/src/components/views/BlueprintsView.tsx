'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  WifiIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ArrowPathIcon,
  DocumentCheckIcon,
  GlobeAltIcon,
  ShareIcon,
  PlusIcon,
  TrashIcon,
  XMarkIcon,
  RectangleStackIcon,
  ComputerDesktopIcon,
  UserGroupIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import toast from 'react-hot-toast';

// ── Types ──────────────────────────────────────────────────────────────────────

interface Blueprint {
  id: string;
  name: string;
  description?: string;
  platform: string;
  config_count: number;
  assignment_count: number;
  created_at: string;
}

interface BlueprintConfig {
  id: string;
  blueprint_id: string;
  config_type: string;
  config_name: string;
  payload: Record<string, unknown>;
  created_at: string;
}

interface BlueprintAssignment {
  id: string;
  blueprint_id: string;
  target_type: 'device' | 'group';
  target_id: string;
  assigned_at: string;
  assigned_by?: string;
}

interface BlueprintDetail extends Blueprint {
  configurations: BlueprintConfig[];
}

type ConfigType =
  | 'wifi'
  | 'vpn'
  | 'filevault'
  | 'gatekeeper'
  | 'software_update'
  | 'screen_lock'
  | 'certificate'
  | 'webfilter'
  | 'airdrop';

// ── Constants ──────────────────────────────────────────────────────────────────

const CONFIG_TYPES: { value: ConfigType; label: string }[] = [
  { value: 'wifi', label: 'Wi-Fi' },
  { value: 'vpn', label: 'VPN' },
  { value: 'filevault', label: 'FileVault' },
  { value: 'gatekeeper', label: 'Gatekeeper' },
  { value: 'software_update', label: 'Software Update' },
  { value: 'screen_lock', label: 'Screen Lock' },
  { value: 'certificate', label: 'Certificate' },
  { value: 'webfilter', label: 'Web Filter' },
  { value: 'airdrop', label: 'AirDrop' },
];

const PLATFORMS = ['all', 'macos', 'ios', 'windows', 'linux'];

const PLATFORM_LABELS: Record<string, string> = {
  all: 'Alle',
  macos: 'macOS',
  ios: 'iOS',
  windows: 'Windows',
  linux: 'Linux',
};

// ── Config type icon ───────────────────────────────────────────────────────────

function ConfigIcon({ type, className = 'w-4 h-4' }: { type: string; className?: string }) {
  switch (type) {
    case 'wifi':
      return <WifiIcon className={className} />;
    case 'vpn':
      return <LockClosedIcon className={className} />;
    case 'filevault':
      return <ShieldCheckIcon className={className} />;
    case 'gatekeeper':
      return <ShieldExclamationIcon className={className} />;
    case 'software_update':
      return <ArrowPathIcon className={className} />;
    case 'screen_lock':
      return <LockClosedIcon className={className} />;
    case 'certificate':
      return <DocumentCheckIcon className={className} />;
    case 'webfilter':
      return <GlobeAltIcon className={className} />;
    case 'airdrop':
      return <ShareIcon className={className} />;
    default:
      return <RectangleStackIcon className={className} />;
  }
}

// ── Dynamic payload form per config type ──────────────────────────────────────

function PayloadForm({
  configType,
  payload,
  onChange,
}: {
  configType: ConfigType;
  payload: Record<string, unknown>;
  onChange: (payload: Record<string, unknown>) => void;
}) {
  const set = (key: string, value: unknown) => onChange({ ...payload, [key]: value });

  switch (configType) {
    case 'wifi':
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">SSID</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.ssid as string) || ''}
              onChange={e => set('ssid', e.target.value)}
              placeholder="Netzwerkname"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Sicherheit</label>
            <select
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.security as string) || 'WPA2'}
              onChange={e => set('security', e.target.value)}
            >
              <option value="WPA2">WPA2</option>
              <option value="WPA3">WPA3</option>
              <option value="none">Keine</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Passwort</label>
            <input
              type="password"
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.password as string) || ''}
              onChange={e => set('password', e.target.value)}
              placeholder="WLAN-Passwort"
            />
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
              <input
                type="checkbox"
                checked={!!(payload.hidden)}
                onChange={e => set('hidden', e.target.checked)}
                className="rounded"
              />
              Verstecktes Netzwerk
            </label>
            <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
              <input
                type="checkbox"
                checked={payload.autoJoin !== false}
                onChange={e => set('autoJoin', e.target.checked)}
                className="rounded"
              />
              Automatisch verbinden
            </label>
          </div>
        </div>
      );

    case 'vpn':
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Server</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.server as string) || ''}
              onChange={e => set('server', e.target.value)}
              placeholder="vpn.example.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Protokoll</label>
            <select
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.protocol as string) || 'IKEv2'}
              onChange={e => set('protocol', e.target.value)}
            >
              <option value="IKEv2">IKEv2</option>
              <option value="L2TP">L2TP</option>
              <option value="WireGuard">WireGuard</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Benutzername</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.username as string) || ''}
              onChange={e => set('username', e.target.value)}
              placeholder="Benutzername"
            />
          </div>
        </div>
      );

    case 'filevault':
      return (
        <div className="space-y-3">
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={payload.enabled !== false}
              onChange={e => set('enabled', e.target.checked)}
              className="rounded"
            />
            FileVault aktivieren
          </label>
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={!!(payload.recoveryKeyEscrow)}
              onChange={e => set('recoveryKeyEscrow', e.target.checked)}
              className="rounded"
            />
            Recovery Key hinterlegen
          </label>
        </div>
      );

    case 'gatekeeper':
      return (
        <div className="space-y-3">
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={payload.allowAppleAndDeveloper !== false}
              onChange={e => set('allowAppleAndDeveloper', e.target.checked)}
              className="rounded"
            />
            Apple und identifizierte Entwickler erlauben
          </label>
        </div>
      );

    case 'software_update':
      return (
        <div className="space-y-3">
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={payload.automatic !== false}
              onChange={e => set('automatic', e.target.checked)}
              className="rounded"
            />
            Automatische Updates
          </label>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Verzögerung (Tage)</label>
            <input
              type="number"
              min={0}
              max={90}
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.deferDays as number) ?? 0}
              onChange={e => set('deferDays', parseInt(e.target.value) || 0)}
            />
          </div>
        </div>
      );

    case 'screen_lock':
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Max. Inaktivität (Minuten)</label>
            <input
              type="number"
              min={1}
              max={60}
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.maxInactiveMinutes as number) ?? 5}
              onChange={e => set('maxInactiveMinutes', parseInt(e.target.value) || 5)}
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={payload.requirePassword !== false}
              onChange={e => set('requirePassword', e.target.checked)}
              className="rounded"
            />
            Passwort beim Entsperren erforderlich
          </label>
        </div>
      );

    case 'certificate':
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Common Name</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={(payload.commonName as string) || ''}
              onChange={e => set('commonName', e.target.value)}
              placeholder="device.example.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">SANs (kommagetrennt)</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={Array.isArray(payload.sans) ? (payload.sans as string[]).join(', ') : ''}
              onChange={e => set('sans', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="san1.example.com, san2.example.com"
            />
          </div>
        </div>
      );

    case 'webfilter':
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Gesperrte Domains (kommagetrennt)</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={Array.isArray(payload.blockedDomains) ? (payload.blockedDomains as string[]).join(', ') : ''}
              onChange={e => set('blockedDomains', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="example.com, bad.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#1D1D1F] mb-1">Erlaubte Domains (kommagetrennt)</label>
            <input
              className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
              value={Array.isArray(payload.allowedDomains) ? (payload.allowedDomains as string[]).join(', ') : ''}
              onChange={e => set('allowedDomains', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="trusted.com"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={payload.safeSearch !== false}
              onChange={e => set('safeSearch', e.target.checked)}
              className="rounded"
            />
            SafeSearch aktivieren
          </label>
        </div>
      );

    case 'airdrop':
      return (
        <div className="space-y-3">
          <label className="flex items-center gap-2 text-sm text-[#1D1D1F] cursor-pointer">
            <input
              type="checkbox"
              checked={!!(payload.enabled)}
              onChange={e => set('enabled', e.target.checked)}
              className="rounded"
            />
            AirDrop aktivieren
          </label>
          <p className="text-xs text-[#6E6E73]">In Unternehmensumgebungen wird AirDrop empfohlen zu deaktivieren.</p>
        </div>
      );

    default:
      return <p className="text-sm text-[#6E6E73]">Keine Konfigurationsoptionen verfügbar.</p>;
  }
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function BlueprintsView() {
  const [blueprints, setBlueprints] = useState<Blueprint[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedBlueprint, setSelectedBlueprint] = useState<BlueprintDetail | null>(null);
  const [assignments, setAssignments] = useState<BlueprintAssignment[]>([]);
  const [panelOpen, setPanelOpen] = useState(false);

  // Create blueprint modal
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newPlatform, setNewPlatform] = useState('all');
  const [creating, setCreating] = useState(false);

  // Add config modal
  const [addConfigOpen, setAddConfigOpen] = useState(false);
  const [newConfigType, setNewConfigType] = useState<ConfigType>('wifi');
  const [newConfigName, setNewConfigName] = useState('');
  const [newConfigPayload, setNewConfigPayload] = useState<Record<string, unknown>>({});
  const [addingConfig, setAddingConfig] = useState(false);

  // Assign modal
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignTargetType, setAssignTargetType] = useState<'device' | 'group'>('device');
  const [assignTargetId, setAssignTargetId] = useState('');
  const [assigning, setAssigning] = useState(false);

  const [applying, setApplying] = useState(false);

  // ── Fetch blueprints ─────────────────────────────────────────────────────────

  const fetchBlueprints = useCallback(async () => {
    try {
      const res = await api.get('/api/blueprints');
      const data = res.data as { blueprints: Blueprint[] };
      setBlueprints(data.blueprints || []);
    } catch {
      toast.error('Blueprints konnten nicht geladen werden');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBlueprints();
  }, [fetchBlueprints]);

  // ── Open detail panel ────────────────────────────────────────────────────────

  const openDetail = async (blueprint: Blueprint) => {
    try {
      const [detailRes, asnRes] = await Promise.all([
        api.get(`/api/blueprints/${blueprint.id}`),
        api.get(`/api/blueprints/${blueprint.id}/assignments`),
      ]);
      setSelectedBlueprint(detailRes.data as BlueprintDetail);
      setAssignments((asnRes.data as { assignments: BlueprintAssignment[] }).assignments || []);
      setPanelOpen(true);
    } catch {
      toast.error('Blueprint-Details konnten nicht geladen werden');
    }
  };

  const closePanel = () => {
    setPanelOpen(false);
    setSelectedBlueprint(null);
    setAssignments([]);
  };

  // ── Create blueprint ─────────────────────────────────────────────────────────

  const handleCreate = async () => {
    if (!newName.trim()) return toast.error('Name ist erforderlich');
    setCreating(true);
    try {
      await api.post('/api/blueprints', {
        name: newName.trim(),
        description: newDescription.trim() || undefined,
        platform: newPlatform,
      });
      toast.success('Blueprint erstellt');
      setCreateOpen(false);
      setNewName('');
      setNewDescription('');
      setNewPlatform('all');
      fetchBlueprints();
    } catch {
      toast.error('Blueprint konnte nicht erstellt werden');
    } finally {
      setCreating(false);
    }
  };

  // ── Delete blueprint ─────────────────────────────────────────────────────────

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Blueprint wirklich löschen?')) return;
    try {
      await api.delete(`/api/blueprints/${id}`);
      toast.success('Blueprint gelöscht');
      if (selectedBlueprint?.id === id) closePanel();
      fetchBlueprints();
    } catch {
      toast.error('Blueprint konnte nicht gelöscht werden');
    }
  };

  // ── Add config ───────────────────────────────────────────────────────────────

  const handleAddConfig = async () => {
    if (!selectedBlueprint || !newConfigName.trim()) return toast.error('Konfigurationsname ist erforderlich');
    setAddingConfig(true);
    try {
      await api.post(`/api/blueprints/${selectedBlueprint.id}/configurations`, {
        config_type: newConfigType,
        config_name: newConfigName.trim(),
        payload: newConfigPayload,
      });
      toast.success('Konfiguration hinzugefügt');
      setAddConfigOpen(false);
      setNewConfigName('');
      setNewConfigPayload({});
      // Reload detail
      const res = await api.get(`/api/blueprints/${selectedBlueprint.id}`);
      setSelectedBlueprint(res.data as BlueprintDetail);
      fetchBlueprints();
    } catch {
      toast.error('Konfiguration konnte nicht hinzugefügt werden');
    } finally {
      setAddingConfig(false);
    }
  };

  // ── Remove config ────────────────────────────────────────────────────────────

  const handleRemoveConfig = async (configId: string) => {
    if (!selectedBlueprint) return;
    try {
      await api.delete(`/api/blueprints/${selectedBlueprint.id}/configurations/${configId}`);
      toast.success('Konfiguration entfernt');
      const res = await api.get(`/api/blueprints/${selectedBlueprint.id}`);
      setSelectedBlueprint(res.data as BlueprintDetail);
      fetchBlueprints();
    } catch {
      toast.error('Konfiguration konnte nicht entfernt werden');
    }
  };

  // ── Assign ───────────────────────────────────────────────────────────────────

  const handleAssign = async () => {
    if (!selectedBlueprint || !assignTargetId.trim()) return toast.error('Ziel-ID ist erforderlich');
    setAssigning(true);
    try {
      await api.post(`/api/blueprints/${selectedBlueprint.id}/assign`, {
        target_type: assignTargetType,
        target_id: assignTargetId.trim(),
      });
      toast.success('Blueprint zugewiesen');
      setAssignOpen(false);
      setAssignTargetId('');
      const res = await api.get(`/api/blueprints/${selectedBlueprint.id}/assignments`);
      setAssignments((res.data as { assignments: BlueprintAssignment[] }).assignments || []);
      fetchBlueprints();
    } catch {
      toast.error('Zuweisung fehlgeschlagen');
    } finally {
      setAssigning(false);
    }
  };

  // ── Apply blueprint ──────────────────────────────────────────────────────────

  const handleApply = async () => {
    if (!selectedBlueprint) return;
    setApplying(true);
    try {
      const res = await api.post(`/api/blueprints/${selectedBlueprint.id}/apply`, {});
      const data = res.data as { assignmentsTargeted: number; configsApplied: number };
      toast.success(`Blueprint angewendet auf ${data.assignmentsTargeted} Ziel(e) mit ${data.configsApplied} Konfiguration(en)`);
    } catch {
      toast.error('Blueprint konnte nicht angewendet werden');
    } finally {
      setApplying(false);
    }
  };

  // ── Config type change reset payload ────────────────────────────────────────

  const handleConfigTypeChange = (type: ConfigType) => {
    setNewConfigType(type);
    setNewConfigPayload({});
  };

  // ── Format date ──────────────────────────────────────────────────────────────

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleDateString('de-CH', { day: '2-digit', month: '2-digit', year: 'numeric' });
    } catch {
      return iso;
    }
  };

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-full" style={{ background: '#F2F2F7', fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif' }}>

      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: '#1D1D1F', letterSpacing: '-0.3px' }}>Blueprints</h1>
          <p style={{ fontSize: 13, color: '#6E6E73', marginTop: 2 }}>
            Gerätekonfigurationsprofile erstellen und zuweisen — nach Vorbild von Apple Business Manager
          </p>
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: '#0071E3', color: 'white', border: 'none',
            borderRadius: 8, padding: '8px 16px', fontSize: 14, fontWeight: 500,
            cursor: 'pointer',
          }}
        >
          <PlusIcon className="w-4 h-4" />
          Neues Blueprint
        </button>
      </div>

      {/* Blueprints table */}
      <div className="border border-[#E5E5EA] rounded-xl bg-white overflow-hidden">
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#6E6E73', fontSize: 14 }}>
            Wird geladen...
          </div>
        ) : blueprints.length === 0 ? (
          <div style={{ padding: 60, textAlign: 'center' }}>
            <RectangleStackIcon className="w-12 h-12 mx-auto mb-3" style={{ color: '#C7C7CC' }} />
            <p style={{ fontSize: 15, fontWeight: 600, color: '#1D1D1F', marginBottom: 4 }}>Keine Blueprints vorhanden</p>
            <p style={{ fontSize: 13, color: '#6E6E73' }}>Erstelle ein Blueprint, um Gerätekonfigurationen zu verwalten</p>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #E5E5EA' }}>
                <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Name</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Plattform</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Konfigurationen</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Zugewiesen</th>
                <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Erstellt</th>
                <th style={{ padding: '10px 16px', textAlign: 'right', fontSize: 11, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em' }}></th>
              </tr>
            </thead>
            <tbody>
              {blueprints.map((bp, idx) => (
                <tr
                  key={bp.id}
                  onClick={() => openDetail(bp)}
                  style={{
                    borderBottom: idx < blueprints.length - 1 ? '1px solid #F2F2F7' : 'none',
                    cursor: 'pointer',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = '#F9F9FB'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                >
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{
                        width: 32, height: 32, borderRadius: 8,
                        background: '#EAF4FF', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      }}>
                        <RectangleStackIcon className="w-4 h-4" style={{ color: '#0071E3' }} />
                      </div>
                      <div>
                        <p style={{ fontSize: 14, fontWeight: 500, color: '#1D1D1F' }}>{bp.name}</p>
                        {bp.description && (
                          <p style={{ fontSize: 12, color: '#6E6E73', marginTop: 1 }}>{bp.description}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      fontSize: 12, padding: '2px 8px', borderRadius: 4,
                      background: '#F2F2F7', color: '#1D1D1F', fontWeight: 500,
                    }}>
                      {PLATFORM_LABELS[bp.platform] || bp.platform}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      fontSize: 12, padding: '2px 8px', borderRadius: 10,
                      background: '#EAF4FF', color: '#0071E3', fontWeight: 600,
                    }}>
                      {bp.config_count}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ fontSize: 13, color: '#1D1D1F' }}>{bp.assignment_count}</span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ fontSize: 13, color: '#6E6E73' }}>{formatDate(bp.created_at)}</span>
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end' }}>
                      <button
                        onClick={(e) => handleDelete(bp.id, e)}
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer', padding: 6,
                          borderRadius: 6, color: '#6E6E73',
                        }}
                        onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = '#FF3B30'; (e.currentTarget as HTMLButtonElement).style.background = '#FFF2F1'; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = '#6E6E73'; (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                        title="Blueprint löschen"
                      >
                        <TrashIcon className="w-4 h-4" />
                      </button>
                      <ChevronRightIcon className="w-4 h-4" style={{ color: '#C7C7CC' }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ─── Detail Panel ───────────────────────────────────────────────────────── */}
      {panelOpen && selectedBlueprint && (
        <div
          className="fixed inset-0 z-40 flex justify-end"
          style={{ background: 'rgba(0,0,0,0.3)' }}
          onClick={closePanel}
        >
          <div
            className="h-full overflow-y-auto"
            style={{
              width: '100%', maxWidth: 560, background: 'white',
              boxShadow: '-8px 0 32px rgba(0,0,0,0.12)',
              animation: 'slideInRight 0.25s ease',
            }}
            onClick={e => e.stopPropagation()}
          >
            <style>{`@keyframes slideInRight { from { transform: translateX(100%); } to { transform: translateX(0); } }`}</style>

            {/* Panel header */}
            <div style={{ padding: '20px 24px', borderBottom: '1px solid #E5E5EA', display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: '#EAF4FF', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <RectangleStackIcon className="w-5 h-5" style={{ color: '#0071E3' }} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <h2 style={{ fontSize: 17, fontWeight: 600, color: '#1D1D1F', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {selectedBlueprint.name}
                </h2>
                {selectedBlueprint.description && (
                  <p style={{ fontSize: 12, color: '#6E6E73', marginTop: 2 }}>{selectedBlueprint.description}</p>
                )}
              </div>
              <button
                onClick={closePanel}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 6, color: '#6E6E73', borderRadius: 6, flexShrink: 0 }}
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div style={{ padding: 24 }}>
              {/* Platform selector */}
              <div style={{ marginBottom: 24 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: '#6E6E73', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 8 }}>
                  Plattform
                </label>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {PLATFORMS.map(p => (
                    <span key={p} style={{
                      fontSize: 12, padding: '4px 10px', borderRadius: 6,
                      background: selectedBlueprint.platform === p ? '#0071E3' : '#F2F2F7',
                      color: selectedBlueprint.platform === p ? 'white' : '#1D1D1F',
                      fontWeight: 500,
                    }}>
                      {PLATFORM_LABELS[p]}
                    </span>
                  ))}
                </div>
              </div>

              {/* Configurations section */}
              <div style={{ marginBottom: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: '#1D1D1F' }}>Konfigurationen</h3>
                  <button
                    onClick={() => setAddConfigOpen(true)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4,
                      background: '#F2F2F7', border: 'none', borderRadius: 6,
                      padding: '5px 10px', fontSize: 13, color: '#0071E3', fontWeight: 500, cursor: 'pointer',
                    }}
                  >
                    <PlusIcon className="w-3.5 h-3.5" />
                    Hinzufügen
                  </button>
                </div>

                {selectedBlueprint.configurations.length === 0 ? (
                  <div style={{
                    border: '1px dashed #E5E5EA', borderRadius: 10, padding: 20,
                    textAlign: 'center', color: '#6E6E73', fontSize: 13,
                  }}>
                    Keine Konfigurationen. Klicke + um eine hinzuzufügen.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {selectedBlueprint.configurations.map(cfg => (
                      <div key={cfg.id} style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '10px 14px', borderRadius: 10, border: '1px solid #E5E5EA', background: '#FAFAFA',
                      }}>
                        <div style={{
                          width: 32, height: 32, borderRadius: 8, background: '#EAF4FF',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          <ConfigIcon type={cfg.config_type} className="w-4 h-4" />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ fontSize: 13, fontWeight: 500, color: '#1D1D1F' }}>{cfg.config_name}</p>
                          <p style={{ fontSize: 11, color: '#6E6E73', marginTop: 1 }}>
                            {CONFIG_TYPES.find(t => t.value === cfg.config_type)?.label || cfg.config_type}
                          </p>
                        </div>
                        <button
                          onClick={() => handleRemoveConfig(cfg.id)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4, color: '#C7C7CC', borderRadius: 4, flexShrink: 0 }}
                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = '#FF3B30'; }}
                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = '#C7C7CC'; }}
                        >
                          <TrashIcon className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Assignments section */}
              <div style={{ marginBottom: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: '#1D1D1F' }}>Zuweisungen</h3>
                  <button
                    onClick={() => setAssignOpen(true)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4,
                      background: '#F2F2F7', border: 'none', borderRadius: 6,
                      padding: '5px 10px', fontSize: 13, color: '#0071E3', fontWeight: 500, cursor: 'pointer',
                    }}
                  >
                    <PlusIcon className="w-3.5 h-3.5" />
                    Gerät zuweisen
                  </button>
                </div>

                {assignments.length === 0 ? (
                  <div style={{
                    border: '1px dashed #E5E5EA', borderRadius: 10, padding: 20,
                    textAlign: 'center', color: '#6E6E73', fontSize: 13,
                  }}>
                    Noch keinem Gerät oder Gruppe zugewiesen.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {assignments.map(asgn => (
                      <div key={asgn.id} style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '10px 14px', borderRadius: 10, border: '1px solid #E5E5EA', background: '#FAFAFA',
                      }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: 6, background: '#F2F2F7',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          {asgn.target_type === 'device'
                            ? <ComputerDesktopIcon className="w-4 h-4" style={{ color: '#6E6E73' }} />
                            : <UserGroupIcon className="w-4 h-4" style={{ color: '#6E6E73' }} />
                          }
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ fontSize: 13, fontWeight: 500, color: '#1D1D1F', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {asgn.target_id}
                          </p>
                          <p style={{ fontSize: 11, color: '#6E6E73', marginTop: 1 }}>
                            {asgn.target_type === 'device' ? 'Gerät' : 'Gruppe'}
                            {asgn.assigned_at ? ` · ${formatDate(asgn.assigned_at)}` : ''}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Apply button */}
              <button
                onClick={handleApply}
                disabled={applying}
                style={{
                  width: '100%', background: applying ? '#A0C4F1' : '#0071E3',
                  color: 'white', border: 'none', borderRadius: 10,
                  padding: '12px 0', fontSize: 15, fontWeight: 600,
                  cursor: applying ? 'not-allowed' : 'pointer',
                }}
              >
                {applying ? 'Wird angewendet...' : 'Blueprint anwenden'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Create Blueprint Modal ──────────────────────────────────────────────── */}
      {createOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.35)', padding: 16 }}
          onClick={() => setCreateOpen(false)}
        >
          <div
            style={{
              background: 'white', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 460,
              boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: '#1D1D1F' }}>Neues Blueprint</h2>
              <button onClick={() => setCreateOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6E6E73' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>Name *</label>
                <input
                  autoFocus
                  className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                  placeholder="z.B. Corporate macOS Standard"
                  onKeyDown={e => { if (e.key === 'Enter') handleCreate(); }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>Beschreibung</label>
                <textarea
                  className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3] resize-none"
                  rows={2}
                  value={newDescription}
                  onChange={e => setNewDescription(e.target.value)}
                  placeholder="Optionale Beschreibung"
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>Plattform</label>
                <select
                  className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
                  value={newPlatform}
                  onChange={e => setNewPlatform(e.target.value)}
                >
                  {PLATFORMS.map(p => (
                    <option key={p} value={p}>{PLATFORM_LABELS[p]}</option>
                  ))}
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 24 }}>
              <button
                onClick={() => setCreateOpen(false)}
                style={{
                  flex: 1, background: '#F2F2F7', border: 'none', borderRadius: 8,
                  padding: '10px 0', fontSize: 14, fontWeight: 500, color: '#1D1D1F', cursor: 'pointer',
                }}
              >
                Abbrechen
              </button>
              <button
                onClick={handleCreate}
                disabled={creating || !newName.trim()}
                style={{
                  flex: 1, background: creating || !newName.trim() ? '#A0C4F1' : '#0071E3',
                  border: 'none', borderRadius: 8, padding: '10px 0',
                  fontSize: 14, fontWeight: 600, color: 'white',
                  cursor: creating || !newName.trim() ? 'not-allowed' : 'pointer',
                }}
              >
                {creating ? 'Erstelle...' : 'Erstellen'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Add Config Modal ────────────────────────────────────────────────────── */}
      {addConfigOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.35)', padding: 16 }}
          onClick={() => setAddConfigOpen(false)}
        >
          <div
            style={{
              background: 'white', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 480,
              boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
              maxHeight: '90vh', overflowY: 'auto',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: '#1D1D1F' }}>Konfiguration hinzufügen</h2>
              <button onClick={() => setAddConfigOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6E6E73' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>Typ</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
                  {CONFIG_TYPES.map(ct => (
                    <button
                      key={ct.value}
                      onClick={() => handleConfigTypeChange(ct.value)}
                      style={{
                        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
                        padding: '10px 6px', borderRadius: 8,
                        border: `1.5px solid ${newConfigType === ct.value ? '#0071E3' : '#E5E5EA'}`,
                        background: newConfigType === ct.value ? '#EAF4FF' : 'white',
                        cursor: 'pointer', fontSize: 11, fontWeight: 500,
                        color: newConfigType === ct.value ? '#0071E3' : '#1D1D1F',
                      }}
                    >
                      <ConfigIcon type={ct.value} className="w-4 h-4" />
                      {ct.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>Konfigurationsname *</label>
                <input
                  className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
                  value={newConfigName}
                  onChange={e => setNewConfigName(e.target.value)}
                  placeholder={`z.B. ${CONFIG_TYPES.find(t => t.value === newConfigType)?.label} Konfiguration`}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 8 }}>Einstellungen</label>
                <div style={{ background: '#FAFAFA', borderRadius: 10, padding: '14px 14px', border: '1px solid #E5E5EA' }}>
                  <PayloadForm
                    configType={newConfigType}
                    payload={newConfigPayload}
                    onChange={setNewConfigPayload}
                  />
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 24 }}>
              <button
                onClick={() => setAddConfigOpen(false)}
                style={{
                  flex: 1, background: '#F2F2F7', border: 'none', borderRadius: 8,
                  padding: '10px 0', fontSize: 14, fontWeight: 500, color: '#1D1D1F', cursor: 'pointer',
                }}
              >
                Abbrechen
              </button>
              <button
                onClick={handleAddConfig}
                disabled={addingConfig || !newConfigName.trim()}
                style={{
                  flex: 1, background: addingConfig || !newConfigName.trim() ? '#A0C4F1' : '#0071E3',
                  border: 'none', borderRadius: 8, padding: '10px 0',
                  fontSize: 14, fontWeight: 600, color: 'white',
                  cursor: addingConfig || !newConfigName.trim() ? 'not-allowed' : 'pointer',
                }}
              >
                {addingConfig ? 'Hinzufügen...' : 'Hinzufügen'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Assign Modal ────────────────────────────────────────────────────────── */}
      {assignOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.35)', padding: 16 }}
          onClick={() => setAssignOpen(false)}
        >
          <div
            style={{
              background: 'white', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 400,
              boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: '#1D1D1F' }}>Gerät zuweisen</h2>
              <button onClick={() => setAssignOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6E6E73' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>Zieltyp</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  {(['device', 'group'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => setAssignTargetType(t)}
                      style={{
                        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                        padding: '8px 0', borderRadius: 8,
                        border: `1.5px solid ${assignTargetType === t ? '#0071E3' : '#E5E5EA'}`,
                        background: assignTargetType === t ? '#EAF4FF' : 'white',
                        cursor: 'pointer', fontSize: 13, fontWeight: 500,
                        color: assignTargetType === t ? '#0071E3' : '#1D1D1F',
                      }}
                    >
                      {t === 'device'
                        ? <ComputerDesktopIcon className="w-4 h-4" />
                        : <UserGroupIcon className="w-4 h-4" />
                      }
                      {t === 'device' ? 'Gerät' : 'Gruppe'}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#1D1D1F', marginBottom: 6 }}>
                  {assignTargetType === 'device' ? 'Geräte-ID' : 'Gruppen-ID'}
                </label>
                <input
                  autoFocus
                  className="w-full border border-[#E5E5EA] rounded-lg px-3 py-2 text-sm outline-none focus:border-[#0071E3]"
                  value={assignTargetId}
                  onChange={e => setAssignTargetId(e.target.value)}
                  placeholder={assignTargetType === 'device' ? 'device-uuid oder hostname' : 'group-uuid oder name'}
                  onKeyDown={e => { if (e.key === 'Enter') handleAssign(); }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 24 }}>
              <button
                onClick={() => setAssignOpen(false)}
                style={{
                  flex: 1, background: '#F2F2F7', border: 'none', borderRadius: 8,
                  padding: '10px 0', fontSize: 14, fontWeight: 500, color: '#1D1D1F', cursor: 'pointer',
                }}
              >
                Abbrechen
              </button>
              <button
                onClick={handleAssign}
                disabled={assigning || !assignTargetId.trim()}
                style={{
                  flex: 1, background: assigning || !assignTargetId.trim() ? '#A0C4F1' : '#0071E3',
                  border: 'none', borderRadius: 8, padding: '10px 0',
                  fontSize: 14, fontWeight: 600, color: 'white',
                  cursor: assigning || !assignTargetId.trim() ? 'not-allowed' : 'pointer',
                }}
              >
                {assigning ? 'Zuweisen...' : 'Zuweisen'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
