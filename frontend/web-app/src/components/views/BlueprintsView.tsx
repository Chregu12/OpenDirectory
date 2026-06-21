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
  PlayIcon,
  DevicePhoneMobileIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ClockIcon,
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

interface MdmDevice {
  udid: string;
  device_name?: string;
  model?: string;
  os_version?: string;
  enrolled_at?: string;
  status?: string;
}

interface BlueprintApplyStatus {
  deviceId: string;
  deviceName?: string | null;
  status: 'queued' | 'applying' | 'applied' | 'failed';
  progress: number;
  error?: string | null;
  startedAt?: string;
  completedAt?: string | null;
}

interface DepDevice {
  serialNumber: string;
  model: string;
  color: string;
  os: string;
  status: 'unassigned' | 'assigned';
  blueprintId: string | null;
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
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>SSID</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={(payload.ssid as string) || ''}
              onChange={e => set('ssid', e.target.value)}
              placeholder="Netzwerkname"
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Sicherheit</label>
            <select
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box', cursor: 'pointer' }}
              value={(payload.security as string) || 'WPA2'}
              onChange={e => set('security', e.target.value)}
            >
              <option value="WPA2">WPA2</option>
              <option value="WPA3">WPA3</option>
              <option value="none">Keine</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Passwort</label>
            <input
              type="password"
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={(payload.password as string) || ''}
              onChange={e => set('password', e.target.value)}
              placeholder="WLAN-Passwort"
            />
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
              <input
                type="checkbox"
                checked={!!(payload.hidden)}
                onChange={e => set('hidden', e.target.checked)}
                className="rounded"
              />
              Verstecktes Netzwerk
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
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
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Server</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={(payload.server as string) || ''}
              onChange={e => set('server', e.target.value)}
              placeholder="vpn.example.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Protokoll</label>
            <select
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box', cursor: 'pointer' }}
              value={(payload.protocol as string) || 'IKEv2'}
              onChange={e => set('protocol', e.target.value)}
            >
              <option value="IKEv2">IKEv2</option>
              <option value="L2TP">L2TP</option>
              <option value="WireGuard">WireGuard</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Benutzername</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
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
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
            <input
              type="checkbox"
              checked={payload.enabled !== false}
              onChange={e => set('enabled', e.target.checked)}
              className="rounded"
            />
            FileVault aktivieren
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
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
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
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
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
            <input
              type="checkbox"
              checked={payload.automatic !== false}
              onChange={e => set('automatic', e.target.checked)}
              className="rounded"
            />
            Automatische Updates
          </label>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Verzögerung (Tage)</label>
            <input
              type="number"
              min={0}
              max={90}
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
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
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Max. Inaktivität (Minuten)</label>
            <input
              type="number"
              min={1}
              max={60}
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={(payload.maxInactiveMinutes as number) ?? 5}
              onChange={e => set('maxInactiveMinutes', parseInt(e.target.value) || 5)}
            />
          </div>
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
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
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Common Name</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={(payload.commonName as string) || ''}
              onChange={e => set('commonName', e.target.value)}
              placeholder="device.example.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>SANs (kommagetrennt)</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
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
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Gesperrte Domains (kommagetrennt)</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={Array.isArray(payload.blockedDomains) ? (payload.blockedDomains as string[]).join(', ') : ''}
              onChange={e => set('blockedDomains', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="example.com, bad.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary, #8b949e)' }}>Erlaubte Domains (kommagetrennt)</label>
            <input
              style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 12px', fontSize: 13, outline: 'none', background: 'var(--bg-base, #0e1115)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
              value={Array.isArray(payload.allowedDomains) ? (payload.allowedDomains as string[]).join(', ') : ''}
              onChange={e => set('allowedDomains', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="trusted.com"
            />
          </div>
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
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
          <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-primary, #e4e6ea)' }}>
            <input
              type="checkbox"
              checked={!!(payload.enabled)}
              onChange={e => set('enabled', e.target.checked)}
              className="rounded"
            />
            AirDrop aktivieren
          </label>
          <p className="text-xs" style={{ color: 'var(--text-secondary, #8b949e)' }}>In Unternehmensumgebungen wird AirDrop empfohlen zu deaktivieren.</p>
        </div>
      );

    default:
      return <p className="text-sm" style={{ color: 'var(--text-secondary, #8b949e)' }}>Keine Konfigurationsoptionen verfügbar.</p>;
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

  // MDM apply modal
  const [applyModalBlueprintId, setApplyModalBlueprintId] = useState<string | null>(null);
  const [applyModalBlueprintName, setApplyModalBlueprintName] = useState('');
  const [mdmDevices, setMdmDevices] = useState<MdmDevice[]>([]);
  const [applyTargetMode, setApplyTargetMode] = useState<'all' | 'specific'>('all');
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [mdmApplying, setMdmApplying] = useState(false);
  const [mdmApplyResult, setMdmApplyResult] = useState<{ queued: number; devices: { deviceId: string; status: string }[] } | null>(null);

  // Blueprint apply statuses (blueprintId -> statuses[])
  const [applyStatuses, setApplyStatuses] = useState<Record<string, BlueprintApplyStatus[]>>({});

  // DEP tab
  const [activeTab, setActiveTab] = useState<'blueprints' | 'dep'>('blueprints');
  const [depDevices, setDepDevices] = useState<DepDevice[]>([]);
  const [depLoading, setDepLoading] = useState(false);
  const [depAssigning, setDepAssigning] = useState(false);
  const [selectedDepSerials, setSelectedDepSerials] = useState<string[]>([]);
  const [depAssignBlueprintId, setDepAssignBlueprintId] = useState('');

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

  // ── Fetch MDM devices ────────────────────────────────────────────────────────

  const fetchMdmDevices = useCallback(async () => {
    try {
      const res = await api.get('/api/mdm/devices');
      const data = res.data as { devices: MdmDevice[] };
      setMdmDevices(data.devices || []);
    } catch {
      setMdmDevices([]);
    }
  }, []);

  // ── Fetch apply statuses for all blueprints ──────────────────────────────────

  const fetchApplyStatuses = useCallback(async (bps: Blueprint[]) => {
    const results: Record<string, BlueprintApplyStatus[]> = {};
    await Promise.all(
      bps.map(async (bp) => {
        try {
          const res = await api.get(`/api/mdm/blueprints/${bp.id}/apply-status`);
          const data = res.data as { statuses: BlueprintApplyStatus[] };
          results[bp.id] = data.statuses || [];
        } catch {
          results[bp.id] = [];
        }
      })
    );
    setApplyStatuses(results);
  }, []);

  useEffect(() => {
    if (blueprints.length > 0) {
      fetchApplyStatuses(blueprints);
    }
  }, [blueprints, fetchApplyStatuses]);

  // ── Fetch DEP devices ────────────────────────────────────────────────────────

  const fetchDepDevices = useCallback(async () => {
    setDepLoading(true);
    try {
      const res = await api.get('/api/mdm/dep/devices');
      const data = res.data as { devices: DepDevice[] };
      setDepDevices(data.devices || []);
    } catch {
      toast.error('DEP-Geräte konnten nicht geladen werden');
    } finally {
      setDepLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'dep') {
      fetchDepDevices();
    }
  }, [activeTab, fetchDepDevices]);

  // ── Open MDM apply modal ─────────────────────────────────────────────────────

  const openApplyModal = async (bp: Blueprint, e: React.MouseEvent) => {
    e.stopPropagation();
    setApplyModalBlueprintId(bp.id);
    setApplyModalBlueprintName(bp.name);
    setApplyTargetMode('all');
    setSelectedDeviceIds([]);
    setMdmApplyResult(null);
    await fetchMdmDevices();
  };

  const closeApplyModal = () => {
    setApplyModalBlueprintId(null);
    setMdmApplyResult(null);
  };

  // ── Submit MDM blueprint apply ───────────────────────────────────────────────

  const handleMdmApply = async () => {
    if (!applyModalBlueprintId) return;
    setMdmApplying(true);
    try {
      const deviceIds = applyTargetMode === 'specific' ? selectedDeviceIds : [];
      const res = await api.post(`/api/mdm/blueprints/${applyModalBlueprintId}/apply`, { deviceIds });
      const data = res.data as { queued: number; devices: { deviceId: string; status: string }[] };
      setMdmApplyResult(data);
      toast.success(`Blueprint auf ${data.queued} Gerät(e) angewendet`);
      // Refresh statuses
      fetchApplyStatuses(blueprints);
    } catch {
      toast.error('Blueprint konnte nicht angewendet werden');
    } finally {
      setMdmApplying(false);
    }
  };

  // ── DEP assign ───────────────────────────────────────────────────────────────

  const handleDepAssign = async () => {
    if (selectedDepSerials.length === 0) return toast.error('Bitte Geräte auswählen');
    setDepAssigning(true);
    try {
      await api.post('/api/mdm/dep/assign', {
        serialNumbers: selectedDepSerials,
        blueprintId: depAssignBlueprintId || undefined,
      });
      toast.success(`${selectedDepSerials.length} Gerät(e) zugewiesen`);
      setSelectedDepSerials([]);
      setDepAssignBlueprintId('');
      fetchDepDevices();
    } catch {
      toast.error('DEP-Zuweisung fehlgeschlagen');
    } finally {
      setDepAssigning(false);
    }
  };

  // ── Get apply status summary for a blueprint ─────────────────────────────────

  const getBlueprintStatusSummary = (blueprintId: string) => {
    const statuses = applyStatuses[blueprintId] || [];
    if (statuses.length === 0) return null;
    const failed = statuses.filter(s => s.status === 'failed').length;
    const latest = statuses.reduce((a, b) => {
      const aTime = a.completedAt || a.startedAt || '';
      const bTime = b.completedAt || b.startedAt || '';
      return aTime > bTime ? a : b;
    });
    return { failed, total: statuses.length, latest };
  };

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
    <div className="min-h-full" style={{ background: 'var(--bg-base, #0e1115)', fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif' }}>

      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)', letterSpacing: '-0.3px' }}>Blueprints</h1>
          <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginTop: 2 }}>
            Gerätekonfigurationsprofile erstellen und zuweisen — nach Vorbild von Apple Business Manager
          </p>
        </div>
        {activeTab === 'blueprints' && (
          <button
            onClick={() => setCreateOpen(true)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: '#006FFF', color: 'white', border: 'none',
              borderRadius: 8, padding: '8px 16px', fontSize: 14, fontWeight: 500,
              cursor: 'pointer',
            }}
          >
            <PlusIcon className="w-4 h-4" />
            Neues Blueprint
          </button>
        )}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', paddingBottom: 0 }}>
        {(['blueprints', 'dep'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '8px 16px', fontSize: 14, fontWeight: 500,
              background: 'none', border: 'none', cursor: 'pointer',
              color: activeTab === tab ? '#006FFF' : 'var(--text-secondary, #8b949e)',
              borderBottom: activeTab === tab ? '2px solid #006FFF' : '2px solid transparent',
              marginBottom: -1,
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            {tab === 'blueprints'
              ? <><RectangleStackIcon className="w-4 h-4" /> Blueprints</>
              : <><DevicePhoneMobileIcon className="w-4 h-4" /> DEP Geräte</>
            }
          </button>
        ))}
      </div>

      {/* ─── Blueprints tab ─────────────────────────────────────────────────────── */}
      {activeTab === 'blueprints' && (
        <div style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, background: 'var(--bg-surface, #161b22)', overflow: 'hidden' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary, #8b949e)', fontSize: 14 }}>
              Wird geladen...
            </div>
          ) : blueprints.length === 0 ? (
            <div style={{ padding: 60, textAlign: 'center' }}>
              <RectangleStackIcon className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted, #6e7681)' }} />
              <p style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary, #e4e6ea)', marginBottom: 4 }}>Keine Blueprints vorhanden</p>
              <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)' }}>Erstelle ein Blueprint, um Gerätekonfigurationen zu verwalten</p>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Name</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Plattform</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Konfigurationen</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Zugewiesen</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Status</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Erstellt</th>
                  <th style={{ padding: '10px 16px', textAlign: 'right', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}></th>
                </tr>
              </thead>
              <tbody>
                {blueprints.map((bp, idx) => {
                  const summary = getBlueprintStatusSummary(bp.id);
                  return (
                    <tr
                      key={bp.id}
                      onClick={() => openDetail(bp)}
                      style={{
                        borderBottom: idx < blueprints.length - 1 ? '1px solid var(--border, rgba(255,255,255,0.07))' : 'none',
                        cursor: 'pointer',
                        transition: 'background 0.1s',
                      }}
                      onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'var(--bg-surface-raised, #1c2128)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                    >
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{
                            width: 32, height: 32, borderRadius: 8,
                            background: 'rgba(0,111,255,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                          }}>
                            <RectangleStackIcon className="w-4 h-4" style={{ color: '#006FFF' }} />
                          </div>
                          <div>
                            <p style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)' }}>{bp.name}</p>
                            {bp.description && (
                              <p style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)', marginTop: 1 }}>{bp.description}</p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{
                          fontSize: 12, padding: '2px 8px', borderRadius: 4,
                          background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', fontWeight: 500,
                        }}>
                          {PLATFORM_LABELS[bp.platform] || bp.platform}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{
                          fontSize: 12, padding: '2px 8px', borderRadius: 10,
                          background: 'rgba(0,111,255,0.12)', color: '#006FFF', fontWeight: 600,
                        }}>
                          {bp.config_count}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ fontSize: 13, color: 'var(--text-primary, #e4e6ea)' }}>{bp.assignment_count}</span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {!summary ? (
                          <span style={{ fontSize: 12, color: 'var(--text-muted, #6e7681)', display: 'flex', alignItems: 'center', gap: 4 }}>
                            <ClockIcon className="w-3.5 h-3.5" />
                            Noch nie angewendet
                          </span>
                        ) : summary.failed > 0 ? (
                          <span style={{ fontSize: 12, color: '#f85149', display: 'flex', alignItems: 'center', gap: 4 }}>
                            <ExclamationCircleIcon className="w-3.5 h-3.5" />
                            Fehler bei {summary.failed} Gerät(en)
                          </span>
                        ) : (
                          <span style={{ fontSize: 12, color: '#3fb950', display: 'flex', alignItems: 'center', gap: 4 }}>
                            <CheckCircleIcon className="w-3.5 h-3.5" />
                            {summary.latest.completedAt
                              ? `Angewendet am ${formatDate(summary.latest.completedAt)}`
                              : 'Wird angewendet…'
                            }
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)' }}>{formatDate(bp.created_at)}</span>
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end' }}>
                          <button
                            onClick={(e) => openApplyModal(bp, e)}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 4,
                              background: 'rgba(0,111,255,0.12)', border: 'none', cursor: 'pointer', padding: '5px 10px',
                              borderRadius: 6, color: '#006FFF', fontSize: 12, fontWeight: 500,
                            }}
                            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = '#006FFF'; (e.currentTarget as HTMLButtonElement).style.color = 'white'; }}
                            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,111,255,0.12)'; (e.currentTarget as HTMLButtonElement).style.color = '#006FFF'; }}
                            title="Blueprint via MDM anwenden"
                          >
                            <PlayIcon className="w-3.5 h-3.5" />
                            Anwenden
                          </button>
                          <button
                            onClick={(e) => handleDelete(bp.id, e)}
                            style={{
                              background: 'none', border: 'none', cursor: 'pointer', padding: 6,
                              borderRadius: 6, color: 'var(--text-muted, #6e7681)',
                            }}
                            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = '#f85149'; (e.currentTarget as HTMLButtonElement).style.background = 'rgba(248,81,73,0.08)'; }}
                            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted, #6e7681)'; (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                            title="Blueprint löschen"
                          >
                            <TrashIcon className="w-4 h-4" />
                          </button>
                          <ChevronRightIcon className="w-4 h-4" style={{ color: 'var(--text-muted, #6e7681)' }} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ─── DEP Geräte tab ─────────────────────────────────────────────────────── */}
      {activeTab === 'dep' && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <p style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)' }}>
              Geräte, die über Apple DEP / Zero-Touch-Enrollment automatisch konfiguriert werden können.
            </p>
            <button
              onClick={fetchDepDevices}
              style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '7px 14px', fontSize: 13, color: 'var(--text-primary, #e4e6ea)', cursor: 'pointer' }}
            >
              <ArrowPathIcon className={`w-4 h-4 ${depLoading ? 'animate-spin' : ''}`} />
              Aktualisieren
            </button>
          </div>

          {/* DEP assign bar */}
          {selectedDepSerials.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(0,111,255,0.08)', border: '1px solid rgba(0,111,255,0.3)', borderRadius: 10, padding: '10px 16px', marginBottom: 16 }}>
              <span style={{ fontSize: 13, fontWeight: 500, color: '#006FFF', flex: 1 }}>
                {selectedDepSerials.length} Gerät(e) ausgewählt
              </span>
              <select
                value={depAssignBlueprintId}
                onChange={e => setDepAssignBlueprintId(e.target.value)}
                style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 6, padding: '5px 10px', fontSize: 13, color: 'var(--text-primary, #e4e6ea)', background: 'var(--bg-surface-raised, #1c2128)', minWidth: 180 }}
              >
                <option value="">Blueprint wählen…</option>
                {blueprints.map(bp => (
                  <option key={bp.id} value={bp.id}>{bp.name}</option>
                ))}
              </select>
              <button
                onClick={handleDepAssign}
                disabled={depAssigning}
                style={{
                  background: depAssigning ? 'rgba(0,111,255,0.5)' : '#006FFF', color: 'white', border: 'none',
                  borderRadius: 6, padding: '6px 14px', fontSize: 13, fontWeight: 600, cursor: depAssigning ? 'not-allowed' : 'pointer',
                }}
              >
                {depAssigning ? 'Zuweisen...' : 'Blueprint zuweisen'}
              </button>
            </div>
          )}

          <div style={{ border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 12, background: 'var(--bg-surface, #161b22)', overflow: 'hidden' }}>
            {depLoading ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary, #8b949e)', fontSize: 14 }}>Wird geladen...</div>
            ) : depDevices.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center' }}>
                <DevicePhoneMobileIcon className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted, #6e7681)' }} />
                <p style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary, #e4e6ea)', marginBottom: 4 }}>Keine DEP-Geräte gefunden</p>
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
                    <th style={{ padding: '10px 16px', width: 40, background: 'var(--bg-surface-raised, #1c2128)' }}></th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Seriennummer</th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Modell</th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Betriebssystem</th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Status</th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--bg-surface-raised, #1c2128)' }}>Blueprint</th>
                  </tr>
                </thead>
                <tbody>
                  {depDevices.map((dev, idx) => (
                    <tr
                      key={dev.serialNumber}
                      style={{ borderBottom: idx < depDevices.length - 1 ? '1px solid var(--border, rgba(255,255,255,0.07))' : 'none' }}
                    >
                      <td style={{ padding: '10px 16px' }}>
                        <input
                          type="checkbox"
                          checked={selectedDepSerials.includes(dev.serialNumber)}
                          onChange={e => {
                            if (e.target.checked) {
                              setSelectedDepSerials(prev => [...prev, dev.serialNumber]);
                            } else {
                              setSelectedDepSerials(prev => prev.filter(s => s !== dev.serialNumber));
                            }
                          }}
                        />
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <span style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text-primary, #e4e6ea)' }}>{dev.serialNumber}</span>
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <DevicePhoneMobileIcon className="w-4 h-4" style={{ color: 'var(--text-secondary, #8b949e)', flexShrink: 0 }} />
                          <div>
                            <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)' }}>{dev.model}</p>
                            <p style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)' }}>{dev.color}</p>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <span style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)' }}>{dev.os}</span>
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <span style={{
                          fontSize: 12, padding: '2px 8px', borderRadius: 10, fontWeight: 500,
                          background: dev.status === 'assigned' ? 'rgba(63,185,80,0.12)' : 'var(--bg-surface-raised, #1c2128)',
                          color: dev.status === 'assigned' ? '#3fb950' : 'var(--text-secondary, #8b949e)',
                        }}>
                          {dev.status === 'assigned' ? 'Zugewiesen' : 'Nicht zugewiesen'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        {dev.blueprintId ? (
                          <span style={{ fontSize: 13, color: '#006FFF', fontWeight: 500 }}>
                            {blueprints.find(b => b.id === dev.blueprintId)?.name || dev.blueprintId}
                          </span>
                        ) : (
                          <span style={{ fontSize: 13, color: 'var(--text-muted, #6e7681)' }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ─── Detail Panel ───────────────────────────────────────────────────────── */}
      {panelOpen && selectedBlueprint && (
        <div
          className="fixed inset-0 z-40 flex justify-end"
          style={{ background: 'rgba(0,0,0,0.5)' }}
          onClick={closePanel}
        >
          <div
            className="h-full overflow-y-auto"
            style={{
              width: '100%', maxWidth: 560, background: 'var(--bg-surface, #161b22)',
              boxShadow: '-8px 0 32px rgba(0,0,0,0.4)',
              animation: 'slideInRight 0.25s ease',
            }}
            onClick={e => e.stopPropagation()}
          >
            <style>{`@keyframes slideInRight { from { transform: translateX(100%); } to { transform: translateX(0); } }`}</style>

            {/* Panel header */}
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border, rgba(255,255,255,0.07))', display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: 'rgba(0,111,255,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <RectangleStackIcon className="w-5 h-5" style={{ color: '#006FFF' }} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <h2 style={{ fontSize: 17, fontWeight: 600, color: 'var(--text-primary, #e4e6ea)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {selectedBlueprint.name}
                </h2>
                {selectedBlueprint.description && (
                  <p style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)', marginTop: 2 }}>{selectedBlueprint.description}</p>
                )}
              </div>
              <button
                onClick={closePanel}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 6, color: 'var(--text-secondary, #8b949e)', borderRadius: 6, flexShrink: 0 }}
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div style={{ padding: 24 }}>
              {/* Platform selector */}
              <div style={{ marginBottom: 24 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 8 }}>
                  Plattform
                </label>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {PLATFORMS.map(p => (
                    <span key={p} style={{
                      fontSize: 12, padding: '4px 10px', borderRadius: 6,
                      background: selectedBlueprint.platform === p ? '#006FFF' : 'var(--bg-surface-raised, #1c2128)',
                      color: selectedBlueprint.platform === p ? 'white' : 'var(--text-primary, #e4e6ea)',
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
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>Konfigurationen</h3>
                  <button
                    onClick={() => setAddConfigOpen(true)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4,
                      background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 6,
                      padding: '5px 10px', fontSize: 13, color: '#006FFF', fontWeight: 500, cursor: 'pointer',
                    }}
                  >
                    <PlusIcon className="w-3.5 h-3.5" />
                    Hinzufügen
                  </button>
                </div>

                {selectedBlueprint.configurations.length === 0 ? (
                  <div style={{
                    border: '1px dashed var(--border, rgba(255,255,255,0.07))', borderRadius: 10, padding: 20,
                    textAlign: 'center', color: 'var(--text-secondary, #8b949e)', fontSize: 13,
                  }}>
                    Keine Konfigurationen. Klicke + um eine hinzuzufügen.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {selectedBlueprint.configurations.map(cfg => (
                      <div key={cfg.id} style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '10px 14px', borderRadius: 10, border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)',
                      }}>
                        <div style={{
                          width: 32, height: 32, borderRadius: 8, background: 'rgba(0,111,255,0.12)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          <ConfigIcon type={cfg.config_type} className="w-4 h-4" />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)' }}>{cfg.config_name}</p>
                          <p style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)', marginTop: 1 }}>
                            {CONFIG_TYPES.find(t => t.value === cfg.config_type)?.label || cfg.config_type}
                          </p>
                        </div>
                        <button
                          onClick={() => handleRemoveConfig(cfg.id)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4, color: 'var(--text-muted, #6e7681)', borderRadius: 4, flexShrink: 0 }}
                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = '#f85149'; }}
                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted, #6e7681)'; }}
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
                  <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary, #e4e6ea)' }}>Zuweisungen</h3>
                  <button
                    onClick={() => setAssignOpen(true)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4,
                      background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 6,
                      padding: '5px 10px', fontSize: 13, color: '#006FFF', fontWeight: 500, cursor: 'pointer',
                    }}
                  >
                    <PlusIcon className="w-3.5 h-3.5" />
                    Gerät zuweisen
                  </button>
                </div>

                {assignments.length === 0 ? (
                  <div style={{
                    border: '1px dashed var(--border, rgba(255,255,255,0.07))', borderRadius: 10, padding: 20,
                    textAlign: 'center', color: 'var(--text-secondary, #8b949e)', fontSize: 13,
                  }}>
                    Noch keinem Gerät oder Gruppe zugewiesen.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {assignments.map(asgn => (
                      <div key={asgn.id} style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '10px 14px', borderRadius: 10, border: '1px solid var(--border, rgba(255,255,255,0.07))', background: 'var(--bg-surface-raised, #1c2128)',
                      }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: 6, background: 'rgba(255,255,255,0.06)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          {asgn.target_type === 'device'
                            ? <ComputerDesktopIcon className="w-4 h-4" style={{ color: 'var(--text-secondary, #8b949e)' }} />
                            : <UserGroupIcon className="w-4 h-4" style={{ color: 'var(--text-secondary, #8b949e)' }} />
                          }
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {asgn.target_id}
                          </p>
                          <p style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)', marginTop: 1 }}>
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
                  width: '100%', background: applying ? 'rgba(0,111,255,0.5)' : '#006FFF',
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
          style={{ background: 'rgba(0,0,0,0.5)', padding: 16 }}
          onClick={() => setCreateOpen(false)}
        >
          <div
            style={{
              background: 'var(--bg-surface, #161b22)', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 460,
              boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
              border: '1px solid var(--border, rgba(255,255,255,0.07))',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>Neues Blueprint</h2>
              <button onClick={() => setCreateOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary, #8b949e)' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>Name *</label>
                <input
                  autoFocus
                  style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                  placeholder="z.B. Corporate macOS Standard"
                  onKeyDown={e => { if (e.key === 'Enter') handleCreate(); }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>Beschreibung</label>
                <textarea
                  style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box', resize: 'none' }}
                  rows={2}
                  value={newDescription}
                  onChange={e => setNewDescription(e.target.value)}
                  placeholder="Optionale Beschreibung"
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>Plattform</label>
                <select
                  style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box', cursor: 'pointer' }}
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
                  flex: 1, background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8,
                  padding: '10px 0', fontSize: 14, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', cursor: 'pointer',
                }}
              >
                Abbrechen
              </button>
              <button
                onClick={handleCreate}
                disabled={creating || !newName.trim()}
                style={{
                  flex: 1, background: creating || !newName.trim() ? 'rgba(0,111,255,0.5)' : '#006FFF',
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

      {/* ─── MDM Blueprint Apply Modal ──────────────────────────────────────────── */}
      {applyModalBlueprintId && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.5)', padding: 16 }}
          onClick={closeApplyModal}
        >
          <div
            style={{
              background: 'var(--bg-surface, #161b22)', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 480,
              boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
              border: '1px solid var(--border, rgba(255,255,255,0.07))',
              maxHeight: '90vh', overflowY: 'auto',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>Blueprint anwenden</h2>
              <button onClick={closeApplyModal} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary, #8b949e)' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <p style={{ fontSize: 14, color: 'var(--text-secondary, #8b949e)', marginBottom: 20 }}>
              <strong style={{ color: 'var(--text-primary, #e4e6ea)' }}>{applyModalBlueprintName}</strong> per MDM-Push auf Geräte anwenden
            </p>

            {mdmApplyResult ? (
              <div>
                <div style={{ background: 'rgba(63,185,80,0.08)', border: '1px solid rgba(63,185,80,0.3)', borderRadius: 10, padding: '14px 16px', marginBottom: 20 }}>
                  <p style={{ fontSize: 14, fontWeight: 600, color: '#3fb950', marginBottom: 6 }}>
                    Blueprint auf {mdmApplyResult.queued} Gerät(e) angewendet
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {mdmApplyResult.devices.map(d => (
                      <div key={d.deviceId} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                        {d.status === 'failed'
                          ? <ExclamationCircleIcon className="w-4 h-4" style={{ color: '#f85149', flexShrink: 0 }} />
                          : <CheckCircleIcon className="w-4 h-4" style={{ color: '#3fb950', flexShrink: 0 }} />
                        }
                        <span style={{ fontFamily: 'monospace', color: 'var(--text-primary, #e4e6ea)' }}>{d.deviceId}</span>
                        <span style={{ color: d.status === 'failed' ? '#f85149' : '#3fb950' }}>{d.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <button
                  onClick={closeApplyModal}
                  style={{ width: '100%', background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '10px 0', fontSize: 14, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', cursor: 'pointer' }}
                >
                  Schliessen
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Target mode */}
                <div>
                  <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 8 }}>Zielgeräte</label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '10px 14px', borderRadius: 8, border: `1.5px solid ${applyTargetMode === 'all' ? '#006FFF' : 'var(--border, rgba(255,255,255,0.07))'}`, background: applyTargetMode === 'all' ? 'rgba(0,111,255,0.08)' : 'var(--bg-surface-raised, #1c2128)' }}>
                      <input
                        type="radio"
                        name="applyTarget"
                        value="all"
                        checked={applyTargetMode === 'all'}
                        onChange={() => { setApplyTargetMode('all'); setSelectedDeviceIds([]); }}
                      />
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)' }}>Alle kompatiblen Geräte</p>
                        <p style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)' }}>{mdmDevices.length} eingeschriebene Gerät(e)</p>
                      </div>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '10px 14px', borderRadius: 8, border: `1.5px solid ${applyTargetMode === 'specific' ? '#006FFF' : 'var(--border, rgba(255,255,255,0.07))'}`, background: applyTargetMode === 'specific' ? 'rgba(0,111,255,0.08)' : 'var(--bg-surface-raised, #1c2128)' }}>
                      <input
                        type="radio"
                        name="applyTarget"
                        value="specific"
                        checked={applyTargetMode === 'specific'}
                        onChange={() => setApplyTargetMode('specific')}
                      />
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)' }}>Bestimmte Geräte</p>
                        <p style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)' }}>Geräte manuell auswählen</p>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Device checklist for specific mode */}
                {applyTargetMode === 'specific' && (
                  <div>
                    <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 8 }}>
                      Geräte auswählen {selectedDeviceIds.length > 0 && `(${selectedDeviceIds.length} ausgewählt)`}
                    </label>
                    {mdmDevices.length === 0 ? (
                      <p style={{ fontSize: 13, color: 'var(--text-muted, #6e7681)', padding: '12px 0' }}>Keine eingeschriebenen Geräte gefunden</p>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 200, overflowY: 'auto', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: 8 }}>
                        {mdmDevices.map(dev => (
                          <label key={dev.udid} style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '7px 8px', borderRadius: 6, background: selectedDeviceIds.includes(dev.udid) ? 'rgba(0,111,255,0.08)' : 'transparent' }}>
                            <input
                              type="checkbox"
                              checked={selectedDeviceIds.includes(dev.udid)}
                              onChange={e => {
                                if (e.target.checked) {
                                  setSelectedDeviceIds(prev => [...prev, dev.udid]);
                                } else {
                                  setSelectedDeviceIds(prev => prev.filter(id => id !== dev.udid));
                                }
                              }}
                            />
                            <ComputerDesktopIcon className="w-4 h-4" style={{ color: 'var(--text-secondary, #8b949e)', flexShrink: 0 }} />
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {dev.device_name || dev.udid}
                              </p>
                              {dev.model && <p style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)' }}>{dev.model}</p>}
                            </div>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Affected count */}
                <div style={{ background: 'var(--bg-surface-raised, #1c2128)', borderRadius: 8, padding: '10px 14px', fontSize: 13, color: 'var(--text-secondary, #8b949e)' }}>
                  {applyTargetMode === 'all'
                    ? `${mdmDevices.length} Gerät(e) werden betroffen sein`
                    : `${selectedDeviceIds.length} Gerät(e) ausgewählt`
                  }
                </div>

                <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                  <button
                    onClick={closeApplyModal}
                    style={{ flex: 1, background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '10px 0', fontSize: 14, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', cursor: 'pointer' }}
                  >
                    Abbrechen
                  </button>
                  <button
                    onClick={handleMdmApply}
                    disabled={mdmApplying || (applyTargetMode === 'specific' && selectedDeviceIds.length === 0)}
                    style={{
                      flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                      background: mdmApplying || (applyTargetMode === 'specific' && selectedDeviceIds.length === 0) ? 'rgba(0,111,255,0.5)' : '#006FFF',
                      border: 'none', borderRadius: 8, padding: '10px 0',
                      fontSize: 14, fontWeight: 600, color: 'white',
                      cursor: mdmApplying || (applyTargetMode === 'specific' && selectedDeviceIds.length === 0) ? 'not-allowed' : 'pointer',
                    }}
                  >
                    <PlayIcon className="w-4 h-4" />
                    {mdmApplying ? 'Wird angewendet...' : 'Jetzt anwenden'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── Add Config Modal ────────────────────────────────────────────────────── */}
      {addConfigOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.5)', padding: 16 }}
          onClick={() => setAddConfigOpen(false)}
        >
          <div
            style={{
              background: 'var(--bg-surface, #161b22)', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 480,
              boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
              border: '1px solid var(--border, rgba(255,255,255,0.07))',
              maxHeight: '90vh', overflowY: 'auto',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>Konfiguration hinzufügen</h2>
              <button onClick={() => setAddConfigOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary, #8b949e)' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>Typ</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
                  {CONFIG_TYPES.map(ct => (
                    <button
                      key={ct.value}
                      onClick={() => handleConfigTypeChange(ct.value)}
                      style={{
                        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
                        padding: '10px 6px', borderRadius: 8,
                        border: `1.5px solid ${newConfigType === ct.value ? '#006FFF' : 'var(--border, rgba(255,255,255,0.07))'}`,
                        background: newConfigType === ct.value ? 'rgba(0,111,255,0.08)' : 'var(--bg-surface-raised, #1c2128)',
                        cursor: 'pointer', fontSize: 11, fontWeight: 500,
                        color: newConfigType === ct.value ? '#006FFF' : 'var(--text-primary, #e4e6ea)',
                      }}
                    >
                      <ConfigIcon type={ct.value} className="w-4 h-4" />
                      {ct.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>Konfigurationsname *</label>
                <input
                  style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
                  value={newConfigName}
                  onChange={e => setNewConfigName(e.target.value)}
                  placeholder={`z.B. ${CONFIG_TYPES.find(t => t.value === newConfigType)?.label} Konfiguration`}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 8 }}>Einstellungen</label>
                <div style={{ background: 'var(--bg-surface-raised, #1c2128)', borderRadius: 10, padding: '14px 14px', border: '1px solid var(--border, rgba(255,255,255,0.07))' }}>
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
                  flex: 1, background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8,
                  padding: '10px 0', fontSize: 14, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', cursor: 'pointer',
                }}
              >
                Abbrechen
              </button>
              <button
                onClick={handleAddConfig}
                disabled={addingConfig || !newConfigName.trim()}
                style={{
                  flex: 1, background: addingConfig || !newConfigName.trim() ? 'rgba(0,111,255,0.5)' : '#006FFF',
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
          style={{ background: 'rgba(0,0,0,0.5)', padding: 16 }}
          onClick={() => setAssignOpen(false)}
        >
          <div
            style={{
              background: 'var(--bg-surface, #161b22)', borderRadius: 16, padding: 28,
              width: '100%', maxWidth: 400,
              boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
              border: '1px solid var(--border, rgba(255,255,255,0.07))',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary, #e4e6ea)' }}>Gerät zuweisen</h2>
              <button onClick={() => setAssignOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary, #8b949e)' }}>
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>Zieltyp</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  {(['device', 'group'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => setAssignTargetType(t)}
                      style={{
                        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                        padding: '8px 0', borderRadius: 8,
                        border: `1.5px solid ${assignTargetType === t ? '#006FFF' : 'var(--border, rgba(255,255,255,0.07))'}`,
                        background: assignTargetType === t ? 'rgba(0,111,255,0.08)' : 'var(--bg-surface-raised, #1c2128)',
                        cursor: 'pointer', fontSize: 13, fontWeight: 500,
                        color: assignTargetType === t ? '#006FFF' : 'var(--text-primary, #e4e6ea)',
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
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>
                  {assignTargetType === 'device' ? 'Geräte-ID' : 'Gruppen-ID'}
                </label>
                <input
                  autoFocus
                  style={{ width: '100%', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none', background: 'var(--bg-surface-raised, #1c2128)', color: 'var(--text-primary, #e4e6ea)', boxSizing: 'border-box' }}
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
                  flex: 1, background: 'var(--bg-surface-raised, #1c2128)', border: '1px solid var(--border, rgba(255,255,255,0.07))', borderRadius: 8,
                  padding: '10px 0', fontSize: 14, fontWeight: 500, color: 'var(--text-primary, #e4e6ea)', cursor: 'pointer',
                }}
              >
                Abbrechen
              </button>
              <button
                onClick={handleAssign}
                disabled={assigning || !assignTargetId.trim()}
                style={{
                  flex: 1, background: assigning || !assignTargetId.trim() ? 'rgba(0,111,255,0.5)' : '#006FFF',
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
