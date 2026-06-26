'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  MagnifyingGlassIcon,
  ArrowPathIcon,
  TrashIcon,
  XMarkIcon,
  CpuChipIcon,
  CloudArrowUpIcon,
  ChevronDownIcon,
  ChevronUpIcon,
} from '@heroicons/react/24/outline';

// ─── API ────────────────────────────────────────────────────────────────────────

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '').replace(/\/$/, '');

// ─── Types ──────────────────────────────────────────────────────────────────────

interface DeviceDriverDeployment {
  id: string;
  deviceId: string;
  status: 'pending' | 'deploying' | 'success' | 'failed';
  deployedAt: string;
  error: string | null;
}

interface DeviceDriver {
  id: string;
  name: string;
  version: string;
  vendor: string;
  os: 'linux' | 'windows' | 'macos' | 'universal';
  deviceType: 'network' | 'storage' | 'display' | 'usb' | 'audio' | 'printer' | 'other';
  format: 'deb' | 'rpm' | 'pkg' | 'exe' | 'msi' | 'zip' | 'inf';
  architecture: 'x86_64' | 'arm64' | 'universal';
  description: string;
  filename: string;
  fileSize: number;
  checksum: string;
  tags: string[];
  deployments: DeviceDriverDeployment[];
  uploadedAt: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val % 1 === 0 ? val : val.toFixed(1)} ${units[i]}`;
}

function formatDate(ds: string): string {
  if (!ds) return '—';
  try {
    return new Date(ds).toLocaleString('de-CH', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return ds; }
}

// ─── Badge components ───────────────────────────────────────────────────────────

const OS_BADGE: Record<DeviceDriver['os'], string> = {
  linux:     'bg-green-100 text-green-700',
  windows:   'bg-blue-100 text-blue-700',
  macos:     'bg-gray-100 text-gray-700',
  universal: 'bg-purple-100 text-purple-700',
};

const OS_LABEL: Record<DeviceDriver['os'], string> = {
  linux:     'Linux',
  windows:   'Windows',
  macos:     'macOS',
  universal: 'Universal',
};

const DEVICE_TYPE_BADGE: Record<DeviceDriver['deviceType'], string> = {
  network: 'bg-indigo-100 text-indigo-700',
  storage: 'bg-amber-100 text-amber-700',
  display: 'bg-cyan-100 text-cyan-700',
  usb:     'bg-orange-100 text-orange-700',
  audio:   'bg-teal-100 text-teal-700',
  printer: 'bg-rose-100 text-rose-700',
  other:   'bg-gray-100 text-gray-600',
};

const DEVICE_TYPE_LABEL: Record<DeviceDriver['deviceType'], string> = {
  network: 'Netzwerk',
  storage: 'Speicher',
  display: 'Anzeige',
  usb:     'USB',
  audio:   'Audio',
  printer: 'Drucker',
  other:   'Sonstiges',
};

const DEPLOY_STATUS_BADGE: Record<DeviceDriverDeployment['status'], string> = {
  pending:   'bg-gray-100 text-gray-600',
  deploying: 'bg-blue-100 text-blue-700',
  success:   'bg-green-100 text-green-700',
  failed:    'bg-red-100 text-red-700',
};

const DEPLOY_STATUS_LABEL: Record<DeviceDriverDeployment['status'], string> = {
  pending:   'Ausstehend',
  deploying: 'Wird deployed',
  success:   'Erfolgreich',
  failed:    'Fehlgeschlagen',
};

function OsBadge({ os }: { os: DeviceDriver['os'] }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${OS_BADGE[os]}`}>
      {OS_LABEL[os]}
    </span>
  );
}

function DeviceTypeBadge({ type }: { type: DeviceDriver['deviceType'] }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${DEVICE_TYPE_BADGE[type]}`}>
      {DEVICE_TYPE_LABEL[type]}
    </span>
  );
}

function FormatBadge({ format }: { format: string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-700">
      {format}
    </span>
  );
}

// ─── Skeleton ───────────────────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <tr className="animate-pulse border-b border-gray-50">
      {[...Array(9)].map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-gray-200 rounded w-full" />
        </td>
      ))}
    </tr>
  );
}

// ─── Deploy Status Row ──────────────────────────────────────────────────────────

function DeploymentStatusPanel({ deployments }: { deployments: DeviceDriverDeployment[] }) {
  if (!deployments || deployments.length === 0) {
    return (
      <div className="px-6 py-3 bg-gray-50 text-xs text-gray-400 italic border-b border-gray-100">
        Noch keine Deployments vorhanden.
      </div>
    );
  }
  return (
    <div className="px-6 py-3 bg-gray-50 border-b border-gray-100">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Deployment-Status</p>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-400">
            <th className="text-left pb-1 font-medium">Gerät-ID</th>
            <th className="text-left pb-1 font-medium">Status</th>
            <th className="text-left pb-1 font-medium">Zeitpunkt</th>
            <th className="text-left pb-1 font-medium">Fehler</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {deployments.map(dep => (
            <tr key={dep.id}>
              <td className="py-1.5 font-mono text-gray-700 pr-4">{dep.deviceId}</td>
              <td className="py-1.5 pr-4">
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-medium ${DEPLOY_STATUS_BADGE[dep.status]}`}>
                  {dep.status === 'deploying' && (
                    <ArrowPathIcon className="w-3 h-3 animate-spin" />
                  )}
                  {DEPLOY_STATUS_LABEL[dep.status]}
                </span>
              </td>
              <td className="py-1.5 text-gray-500 pr-4">{formatDate(dep.deployedAt)}</td>
              <td className="py-1.5 text-red-500">{dep.error || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Deploy Panel ───────────────────────────────────────────────────────────────

function DeployPanel({ driverId, onDeployed }: { driverId: string; onDeployed: () => void }) {
  const [deviceIds, setDeviceIds] = useState('');
  const [deploying, setDeploying] = useState(false);
  const [error, setError]         = useState<string | null>(null);
  const [success, setSuccess]     = useState(false);

  const handleDeploy = async () => {
    const ids = deviceIds.split(',').map(s => s.trim()).filter(Boolean);
    if (ids.length === 0) {
      setError('Bitte mindestens eine Geräte-ID eingeben.');
      return;
    }
    setDeploying(true);
    setError(null);
    setSuccess(false);
    try {
      const res = await fetch(`${API_BASE}/api/devices/drivers/${driverId}/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceIds: ids }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setSuccess(true);
      setDeviceIds('');
      onDeployed();
    } catch (e: any) {
      setError(e.message || 'Deployment fehlgeschlagen');
    } finally {
      setDeploying(false);
    }
  };

  return (
    <div className="px-6 py-4 bg-blue-50 border-b border-blue-100">
      <p className="text-xs font-semibold text-blue-700 uppercase tracking-wider mb-2">Treiber deployen</p>
      <div className="flex items-center gap-3">
        <input
          type="text"
          placeholder="Geräte-IDs (kommagetrennt)"
          value={deviceIds}
          onChange={e => { setDeviceIds(e.target.value); setError(null); setSuccess(false); }}
          className="flex-1 px-3 py-2 text-sm border border-blue-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
        />
        <button
          onClick={handleDeploy}
          disabled={deploying}
          className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-60"
        >
          {deploying ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <CloudArrowUpIcon className="w-4 h-4" />}
          {deploying ? 'Wird deployed…' : 'Jetzt deployen'}
        </button>
      </div>
      {error   && <p className="mt-2 text-xs text-red-600">{error}</p>}
      {success && <p className="mt-2 text-xs text-green-600">Deployment erfolgreich gestartet.</p>}
    </div>
  );
}

// ─── Upload Form ────────────────────────────────────────────────────────────────

interface UploadFormData {
  name: string;
  version: string;
  vendor: string;
  os: DeviceDriver['os'];
  deviceType: DeviceDriver['deviceType'];
  format: DeviceDriver['format'];
  architecture: DeviceDriver['architecture'];
  description: string;
  file: File | null;
}

const EMPTY_FORM: UploadFormData = {
  name: '',
  version: '',
  vendor: '',
  os: 'linux',
  deviceType: 'network',
  format: 'deb',
  architecture: 'x86_64',
  description: '',
  file: null,
};

function UploadForm({ onUploaded, onCancel }: { onUploaded: () => void; onCancel: () => void }) {
  const [form, setForm]         = useState<UploadFormData>(EMPTY_FORM);
  const [uploading, setUploading] = useState(false);
  const [error, setError]       = useState<string | null>(null);

  const set = (field: keyof UploadFormData, value: any) =>
    setForm(prev => ({ ...prev, [field]: value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) { setError('Name ist erforderlich.'); return; }
    if (!form.vendor.trim()) { setError('Anbieter ist erforderlich.'); return; }
    if (!form.file) { setError('Bitte eine Datei auswählen.'); return; }

    setUploading(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('name', form.name.trim());
      fd.append('version', form.version.trim() || '1.0.0');
      fd.append('vendor', form.vendor.trim());
      fd.append('os', form.os);
      fd.append('deviceType', form.deviceType);
      fd.append('format', form.format);
      fd.append('architecture', form.architecture);
      fd.append('description', form.description.trim());
      fd.append('driver', form.file);

      const res = await fetch(`${API_BASE}/api/devices/drivers/upload`, {
        method: 'POST',
        body: fd,
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setForm(EMPTY_FORM);
      onUploaded();
    } catch (e: any) {
      setError(e.message || 'Upload fehlgeschlagen');
    } finally {
      setUploading(false);
    }
  };

  const fieldClass = "w-full px-3 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white";
  const labelClass = "block text-xs font-medium text-gray-600 mb-1";

  return (
    <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-6">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <CloudArrowUpIcon className="w-5 h-5 text-blue-600" />
          <h3 className="text-base font-semibold text-gray-900">Treiber hochladen</h3>
        </div>
        <button onClick={onCancel} className="text-gray-400 hover:text-gray-600">
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Row 1: Name, Version, Anbieter */}
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className={labelClass}>Name <span className="text-red-500">*</span></label>
            <input
              type="text"
              required
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="z.B. Realtek NIC Driver"
              className={fieldClass}
            />
          </div>
          <div>
            <label className={labelClass}>Version</label>
            <input
              type="text"
              value={form.version}
              onChange={e => set('version', e.target.value)}
              placeholder="1.0.0"
              className={fieldClass}
            />
          </div>
          <div>
            <label className={labelClass}>Anbieter <span className="text-red-500">*</span></label>
            <input
              type="text"
              required
              value={form.vendor}
              onChange={e => set('vendor', e.target.value)}
              placeholder="z.B. Realtek"
              className={fieldClass}
            />
          </div>
        </div>

        {/* Row 2: OS, Gerätetyp, Format, Architektur */}
        <div className="grid grid-cols-4 gap-4">
          <div>
            <label className={labelClass}>Betriebssystem</label>
            <select value={form.os} onChange={e => set('os', e.target.value as DeviceDriver['os'])} className={fieldClass}>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="universal">Universal</option>
            </select>
          </div>
          <div>
            <label className={labelClass}>Gerätetyp</label>
            <select value={form.deviceType} onChange={e => set('deviceType', e.target.value as DeviceDriver['deviceType'])} className={fieldClass}>
              <option value="network">Netzwerk</option>
              <option value="storage">Speicher</option>
              <option value="display">Anzeige</option>
              <option value="usb">USB</option>
              <option value="audio">Audio</option>
              <option value="printer">Drucker</option>
              <option value="other">Sonstiges</option>
            </select>
          </div>
          <div>
            <label className={labelClass}>Format</label>
            <select value={form.format} onChange={e => set('format', e.target.value as DeviceDriver['format'])} className={fieldClass}>
              <option value="deb">deb</option>
              <option value="rpm">rpm</option>
              <option value="pkg">pkg</option>
              <option value="exe">exe</option>
              <option value="msi">msi</option>
              <option value="zip">zip</option>
              <option value="inf">inf</option>
            </select>
          </div>
          <div>
            <label className={labelClass}>Architektur</label>
            <select value={form.architecture} onChange={e => set('architecture', e.target.value as DeviceDriver['architecture'])} className={fieldClass}>
              <option value="x86_64">x86_64</option>
              <option value="arm64">arm64</option>
              <option value="universal">universal</option>
            </select>
          </div>
        </div>

        {/* Row 3: Beschreibung */}
        <div>
          <label className={labelClass}>Beschreibung</label>
          <textarea
            value={form.description}
            onChange={e => set('description', e.target.value)}
            placeholder="Optionale Beschreibung des Treibers…"
            rows={2}
            className={`${fieldClass} resize-none`}
          />
        </div>

        {/* Row 4: Datei */}
        <div>
          <label className={labelClass}>Datei <span className="text-red-500">*</span></label>
          <input
            type="file"
            onChange={e => set('file', e.target.files?.[0] ?? null)}
            className="w-full text-sm text-gray-600 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 file:transition-colors"
          />
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>
        )}

        <div className="flex items-center justify-end gap-3 pt-1">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
          >
            Abbrechen
          </button>
          <button
            type="submit"
            disabled={uploading}
            className="flex items-center gap-2 px-5 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-60"
          >
            {uploading ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <CloudArrowUpIcon className="w-4 h-4" />}
            {uploading ? 'Wird hochgeladen…' : 'Hochladen'}
          </button>
        </div>
      </form>
    </div>
  );
}

// ─── Driver Row ─────────────────────────────────────────────────────────────────

function DriverRow({ driver, onDelete, onDeployed }: {
  driver: DeviceDriver;
  onDelete: (id: string) => void;
  onDeployed: () => void;
}) {
  const [showDeploy, setShowDeploy]       = useState(false);
  const [showStatus, setShowStatus]       = useState(false);
  const [deleting, setDeleting]           = useState(false);

  const handleDelete = async () => {
    if (!window.confirm(`Treiber "${driver.name}" wirklich löschen?`)) return;
    setDeleting(true);
    try {
      await fetch(`${API_BASE}/api/devices/drivers/${driver.id}`, { method: 'DELETE' });
      onDelete(driver.id);
    } catch {
      setDeleting(false);
    }
  };

  return (
    <>
      <tr className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
        <td className="px-4 py-3">
          <div>
            <p className="text-sm font-medium text-gray-900">{driver.name}</p>
            {driver.filename && (
              <p className="text-xs text-gray-400 font-mono truncate max-w-[160px]">{driver.filename}</p>
            )}
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="text-sm text-gray-700 font-mono">{driver.version || '—'}</span>
        </td>
        <td className="px-4 py-3">
          <span className="text-sm text-gray-600">{driver.vendor || '—'}</span>
        </td>
        <td className="px-4 py-3">
          <OsBadge os={driver.os} />
        </td>
        <td className="px-4 py-3">
          <DeviceTypeBadge type={driver.deviceType} />
        </td>
        <td className="px-4 py-3">
          <FormatBadge format={driver.format} />
        </td>
        <td className="px-4 py-3">
          <span className="text-xs text-gray-600 font-mono">{driver.architecture || '—'}</span>
        </td>
        <td className="px-4 py-3">
          <span className="text-xs text-gray-500">{formatBytes(driver.fileSize)}</span>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5">
            {/* Deploy toggle */}
            <button
              onClick={() => { setShowDeploy(prev => !prev); setShowStatus(false); }}
              className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors"
            >
              <CloudArrowUpIcon className="w-3.5 h-3.5" />
              Deployen
              {showDeploy ? <ChevronUpIcon className="w-3 h-3" /> : <ChevronDownIcon className="w-3 h-3" />}
            </button>
            {/* Status toggle */}
            {driver.deployments && driver.deployments.length > 0 && (
              <button
                onClick={() => { setShowStatus(prev => !prev); setShowDeploy(false); }}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Status
                <span className="ml-0.5 bg-gray-200 text-gray-700 text-xs px-1.5 rounded-full">
                  {driver.deployments.length}
                </span>
              </button>
            )}
            {/* Delete */}
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors disabled:opacity-50"
            >
              <TrashIcon className="w-3.5 h-3.5" />
              {deleting ? '…' : 'Löschen'}
            </button>
          </div>
        </td>
      </tr>

      {/* Inline panels spanning full width */}
      {showDeploy && (
        <tr>
          <td colSpan={9} className="p-0">
            <DeployPanel
              driverId={driver.id}
              onDeployed={() => { setShowDeploy(false); onDeployed(); }}
            />
          </td>
        </tr>
      )}
      {showStatus && (
        <tr>
          <td colSpan={9} className="p-0">
            <DeploymentStatusPanel deployments={driver.deployments} />
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Main Tab Component ─────────────────────────────────────────────────────────

export default function DeviceDriversTab() {
  const [drivers,       setDrivers]       = useState<DeviceDriver[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [showUpload,    setShowUpload]    = useState(false);
  const [osFilter,      setOsFilter]      = useState<'all' | DeviceDriver['os']>('all');
  const [typeFilter,    setTypeFilter]    = useState<'all' | DeviceDriver['deviceType']>('all');
  const [searchTerm,    setSearchTerm]    = useState('');

  const loadDrivers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/devices/drivers`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setDrivers(Array.isArray(data) ? data : (data.data ?? data.drivers ?? []));
    } catch {
      setDrivers([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDrivers(); }, [loadDrivers]);

  const handleDelete = (id: string) => setDrivers(prev => prev.filter(d => d.id !== id));

  const filtered = drivers.filter(d => {
    if (osFilter   !== 'all' && d.os         !== osFilter)   return false;
    if (typeFilter !== 'all' && d.deviceType !== typeFilter) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      if (
        !d.name?.toLowerCase().includes(q) &&
        !d.vendor?.toLowerCase().includes(q) &&
        !d.filename?.toLowerCase().includes(q)
      ) return false;
    }
    return true;
  });

  return (
    <div className="space-y-5">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            <CpuChipIcon className="w-5 h-5 text-blue-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Geräte-Treiber</h2>
            {!loading && (
              <p className="text-xs text-gray-400">{drivers.length} Treiber verfügbar</p>
            )}
          </div>
        </div>
        <button
          onClick={() => setShowUpload(prev => !prev)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
        >
          <CloudArrowUpIcon className="w-4 h-4" />
          Treiber hochladen
        </button>
      </div>

      {/* Upload form (collapsible) */}
      {showUpload && (
        <UploadForm
          onUploaded={() => { setShowUpload(false); loadDrivers(); }}
          onCancel={() => setShowUpload(false)}
        />
      )}

      {/* Filter bar */}
      <div className="flex items-center gap-4 flex-wrap">
        {/* OS filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-gray-500 font-medium">BS:</span>
          {(['all', 'linux', 'windows', 'macos', 'universal'] as const).map(os => (
            <button
              key={os}
              onClick={() => setOsFilter(os)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                osFilter === os
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'
              }`}
            >
              {os === 'all' ? 'Alle' : OS_LABEL[os as DeviceDriver['os']]}
            </button>
          ))}
        </div>

        {/* Device type filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-gray-500 font-medium">Gerätetyp:</span>
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value as typeof typeFilter)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white text-gray-700"
          >
            <option value="all">Alle</option>
            <option value="network">Netzwerk</option>
            <option value="storage">Speicher</option>
            <option value="display">Anzeige</option>
            <option value="usb">USB</option>
            <option value="audio">Audio</option>
            <option value="printer">Drucker</option>
            <option value="other">Sonstiges</option>
          </select>
        </div>

        {/* Search */}
        <div className="relative ml-auto">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Treiber suchen…"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="pl-9 pr-4 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent w-52"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr>
                {['Name', 'Version', 'Anbieter', 'BS', 'Gerätetyp', 'Format', 'Architektur', 'Grösse', 'Aktionen'].map(col => (
                  <th key={col} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <><SkeletonRow /><SkeletonRow /><SkeletonRow /></>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-16 text-center">
                    <CpuChipIcon className="mx-auto w-12 h-12 text-gray-300 mb-3" />
                    {drivers.length === 0 ? (
                      <>
                        <p className="text-sm font-medium text-gray-900 mb-1">Noch keine Geräte-Treiber vorhanden</p>
                        <p className="text-xs text-gray-500 mb-4">Laden Sie den ersten Treiber hoch, um zu beginnen.</p>
                        <button
                          onClick={() => setShowUpload(true)}
                          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                        >
                          <CloudArrowUpIcon className="w-4 h-4" />
                          Treiber hochladen
                        </button>
                      </>
                    ) : (
                      <p className="text-sm text-gray-500">Keine Treiber entsprechen den Filterkriterien.</p>
                    )}
                  </td>
                </tr>
              ) : (
                filtered.map(driver => (
                  <DriverRow
                    key={driver.id}
                    driver={driver}
                    onDelete={handleDelete}
                    onDeployed={loadDrivers}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
