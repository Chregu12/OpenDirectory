'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  ArrowPathIcon,
  TrashIcon,
  XMarkIcon,
  ArrowUpTrayIcon,
  CircleStackIcon,
} from '@heroicons/react/24/outline';

// ─── Types ────────────────────────────────────────────────────────────────────

interface PrinterDriver {
  id: string;
  name: string;
  version: string;
  vendor: string;
  os: 'linux' | 'windows' | 'macos' | 'universal';
  format: 'ppd' | 'inf' | 'cab' | 'pkg' | 'zip';
  models: string[];
  filename: string;
  fileSize: number;
  assignedPrinters: string[];
  uploadedAt: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '').replace(/\/$/, '');

const OS_LABELS: Record<PrinterDriver['os'], string> = {
  linux:     'Linux',
  windows:   'Windows',
  macos:     'macOS',
  universal: 'Universal',
};

const OS_BADGE_STYLES: Record<PrinterDriver['os'], string> = {
  linux:     'bg-green-100 text-green-700',
  windows:   'bg-blue-100 text-blue-700',
  macos:     'bg-gray-100 text-gray-700',
  universal: 'bg-purple-100 text-purple-700',
};

const FORMAT_BADGE_STYLES: Record<PrinterDriver['format'], string> = {
  ppd: 'bg-teal-100 text-teal-700',
  inf: 'bg-indigo-100 text-indigo-700',
  cab: 'bg-orange-100 text-orange-700',
  pkg: 'bg-pink-100 text-pink-700',
  zip: 'bg-yellow-100 text-yellow-700',
};

// Default format per OS
const OS_DEFAULT_FORMAT: Record<PrinterDriver['os'], PrinterDriver['format']> = {
  linux:     'ppd',
  windows:   'inf',
  macos:     'pkg',
  universal: 'zip',
};

// Accepted file extensions per format
const FORMAT_ACCEPT: Record<PrinterDriver['format'], string> = {
  ppd: '.ppd',
  inf: '.inf',
  cab: '.cab',
  pkg: '.pkg',
  zip: '.zip',
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('de-CH', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function OsBadge({ os }: { os: PrinterDriver['os'] }) {
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${OS_BADGE_STYLES[os]}`}>
      {OS_LABELS[os]}
    </span>
  );
}

function FormatBadge({ format }: { format: PrinterDriver['format'] }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${FORMAT_BADGE_STYLES[format]}`}>
      {format}
    </span>
  );
}

function SkeletonRow() {
  return (
    <tr>
      {Array.from({ length: 9 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-gray-200 rounded animate-pulse" style={{ width: i === 0 ? '60%' : i === 5 ? '40%' : '70%' }} />
        </td>
      ))}
    </tr>
  );
}

// ─── Upload Form ──────────────────────────────────────────────────────────────

interface UploadFormProps {
  onUploaded: (driver: PrinterDriver) => void;
  onCancel: () => void;
}

function UploadForm({ onUploaded, onCancel }: UploadFormProps) {
  const fileRef = useRef<HTMLInputElement>(null);

  const [name, setName]         = useState('');
  const [version, setVersion]   = useState('');
  const [vendor, setVendor]     = useState('');
  const [os, setOs]             = useState<PrinterDriver['os']>('linux');
  const [format, setFormat]     = useState<PrinterDriver['format']>('ppd');
  const [models, setModels]     = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError]       = useState<string | null>(null);

  // Auto-set format when OS changes
  const handleOsChange = (newOs: PrinterDriver['os']) => {
    setOs(newOs);
    setFormat(OS_DEFAULT_FORMAT[newOs]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!name.trim()) { setError('Bitte einen Namen eingeben.'); return; }
    if (!vendor.trim()) { setError('Bitte einen Anbieter eingeben.'); return; }
    const file = fileRef.current?.files?.[0];
    if (!file) { setError('Bitte eine Treiber-Datei auswählen.'); return; }

    setUploading(true);
    try {
      const fd = new FormData();
      fd.append('name', name.trim());
      fd.append('version', version.trim() || '1.0.0');
      fd.append('vendor', vendor.trim());
      fd.append('os', os);
      fd.append('format', format);
      fd.append('models', models.trim());
      fd.append('driver', file);

      const res = await fetch(`${API_BASE}/api/printer/drivers/upload`, {
        method: 'POST',
        body: fd,
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.error ?? `Fehler ${res.status}`);
      }

      const driver: PrinterDriver = await res.json();
      onUploaded(driver);
    } catch (err: any) {
      setError(err?.message ?? 'Upload fehlgeschlagen.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="border-2 border-blue-200 rounded-xl p-5 bg-blue-50/30 space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-blue-700">Treiber hochladen</p>
        <button
          type="button"
          onClick={onCancel}
          className="text-gray-400 hover:text-gray-600"
        >
          <XMarkIcon className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          {/* Name */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white"
              placeholder="HP Universal PCL6"
              autoFocus
            />
          </div>
          {/* Version */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Version</label>
            <input
              value={version}
              onChange={e => setVersion(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white"
              placeholder="1.0.0"
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {/* Vendor */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Anbieter *</label>
            <input
              value={vendor}
              onChange={e => setVendor(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white"
              placeholder="HP"
            />
          </div>
          {/* OS */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Betriebssystem</label>
            <select
              value={os}
              onChange={e => handleOsChange(e.target.value as PrinterDriver['os'])}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white"
            >
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="universal">Universal</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {/* Format */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Format</label>
            <select
              value={format}
              onChange={e => setFormat(e.target.value as PrinterDriver['format'])}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white"
            >
              <option value="ppd">PPD</option>
              <option value="inf">INF</option>
              <option value="cab">CAB</option>
              <option value="pkg">PKG</option>
              <option value="zip">ZIP</option>
            </select>
          </div>
          {/* File */}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Datei *</label>
            <input
              ref={fileRef}
              type="file"
              accept={FORMAT_ACCEPT[format]}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white file:mr-2 file:text-xs file:font-medium file:border-0 file:bg-blue-50 file:text-blue-700 file:rounded file:px-2 file:py-0.5"
            />
          </div>
        </div>

        {/* Compatible models */}
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Kompatible Modelle (kommagetrennt)</label>
          <input
            value={models}
            onChange={e => setModels(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 bg-white"
            placeholder="HP LaserJet 4000, HP LaserJet 4050"
          />
        </div>

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg"
          >
            Abbrechen
          </button>
          <button
            type="submit"
            disabled={uploading}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50"
          >
            {uploading
              ? <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Hochladen…</>
              : <><ArrowUpTrayIcon className="w-4 h-4" /> Hochladen</>
            }
          </button>
        </div>
      </form>
    </div>
  );
}

// ─── Main Tab Component ───────────────────────────────────────────────────────

export default function PrinterDriversTab() {
  const [drivers, setDrivers]         = useState<PrinterDriver[]>([]);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState<string | null>(null);
  const [showUpload, setShowUpload]   = useState(false);
  const [deletingId, setDeletingId]   = useState<string | null>(null);

  const loadDrivers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/printer/drivers`);
      if (!res.ok) throw new Error(`Fehler ${res.status}`);
      const data = await res.json();
      setDrivers(Array.isArray(data) ? data : (data?.drivers ?? data?.data ?? []));
    } catch (err: any) {
      setError(err?.message ?? 'Treiber konnten nicht geladen werden.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDrivers(); }, [loadDrivers]);

  const handleDelete = async (driver: PrinterDriver) => {
    if (!window.confirm(`Treiber "${driver.name}" (${driver.filename}) wirklich löschen?`)) return;
    setDeletingId(driver.id);
    try {
      const res = await fetch(`${API_BASE}/api/printer/drivers/${driver.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.error ?? `Fehler ${res.status}`);
      }
      setDrivers(prev => prev.filter(d => d.id !== driver.id));
    } catch (err: any) {
      // Surface error inline — no toast dependency
      setError(err?.message ?? 'Treiber konnte nicht gelöscht werden.');
    } finally {
      setDeletingId(null);
    }
  };

  const handleUploaded = (driver: PrinterDriver) => {
    setDrivers(prev => [driver, ...prev]);
    setShowUpload(false);
  };

  return (
    <div className="space-y-4">

      {/* Section header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-500">Verwalte Druckertreiber für alle Betriebssysteme.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadDrivers}
            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
            title="Aktualisieren"
          >
            <ArrowPathIcon className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          {!showUpload && (
            <button
              onClick={() => setShowUpload(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg"
            >
              <ArrowUpTrayIcon className="w-4 h-4" />
              Treiber hochladen
            </button>
          )}
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center justify-between p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-600 ml-4">
            <XMarkIcon className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Upload form (inline panel) */}
      {showUpload && (
        <UploadForm
          onUploaded={handleUploaded}
          onCancel={() => setShowUpload(false)}
        />
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                {['Name', 'Version', 'Anbieter', 'BS', 'Format', 'Modelle', 'Zugewiesen', 'Hochgeladen', 'Aktionen'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              <SkeletonRow />
              <SkeletonRow />
              <SkeletonRow />
            </tbody>
          </table>
        </div>
      )}

      {/* Empty state */}
      {!loading && drivers.length === 0 && !error && (
        <div className="flex flex-col items-center justify-center py-16 text-center text-gray-400 space-y-3">
          <CircleStackIcon className="w-12 h-12 opacity-30" />
          <div>
            <p className="font-medium text-gray-600">Noch keine Treiber hochgeladen</p>
            <p className="text-sm mt-1 max-w-xs">Lade einen Druckertreiber hoch, um ihn Druckern zuweisen zu können.</p>
          </div>
          {!showUpload && (
            <button
              onClick={() => setShowUpload(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg mt-2"
            >
              <ArrowUpTrayIcon className="w-4 h-4" />
              Treiber hochladen
            </button>
          )}
        </div>
      )}

      {/* Driver table */}
      {!loading && drivers.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                {['Name', 'Version', 'Anbieter', 'BS', 'Format', 'Modelle', 'Zugewiesen', 'Hochgeladen', 'Aktionen'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {drivers.map(driver => (
                <tr key={driver.id} className="hover:bg-gray-50">

                  {/* Name */}
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900 truncate max-w-[180px]" title={driver.name}>
                      {driver.name}
                    </div>
                    <div className="text-xs text-gray-400 truncate max-w-[180px]" title={driver.filename}>
                      {driver.filename}
                      {driver.fileSize > 0 && <span className="ml-1 text-gray-300">· {fmtBytes(driver.fileSize)}</span>}
                    </div>
                  </td>

                  {/* Version */}
                  <td className="px-4 py-3 text-gray-600 whitespace-nowrap">
                    {driver.version || '—'}
                  </td>

                  {/* Vendor */}
                  <td className="px-4 py-3 text-gray-600 whitespace-nowrap">
                    {driver.vendor || '—'}
                  </td>

                  {/* OS badge */}
                  <td className="px-4 py-3 whitespace-nowrap">
                    <OsBadge os={driver.os} />
                  </td>

                  {/* Format badge */}
                  <td className="px-4 py-3 whitespace-nowrap">
                    <FormatBadge format={driver.format} />
                  </td>

                  {/* Compatible models */}
                  <td className="px-4 py-3 max-w-[180px]">
                    {driver.models && driver.models.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {driver.models.slice(0, 2).map(m => (
                          <span key={m} className="px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded text-xs truncate max-w-[120px]" title={m}>
                            {m}
                          </span>
                        ))}
                        {driver.models.length > 2 && (
                          <span className="px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded text-xs">
                            +{driver.models.length - 2}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>

                  {/* Assigned printers */}
                  <td className="px-4 py-3 whitespace-nowrap">
                    {driver.assignedPrinters && driver.assignedPrinters.length > 0 ? (
                      <span className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded-full text-xs font-medium">
                        {driver.assignedPrinters.length}
                      </span>
                    ) : (
                      <span className="text-gray-400 text-xs">—</span>
                    )}
                  </td>

                  {/* Uploaded at */}
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {driver.uploadedAt ? fmtDate(driver.uploadedAt) : '—'}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDelete(driver)}
                      disabled={deletingId === driver.id}
                      className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-40"
                      title="Treiber löschen"
                    >
                      {deletingId === driver.id
                        ? <ArrowPathIcon className="w-4 h-4 animate-spin" />
                        : <TrashIcon className="w-4 h-4" />
                      }
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
