'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowPathIcon,
  ArrowUpTrayIcon,
  BookOpenIcon,
  TrashIcon,
  CpuChipIcon,
  MagnifyingGlassIcon,
  SparklesIcon,
  CloudArrowDownIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import { DriverCatalogBrowser } from '@/components/drivers';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface DeviceDriver {
  id: string;
  name: string;
  version?: string;
  vendor?: string;
  deviceType?: string;
  format?: string;
  os?: string[] | string;
  architecture?: string;
  uploadedAt?: string;
  source?: string;
}

interface DriverRecommendation {
  id: string;
  name: string;
  version?: string;
  vendor?: string;
  deviceType?: string;
  format?: string;
  os?: string[] | string;
  downloadUrl?: string;
  aptPackage?: string;
  matchScore?: number;
  matchedVia?: string;
  description?: string;
}

// Older driver records may store `os` as a plain string instead of an array.
function toOsList(os?: string[] | string): string[] {
  if (!os) return [];
  return Array.isArray(os) ? os : [os];
}

const DEVICE_TYPE_COLOR: Record<string, string> = {
  network:  'bg-blue-100 text-blue-700',
  display:  'bg-purple-100 text-purple-700',
  audio:    'bg-green-100 text-green-700',
  storage:  'bg-yellow-100 text-yellow-700',
  usb:      'bg-orange-100 text-orange-700',
  printer:  'bg-pink-100 text-pink-700',
  firmware: 'bg-red-100 text-red-700',
  other:    'bg-gray-100 text-gray-600',
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function DeviceDriversTab() {
  const [drivers, setDrivers]               = useState<DeviceDriver[]>([]);
  const [loading, setLoading]               = useState(true);
  const [driversError, setDriversError]     = useState(false);
  const [showCatalog, setShowCatalog]       = useState(false);
  const [uploading, setUploading]           = useState(false);
  const [deletingId, setDeletingId]         = useState<string | null>(null);

  // Recommendations panel state
  const [deviceSearch, setDeviceSearch]     = useState('');
  const [recs, setRecs]                     = useState<DriverRecommendation[] | null>(null);
  const [recsLoading, setRecsLoading]       = useState(false);
  const [importingId, setImportingId]       = useState<string | null>(null);
  const [importedIds, setImportedIds]       = useState<Set<string>>(new Set());

  // ── Load installed drivers ─────────────────────────────────────────────────

  const loadDrivers = useCallback(async () => {
    setLoading(true);
    setDriversError(false);
    try {
      const res = await api.get('/api/devices/drivers');
      const data = res.data?.drivers ?? res.data?.data ?? res.data ?? [];
      setDrivers(Array.isArray(data) ? data : []);
    } catch {
      setDrivers([]);
      setDriversError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDrivers(); }, [loadDrivers]);

  // ── Upload ─────────────────────────────────────────────────────────────────

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const form = new FormData();
      form.append('driver', file);
      await api.post('/api/devices/drivers/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      toast.success(`Treiber "${file.name}" hochgeladen`);
      await loadDrivers();
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Upload fehlgeschlagen');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  // ── Delete ─────────────────────────────────────────────────────────────────

  const handleDelete = async (driver: DeviceDriver) => {
    if (!confirm(`Treiber "${driver.name}" wirklich löschen?`)) return;
    setDeletingId(driver.id);
    try {
      await api.delete(`/api/devices/drivers/${driver.id}`);
      setDrivers(prev => prev.filter(d => d.id !== driver.id));
      toast.success(`Treiber "${driver.name}" gelöscht`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Löschen fehlgeschlagen');
    } finally {
      setDeletingId(null);
    }
  };

  // ── Catalog import callback ────────────────────────────────────────────────

  const handleCatalogImported = async (driverName: string) => {
    toast.success(`Treiber "${driverName}" importiert`);
    await loadDrivers();
  };

  // ── Fetch driver recommendations for a device ──────────────────────────────

  const fetchRecommendations = async () => {
    const hostname = deviceSearch.trim();
    if (!hostname) return;
    setRecsLoading(true);
    setRecs(null);
    try {
      const res = await api.get(
        `/api/devices/${encodeURIComponent(hostname)}/driver-recommendations`
      );
      setRecs(res.data?.recommendations ?? []);
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? err.message ?? 'Empfehlungen konnten nicht geladen werden');
      setRecs([]);
    } finally {
      setRecsLoading(false);
    }
  };

  // ── Import a recommended driver from its URL ───────────────────────────────

  const handleImportRecommended = async (rec: DriverRecommendation) => {
    if (!rec.downloadUrl) { toast.error('Kein Download-Link vorhanden'); return; }
    setImportingId(rec.id);
    try {
      await api.post('/api/devices/drivers/import-url', {
        url: rec.downloadUrl,
        name: rec.name,
        version: rec.version,
        vendor: rec.vendor,
        os: rec.os,
        deviceType: rec.deviceType,
        format: rec.format,
        description: rec.description,
      });
      setImportedIds(prev => new Set(prev).add(rec.id));
      toast.success(`"${rec.name}" importiert`);
      await loadDrivers();
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? err.message ?? 'Import fehlgeschlagen');
    } finally {
      setImportingId(null);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* ── Recommendations panel ── */}
      <div
        className="rounded-2xl border border-blue-100 bg-blue-50/60 p-5"
        aria-live="polite"
        aria-busy={recsLoading}
      >
        <div className="flex items-center gap-2 mb-3">
          <SparklesIcon className="w-5 h-5 text-blue-600" />
          <h3 className="text-sm font-semibold text-blue-900">Treiber-Empfehlungen für ein Gerät</h3>
        </div>
        <p className="text-xs text-blue-700 mb-3">
          Hostname eingeben — das System erkennt Hersteller und Modell automatisch beim Domain-Join und schlägt passende Treiber vor.
        </p>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <label htmlFor="device-driver-hostname" className="sr-only">Hostname für Treiber-Empfehlungen</label>
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
            <input
              id="device-driver-hostname"
              type="text"
              value={deviceSearch}
              onChange={e => setDeviceSearch(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && fetchRecommendations()}
              placeholder="Hostname eingeben, z.B. DESKTOP-AB1234"
              className="w-full pl-9 pr-3 py-2 text-sm border border-blue-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>
          <button
            onClick={fetchRecommendations}
            disabled={!deviceSearch.trim() || recsLoading}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg transition-colors"
          >
            {recsLoading ? (
              <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Suche…</>
            ) : (
              'Empfehlungen laden'
            )}
          </button>
        </div>

        {/* Recommendation results */}
        {recs !== null && (
          <div className="mt-4">
            {recs.length === 0 ? (
              <p className="text-sm text-blue-600 text-center py-4">
                Keine Empfehlungen gefunden. Das Gerät wurde möglicherweise noch nicht in die Domain aufgenommen oder das Hardware-Profil ist nicht vorhanden.
              </p>
            ) : (
              <div className="space-y-2">
                <p className="text-xs text-blue-600 font-medium">{recs.length} Treiber empfohlen:</p>
                <div className="border border-blue-200 rounded-xl overflow-hidden divide-y divide-blue-100 bg-white">
                  {recs.slice(0, 12).map(rec => {
                    const imported = importedIds.has(rec.id);
                    const importing = importingId === rec.id;
                    return (
                      <div key={rec.id} className="flex items-center gap-3 px-4 py-3">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 truncate" title={rec.name}>{rec.name}</p>
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            {rec.version && <span className="text-xs text-gray-400">v{rec.version}</span>}
                            {rec.deviceType && (
                              <span className={`px-1.5 py-0.5 text-xs rounded font-medium ${DEVICE_TYPE_COLOR[rec.deviceType] ?? DEVICE_TYPE_COLOR.other}`}>
                                {rec.deviceType}
                              </span>
                            )}
                            {toOsList(rec.os).map(o => (
                              <span key={o} className="px-1.5 py-0.5 text-xs rounded bg-slate-100 text-slate-600 font-medium">{o}</span>
                            ))}
                            {rec.matchScore != null && rec.matchScore > 0 && (
                              <span className="text-xs text-green-600 font-medium">✓ Modell-Match</span>
                            )}
                          </div>
                        </div>
                        {rec.aptPackage ? (
                          <code
                            className="px-2 py-1 text-xs bg-gray-900 text-green-400 rounded font-mono cursor-pointer hover:bg-gray-800 transition-colors"
                            title="Klicken zum Kopieren"
                            onClick={() => {
                              navigator.clipboard?.writeText(`apt install ${rec.aptPackage}`);
                              toast.success(`"apt install ${rec.aptPackage}" kopiert`);
                            }}
                          >
                            apt install {rec.aptPackage}
                          </code>
                        ) : (
                          <button
                            onClick={() => handleImportRecommended(rec)}
                            disabled={importing || imported || !rec.downloadUrl}
                            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                              imported
                                ? 'text-green-700 bg-green-50 cursor-default'
                                : importing
                                ? 'text-blue-500 bg-blue-50 cursor-wait'
                                : !rec.downloadUrl
                                ? 'text-gray-300 bg-gray-50 cursor-not-allowed'
                                : 'text-blue-700 bg-blue-50 hover:bg-blue-100'
                            }`}
                            title={!rec.downloadUrl ? 'Kein Download-Link' : undefined}
                          >
                            {imported ? (
                              <><CheckCircleIcon className="w-3.5 h-3.5" /> Importiert</>
                            ) : importing ? (
                              <><ArrowPathIcon className="w-3.5 h-3.5 animate-spin" /> …</>
                            ) : (
                              <><CloudArrowDownIcon className="w-3.5 h-3.5" /> Importieren</>
                            )}
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Installed drivers ── */}
      <div>
        <div className="flex items-center justify-between gap-2 flex-wrap mb-4">
          <div>
            <h2 className="text-base font-semibold text-gray-900">Geräte-Treiber</h2>
            <p className="text-xs text-gray-400 mt-0.5">Netzwerkadapter, Grafikkarten, USB-Geräte und mehr</p>
          </div>
          <div className="flex gap-2">
            <label
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50 rounded-lg cursor-pointer transition-colors ${uploading ? 'opacity-50 pointer-events-none' : ''}`}
              title="Erlaubte Formate: INF, EXE, DEB, RPM, ZIP, TAR, KO, SYS"
            >
              {uploading ? (
                <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Hochladen…</>
              ) : (
                <><ArrowUpTrayIcon className="w-4 h-4" /> Treiber hochladen</>
              )}
              <input
                type="file"
                className="hidden"
                accept=".inf,.exe,.deb,.rpm,.zip,.tar,.tar.gz,.ko,.sys"
                onChange={handleUpload}
                disabled={uploading}
              />
            </label>
            <button
              onClick={() => setShowCatalog(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
            >
              <BookOpenIcon className="w-4 h-4" />
              Aus Katalog
            </button>
          </div>
        </div>

        <div aria-live="polite" aria-busy={loading}>
        {loading ? (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-14 bg-gray-100 rounded-xl animate-pulse" />
            ))}
          </div>
        ) : driversError ? (
          <div className="flex flex-col items-center justify-center py-16 text-center text-gray-400 space-y-2">
            <ExclamationTriangleIcon className="w-12 h-12 opacity-30 text-red-400" />
            <p className="font-medium text-gray-600">Treiber konnten nicht geladen werden</p>
            <p className="text-sm max-w-xs">
              Beim Laden der Geräte-Treiber ist ein Fehler aufgetreten.
            </p>
            <button
              onClick={() => loadDrivers()}
              className="mt-2 flex items-center gap-2 px-4 py-2 text-sm font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors"
            >
              <ArrowPathIcon className="w-4 h-4" />
              Erneut versuchen
            </button>
          </div>
        ) : drivers.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center text-gray-400 space-y-2">
            <CpuChipIcon className="w-12 h-12 opacity-30" />
            <p className="font-medium text-gray-600">Keine Geräte-Treiber installiert</p>
            <p className="text-sm max-w-xs">
              Lade einen Treiber hoch oder importiere einen aus dem Online-Katalog.
            </p>
            <button
              onClick={() => setShowCatalog(true)}
              className="mt-2 flex items-center gap-2 px-4 py-2 text-sm font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors"
            >
              <BookOpenIcon className="w-4 h-4" />
              Treiber-Katalog öffnen
            </button>
          </div>
        ) : (
          <div className="border border-gray-200 rounded-xl overflow-hidden divide-y divide-gray-100">
            {drivers.map(driver => (
              <div key={driver.id} className="flex items-center gap-4 px-4 py-3 hover:bg-gray-50 transition-colors">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate" title={driver.name}>{driver.name}</p>
                  <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                    {driver.version && <span className="text-xs text-gray-400">v{driver.version}</span>}
                    {driver.vendor && <span className="text-xs text-gray-500">{driver.vendor}</span>}
                    {driver.deviceType && (
                      <span className={`px-1.5 py-0.5 text-xs rounded font-medium ${DEVICE_TYPE_COLOR[driver.deviceType] ?? DEVICE_TYPE_COLOR.other}`}>
                        {driver.deviceType}
                      </span>
                    )}
                    {driver.format && (
                      <span className="px-1.5 py-0.5 text-xs rounded bg-orange-100 text-orange-700 font-medium">
                        {driver.format}
                      </span>
                    )}
                    {toOsList(driver.os).map(os => (
                      <span key={os} className="px-1.5 py-0.5 text-xs rounded bg-blue-100 text-blue-700 font-medium">{os}</span>
                    ))}
                    {driver.architecture && <span className="text-xs text-gray-400">{driver.architecture}</span>}
                    {driver.source && <span className="text-xs text-gray-300">· {driver.source}</span>}
                  </div>
                </div>
                <button
                  onClick={() => handleDelete(driver)}
                  disabled={deletingId === driver.id}
                  aria-label={`Treiber "${driver.name}" löschen`}
                  className="text-gray-400 hover:text-red-600 p-1.5 rounded-lg hover:bg-red-50 transition-colors disabled:opacity-40"
                  title="Treiber löschen"
                >
                  {deletingId === driver.id ? (
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  ) : (
                    <TrashIcon className="w-4 h-4" />
                  )}
                </button>
              </div>
            ))}
          </div>
        )}
        </div>
      </div>

      {/* Catalog browser modal */}
      {showCatalog && (
        <DriverCatalogBrowser
          onClose={() => setShowCatalog(false)}
          onImported={handleCatalogImported}
          importTarget="device"
        />
      )}
    </div>
  );
}
