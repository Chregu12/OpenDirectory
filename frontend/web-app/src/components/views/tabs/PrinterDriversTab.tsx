'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowPathIcon,
  ArrowUpTrayIcon,
  BookOpenIcon,
  TrashIcon,
  CheckBadgeIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';
import { DriverCatalogBrowser } from '@/components/drivers';
import toast from 'react-hot-toast';

// ─── Types ────────────────────────────────────────────────────────────────────

interface PrinterDriver {
  id: string;
  name: string;
  version?: string;
  vendor?: string;
  format?: string;
  os?: string[] | string;
  uploadedAt?: string;
  source?: string;
}

// The printer-service upload route stores `os` as a plain string (single
// value), while catalog imports store it as an array — normalize both.
function toOsList(os?: string[] | string): string[] {
  if (!os) return [];
  return Array.isArray(os) ? os : [os];
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function PrinterDriversTab() {
  const [drivers, setDrivers]           = useState<PrinterDriver[]>([]);
  const [loading, setLoading]           = useState(true);
  const [showCatalog, setShowCatalog]   = useState(false);
  const [uploading, setUploading]       = useState(false);
  const [deletingId, setDeletingId]     = useState<string | null>(null);

  // ── Load drivers ──────────────────────────────────────────────────────────

  const loadDrivers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/api/printer/drivers');
      const data = res.data?.drivers ?? res.data?.data ?? res.data ?? [];
      setDrivers(Array.isArray(data) ? data : []);
    } catch {
      setDrivers([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDrivers();
  }, [loadDrivers]);

  // ── Upload ────────────────────────────────────────────────────────────────

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const form = new FormData();
      form.append('driver', file);
      await api.post('/api/printer/drivers/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      toast.success(`Treiber "${file.name}" hochgeladen`);
      await loadDrivers();
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Upload fehlgeschlagen');
    } finally {
      setUploading(false);
      // Reset file input
      e.target.value = '';
    }
  };

  // ── Delete ────────────────────────────────────────────────────────────────

  const handleDelete = async (driver: PrinterDriver) => {
    if (!confirm(`Treiber "${driver.name}" wirklich löschen?`)) return;
    setDeletingId(driver.id);
    try {
      await api.delete(`/api/printer/drivers/${driver.id}`);
      setDrivers(prev => prev.filter(d => d.id !== driver.id));
      toast.success(`Treiber "${driver.name}" gelöscht`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Löschen fehlgeschlagen');
    } finally {
      setDeletingId(null);
    }
  };

  // ── After catalog import ──────────────────────────────────────────────────

  const handleCatalogImported = async (driverName: string) => {
    toast.success(`Treiber "${driverName}" importiert`);
    await loadDrivers();
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4">
      {/* Action bar */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Drucker-Treiber</h2>
          <p className="text-xs text-gray-400 mt-0.5">Installierte Treiber verwalten und neue importieren</p>
        </div>
        <div className="flex gap-2">
          {/* Upload button */}
          <label className={`flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50 rounded-lg cursor-pointer transition-colors ${uploading ? 'opacity-50 pointer-events-none' : ''}`}>
            {uploading ? (
              <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Hochladen…</>
            ) : (
              <><ArrowUpTrayIcon className="w-4 h-4" /> Treiber hochladen</>
            )}
            <input
              type="file"
              className="hidden"
              accept=".ppd,.inf,.exe,.deb,.rpm,.zip,.tar,.tar.gz"
              onChange={handleUpload}
              disabled={uploading}
            />
          </label>

          {/* Catalog button */}
          <button
            onClick={() => setShowCatalog(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
          >
            <BookOpenIcon className="w-4 h-4" />
            Aus Katalog
          </button>
        </div>
      </div>

      {/* Driver list */}
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-14 bg-gray-100 rounded-xl animate-pulse" />
          ))}
        </div>
      ) : drivers.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center text-gray-400 space-y-2">
          <CheckBadgeIcon className="w-12 h-12 opacity-30" />
          <p className="font-medium text-gray-600">Keine Treiber installiert</p>
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
                <p className="text-sm font-medium text-gray-900 truncate">{driver.name}</p>
                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                  {driver.version && (
                    <span className="text-xs text-gray-400">v{driver.version}</span>
                  )}
                  {driver.vendor && (
                    <span className="text-xs text-gray-500">{driver.vendor}</span>
                  )}
                  {driver.format && (
                    <span className="px-1.5 py-0.5 text-xs rounded bg-orange-100 text-orange-700 font-medium">
                      {driver.format}
                    </span>
                  )}
                  {toOsList(driver.os).map(os => (
                    <span key={os} className="px-1.5 py-0.5 text-xs rounded bg-blue-100 text-blue-700 font-medium">
                      {os}
                    </span>
                  ))}
                  {driver.source && (
                    <span className="text-xs text-gray-300">· {driver.source}</span>
                  )}
                </div>
              </div>
              <button
                onClick={() => handleDelete(driver)}
                disabled={deletingId === driver.id}
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

      {/* Catalog browser modal */}
      {showCatalog && (
        <DriverCatalogBrowser
          onClose={() => setShowCatalog(false)}
          onImported={handleCatalogImported}
        />
      )}
    </div>
  );
}
