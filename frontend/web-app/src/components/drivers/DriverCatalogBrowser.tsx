'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  XMarkIcon,
  MagnifyingGlassIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ArrowDownTrayIcon,
} from '@heroicons/react/24/outline';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface CatalogEntry {
  id: string;
  source: 'dell' | 'hp' | 'lenovo' | 'brother' | 'canon' | 'epson' | 'openprinting' | 'generic' | 'url';
  name: string;
  version: string;
  vendor: string;
  os: string[];
  deviceType: string;
  format: string;
  architecture: string;
  description: string;
  downloadUrl: string;
  models: string[];
  fileSize: number;
  tags: string[];
  licenseType: 'open-source' | 'freeware' | 'commercial';
}

interface ImportState {
  entryId: string;
  status: 'importing' | 'success' | 'error';
  error?: string;
}

interface VendorCount {
  vendor: string;
  count: number;
}

interface DriverCatalogBrowserProps {
  onClose: () => void;
  onImported?: (driverName: string) => void;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const VENDOR_COLORS: Record<string, string> = {
  dell:         'bg-blue-600',
  hp:           'bg-indigo-600',
  lenovo:       'bg-red-600',
  brother:      'bg-teal-600',
  canon:        'bg-red-500',
  epson:        'bg-cyan-600',
  openprinting: 'bg-orange-500',
  generic:      'bg-gray-500',
};

const OS_BADGE_COLORS: Record<string, string> = {
  linux:     'bg-green-100 text-green-700',
  windows:   'bg-blue-100 text-blue-700',
  macos:     'bg-gray-100 text-gray-700',
  universal: 'bg-purple-100 text-purple-700',
};

const LICENSE_BADGE: Record<string, string> = {
  'open-source': 'bg-green-100 text-green-700',
  freeware:      'bg-blue-100 text-blue-700',
  commercial:    'bg-amber-100 text-amber-700',
};

const LICENSE_LABEL: Record<string, string> = {
  'open-source': 'Open Source',
  freeware:      'Freeware',
  commercial:    'Kommerziell',
};

const OS_OPTIONS = ['Alle', 'Linux', 'Windows', 'macOS', 'Universal'];
const DEVICE_TYPE_OPTIONS = ['Alle', 'Drucker', 'Netzwerk', 'Anzeige', 'Speicher', 'USB', 'Audio'];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '—';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(1)} MB`;
  const kb = bytes / 1024;
  return `${kb.toFixed(0)} KB`;
}

function vendorKey(v: string): string {
  return v.toLowerCase().replace(/\s+/g, '');
}

function getVendorColor(vendor: string): string {
  return VENDOR_COLORS[vendorKey(vendor)] ?? 'bg-gray-500';
}

function getVendorInitial(vendor: string): string {
  return (vendor || 'G').charAt(0).toUpperCase();
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SkeletonCard() {
  return (
    <div className="border border-gray-200 rounded-xl p-4 animate-pulse space-y-3">
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-xl bg-gray-200 flex-shrink-0" />
        <div className="flex-1 space-y-2">
          <div className="h-4 bg-gray-200 rounded w-3/4" />
          <div className="h-3 bg-gray-100 rounded w-1/2" />
        </div>
      </div>
      <div className="flex gap-2">
        <div className="h-5 bg-gray-100 rounded-full w-16" />
        <div className="h-5 bg-gray-100 rounded-full w-14" />
        <div className="h-5 bg-gray-100 rounded-full w-12" />
      </div>
      <div className="h-3 bg-gray-100 rounded w-full" />
      <div className="h-3 bg-gray-100 rounded w-5/6" />
    </div>
  );
}

function OsBadge({ os }: { os: string }) {
  const key = os.toLowerCase();
  const cls = OS_BADGE_COLORS[key] ?? 'bg-gray-100 text-gray-600';
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>
      {os}
    </span>
  );
}

// ─── Driver Result Card ───────────────────────────────────────────────────────

function DriverCard({
  entry,
  importState,
  onImport,
}: {
  entry: CatalogEntry;
  importState?: ImportState;
  onImport: (entry: CatalogEntry) => void;
}) {
  const color = getVendorColor(entry.vendor);
  const initial = getVendorInitial(entry.vendor);
  const isImporting = importState?.status === 'importing';
  const isSuccess   = importState?.status === 'success';
  const isError     = importState?.status === 'error';

  return (
    <div className="border border-gray-200 rounded-xl p-4 hover:shadow-sm transition-shadow bg-white space-y-3">
      <div className="flex items-start gap-3">
        {/* Vendor avatar */}
        <div className={`w-10 h-10 rounded-xl ${color} flex items-center justify-center text-white font-bold text-sm flex-shrink-0`}>
          {initial}
        </div>

        {/* Name + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="font-medium text-gray-900 text-sm truncate">{entry.name}</p>
              <p className="text-xs text-gray-400 mt-0.5">
                v{entry.version} · {entry.vendor} · {entry.architecture}
              </p>
            </div>
            <div className="flex-shrink-0 text-xs text-gray-400">
              {formatBytes(entry.fileSize)}
            </div>
          </div>
        </div>
      </div>

      {/* Badges row */}
      <div className="flex flex-wrap gap-1.5">
        {entry.os.map(os => (
          <OsBadge key={os} os={os} />
        ))}
        {entry.deviceType && (
          <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
            {entry.deviceType}
          </span>
        )}
        {entry.format && (
          <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-700">
            {entry.format}
          </span>
        )}
        {entry.licenseType && (
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${LICENSE_BADGE[entry.licenseType] ?? 'bg-gray-100 text-gray-600'}`}>
            {LICENSE_LABEL[entry.licenseType] ?? entry.licenseType}
          </span>
        )}
      </div>

      {/* Description */}
      {entry.description && (
        <p className="text-xs text-gray-500 line-clamp-2 leading-relaxed">
          {entry.description}
        </p>
      )}

      {/* Compatible models */}
      {entry.models && entry.models.length > 0 && (
        <div className="text-xs text-gray-400">
          <span className="font-medium text-gray-600">Modelle: </span>
          {entry.models.slice(0, 3).join(', ')}
          {entry.models.length > 3 && (
            <span className="ml-1 text-blue-500 font-medium">+{entry.models.length - 3} mehr</span>
          )}
        </div>
      )}

      {/* Import button + status */}
      <div className="pt-1 border-t border-gray-100 flex items-center justify-between gap-2">
        {isError && (
          <p className="text-xs text-red-600 flex items-center gap-1 flex-1 min-w-0 truncate">
            <ExclamationCircleIcon className="w-3.5 h-3.5 flex-shrink-0" />
            {importState?.error ?? 'Fehler beim Importieren'}
          </p>
        )}
        {!isError && <div className="flex-1" />}

        {isSuccess ? (
          <span className="flex items-center gap-1.5 text-sm font-medium text-green-600">
            <CheckCircleIcon className="w-4 h-4" />
            Importiert
          </span>
        ) : (
          <button
            onClick={() => onImport(entry)}
            disabled={isImporting}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 transition-colors flex-shrink-0"
          >
            {isImporting ? (
              <>
                <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                Wird importiert…
              </>
            ) : (
              <>
                <ArrowDownTrayIcon className="w-3.5 h-3.5" />
                Importieren
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}

// ─── URL Import Panel ─────────────────────────────────────────────────────────

function UrlImportPanel({ onImported }: { onImported?: (name: string) => void }) {
  const [url, setUrl]           = useState('');
  const [name, setName]         = useState('');
  const [version, setVersion]   = useState('');
  const [vendor, setVendor]     = useState('');
  const [os, setOs]             = useState('');
  const [deviceType, setDeviceType] = useState('');
  const [format, setFormat]     = useState('');
  const [importing, setImporting] = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [success, setSuccess]   = useState(false);

  const handleImport = async () => {
    if (!url.trim()) return;
    setImporting(true);
    setError(null);
    setSuccess(false);
    try {
      await api.post('/api/printer/catalog/import-url', {
        url: url.trim(),
        name: name.trim() || undefined,
        version: version.trim() || undefined,
        vendor: vendor.trim() || undefined,
        os: os || undefined,
        deviceType: deviceType || undefined,
        format: format || undefined,
      });
      setSuccess(true);
      if (onImported) onImported(name.trim() || url.trim());
      setUrl('');
      setName('');
      setVersion('');
      setVendor('');
      setOs('');
      setDeviceType('');
      setFormat('');
    } catch (err: any) {
      setError(err?.response?.data?.error ?? 'Import fehlgeschlagen');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="space-y-2.5">
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">URL</label>
        <input
          value={url}
          onChange={e => { setUrl(e.target.value); setSuccess(false); }}
          className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
          placeholder="https://download.example.com/driver.exe"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
          placeholder="Treibername"
        />
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Version</label>
          <input
            value={version}
            onChange={e => setVersion(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
            placeholder="1.0.0"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Hersteller</label>
          <input
            value={vendor}
            onChange={e => setVendor(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
            placeholder="HP, Dell…"
          />
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Betriebssystem</label>
        <select
          value={os}
          onChange={e => setOs(e.target.value)}
          className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="">Auswählen…</option>
          {['Linux', 'Windows', 'macOS', 'Universal'].map(o => (
            <option key={o} value={o}>{o}</option>
          ))}
        </select>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Gerätetyp</label>
          <select
            value={deviceType}
            onChange={e => setDeviceType(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Typ…</option>
            {['Drucker', 'Netzwerk', 'Anzeige', 'Speicher', 'USB', 'Audio'].map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Format</label>
          <select
            value={format}
            onChange={e => setFormat(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Format…</option>
            {['PPD', 'INF', 'EXE', 'DEB', 'RPM', 'ZIP', 'TAR'].map(f => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <p className="text-xs text-red-600 flex items-start gap-1">
          <ExclamationCircleIcon className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          {error}
        </p>
      )}
      {success && (
        <p className="text-xs text-green-600 flex items-center gap-1">
          <CheckCircleIcon className="w-3.5 h-3.5" />
          Importiert!
        </p>
      )}

      <button
        onClick={handleImport}
        disabled={importing || !url.trim()}
        className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 transition-colors"
      >
        {importing ? (
          <><ArrowPathIcon className="w-3.5 h-3.5 animate-spin" /> Importieren…</>
        ) : (
          <><ArrowDownTrayIcon className="w-3.5 h-3.5" /> Importieren</>
        )}
      </button>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function DriverCatalogBrowser({ onClose, onImported }: DriverCatalogBrowserProps) {
  const [query, setQuery]               = useState('');
  const [results, setResults]           = useState<CatalogEntry[]>([]);
  const [loading, setLoading]           = useState(false);
  const [vendors, setVendors]           = useState<VendorCount[]>([]);
  const [selectedVendor, setSelectedVendor] = useState<string>('alle');
  const [selectedOs, setSelectedOs]     = useState('Alle');
  const [selectedType, setSelectedType] = useState('Alle');
  const [importStates, setImportStates] = useState<ImportState[]>([]);
  const [total, setTotal]               = useState(0);
  const [hasSearched, setHasSearched]   = useState(false);

  // ── Load vendors ────────────────────────────────────────────────────────────

  useEffect(() => {
    api.get('/api/printer/catalog/vendors')
      .then(res => {
        const data = res.data?.vendors ?? res.data ?? [];
        setVendors(data);
      })
      .catch(() => {
        // Fallback vendor list
        setVendors([
          { vendor: 'Dell',         count: 12 },
          { vendor: 'HP',           count: 8  },
          { vendor: 'Lenovo',       count: 6  },
          { vendor: 'Brother',      count: 9  },
          { vendor: 'Canon',        count: 7  },
          { vendor: 'Epson',        count: 5  },
          { vendor: 'OpenPrinting', count: 0  },
          { vendor: 'Generic',      count: 4  },
        ]);
      });
  }, []);

  // ── Search ──────────────────────────────────────────────────────────────────

  const doSearch = useCallback(async (q: string, vendor: string, os: string, type: string) => {
    setLoading(true);
    setHasSearched(true);
    try {
      const params: Record<string, string> = { q };
      if (vendor !== 'alle') params.vendor = vendor;
      if (os !== 'Alle')     params.os     = os;
      if (type !== 'Alle')   params.deviceType = type;

      const res = await api.get('/api/printer/catalog/search', { params });
      const data = res.data;
      const items: CatalogEntry[] = data?.entries ?? data?.results ?? data ?? [];
      setResults(items);
      setTotal(data?.total ?? items.length);
    } catch {
      // Show empty state on error
      setResults([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load — show all
  useEffect(() => {
    doSearch('', 'alle', 'Alle', 'Alle');
  }, [doSearch]);

  const handleSearch = () => {
    doSearch(query, selectedVendor, selectedOs, selectedType);
  };

  const handleVendorSelect = (v: string) => {
    setSelectedVendor(v);
    doSearch(query, v, selectedOs, selectedType);
  };

  const handleOsChange = (os: string) => {
    setSelectedOs(os);
    doSearch(query, selectedVendor, os, selectedType);
  };

  const handleTypeChange = (type: string) => {
    setSelectedType(type);
    doSearch(query, selectedVendor, selectedOs, type);
  };

  // ── Import ──────────────────────────────────────────────────────────────────

  const handleImport = async (entry: CatalogEntry) => {
    setImportStates(prev => [
      ...prev.filter(s => s.entryId !== entry.id),
      { entryId: entry.id, status: 'importing' },
    ]);
    try {
      await api.post('/api/printer/catalog/import', { entry });
      setImportStates(prev => [
        ...prev.filter(s => s.entryId !== entry.id),
        { entryId: entry.id, status: 'success' },
      ]);
      if (onImported) onImported(entry.name);
    } catch (err: any) {
      const msg = err?.response?.data?.error ?? 'Import fehlgeschlagen';
      setImportStates(prev => [
        ...prev.filter(s => s.entryId !== entry.id),
        { entryId: entry.id, status: 'error', error: msg },
      ]);
    }
  };

  const getImportState = (id: string) => importStates.find(s => s.entryId === id);

  // ── Keyboard ────────────────────────────────────────────────────────────────

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') handleSearch();
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col">

        {/* ── Header ── */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 flex-shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Treiber-Katalog</h2>
            <p className="text-xs text-gray-400 mt-0.5">Treiber aus Online-Quellen suchen und importieren</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-700 p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* ── Search Bar ── */}
        <div className="px-6 py-3 border-b border-gray-100 flex-shrink-0 space-y-2.5">
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                className="w-full border border-gray-300 rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder='Suche: "HP LaserJet", "Dell WiFi", "Universal PCL"…'
                autoFocus
              />
            </div>
            <button
              onClick={handleSearch}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-60 transition-colors"
            >
              {loading ? (
                <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Suche…</>
              ) : (
                <><MagnifyingGlassIcon className="w-4 h-4" /> Suchen</>
              )}
            </button>
          </div>

          {/* Filter bar */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-medium text-gray-500">Filter:</span>
            <select
              value={selectedOs}
              onChange={e => handleOsChange(e.target.value)}
              className="border border-gray-200 rounded-lg px-2.5 py-1 text-xs bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              {OS_OPTIONS.map(o => (
                <option key={o} value={o}>{o === 'Alle' ? 'Alle BS' : o}</option>
              ))}
            </select>
            <select
              value={selectedType}
              onChange={e => handleTypeChange(e.target.value)}
              className="border border-gray-200 rounded-lg px-2.5 py-1 text-xs bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              {DEVICE_TYPE_OPTIONS.map(t => (
                <option key={t} value={t}>{t === 'Alle' ? 'Alle Geräte' : t}</option>
              ))}
            </select>
          </div>
        </div>

        {/* ── Body: sidebar + results ── */}
        <div className="flex flex-1 min-h-0 overflow-hidden">

          {/* Sidebar */}
          <div className="w-52 flex-shrink-0 border-r border-gray-100 flex flex-col overflow-hidden">
            {/* Vendor list */}
            <div className="flex-1 overflow-y-auto p-3 space-y-0.5">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide px-2 mb-2">Hersteller</p>

              {/* Alle */}
              <button
                onClick={() => handleVendorSelect('alle')}
                className={`w-full flex items-center justify-between px-2 py-1.5 rounded-lg text-sm transition-colors ${
                  selectedVendor === 'alle'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <span className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${selectedVendor === 'alle' ? 'bg-blue-600' : 'bg-gray-300'}`} />
                  Alle
                </span>
              </button>

              {/* Vendor items */}
              {vendors.map(v => {
                const key = vendorKey(v.vendor);
                const isActive = selectedVendor === key || selectedVendor === v.vendor;
                return (
                  <button
                    key={v.vendor}
                    onClick={() => handleVendorSelect(key)}
                    className={`w-full flex items-center justify-between px-2 py-1.5 rounded-lg text-sm transition-colors ${
                      isActive
                        ? 'bg-blue-50 text-blue-700 font-medium'
                        : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    <span className="flex items-center gap-2 min-w-0">
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${isActive ? 'bg-blue-600' : 'bg-gray-300'}`} />
                      <span className="truncate">{v.vendor}</span>
                    </span>
                    {v.count > 0 && (
                      <span className={`text-xs flex-shrink-0 ${isActive ? 'text-blue-500' : 'text-gray-400'}`}>
                        ({v.count === Infinity ? '∞' : v.count})
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* URL Import */}
            <div className="border-t border-gray-100 p-3 flex-shrink-0">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2.5">URL-Import</p>
              <UrlImportPanel onImported={onImported} />
            </div>
          </div>

          {/* Results pane */}
          <div className="flex-1 overflow-y-auto p-4">
            {/* Result count header */}
            {!loading && hasSearched && (
              <p className="text-xs text-gray-500 mb-3 px-0.5">
                {results.length === 0
                  ? 'Keine Ergebnisse'
                  : `${total} Treiber gefunden`}
              </p>
            )}

            {/* Loading skeletons */}
            {loading && (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <SkeletonCard key={i} />
                ))}
              </div>
            )}

            {/* Results */}
            {!loading && results.length > 0 && (
              <div className="space-y-3">
                {results.map(entry => (
                  <DriverCard
                    key={entry.id}
                    entry={entry}
                    importState={getImportState(entry.id)}
                    onImport={handleImport}
                  />
                ))}
              </div>
            )}

            {/* Empty state */}
            {!loading && hasSearched && results.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 text-center text-gray-400 space-y-3">
                <MagnifyingGlassIcon className="w-12 h-12 opacity-30" />
                <p className="font-medium text-gray-600">Keine Treiber gefunden</p>
                <p className="text-sm max-w-sm">
                  Versuche eine andere Suchanfrage oder importiere einen Treiber via URL im linken Panel.
                </p>
              </div>
            )}

            {/* Initial state (before any search completes) */}
            {!loading && !hasSearched && (
              <div className="flex flex-col items-center justify-center py-20 text-center text-gray-400 space-y-3">
                <ArrowPathIcon className="w-8 h-8 opacity-30 animate-spin" />
                <p className="text-sm">Katalog wird geladen…</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
