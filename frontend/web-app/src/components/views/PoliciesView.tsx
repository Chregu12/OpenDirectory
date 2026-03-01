'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  PlusIcon,
  TrashIcon,
  PencilIcon,
  ArrowDownTrayIcon,
  ChevronRightIcon,
  ChevronLeftIcon,
  CheckIcon,
  XMarkIcon,
  ClipboardDocumentIcon,
  ServerIcon,
  ComputerDesktopIcon,
  GlobeAltIcon,
  LockClosedIcon,
  BoltIcon,
  ClockIcon,
  DocumentTextIcon,
  PlayIcon,
  CodeBracketIcon,
  CpuChipIcon,
  DevicePhoneMobileIcon,
  FolderIcon,
  PrinterIcon,
  CloudIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  UserGroupIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

// ── Types ─────────────────────────────────────────────────────────────────────
interface PolicyTemplate {
  id: string;
  templateId: string;
  category: string;
  name: string;
  description: string;
  icon: string;
  targets: { platforms: string[]; groups: string[] };
  settings: Record<string, unknown>;
}

interface Policy {
  id: string;
  name: string;
  description: string;
  type: string;
  category: string;
  enabled: boolean;
  version: string;
  platforms: string[];
  target_groups: string[];
  deploy_status: 'draft' | 'compiled' | 'deployed' | 'needs_recompile';
  last_deployed?: string;
  created_at: string;
  updated_at: string;
}

interface PolicyVersion {
  id: string;
  version: string;
  compiled_at: string;
  deployed_by?: string;
  comment?: string;
}

interface PrintQuota {
  id: string;
  user_name: string;
  quota_limit: number;
  used_pages: number;
  period: string;
}

interface CompiledArtifact {
  type: string;
  filename: string;
  content: string;
  description: string;
  apply_command?: string;
  install_path?: string;
  sysvol_path?: string;
}

interface CompiledResult {
  policy_id: string;
  policy_name: string;
  version: string;
  compiled_at: string;
  artifacts: {
    windows?: CompiledArtifact[];
    linux?: CompiledArtifact[];
    macos?: CompiledArtifact[];
  };
}

interface ComplianceSummary {
  overall: {
    total_devices: number;
    compliant_devices: number;
    stale_devices: number;
    pct_compliant: number | null;
  };
  policies: Array<{
    policy_id: string;
    policy_name: string;
    total_devices: number;
    compliant_devices: number;
    pct_compliant: number | null;
  }>;
  devices: Array<{
    device_id: string;
    device_name: string;
    platform: string;
    last_seen: string | null;
    stale: boolean;
    hours_since_heartbeat: number | null;
    total_policies: number;
    compliant_policies: number;
    last_check: string | null;
  }>;
}

type Platform = 'windows' | 'linux' | 'macos';
type WizardStep = 1 | 2 | 3 | 4;

// ── Constants ─────────────────────────────────────────────────────────────────
const PLATFORM_ICONS: Record<Platform, React.ElementType> = {
  windows: ComputerDesktopIcon,
  linux:   ServerIcon,
  macos:   DevicePhoneMobileIcon,
};

const PLATFORM_COLORS: Record<Platform, string> = {
  windows: 'blue',
  linux:   'orange',
  macos:   'gray',
};

const PLATFORM_LABELS: Record<Platform, string> = {
  windows: 'Windows',
  linux:   'Linux',
  macos:   'macOS',
};

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  hardening:  ShieldCheckIcon,
  password:   LockClosedIcon,
  network:    GlobeAltIcon,
  compliance: DocumentTextIcon,
  software:   CpuChipIcon,
  custom:     CodeBracketIcon,
  drives:     FolderIcon,
  printers:   PrinterIcon,
  cloud:      CloudIcon,
};

const STATUS_COLORS: Record<string, string> = {
  draft:           'bg-gray-100 text-gray-600',
  compiled:        'bg-blue-100 text-blue-700',
  deployed:        'bg-green-100 text-green-700',
  needs_recompile: 'bg-amber-100 text-amber-700',
};

const STATUS_LABELS: Record<string, string> = {
  draft:           'Entwurf',
  compiled:        'Kompiliert',
  deployed:        'Deployed',
  needs_recompile: 'Neu kompilieren',
};

// ── Helper components ─────────────────────────────────────────────────────────
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); }); }}
      className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-700 transition-colors"
      title="Kopieren"
    >
      {copied ? <CheckIcon className="h-4 w-4 text-green-500" /> : <ClipboardDocumentIcon className="h-4 w-4" />}
    </button>
  );
}

function PlatformBadge({ platform }: { platform: Platform }) {
  const Icon = PLATFORM_ICONS[platform];
  const color = PLATFORM_COLORS[platform];
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-${color}-100 text-${color}-700`}>
      <Icon className="h-3 w-3" />
      {PLATFORM_LABELS[platform]}
    </span>
  );
}

// ── Settings Editor (intent fields) ──────────────────────────────────────────
interface OdShare {
  id: string; name: string; protocol: string; server: string; path: string;
  drive_letter: string; enabled: boolean; description?: string;
  permissions?: string; username?: string; has_credentials?: boolean;
  unc_path?: string; smb_url?: string; nfs_path?: string;
}
interface OdPrinter {
  id: string; name: string; ip: string; model: string; protocol: string;
  location: string; driver: string;
  status?: string; queueDepth?: number; isMultifunction?: boolean;
  scanFormats?: string[];
}

// Nur ID + Policy-spezifische Overrides speichern.
// Alle anderen Felder (server, ip, driver …) werden zur Compile-Zeit
// vom Backend aus der DB aufgelöst — so bleibt die Policy immer aktuell.
function shareToCompilerFormat(s: OdShare) {
  return { _shareId: s.id };
}
function printerToCompilerFormat(_p: OdPrinter, isDefault: boolean) {
  return { _printerId: _p.id, default: isDefault };
}

function SettingsEditor({
  settings, onChange,
}: { settings: Record<string, unknown>; onChange: (s: Record<string, unknown>) => void }) {
  const [availableShares,   setAvailableShares]   = useState<OdShare[]>([]);
  const [availablePrinters, setAvailablePrinters] = useState<OdPrinter[]>([]);

  useEffect(() => {
    // Backend /api/network/shares → { shares: [...] }
    fetch('/api/network/shares')
      .then(r => r.ok ? r.json() : null)
      .then(d => d?.shares && setAvailableShares(d.shares));
    // Backend /api/printer/printers → { success: true, data: [...] }
    fetch('/api/printer/printers')
      .then(r => r.ok ? r.json() : null)
      .then(d => d?.data && setAvailablePrinters(d.data));
  }, []);

  const set = (section: string, field: string, value: unknown) => {
    onChange({
      ...settings,
      [section]: { ...(settings[section] as Record<string, unknown> || {}), [field]: value },
    });
  };
  const get = (section: string, field: string) =>
    ((settings[section] as Record<string, unknown>) || {})[field];

  const selectedShareIds   = new Set(((settings.networkDrives as Record<string,unknown>[] | undefined) || []).map(d => d._shareId as string));
  const selectedPrinterIds = new Set(((settings.printers      as Record<string,unknown>[] | undefined) || []).map(p => p._printerId as string));

  const toggleShare = (share: OdShare, checked: boolean) => {
    const current = (settings.networkDrives as Record<string,unknown>[] | undefined) || [];
    const updated  = checked
      ? [...current, shareToCompilerFormat(share)]
      : current.filter(d => d._shareId !== share.id);
    onChange({ ...settings, networkDrives: updated });
  };

  const togglePrinter = (printer: OdPrinter, checked: boolean) => {
    const current  = (settings.printers as Record<string,unknown>[] | undefined) || [];
    const isFirst  = current.length === 0;
    const updated  = checked
      ? [...current, printerToCompilerFormat(printer, isFirst)]
      : current.filter(p => p._printerId !== printer.id);
    onChange({ ...settings, printers: updated });
  };

  const setDefaultPrinter = (printerId: string) => {
    const current = (settings.printers as Record<string,unknown>[] | undefined) || [];
    onChange({ ...settings, printers: current.map(p => ({ ...p, default: p._printerId === printerId })) });
  };

  return (
    <div className="space-y-5">

      {/* Password */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <LockClosedIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Passwort-Richtlinie</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.password}
              onChange={e => onChange({ ...settings, password: e.target.checked ? { minLength: 12, complexity: true, maxAgeDays: 90 } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.password && (
          <div className="p-4 grid grid-cols-2 md:grid-cols-3 gap-3">
            {[
              { field: 'minLength', label: 'Min. Länge', type: 'number', placeholder: '12' },
              { field: 'maxAgeDays', label: 'Max. Alter (Tage)', type: 'number', placeholder: '90' },
              { field: 'historyLength', label: 'Passwort-Verlauf', type: 'number', placeholder: '10' },
              { field: 'lockoutThreshold', label: 'Sperrung nach X Fehlern', type: 'number', placeholder: '5' },
              { field: 'lockoutDuration', label: 'Sperre (Minuten)', type: 'number', placeholder: '30' },
            ].map(({ field, label, type, placeholder }) => (
              <div key={field}>
                <label className="block text-xs text-gray-500 mb-1">{label}</label>
                <input
                  type={type} placeholder={placeholder}
                  value={String(get('password', field) ?? '')}
                  onChange={e => set('password', field, e.target.value ? Number(e.target.value) : undefined)}
                  className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            ))}
            <div className="flex items-center gap-2 col-span-1">
              <input type="checkbox" id="pw-complexity"
                checked={!!(get('password', 'complexity'))}
                onChange={e => set('password', 'complexity', e.target.checked)}
                className="h-4 w-4 rounded" />
              <label htmlFor="pw-complexity" className="text-xs text-gray-600">Komplexität (Gross/Klein/Zahl/Symbol)</label>
            </div>
          </div>
        )}
      </div>

      {/* Screen Lock */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <ClockIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Bildschirmsperre</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.screenLock}
              onChange={e => onChange({ ...settings, screenLock: e.target.checked ? { enabled: true, timeoutMinutes: 5, requirePassword: true } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.screenLock && (
          <div className="p-4 grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Timeout (Minuten)</label>
              <input type="number" value={String(get('screenLock', 'timeoutMinutes') ?? '5')}
                onChange={e => set('screenLock', 'timeoutMinutes', Number(e.target.value))}
                className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="sl-pw"
                checked={!!(get('screenLock', 'requirePassword'))}
                onChange={e => set('screenLock', 'requirePassword', e.target.checked)}
                className="h-4 w-4 rounded" />
              <label htmlFor="sl-pw" className="text-xs text-gray-600">Passwort nach Sperre erforderlich</label>
            </div>
          </div>
        )}
      </div>

      {/* Firewall */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <ShieldCheckIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Firewall</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.firewall}
              onChange={e => onChange({ ...settings, firewall: e.target.checked ? { enabled: true, defaultDeny: true } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.firewall && (
          <div className="p-4 flex flex-wrap gap-4">
            {[
              { field: 'enabled', label: 'Firewall einschalten' },
              { field: 'defaultDeny', label: 'Default Deny (eingehend)' },
              { field: 'stealth', label: 'Stealth-Modus (macOS)' },
            ].map(({ field, label }) => (
              <label key={field} className="flex items-center gap-2 text-xs text-gray-600">
                <input type="checkbox"
                  checked={!!(get('firewall', field))}
                  onChange={e => set('firewall', field, e.target.checked)}
                  className="h-4 w-4 rounded" />
                {label}
              </label>
            ))}
          </div>
        )}
      </div>

      {/* SSH (Linux) */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <GlobeAltIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">SSH (Linux)</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.ssh}
              onChange={e => onChange({ ...settings, ssh: e.target.checked ? { enabled: true, permitRootLogin: false, passwordAuth: false, port: 22 } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.ssh && (
          <div className="p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-gray-500 mb-1">Port</label>
                <input type="number" value={String(get('ssh', 'port') ?? '22')}
                  onChange={e => set('ssh', 'port', Number(e.target.value))}
                  className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1">Erlaubte Gruppen (kommagetrennt)</label>
                <input type="text" placeholder="Domain Admins, IT"
                  value={((get('ssh', 'allowGroups') as string[]) || []).join(', ')}
                  onChange={e => set('ssh', 'allowGroups', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
              </div>
            </div>
            <div className="flex gap-4">
              {[
                { field: 'permitRootLogin', label: 'Root-Login erlauben' },
                { field: 'passwordAuth',   label: 'Passwort-Auth erlauben' },
              ].map(({ field, label }) => (
                <label key={field} className="flex items-center gap-2 text-xs text-gray-600">
                  <input type="checkbox"
                    checked={!!(get('ssh', field))}
                    onChange={e => set('ssh', field, e.target.checked)}
                    className="h-4 w-4 rounded" />
                  {label}
                </label>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Audit */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <DocumentTextIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Audit & Logging</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.audit}
              onChange={e => onChange({ ...settings, audit: e.target.checked ? { enabled: true, logLogin: true, logFileAccess: true } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.audit && (
          <div className="p-4 flex flex-wrap gap-4">
            {[
              { field: 'logLogin',      label: 'Login-Events' },
              { field: 'logFileAccess', label: 'Datei-Zugriff' },
              { field: 'logNetworkConn', label: 'Netzwerk-Verbindungen' },
            ].map(({ field, label }) => (
              <label key={field} className="flex items-center gap-2 text-xs text-gray-600">
                <input type="checkbox"
                  checked={!!(get('audit', field))}
                  onChange={e => set('audit', field, e.target.checked)}
                  className="h-4 w-4 rounded" />
                {label}
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Encryption */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <LockClosedIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Verschlüsselung</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.encryption}
              onChange={e => onChange({ ...settings, encryption: e.target.checked ? { requireBitLocker: true, requireFileVault: true } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.encryption && (
          <div className="p-4 flex flex-wrap gap-4">
            {[
              { field: 'requireBitLocker',  label: 'BitLocker (Windows)' },
              { field: 'requireFileVault',  label: 'FileVault (macOS)' },
            ].map(({ field, label }) => (
              <label key={field} className="flex items-center gap-2 text-xs text-gray-600">
                <input type="checkbox"
                  checked={!!(get('encryption', field))}
                  onChange={e => set('encryption', field, e.target.checked)}
                  className="h-4 w-4 rounded" />
                {label}
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Browser */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <GlobeAltIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Browser-Einstellungen</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.browser}
              onChange={e => onChange({ ...settings, browser: e.target.checked ? { homepage: 'https://opendirectory.heusser.local' } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.browser && (
          <div className="p-4 grid grid-cols-1 gap-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Startseite (Homepage)</label>
              <input type="url" placeholder="https://opendirectory.heusser.local"
                value={String(get('browser', 'homepage') ?? '')}
                onChange={e => set('browser', 'homepage', e.target.value)}
                className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
        )}
      </div>

      {/* Network Drives — aus OpenDirectory-Freigaben auswählen */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <FolderIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Netzlaufwerke</h4>
          <span className="ml-auto text-xs text-gray-400">Aus OpenDirectory-Freigaben auswählen</span>
        </div>
        <div className="p-4">
          {availableShares.length === 0 ? (
            <p className="text-xs text-gray-400 italic">
              Keine Freigaben konfiguriert — bitte zuerst unter{' '}
              <span className="font-medium text-gray-600">Netzwerk → Datei-Shares</span> anlegen.
            </p>
          ) : (
            <div className="space-y-2">
              {availableShares.map(share => {
                const selected = selectedShareIds.has(share.id);
                return (
                  <label key={share.id}
                    className={`flex items-center gap-3 p-2.5 rounded-lg border cursor-pointer transition-colors ${
                      selected ? 'border-blue-300 bg-blue-50' : 'border-gray-100 hover:border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <input type="checkbox" checked={selected}
                      onChange={e => toggleShare(share, e.target.checked)}
                      className="h-4 w-4 rounded text-blue-600" />
                    <FolderIcon className={`h-4 w-4 flex-shrink-0 ${selected ? 'text-blue-500' : 'text-gray-400'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-800 truncate">{share.name}</p>
                      <p className="text-xs text-gray-400 truncate">
                        {share.protocol.toUpperCase()} · {share.server}/{share.path}
                        {share.drive_letter && <> · <span className="font-mono">{share.drive_letter}:</span></>}
                      </p>
                    </div>
                    {selected && (
                      <span className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded font-medium flex-shrink-0">
                        eingeschlossen
                      </span>
                    )}
                  </label>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Printers — aus OpenDirectory-Druckern auswählen */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <PrinterIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Drucker</h4>
          <span className="ml-auto text-xs text-gray-400">Aus OpenDirectory-Druckern auswählen</span>
        </div>
        <div className="p-4">
          {availablePrinters.length === 0 ? (
            <p className="text-xs text-gray-400 italic">
              Keine Drucker konfiguriert — bitte zuerst unter{' '}
              <span className="font-medium text-gray-600">Drucker</span> anlegen.
            </p>
          ) : (
            <div className="space-y-2">
              {availablePrinters.map(printer => {
                const selected    = selectedPrinterIds.has(printer.id);
                const selectedObj = selected
                  ? ((settings.printers as Record<string,unknown>[] | undefined) || []).find(p => p._printerId === printer.id)
                  : null;
                const isDefault   = !!(selectedObj?.default);
                return (
                  <div key={printer.id}
                    className={`flex items-center gap-3 p-2.5 rounded-lg border transition-colors ${
                      selected ? 'border-blue-300 bg-blue-50' : 'border-gray-100'
                    }`}
                  >
                    <label className="flex items-center gap-3 flex-1 min-w-0 cursor-pointer">
                      <input type="checkbox" checked={selected}
                        onChange={e => togglePrinter(printer, e.target.checked)}
                        className="h-4 w-4 rounded text-blue-600" />
                      <PrinterIcon className={`h-4 w-4 flex-shrink-0 ${selected ? 'text-blue-500' : 'text-gray-400'}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-800 truncate">{printer.name}</p>
                        <p className="text-xs text-gray-400 truncate">
                          {printer.model} · {printer.ip} · {(printer.protocol || 'ipp').toUpperCase()}
                          {printer.location && <> · {printer.location}</>}
                        </p>
                      </div>
                    </label>
                    {selected && (
                      <button
                        onClick={() => setDefaultPrinter(printer.id)}
                        className={`text-xs px-2 py-0.5 rounded font-medium flex-shrink-0 transition-colors ${
                          isDefault
                            ? 'bg-green-100 text-green-700'
                            : 'bg-gray-100 text-gray-500 hover:bg-green-50 hover:text-green-600'
                        }`}
                      >
                        {isDefault ? 'Standard' : 'Als Standard'}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Cloud Storage */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <CloudIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Cloud-Speicher</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.cloudStorage}
              onChange={e => onChange({ ...settings, cloudStorage: e.target.checked ? { oneDrive: { enabled: false }, iCloud: { enabled: false }, googleDrive: { enabled: false } } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.cloudStorage && (() => {
          const cloud = settings.cloudStorage as Record<string, unknown>;
          const od    = (cloud.oneDrive    as Record<string, unknown>) || {};
          const ic    = (cloud.iCloud       as Record<string, unknown>) || {};
          const gd    = (cloud.googleDrive  as Record<string, unknown>) || {};

          const setCloud = (provider: string, field: string, value: unknown) => {
            onChange({
              ...settings,
              cloudStorage: {
                ...cloud,
                [provider]: { ...(cloud[provider] as Record<string, unknown> || {}), [field]: value },
              },
            });
          };

          return (
            <div className="p-4 space-y-4">

              {/* OneDrive */}
              <div className="border border-blue-100 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-3">
                  <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                    <input type="checkbox"
                      checked={!!od.enabled}
                      onChange={e => setCloud('oneDrive', 'enabled', e.target.checked)}
                      className="h-4 w-4 rounded" />
                    Microsoft OneDrive
                  </label>
                  <span className="ml-auto text-xs text-blue-600 bg-blue-50 px-2 py-0.5 rounded">Windows · Linux · macOS</span>
                </div>
                {od.enabled && (
                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs text-gray-500 mb-1">Tenant-ID (Azure AD)</label>
                      <input type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        value={String(od.tenantId ?? '')}
                        onChange={e => setCloud('oneDrive', 'tenantId', e.target.value)}
                        className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-500" />
                    </div>
                    <div className="flex flex-wrap gap-3">
                      {[
                        { field: 'silentSignIn',    label: 'Silent Sign-In (AAD SSO)' },
                        { field: 'knownFolderMove', label: 'Known Folder Move (Desktop/Dokumente/Bilder)' },
                        { field: 'filesOnDemand',   label: 'Files On Demand (nur Metadaten lokal)' },
                      ].map(({ field, label }) => (
                        <label key={field} className="flex items-center gap-2 text-xs text-gray-600">
                          <input type="checkbox"
                            checked={!!od[field]}
                            onChange={e => setCloud('oneDrive', field, e.target.checked)}
                            className="h-3.5 w-3.5 rounded" />
                          {label}
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* iCloud */}
              <div className="border border-gray-100 rounded-lg p-3">
                <div className="flex items-center gap-2">
                  <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                    <input type="checkbox"
                      checked={ic.enabled !== false}
                      onChange={e => setCloud('iCloud', 'enabled', e.target.checked)}
                      className="h-4 w-4 rounded" />
                    iCloud (Apple)
                  </label>
                  <span className="ml-auto text-xs text-gray-500 bg-gray-50 px-2 py-0.5 rounded">macOS · Windows</span>
                </div>
                <p className="text-xs text-gray-400 mt-1.5 ml-6">
                  {ic.enabled !== false
                    ? 'iCloud wird erlaubt (keine Policy gesetzt).'
                    : 'iCloud wird per MDM-Payload (macOS) und GPO (Windows) deaktiviert.'}
                </p>
              </div>

              {/* Google Drive */}
              <div className="border border-green-100 rounded-lg p-3">
                <div className="flex items-center gap-2">
                  <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                    <input type="checkbox"
                      checked={!!gd.enabled}
                      onChange={e => setCloud('googleDrive', 'enabled', e.target.checked)}
                      className="h-4 w-4 rounded" />
                    Google Drive
                  </label>
                  <span className="ml-auto text-xs text-green-600 bg-green-50 px-2 py-0.5 rounded">Windows · Linux · macOS</span>
                </div>
                {gd.enabled && (
                  <p className="text-xs text-gray-400 mt-1.5 ml-6">
                    Windows: PowerShell Silent-Install · Linux: rclone systemd-Service · macOS: brew cask
                  </p>
                )}
              </div>

            </div>
          );
        })()}
      </div>

      {/* Automatische Updates */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <BoltIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Automatische Updates</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.updates}
              onChange={e => onChange({ ...settings, updates: e.target.checked ? { automatic: true } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.updates && (
          <div className="p-4">
            <label className="flex items-center gap-2 text-xs text-gray-600">
              <input type="checkbox"
                checked={!!((settings.updates as Record<string,unknown>).automatic)}
                onChange={e => set('updates', 'automatic', e.target.checked)}
                className="h-4 w-4 rounded" />
              Automatische Installation aktivieren
            </label>
            <p className="text-xs text-gray-400 mt-1.5 ml-6">Windows Update Policy 4 · Linux apt unattended-upgrades · macOS softwareupdate --schedule on</p>
          </div>
        )}
      </div>

      {/* Sudo (Linux) */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 flex items-center gap-2">
          <ServerIcon className="h-4 w-4 text-gray-500" />
          <h4 className="text-sm font-medium text-gray-700">Sudo-Konfiguration (Linux)</h4>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-500">
            <input type="checkbox" checked={!!settings.sudo}
              onChange={e => onChange({ ...settings, sudo: e.target.checked ? { adminGroups: ['Domain Admins', 'sudo'] } : undefined })}
              className="h-3.5 w-3.5 rounded" />
            Aktivieren
          </label>
        </div>
        {settings.sudo && (
          <div className="p-4">
            <label className="block text-xs text-gray-500 mb-1">Admin-Gruppen (kommagetrennt)</label>
            <input type="text" placeholder="Domain Admins, sudo"
              value={((((settings.sudo as Record<string,unknown>).adminGroups) as string[]) || []).join(', ')}
              onChange={e => set('sudo', 'adminGroups', e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean))}
              className="w-full border border-gray-300 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
            <p className="text-xs text-gray-400 mt-1.5">Schreibt <code className="bg-gray-100 px-1 rounded">%Gruppe ALL=(ALL:ALL) ALL</code> in <code className="bg-gray-100 px-1 rounded">/etc/sudoers.d/od-policy</code></p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Artifact Viewer ───────────────────────────────────────────────────────────
function ArtifactViewer({ compiled, policyId }: { compiled: CompiledResult; policyId: string }) {
  const [activePlatform, setActivePlatform] = useState<Platform>('windows');
  const platforms = Object.keys(compiled.artifacts || {}) as Platform[];

  const artifacts = compiled.artifacts[activePlatform] || [];

  return (
    <div className="space-y-4">
      {/* Platform Tabs */}
      <div className="flex gap-2 flex-wrap">
        {platforms.map(p => {
          const Icon = PLATFORM_ICONS[p];
          return (
            <button
              key={p}
              onClick={() => setActivePlatform(p)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activePlatform === p
                  ? `bg-${PLATFORM_COLORS[p]}-600 text-white`
                  : `bg-${PLATFORM_COLORS[p]}-50 text-${PLATFORM_COLORS[p]}-700 hover:bg-${PLATFORM_COLORS[p]}-100`
              }`}
            >
              <Icon className="h-4 w-4" />
              {PLATFORM_LABELS[p]}
              <span className="ml-1 px-1.5 py-0.5 rounded-full text-xs bg-white/20">
                {compiled.artifacts[p]?.length || 0}
              </span>
            </button>
          );
        })}
      </div>

      {/* Artifacts */}
      <div className="space-y-3">
        {artifacts.map((artifact, i) => (
          <div key={i} className="border border-gray-200 rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-xs px-2 py-0.5 rounded bg-blue-100 text-blue-700 font-mono flex-shrink-0">{artifact.type}</span>
                <span className="text-sm font-medium text-gray-800 font-mono truncate">{artifact.filename}</span>
              </div>
              <div className="flex items-center gap-1 flex-shrink-0">
                <CopyButton text={artifact.content} />
                <a
                  href={`/api/policies/${policyId}/artifact/${activePlatform}/${artifact.filename}`}
                  className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-700 transition-colors"
                  title="Herunterladen"
                  download
                >
                  <ArrowDownTrayIcon className="h-4 w-4" />
                </a>
              </div>
            </div>
            {artifact.description && (
              <div className="px-4 py-1.5 bg-blue-50 text-xs text-blue-700 border-b border-gray-200">
                {artifact.description}
              </div>
            )}
            {artifact.apply_command && (
              <div className="px-4 py-1.5 bg-gray-800 flex items-center justify-between">
                <code className="text-xs text-green-400 font-mono">{artifact.apply_command}</code>
                <CopyButton text={artifact.apply_command} />
              </div>
            )}
            <pre className="p-4 text-xs font-mono text-gray-700 overflow-x-auto bg-white max-h-48 overflow-y-auto whitespace-pre">{artifact.content}</pre>
          </div>
        ))}
        {artifacts.length === 0 && (
          <div className="text-center py-8 text-gray-400 text-sm">
            Keine Artefakte für {PLATFORM_LABELS[activePlatform]}
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════
export default function PoliciesView() {
  const [policies,   setPolicies]   = useState<Policy[]>([]);
  const [templates,  setTemplates]  = useState<PolicyTemplate[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [activeView, setActiveView] = useState<'list' | 'wizard' | 'detail'>('list');
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);
  const [compiledResult, setCompiledResult] = useState<CompiledResult | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [templateCategory, setTemplateCategory] = useState('all');

  // Wizard state
  const [wizardStep, setWizardStep]   = useState<WizardStep>(1);
  const [selectedTemplate, setSelectedTemplate] = useState<PolicyTemplate | null>(null);
  const [policyName, setPolicyName]   = useState('');
  const [policyDesc, setPolicyDesc]   = useState('');
  const [platforms,  setPlatforms]    = useState<Platform[]>(['windows', 'linux', 'macos']);
  const [settings,   setSettings]     = useState<Record<string, unknown>>({});
  const [saving, setSaving] = useState(false);
  const [recompiling, setRecompiling] = useState<string | null>(null);

  // Detail view state
  const [detailTab, setDetailTab] = useState<'artifacts' | 'history' | 'quotas' | 'compliance'>('artifacts');
  const [versionHistory, setVersionHistory] = useState<PolicyVersion[]>([]);
  const [printQuotas, setPrintQuotas] = useState<PrintQuota[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // LLDAP groups for wizard
  const [lldapGroups, setLldapGroups] = useState<string[]>([]);
  const [targetGroups, setTargetGroups] = useState<string[]>([]);

  // Compliance Live-Status
  const [complianceSummary, setComplianceSummary] = useState<ComplianceSummary | null>(null);

  const loadPolicies = useCallback(async () => {
    try {
      const r = await fetch('/api/policies');
      if (r.ok) {
        const data = await r.json();
        setPolicies((data.policies || data.data || []).filter((p: Policy) => p.type === 'policy-as-code' || true));
      }
    } catch {}
  }, []);

  const loadTemplates = useCallback(async () => {
    try {
      const r = await fetch('/api/policies/templates');
      if (r.ok) {
        const data = await r.json();
        setTemplates(data.templates || []);
      }
    } catch {}
  }, []);

  const loadComplianceSummary = useCallback(async () => {
    try {
      const r = await fetch('/api/compliance/summary');
      if (r.ok) setComplianceSummary(await r.json());
    } catch {}
  }, []);

  useEffect(() => {
    Promise.all([loadPolicies(), loadTemplates()]).finally(() => setLoading(false));
    loadComplianceSummary();
    const complianceInterval = setInterval(loadComplianceSummary, 30_000);
    // Load LLDAP groups for wizard
    fetch('/api/lldap/groups')
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        const groups: string[] = (d?.groups || d?.data || []).map((g: {name?: string; cn?: string}) => g.name || g.cn || '').filter(Boolean);
        setLldapGroups(groups);
      })
      .catch(() => {});
    // Load print quotas
    fetch('/api/printer/quotas')
      .then(r => r.ok ? r.json() : null)
      .then(d => d?.data && setPrintQuotas(d.data))
      .catch(() => {});
    return () => clearInterval(complianceInterval);
  }, [loadPolicies, loadTemplates, loadComplianceSummary]);

  const openWizard = (template?: PolicyTemplate) => {
    setWizardStep(1);
    if (template) {
      setSelectedTemplate(template);
      setPolicyName(template.name);
      setPolicyDesc(template.description);
      setPlatforms(template.targets.platforms as Platform[]);
      setTargetGroups(template.targets.groups);
      setSettings(template.settings as Record<string, unknown>);
      setWizardStep(2); // skip template selection
    } else {
      setSelectedTemplate(null);
      setPolicyName('');
      setPolicyDesc('');
      setPlatforms(['windows', 'linux', 'macos']);
      setTargetGroups([]);
      setSettings({});
    }
    setCompiledResult(null);
    setActiveView('wizard');
  };

  const handleCompile = async () => {
    if (!policyName) { toast.error('Policy-Name erforderlich'); return; }
    setCompiling(true);
    try {
      const intent = {
        name: policyName,
        description: policyDesc,
        targets: { platforms, groups: targetGroups },
        settings,
      };
      const r = await fetch('/api/policies/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(intent),
      });
      if (r.ok) {
        const data = await r.json();
        setCompiledResult(data.result);
        toast.success('Policy kompiliert!');
        setWizardStep(4);
      } else {
        toast.error('Kompilierung fehlgeschlagen');
      }
    } catch { toast.error('Fehler beim Kompilieren'); }
    finally { setCompiling(false); }
  };

  const handleSaveAndDeploy = async () => {
    setSaving(true);
    try {
      const intent = {
        name: policyName,
        description: policyDesc,
        targets: { platforms, groups: targetGroups },
        settings,
      };
      const r = await fetch('/api/policies/save-compiled', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: policyName,
          description: policyDesc,
          category: selectedTemplate?.category || 'custom',
          intent,
          platforms,
          target_groups: targetGroups,
        }),
      });
      if (r.ok) {
        toast.success(`Policy «${policyName}» gespeichert!`);
        loadPolicies();
        setActiveView('list');
      } else { toast.error('Speichern fehlgeschlagen'); }
    } catch { toast.error('Fehler'); }
    finally { setSaving(false); }
  };

  const handleDeletePolicy = async (id: string) => {
    try {
      const r = await fetch(`/api/policies/${id}`, { method: 'DELETE' });
      if (r.ok) { setPolicies(prev => prev.filter(p => p.id !== id)); toast.success('Policy gelöscht'); }
    } catch {}
  };

  const handleRecompile = async (policyId: string) => {
    setRecompiling(policyId);
    try {
      const r = await fetch(`/api/policies/${policyId}/recompile`, { method: 'POST' });
      if (r.ok) {
        toast.success('Policy neu kompiliert!');
        loadPolicies();
      } else { toast.error('Recompile fehlgeschlagen'); }
    } catch { toast.error('Fehler'); }
    finally { setRecompiling(null); }
  };

  const handleViewDetail = async (policy: Policy) => {
    setSelectedPolicy(policy);
    setCompiledResult(null);
    setVersionHistory([]);
    setDetailTab('artifacts');
    setActiveView('detail');
    // Load compiled result + version history in parallel
    setLoadingHistory(true);
    try {
      const [compR, histR] = await Promise.all([
        fetch(`/api/policies/${policy.id}/compiled`),
        fetch(`/api/policies/${policy.id}/versions`),
      ]);
      if (compR.ok) {
        const data = await compR.json();
        if (data.compiled) setCompiledResult(data.compiled);
      }
      if (histR.ok) {
        const data = await histR.json();
        setVersionHistory(data.versions || []);
      }
    } catch {}
    finally { setLoadingHistory(false); }
  };

  const handleDeploy = async (policyId: string) => {
    setDeploying(true);
    try {
      const r = await fetch(`/api/policies/${policyId}/deploy/windows`, { method: 'POST' });
      if (r.ok) {
        const data = await r.json();
        if (data.success && data.auto) {
          toast.success(`GPO automatisch deployed! GUID: ${data.gpo_guid}`);
          loadPolicies();
        } else if (data.success) {
          toast.success('Deployment-Anleitung verfügbar — manueller scp nötig');
          console.log('SYSVOL instructions:', data.instructions);
        } else {
          toast.error(data.message || 'DC nicht konfiguriert');
        }
      } else { toast.error('Deploy fehlgeschlagen'); }
    } catch { toast.error('Netzwerkfehler beim Deploy'); }
    finally { setDeploying(false); }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  // ── Policy List View ─────────────────────────────────────────────────────
  if (activeView === 'list') {
    const filteredTemplates = templateCategory === 'all'
      ? templates
      : templates.filter(t => t.category === templateCategory);

    const categories = ['all', 'hardening', 'password', 'network', 'compliance', 'software', 'drives', 'printers', 'cloud'];

    return (
      <div className="space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Policy-as-Code</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Intent-basierte Richtlinien → Windows GPO · Linux-Configs · macOS Profiles
            </p>
          </div>
          <button
            onClick={() => openWizard()}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 text-sm font-medium"
          >
            <PlusIcon className="h-4 w-4" />
            Neue Policy
          </button>
        </div>

        {/* Architecture Banner */}
        <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-100 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-blue-900 mb-3">Architektur</h3>
          <div className="flex items-start gap-3 flex-wrap">
            {[
              { icon: CodeBracketIcon, label: 'Intent YAML/JSON', sub: 'Policy definieren', color: 'blue' },
              { icon: BoltIcon,        label: 'Policy Compiler',  sub: 'OS-Artefakte erzeugen', color: 'indigo' },
              { icon: ComputerDesktopIcon, label: 'Windows → GPO', sub: 'SYSVOL · Registry.pol', color: 'sky' },
              { icon: ServerIcon,      label: 'Linux → Configs',  sub: 'sshd · sysctl · PAM', color: 'orange' },
              { icon: DevicePhoneMobileIcon, label: 'macOS → Profiles', sub: '.mobileconfig · LaunchDaemon', color: 'gray' },
            ].map(({ icon: Icon, label, sub, color }) => (
              <div key={label} className={`flex items-center gap-2 bg-white rounded-lg px-3 py-2 shadow-sm border border-${color}-100`}>
                <Icon className={`h-5 w-5 text-${color}-500 flex-shrink-0`} />
                <div>
                  <p className="text-xs font-medium text-gray-800">{label}</p>
                  <p className="text-xs text-gray-400">{sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Compliance Live-Status */}
        {complianceSummary && complianceSummary.overall.total_devices > 0 && (
          <div className="bg-white border border-gray-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-700 flex items-center gap-2">
                <ShieldCheckIcon className="h-4 w-4 text-green-500" />
                Compliance Live-Status
              </h3>
              <span className="text-xs text-gray-400 flex items-center gap-1">
                <ArrowPathIcon className="h-3 w-3" />
                alle 30s
              </span>
            </div>
            {/* Overall metrics */}
            <div className="grid grid-cols-3 gap-3 mb-4">
              {[
                {
                  label: 'Compliant',
                  value: `${complianceSummary.overall.compliant_devices}/${complianceSummary.overall.total_devices}`,
                  sub: complianceSummary.overall.pct_compliant !== null ? `${complianceSummary.overall.pct_compliant}%` : '—',
                  color: 'green',
                },
                {
                  label: 'Stale (>24h)',
                  value: complianceSummary.overall.stale_devices,
                  sub: 'kein Heartbeat',
                  color: complianceSummary.overall.stale_devices > 0 ? 'amber' : 'gray',
                },
                {
                  label: 'Geräte gesamt',
                  value: complianceSummary.overall.total_devices,
                  sub: 'registriert',
                  color: 'blue',
                },
              ].map(m => (
                <div key={m.label} className={`bg-${m.color}-50 border border-${m.color}-100 rounded-lg p-3 text-center`}>
                  <p className={`text-lg font-bold text-${m.color}-700`}>{m.value}</p>
                  <p className="text-xs font-medium text-gray-600">{m.label}</p>
                  <p className={`text-xs text-${m.color}-500`}>{m.sub}</p>
                </div>
              ))}
            </div>
            {/* Per-device status */}
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {complianceSummary.devices.map(d => {
                const allOk = !d.stale && d.total_policies > 0 && d.compliant_policies === d.total_policies;
                const partial = !d.stale && d.compliant_policies > 0 && d.compliant_policies < d.total_policies;
                const badge = d.stale
                  ? { cls: 'bg-gray-100 text-gray-500', label: 'Stale' }
                  : allOk
                    ? { cls: 'bg-green-100 text-green-700', label: 'Compliant' }
                    : partial
                      ? { cls: 'bg-amber-100 text-amber-700', label: `${d.compliant_policies}/${d.total_policies}` }
                      : { cls: 'bg-red-100 text-red-700', label: 'Non-compliant' };
                return (
                  <div key={d.device_id} className="flex items-center justify-between text-xs py-1 px-2 rounded hover:bg-gray-50">
                    <span className="font-medium text-gray-700 truncate mr-2">{d.device_name || d.device_id}</span>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-gray-400">{d.platform}</span>
                      {d.last_seen && (
                        <span className="text-gray-400" title={new Date(d.last_seen).toLocaleString('de-CH')}>
                          {d.hours_since_heartbeat !== null ? `${d.hours_since_heartbeat}h` : '—'}
                        </span>
                      )}
                      <span className={`px-1.5 py-0.5 rounded font-medium ${badge.cls}`}>{badge.label}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Templates */}
        <div>
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Quick-Start Templates</h3>
          {/* Category filter */}
          <div className="flex gap-2 mb-4 flex-wrap">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setTemplateCategory(cat)}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                  templateCategory === cat ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {({ all: 'Alle', hardening: 'Hardening', password: 'Passwort', network: 'Netzwerk', compliance: 'Compliance', software: 'Software', drives: 'Laufwerke', printers: 'Drucker', cloud: 'Cloud' } as Record<string,string>)[cat] ?? cat}
              </button>
            ))}
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {filteredTemplates.map(tpl => {
              const Icon = CATEGORY_ICONS[tpl.category] || ShieldCheckIcon;
              return (
                <div key={tpl.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-sm hover:border-blue-200 transition-all cursor-pointer group"
                  onClick={() => openWizard(tpl)}>
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-blue-50 group-hover:bg-blue-100 flex-shrink-0">
                      <Icon className="h-5 w-5 text-blue-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 group-hover:text-blue-700">{tpl.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{tpl.description}</p>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {(tpl.targets.platforms as Platform[]).map(p => (
                          <PlatformBadge key={p} platform={p} />
                        ))}
                      </div>
                    </div>
                    <ChevronRightIcon className="h-4 w-4 text-gray-300 group-hover:text-blue-500 flex-shrink-0 mt-0.5" />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Needs-Recompile Banner */}
        {policies.some(p => p.deploy_status === 'needs_recompile') && (
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-2">
            <ExclamationTriangleIcon className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-amber-800">
              <span className="font-medium">Infrastruktur geändert.</span>{' '}
              Netzlaufwerke oder Drucker wurden geändert. Betroffene Policies müssen neu kompiliert werden.
            </p>
          </div>
        )}

        {/* Existing Policies */}
        {policies.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Gespeicherte Policies ({policies.length})</h3>
            <div className="space-y-2">
              {policies.map(policy => (
                <div key={policy.id} className={`border rounded-lg p-4 hover:shadow-sm transition-shadow ${policy.deploy_status === 'needs_recompile' ? 'border-amber-200 bg-amber-50/30' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h4 className="text-sm font-medium text-gray-900">{policy.name}</h4>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[policy.deploy_status] || 'bg-gray-100 text-gray-600'}`}>
                          {STATUS_LABELS[policy.deploy_status] || policy.deploy_status}
                        </span>
                        <span className="text-xs text-gray-400">v{policy.version}</span>
                      </div>
                      {policy.description && <p className="text-xs text-gray-500 mt-0.5">{policy.description}</p>}
                      <div className="flex gap-1 mt-1.5 flex-wrap">
                        {(policy.platforms as unknown as Platform[] || []).map(p => (
                          <PlatformBadge key={p} platform={p} />
                        ))}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {policy.deploy_status === 'needs_recompile' && (
                        <button
                          onClick={() => handleRecompile(policy.id)}
                          disabled={recompiling === policy.id}
                          className="flex items-center gap-1 text-xs bg-amber-500 text-white px-2.5 py-1.5 rounded hover:bg-amber-600 disabled:opacity-60"
                          title="Neu kompilieren"
                        >
                          <ArrowPathIcon className={`h-3.5 w-3.5 ${recompiling === policy.id ? 'animate-spin' : ''}`} />
                          {recompiling === policy.id ? '…' : 'Recompile'}
                        </button>
                      )}
                      <button onClick={() => handleViewDetail(policy)} className="text-blue-400 hover:text-blue-600 p-1.5 rounded hover:bg-blue-50" title="Artefakte anzeigen">
                        <DocumentTextIcon className="h-4 w-4" />
                      </button>
                      <button onClick={() => handleDeploy(policy.id)} disabled={deploying} className="text-green-400 hover:text-green-600 p-1.5 rounded hover:bg-green-50" title="Deploy">
                        <PlayIcon className="h-4 w-4" />
                      </button>
                      <button onClick={() => handleDeletePolicy(policy.id)} className="text-red-400 hover:text-red-600 p-1.5 rounded hover:bg-red-50" title="Löschen">
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {policies.length === 0 && templates.length === 0 && (
          <div className="text-center py-16 border-2 border-dashed border-gray-200 rounded-xl">
            <ShieldCheckIcon className="h-12 w-12 mx-auto text-gray-300 mb-3" />
            <p className="text-gray-500">Noch keine Policies. Starte mit einem Template.</p>
          </div>
        )}

        {/* Print Quotas */}
        {printQuotas.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-1.5">
              <PrinterIcon className="h-4 w-4 text-gray-400" />
              Druck-Quotas
            </h3>
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="text-left px-4 py-2 text-xs font-medium text-gray-500">Benutzer</th>
                    <th className="text-right px-4 py-2 text-xs font-medium text-gray-500">Verbraucht</th>
                    <th className="text-right px-4 py-2 text-xs font-medium text-gray-500">Limit</th>
                    <th className="text-left px-4 py-2 text-xs font-medium text-gray-500">Fortschritt</th>
                    <th className="text-left px-4 py-2 text-xs font-medium text-gray-500">Periode</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {printQuotas.map(q => {
                    const pct = q.quota_limit > 0 ? Math.min(100, Math.round((q.used_pages / q.quota_limit) * 100)) : 0;
                    const color = pct >= 90 ? 'red' : pct >= 70 ? 'amber' : 'green';
                    return (
                      <tr key={q.id} className="hover:bg-gray-50">
                        <td className="px-4 py-2.5 font-medium text-gray-800">{q.user_name}</td>
                        <td className="px-4 py-2.5 text-right text-gray-600">{q.used_pages}</td>
                        <td className="px-4 py-2.5 text-right text-gray-500">{q.quota_limit}</td>
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-gray-200 rounded-full h-1.5 max-w-[120px]">
                              <div className={`h-1.5 rounded-full bg-${color}-500`} style={{ width: `${pct}%` }} />
                            </div>
                            <span className={`text-xs text-${color}-600 font-medium`}>{pct}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-2.5 text-xs text-gray-400">{q.period || 'monthly'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    );
  }

  // ── Detail View (Compiled Artifacts + History + Quotas) ──────────────────
  if (activeView === 'detail' && selectedPolicy) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 flex-wrap">
          <button onClick={() => setActiveView('list')} className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700">
            <ChevronLeftIcon className="h-4 w-4" />Zurück
          </button>
          <h2 className="text-xl font-semibold text-gray-900">{selectedPolicy.name}</h2>
          <span className={`px-2.5 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[selectedPolicy.deploy_status] || 'bg-gray-100 text-gray-600'}`}>
            {STATUS_LABELS[selectedPolicy.deploy_status] || selectedPolicy.deploy_status}
          </span>
          {selectedPolicy.deploy_status === 'needs_recompile' && (
            <button
              onClick={async () => { await handleRecompile(selectedPolicy.id); await handleViewDetail(selectedPolicy); }}
              disabled={!!recompiling}
              className="flex items-center gap-1 text-xs bg-amber-500 text-white px-3 py-1.5 rounded hover:bg-amber-600 disabled:opacity-60"
            >
              <ArrowPathIcon className={`h-3.5 w-3.5 ${recompiling ? 'animate-spin' : ''}`} />
              Neu kompilieren
            </button>
          )}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-gray-200">
          {([
            { id: 'artifacts',  label: 'Artefakte',  icon: DocumentTextIcon },
            { id: 'history',    label: 'Versionen',  icon: ClockIcon },
            { id: 'compliance', label: 'Compliance', icon: ShieldCheckIcon },
          ] as {id: typeof detailTab; label: string; icon: React.ElementType}[]).map(tab => {
            const Icon = tab.icon;
            return (
              <button key={tab.id} onClick={() => setDetailTab(tab.id)}
                className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  detailTab === tab.id ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}>
                <Icon className="h-4 w-4" />{tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab: Artefakte */}
        {detailTab === 'artifacts' && (
          compiledResult ? (
            <ArtifactViewer compiled={compiledResult} policyId={selectedPolicy.id} />
          ) : (
            <div className="text-center py-16 border-2 border-dashed border-gray-200 rounded-xl">
              <CodeBracketIcon className="h-10 w-10 mx-auto text-gray-300 mb-3" />
              <p className="text-gray-500">Keine kompilierten Artefakte vorhanden</p>
            </div>
          )
        )}

        {/* Tab: Versionshistorie */}
        {detailTab === 'history' && (
          <div className="space-y-3">
            {loadingHistory && (
              <div className="flex items-center gap-2 text-sm text-gray-400 py-8 justify-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-400" />
                Lade Versionshistorie…
              </div>
            )}
            {!loadingHistory && versionHistory.length === 0 && (
              <div className="text-center py-12 border-2 border-dashed border-gray-200 rounded-xl text-gray-400 text-sm">
                Keine Versionen gespeichert
              </div>
            )}
            {versionHistory.map(v => (
              <div key={v.id} className="flex items-center justify-between border border-gray-200 rounded-lg px-4 py-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-800">v{v.version}</span>
                    {v.deployed_by && (
                      <span className="text-xs text-gray-400">von {v.deployed_by}</span>
                    )}
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {v.compiled_at ? new Date(v.compiled_at).toLocaleString('de-CH') : '—'}
                    {v.comment && <span className="ml-2 italic">{v.comment}</span>}
                  </p>
                </div>
                <span className="text-xs px-2 py-0.5 bg-blue-50 text-blue-600 rounded font-mono">v{v.version}</span>
              </div>
            ))}
          </div>
        )}

        {/* Tab: Compliance */}
        {detailTab === 'compliance' && (() => {
          const policyCompliance = complianceSummary?.policies.find(
            p => p.policy_id === selectedPolicy.id
          );
          const deviceCompliance = complianceSummary?.devices.filter(
            d => d.total_policies > 0
          ) ?? [];

          return (
            <div className="space-y-4">
              {/* Policy summary bar */}
              {policyCompliance ? (
                <div className="bg-white border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Policy-Compliance</span>
                    <span className={`text-sm font-bold ${
                      (policyCompliance.pct_compliant ?? 0) >= 80 ? 'text-green-600' : 'text-red-600'
                    }`}>
                      {policyCompliance.pct_compliant !== null ? `${policyCompliance.pct_compliant}%` : '—'}
                    </span>
                  </div>
                  <div className="w-full bg-gray-100 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full transition-all ${
                        (policyCompliance.pct_compliant ?? 0) >= 80 ? 'bg-green-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${policyCompliance.pct_compliant ?? 0}%` }}
                    />
                  </div>
                  <p className="text-xs text-gray-400 mt-1">
                    {policyCompliance.compliant_devices} von {policyCompliance.total_devices} Geräten compliant
                  </p>
                </div>
              ) : (
                <div className="text-center py-8 text-sm text-gray-400 border-2 border-dashed border-gray-200 rounded-lg">
                  Noch keine Compliance-Daten für diese Policy
                </div>
              )}

              {/* Per-device list */}
              {deviceCompliance.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Geräte</h4>
                  {deviceCompliance.map(d => {
                    const allOk = !d.stale && d.total_policies > 0 && d.compliant_policies === d.total_policies;
                    const partial = !d.stale && d.compliant_policies > 0 && d.compliant_policies < d.total_policies;
                    const status = d.stale ? 'stale' : allOk ? 'ok' : partial ? 'partial' : 'fail';
                    const statusConfig = {
                      ok:      { cls: 'bg-green-100 text-green-700 border-green-200', label: 'Compliant', dot: 'bg-green-500' },
                      partial: { cls: 'bg-amber-100 text-amber-700 border-amber-200', label: `${d.compliant_policies}/${d.total_policies}`, dot: 'bg-amber-500' },
                      fail:    { cls: 'bg-red-100 text-red-700 border-red-200',       label: 'Non-compliant', dot: 'bg-red-500' },
                      stale:   { cls: 'bg-gray-100 text-gray-500 border-gray-200',    label: 'Stale', dot: 'bg-gray-400' },
                    }[status];
                    return (
                      <div key={d.device_id} className={`flex items-center justify-between border rounded-lg px-3 py-2.5 ${statusConfig.cls}`}>
                        <div className="flex items-center gap-2 min-w-0">
                          <span className={`h-2 w-2 rounded-full flex-shrink-0 ${statusConfig.dot}`} />
                          <span className="text-sm font-medium truncate">{d.device_name || d.device_id}</span>
                          <span className="text-xs opacity-70">{d.platform}</span>
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0 text-xs">
                          {d.last_check && (
                            <span className="opacity-60" title={new Date(d.last_check).toLocaleString('de-CH')}>
                              {new Date(d.last_check).toLocaleString('de-CH', { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit' })}
                            </span>
                          )}
                          <span className="font-semibold">{statusConfig.label}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Push-to-all button */}
              <div className="pt-2">
                <button
                  onClick={async () => {
                    try {
                      const r = await fetch(`/api/policies/${selectedPolicy.id}/assign`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ push: true }) });
                      if (r.ok) { toast.success('Policy an alle Geräte gepusht'); loadComplianceSummary(); }
                      else toast.error('Push fehlgeschlagen');
                    } catch { toast.error('Netzwerkfehler'); }
                  }}
                  className="flex items-center gap-2 text-sm bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
                >
                  <PlayIcon className="h-4 w-4" />
                  Push to all devices
                </button>
              </div>
            </div>
          );
        })()}
      </div>
    );
  }

  // ── Wizard View ───────────────────────────────────────────────────────────
  const wizardSteps = [
    { n: 1, label: 'Template' },
    { n: 2, label: 'Name & Scope' },
    { n: 3, label: 'Einstellungen' },
    { n: 4, label: 'Kompilieren' },
  ];

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Wizard Header */}
      <div className="flex items-center justify-between">
        <button onClick={() => setActiveView('list')} className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700">
          <ChevronLeftIcon className="h-4 w-4" />Zurück
        </button>
        <h2 className="text-lg font-semibold text-gray-900">Neue Policy erstellen</h2>
        <div />
      </div>

      {/* Progress */}
      <div className="flex items-center gap-2">
        {wizardSteps.map((step, i) => (
          <React.Fragment key={step.n}>
            <div className={`flex items-center justify-center w-8 h-8 rounded-full text-xs font-medium ${
              wizardStep > step.n ? 'bg-blue-600 text-white' :
              wizardStep === step.n ? 'bg-blue-600 text-white ring-4 ring-blue-100' :
              'bg-gray-200 text-gray-500'
            }`}>
              {wizardStep > step.n ? <CheckIcon className="h-4 w-4" /> : step.n}
            </div>
            <span className={`text-xs ${wizardStep >= step.n ? 'text-blue-700 font-medium' : 'text-gray-400'}`}>{step.label}</span>
            {i < wizardSteps.length - 1 && <ChevronRightIcon className="h-4 w-4 text-gray-300 flex-shrink-0" />}
          </React.Fragment>
        ))}
      </div>

      {/* Step 1: Template selection */}
      {wizardStep === 1 && (
        <div className="space-y-4">
          <p className="text-sm text-gray-600">Wähle ein Template als Ausgangspunkt oder erstelle eine leere Policy:</p>
          <button
            onClick={() => { setSelectedTemplate(null); setSettings({}); setWizardStep(2); }}
            className="w-full flex items-center gap-3 p-4 border-2 border-dashed border-gray-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 text-left"
          >
            <PlusIcon className="h-6 w-6 text-gray-400" />
            <div>
              <p className="text-sm font-medium text-gray-700">Leere Policy</p>
              <p className="text-xs text-gray-500">Von Grund auf neu konfigurieren</p>
            </div>
          </button>
          <div className="grid gap-3">
            {templates.map(tpl => {
              const Icon = CATEGORY_ICONS[tpl.category] || ShieldCheckIcon;
              return (
                <button key={tpl.id}
                  onClick={() => {
                    setSelectedTemplate(tpl);
                    setPolicyName(tpl.name);
                    setPolicyDesc(tpl.description);
                    setPlatforms(tpl.targets.platforms as Platform[]);
                    setSettings(tpl.settings as Record<string, unknown>);
                    setWizardStep(2);
                  }}
                  className="flex items-center gap-3 p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 text-left transition-all"
                >
                  <Icon className="h-5 w-5 text-blue-600 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900">{tpl.name}</p>
                    <p className="text-xs text-gray-500 truncate">{tpl.description}</p>
                  </div>
                  <div className="flex gap-1 flex-shrink-0">
                    {(tpl.targets.platforms as Platform[]).slice(0, 2).map(p => <PlatformBadge key={p} platform={p} />)}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Step 2: Name + Scope */}
      {wizardStep === 2 && (
        <div className="space-y-5">
          {selectedTemplate && (
            <div className="bg-blue-50 border border-blue-100 rounded-lg p-3 text-xs text-blue-700">
              Template: <span className="font-medium">{selectedTemplate.name}</span>
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Policy-Name *</label>
            <input type="text" value={policyName} onChange={e => setPolicyName(e.target.value)}
              placeholder="z.B. Workstation Baseline v1"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" autoFocus />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Beschreibung</label>
            <textarea value={policyDesc} onChange={e => setPolicyDesc(e.target.value)}
              rows={2} placeholder="Was macht diese Policy?"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Ziel-Plattformen</label>
            <div className="flex gap-2 flex-wrap">
              {(['windows', 'linux', 'macos'] as Platform[]).map(p => {
                const Icon = PLATFORM_ICONS[p];
                const active = platforms.includes(p);
                return (
                  <button key={p}
                    onClick={() => setPlatforms(prev => active ? prev.filter(x => x !== p) : [...prev, p])}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg border-2 text-sm font-medium transition-all ${
                      active ? `border-${PLATFORM_COLORS[p]}-500 bg-${PLATFORM_COLORS[p]}-50 text-${PLATFORM_COLORS[p]}-700` : 'border-gray-200 text-gray-500'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {PLATFORM_LABELS[p]}
                    {active && <CheckIcon className="h-3.5 w-3.5" />}
                  </button>
                );
              })}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1 flex items-center gap-1.5">
              <UserGroupIcon className="h-4 w-4 text-gray-400" />
              Ziel-Gruppen
              <span className="text-xs font-normal text-gray-400">(leer = alle Benutzer/Geräte)</span>
            </label>
            {lldapGroups.length > 0 ? (
              <div className="border border-gray-300 rounded-lg p-2 max-h-40 overflow-y-auto space-y-0.5">
                {lldapGroups.map(grp => (
                  <label key={grp} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-gray-50 cursor-pointer">
                    <input type="checkbox"
                      checked={targetGroups.includes(grp)}
                      onChange={e => setTargetGroups(prev => e.target.checked ? [...prev, grp] : prev.filter(g => g !== grp))}
                      className="h-4 w-4 rounded text-blue-600" />
                    <span className="text-sm text-gray-700">{grp}</span>
                  </label>
                ))}
              </div>
            ) : (
              <div className="space-y-1.5">
                <input type="text"
                  placeholder="Gruppen kommagetrennt eingeben: IT, Workstations"
                  value={targetGroups.join(', ')}
                  onChange={e => setTargetGroups(e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                <p className="text-xs text-gray-400">LLDAP nicht verbunden — Gruppen manuell eingeben</p>
              </div>
            )}
            {targetGroups.length > 0 && (
              <div className="flex gap-1.5 mt-2 flex-wrap">
                {targetGroups.map(g => (
                  <span key={g} className="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs">
                    {g}
                    <button onClick={() => setTargetGroups(prev => prev.filter(x => x !== g))} className="hover:text-blue-900">
                      <XMarkIcon className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Step 3: Settings */}
      {wizardStep === 3 && (
        <div className="space-y-4">
          <p className="text-sm text-gray-600">
            Konfiguriere die Policy-Einstellungen. Der Compiler erzeugt daraus plattformspezifische Artefakte.
          </p>
          <SettingsEditor settings={settings} onChange={setSettings} />
        </div>
      )}

      {/* Step 4: Preview + Deploy */}
      {wizardStep === 4 && (
        <div className="space-y-4">
          {compiledResult ? (
            <>
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <CheckIcon className="h-5 w-5 text-green-600" />
                  <p className="text-sm font-medium text-green-800">Policy erfolgreich kompiliert!</p>
                </div>
                <p className="text-xs text-green-600 mt-1">
                  {Object.values(compiledResult.artifacts).flat().length} Artefakte für {Object.keys(compiledResult.artifacts).join(', ')}
                </p>
              </div>
              <ArtifactViewer compiled={compiledResult} policyId="preview" />
            </>
          ) : (
            <div className="text-center py-12 border-2 border-dashed border-gray-200 rounded-xl">
              <BoltIcon className="h-10 w-10 mx-auto text-gray-300 mb-3" />
              <p className="text-gray-500 text-sm">Policy noch nicht kompiliert</p>
              <button onClick={handleCompile} disabled={compiling}
                className="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-60">
                {compiling ? 'Kompiliere…' : 'Jetzt kompilieren'}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Footer Navigation */}
      <div className="flex items-center justify-between pt-4 border-t border-gray-200">
        <button
          onClick={() => wizardStep === 1 ? setActiveView('list') : setWizardStep(s => (s - 1) as WizardStep)}
          className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-800"
        >
          {wizardStep > 1 && <ChevronLeftIcon className="h-4 w-4" />}
          {wizardStep === 1 ? 'Abbrechen' : 'Zurück'}
        </button>
        <div className="flex gap-2">
          {wizardStep === 3 && (
            <button onClick={handleCompile} disabled={compiling}
              className="flex items-center gap-2 bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-60">
              <BoltIcon className="h-4 w-4" />
              {compiling ? 'Kompiliere…' : 'Kompilieren'}
            </button>
          )}
          {wizardStep < 4 && wizardStep !== 3 && (
            <button
              onClick={() => setWizardStep(s => (s + 1) as WizardStep)}
              disabled={wizardStep === 2 && !policyName}
              className="flex items-center gap-1 bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-40"
            >
              Weiter <ChevronRightIcon className="h-4 w-4" />
            </button>
          )}
          {wizardStep === 4 && compiledResult && (
            <button onClick={handleSaveAndDeploy} disabled={saving}
              className="flex items-center gap-2 bg-green-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-green-700 disabled:opacity-60">
              <CheckIcon className="h-4 w-4" />
              {saving ? 'Speichern…' : 'Speichern & Bereitstellen'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
