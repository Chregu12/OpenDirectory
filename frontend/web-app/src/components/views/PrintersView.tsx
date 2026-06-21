'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  PrinterIcon,
  PlusIcon,
  XMarkIcon,
  TrashIcon,
  SparklesIcon,
  MagnifyingGlassIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ChevronRightIcon,
  ChevronLeftIcon,
  Cog6ToothIcon,
  StarIcon,
  FolderIcon,
  InformationCircleIcon,
  ClipboardDocumentIcon,
} from '@heroicons/react/24/outline';
import { StarIcon as StarIconSolid } from '@heroicons/react/24/solid';
import { printerApi } from '@/lib/api';
import toast from 'react-hot-toast';
import PrinterSetupWizard from '@/components/setup/PrinterSetupWizard';

// ─── Types ───────────────────────────────────────────────────────────────────

type PrinterProtocol = 'IPP' | 'LPD' | 'SMB';
type PrinterStatus   = 'online' | 'offline' | 'error';
type JobStatus       = 'pending' | 'printing' | 'completed' | 'failed' | 'cancelled';
type PrinterTab      = 'printers' | 'scanners' | 'jobs' | 'quotas' | 'scan-destinations' | 'print-pools';

interface Printer {
  id: string;
  name: string;
  ip: string;
  model: string;
  protocol: PrinterProtocol;
  status: PrinterStatus;
  queueDepth: number;
  location?: string;
  isMultifunction?: boolean;
  scanFormats?: string[];
}

interface ScanProfile {
  id: string;
  name: string;
  resolution: string;
  color: string;
  format: string;
  destination: string;
  isDefault?: boolean;
}

interface Scanner {
  id: string;
  name: string;
  ip: string;
  model: string;
  status: PrinterStatus;
  formats: string[];
  profiles?: ScanProfile[];
}

interface PrintJob {
  id: string;
  documentName: string;
  user: string;
  printer: string;
  pages: number;
  submitted: string;
  status: JobStatus;
}

interface PrintQuota {
  userId: string;
  username: string;
  used: number;
  limit: number;
  resetDate: string;
}

interface ProbeResult {
  ip: string;
  hostname?: string;
  vendor?: string;
  model?: string;
  protocols: PrinterProtocol[];
  snmpInfo?: Record<string, string>;
}

interface DriverOption {
  id: string;
  name: string;
  version?: string;
  recommended?: boolean;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function StatusDot({ status }: { status: PrinterStatus }) {
  const colors: Record<PrinterStatus, string> = {
    online:  'bg-green-500',
    offline: 'bg-gray-400',
    error:   'bg-red-500',
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${colors[status]}`} />;
}

function JobStatusBadge({ status }: { status: JobStatus }) {
  const styles: Record<JobStatus, string> = {
    pending:   'bg-[rgba(210,153,34,0.15)] text-[#d29922]',
    printing:  'bg-[rgba(0,111,255,0.15)] text-[#006FFF]',
    completed: 'bg-[rgba(63,185,80,0.15)] text-[#3fb950]',
    failed:    'bg-[rgba(248,81,73,0.15)] text-[#f85149]',
    cancelled: 'bg-[rgba(139,148,158,0.15)] text-[#8b949e]',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${styles[status]}`}>
      {status}
    </span>
  );
}

function ProtocolBadge({ protocol }: { protocol: PrinterProtocol }) {
  const styles: Record<PrinterProtocol, string> = {
    IPP: 'bg-[rgba(0,111,255,0.15)] text-[#006FFF]',
    LPD: 'bg-[rgba(163,113,247,0.15)] text-[#a371f7]',
    SMB: 'bg-[rgba(210,153,34,0.15)] text-[#d29922]',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[protocol]}`}>
      {protocol}
    </span>
  );
}

function isLikelyMultifunction(vendor?: string, model?: string): boolean {
  const text = `${vendor ?? ''} ${model ?? ''}`.toLowerCase();
  return text.includes('officejet') || text.includes('mfc') ||
    text.includes('imagerunner') || text.includes('workforce') ||
    text.includes('pixma') || text.includes('mfp') ||
    text.includes('all-in-one') || text.includes('envy') ||
    text.includes('deskjet') || text.includes('ecotank');
}

// ─── Add Printer Wizard ───────────────────────────────────────────────────────
// Step 1: Enter IP → probe → detect device
// Step 2: Select driver from list returned by backend
// Step 3: Set name, location, confirm

type WizardStep = 1 | 2 | 3;

const VENDOR_OPTIONS = ['HP', 'Canon', 'Epson', 'Brother', 'Dymo', 'Xerox', 'Lexmark', 'Ricoh', 'Samsung', 'Other'] as const;

function AddPrinterWizard({ onClose, onAdded }: {
  onClose: () => void;
  onAdded: (p: Printer) => void;
}) {
  const [step, setStep]             = useState<WizardStep>(1);
  const [ip, setIp]                 = useState('');
  const [probing, setProbing]       = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  // Manual entry (fallback when probe service is unavailable)
  const [manualMode, setManualMode] = useState(false);
  const [manualVendor, setManualVendor] = useState('HP');
  const [manualModel, setManualModel]   = useState('');
  const [drivers, setDrivers]       = useState<DriverOption[]>([]);
  const [loadingDrivers, setLoadingDrivers] = useState(false);
  const [selectedDriver, setSelectedDriver] = useState<DriverOption | null>(null);
  const [selectedProtocol, setSelectedProtocol] = useState<PrinterProtocol>('IPP');
  const [printerName, setPrinterName] = useState('');
  const [location, setLocation]     = useState('');
  const [saving, setSaving]         = useState(false);
  // Multifunction device support
  const [isMultifunction, setIsMultifunction] = useState(false);
  const [autoDetectedMF, setAutoDetectedMF]   = useState(false);
  const [scanFormats, setScanFormats]         = useState<string[]>(['PDF', 'JPEG']);

  // Step 1: probe the IP via backend; on failure fall back to manual entry
  const handleProbe = async () => {
    const trimmed = ip.trim();
    if (!trimmed) { toast.error('Enter an IP address or hostname'); return; }
    setProbing(true);
    setProbeError(null);
    setProbeResult(null);
    setManualMode(false);
    try {
      const res = await printerApi.probePrinter(trimmed);
      const result: ProbeResult = res.data;
      setProbeResult(result);
      setSelectedProtocol(result.protocols?.[0] ?? 'IPP');
      if (result.model) setPrinterName(result.model.replace(/\s+/g, '-'));
      const detected = isLikelyMultifunction(result.vendor, result.model);
      setIsMultifunction(detected);
      setAutoDetectedMF(detected);
      await loadDrivers(result.vendor, result.model);
      setStep(2);
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 404) {
        setProbeError('No printer found at that address. Check the IP and make sure the printer is on.');
      } else {
        setProbeError('Auto-detection unavailable. Enter the make and model manually to continue.');
      }
      setManualMode(true);
    } finally {
      setProbing(false);
    }
  };

  // Advance from step 1 using manually-entered vendor/model
  const handleManualNext = async () => {
    const trimmed = ip.trim();
    if (!trimmed) { toast.error('Enter an IP address or hostname'); return; }
    const result: ProbeResult = {
      ip: trimmed,
      vendor: manualVendor,
      model: manualModel.trim() || manualVendor,
      protocols: [selectedProtocol],
    };
    setProbeResult(result);
    if (!printerName) setPrinterName((manualModel.trim() || manualVendor).replace(/\s+/g, '-'));
    const detected = isLikelyMultifunction(manualVendor, manualModel.trim());
    setIsMultifunction(detected);
    setAutoDetectedMF(detected);
    await loadDrivers(manualVendor, manualModel.trim());
    setStep(2);
  };

  const loadDrivers = async (vendor?: string, model?: string) => {
    setLoadingDrivers(true);
    try {
      // Try a driver lookup endpoint; backend returns compatible drivers for this vendor/model
      const res = await printerApi.discoverPrinters();
      // If the backend returns drivers in the same payload, pick them; otherwise use generic list
      const raw: DriverOption[] = (res.data?.drivers ?? []) as DriverOption[];
      if (raw.length > 0) {
        setDrivers(raw);
        const rec = raw.find((d: DriverOption) => d.recommended) ?? raw[0];
        setSelectedDriver(rec ?? null);
      } else {
        // Build generic driver list from vendor/model info
        const generics = buildGenericDriverList(vendor, model);
        setDrivers(generics);
        setSelectedDriver(generics.find(d => d.recommended) ?? generics[0] ?? null);
      }
    } catch {
      const generics = buildGenericDriverList(vendor, model);
      setDrivers(generics);
      setSelectedDriver(generics.find(d => d.recommended) ?? generics[0] ?? null);
    } finally {
      setLoadingDrivers(false);
    }
  };

  // Build a realistic driver list based on vendor/model info from SNMP/probe
  function buildGenericDriverList(vendor?: string, model?: string): DriverOption[] {
    const v = (vendor ?? '').toLowerCase();
    const m = (model ?? '').toLowerCase();
    // Strip leading vendor name from model to avoid "HP HP OfficeJet" duplicates
    const modelClean = vendor && model
      ? model.replace(new RegExp(`^${vendor}\\s+`, 'i'), '')
      : (model ?? 'Printer');
    if (v.includes('hp') || m.includes('hp') || m.includes('laserjet') || m.includes('officejet')) {
      return [
        { id: 'hp-pcl6',   name: 'HP Universal Print Driver (PCL6)',  version: '7.0.1', recommended: true },
        { id: 'hp-pcl5',   name: 'HP Universal Print Driver (PCL5)',  version: '7.0.1' },
        { id: 'hp-ps',     name: 'HP Universal Print Driver (PS)',     version: '7.0.1' },
        { id: 'hp-model',  name: `HP ${modelClean} Specific`,         version: '1.0.0' },
      ];
    }
    if (v.includes('canon') || m.includes('canon') || m.includes('imagerunner') || m.includes('pixma')) {
      return [
        { id: 'canon-ufrii',  name: 'Canon Generic UFR II',             version: '3.90', recommended: true },
        { id: 'canon-pcl5e',  name: 'Canon Generic PCL5e',              version: '3.90' },
        { id: 'canon-ps',     name: 'Canon Generic PS3',                version: '3.90' },
        { id: 'canon-model',  name: `Canon ${modelClean} Specific`,     version: '1.0.0' },
      ];
    }
    if (v.includes('epson') || m.includes('epson')) {
      return [
        { id: 'epson-esc',   name: 'Epson ESC/P Universal Driver',      version: '3.2.0', recommended: true },
        { id: 'epson-pcl',   name: 'Epson PCL Driver',                  version: '3.2.0' },
        { id: 'epson-model', name: `Epson ${modelClean} Specific`,      version: '1.0.0' },
      ];
    }
    if (v.includes('brother') || m.includes('brother')) {
      return [
        { id: 'brother-brlaser', name: 'Brother BrLaser Universal',    version: '4.0.0', recommended: true },
        { id: 'brother-pcl',     name: 'Brother PCL Driver',            version: '4.0.0' },
        { id: 'brother-model',   name: `Brother ${modelClean} Specific`, version: '1.0.0' },
      ];
    }
    if (v.includes('dymo') || m.includes('dymo') || m.includes('label')) {
      return [
        { id: 'dymo-lw',    name: 'DYMO LabelWriter Driver',            version: '8.7.4', recommended: true },
        { id: 'dymo-model', name: `DYMO ${modelClean} Specific`,        version: '1.0.0' },
      ];
    }
    if (v.includes('xerox') || m.includes('xerox')) {
      return [
        { id: 'xerox-global', name: 'Xerox Global Print Driver (PCL6)', version: '5.8.0', recommended: true },
        { id: 'xerox-ps',     name: 'Xerox Global Print Driver (PS)',    version: '5.8.0' },
        { id: 'xerox-model',  name: `Xerox ${modelClean} Specific`,     version: '1.0.0' },
      ];
    }
    // Generic fallback
    return [
      { id: 'generic-pcl6',  name: 'Generic PCL6 Driver',   version: '1.0', recommended: true },
      { id: 'generic-pcl5',  name: 'Generic PCL5 Driver',   version: '1.0' },
      { id: 'generic-ps',    name: 'Generic PostScript 3',  version: '1.0' },
    ];
  }

  const handleAddPrinter = async () => {
    if (!printerName.trim()) { toast.error('Printer name is required'); return; }
    if (!selectedDriver) { toast.error('Select a driver'); return; }
    setSaving(true);
    const payload = {
      name:            printerName.trim(),
      ip:              ip.trim(),
      model:           probeResult?.model ?? '',
      protocol:        selectedProtocol,
      driver:          selectedDriver.name,
      location:        location.trim() || undefined,
      isMultifunction: isMultifunction,
      scanFormats:     isMultifunction ? scanFormats : [],
    };
    try {
      const res = await printerApi.addPrinter(payload);
      onAdded(res.data);
      toast.success(`Printer "${payload.name}" added`);
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Failed to add printer');
    } finally {
      setSaving(false);
    }
  };

  const STEPS = ['Find Device', 'Select Driver', 'Confirm'];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-lg mx-4 flex flex-col">

        {/* Title bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[rgba(255,255,255,0.07)]">
          <h2 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Add Network Printer</h2>
          <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-0 px-6 py-3 border-b border-[rgba(255,255,255,0.07)] bg-[var(--bg-surface-raised,#1c2128)]">
          {STEPS.map((label, i) => {
            const n = i + 1;
            const done    = step > n;
            const active  = step === n;
            return (
              <React.Fragment key={n}>
                <div className="flex items-center gap-1.5">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold ${
                    done   ? 'bg-[#006FFF] text-white' :
                    active ? 'bg-[rgba(0,111,255,0.15)] text-[#006FFF] ring-2 ring-[#006FFF]' :
                             'bg-[rgba(255,255,255,0.08)] text-[var(--text-muted,#6e7681)]'
                  }`}>
                    {done ? <CheckCircleIcon className="w-4 h-4" /> : n}
                  </div>
                  <span className={`text-xs font-medium ${active ? 'text-[#006FFF]' : done ? 'text-[#006FFF]' : 'text-[var(--text-muted,#6e7681)]'}`}>
                    {label}
                  </span>
                </div>
                {i < STEPS.length - 1 && (
                  <ChevronRightIcon className="w-3.5 h-3.5 text-[var(--text-muted,#6e7681)] mx-2 flex-shrink-0" />
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Content */}
        <div className="p-6">

          {/* ── Step 1: Find Device ── */}
          {step === 1 && (
            <div className="space-y-4">
              <p className="text-sm text-[var(--text-secondary,#8b949e)]">
                Enter the IP address or hostname of the printer. The service will probe the device to detect its make, model, and supported protocols.
              </p>
              <div>
                <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1.5">
                  IP Address / Hostname
                </label>
                <div className="flex gap-2">
                  <input
                    value={ip}
                    onChange={e => { setIp(e.target.value); setProbeError(null); setManualMode(false); }}
                    onKeyDown={e => e.key === 'Enter' && handleProbe()}
                    className="flex-1 border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                    style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
                    placeholder="192.168.1.50"
                    autoFocus
                  />
                  <button
                    onClick={handleProbe}
                    disabled={probing || !ip.trim()}
                    className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-50"
                  >
                    {probing
                      ? <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Probing…</>
                      : <><MagnifyingGlassIcon className="w-4 h-4" /> Probe</>
                    }
                  </button>
                </div>
              </div>

              {probeError && (
                <div className="flex items-start gap-2 p-3 bg-[rgba(210,153,34,0.15)] border border-[rgba(210,153,34,0.3)] rounded-lg text-sm text-[#d29922]">
                  <ExclamationCircleIcon className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  {probeError}
                </div>
              )}

              {/* Manual entry — shown after a failed probe */}
              {manualMode && (
                <div className="border border-[rgba(255,255,255,0.07)] rounded-lg p-4 space-y-3 bg-[var(--bg-surface-raised,#1c2128)]">
                  <p className="text-xs font-semibold text-[var(--text-secondary,#8b949e)] uppercase tracking-wide">Enter device details manually</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Manufacturer</label>
                      <select
                        value={manualVendor}
                        onChange={e => setManualVendor(e.target.value)}
                        className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-2.5 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                        style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
                      >
                        {VENDOR_OPTIONS.map(v => <option key={v} value={v}>{v}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Model (optional)</label>
                      <input
                        value={manualModel}
                        onChange={e => setManualModel(e.target.value)}
                        className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-2.5 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                        style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
                        placeholder="e.g. LaserJet Pro M404n"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Protocol</label>
                    <div className="flex gap-2">
                      {(['IPP', 'LPD', 'SMB'] as PrinterProtocol[]).map(p => (
                        <button key={p} onClick={() => setSelectedProtocol(p)}
                          className={`flex-1 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                            selectedProtocol === p ? 'bg-[#006FFF] text-white border-[#006FFF]' : 'text-[var(--text-secondary,#8b949e)] border-[rgba(255,255,255,0.07)] hover:bg-[rgba(255,255,255,0.04)]'
                          }`}
                          style={selectedProtocol !== p ? { background: 'var(--bg-surface-raised,#1c2128)' } : undefined}>
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Step 2: Select Driver ── */}
          {step === 2 && probeResult && (
            <div className="space-y-4">
              {/* Device info card */}
              <div className="bg-[rgba(0,111,255,0.1)] border border-[rgba(0,111,255,0.2)] rounded-lg p-4 space-y-2">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircleIcon className="w-4 h-4 text-[#006FFF]" />
                  <span className="text-sm font-medium text-[#006FFF]">Device found</span>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <span className="text-[var(--text-muted,#6e7681)]">Address</span>
                  <span className="font-mono text-[var(--text-primary,#e4e6ea)]">{probeResult.ip}</span>
                  {probeResult.hostname && <>
                    <span className="text-[var(--text-muted,#6e7681)]">Hostname</span>
                    <span className="text-[var(--text-primary,#e4e6ea)]">{probeResult.hostname}</span>
                  </>}
                  {probeResult.vendor && <>
                    <span className="text-[var(--text-muted,#6e7681)]">Vendor</span>
                    <span className="text-[var(--text-primary,#e4e6ea)]">{probeResult.vendor}</span>
                  </>}
                  {probeResult.model && <>
                    <span className="text-[var(--text-muted,#6e7681)]">Model</span>
                    <span className="text-[var(--text-primary,#e4e6ea)] font-medium">{probeResult.model}</span>
                  </>}
                  <span className="text-[var(--text-muted,#6e7681)]">Protocols</span>
                  <span className="text-[var(--text-primary,#e4e6ea)]">{(probeResult.protocols ?? ['IPP']).join(', ')}</span>
                </div>
              </div>

              {/* Protocol selector */}
              <div>
                <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1.5">Connection Protocol</label>
                <div className="flex gap-2">
                  {(['IPP', 'LPD', 'SMB'] as PrinterProtocol[]).map(p => {
                    const detected = probeResult.protocols?.includes(p);
                    return (
                      <button
                        key={p}
                        onClick={() => setSelectedProtocol(p)}
                        className={`flex-1 py-2 rounded-lg text-sm font-medium border transition-colors ${
                          selectedProtocol === p
                            ? 'bg-[#006FFF] text-white border-[#006FFF]'
                            : 'text-[var(--text-secondary,#8b949e)] border-[rgba(255,255,255,0.07)] hover:bg-[rgba(255,255,255,0.04)]'
                        }`}
                        style={selectedProtocol !== p ? { background: 'var(--bg-surface-raised,#1c2128)' } : undefined}
                      >
                        {p}
                        {detected && (
                          <span className={`ml-1 text-xs ${selectedProtocol === p ? 'text-blue-200' : 'text-[#3fb950]'}`}>
                            ✓
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
                <p className="text-xs text-[var(--text-muted,#6e7681)] mt-1">✓ = detected on this device</p>
              </div>

              {/* Driver list */}
              <div>
                <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1.5">
                  Driver
                  {loadingDrivers && <ArrowPathIcon className="w-3 h-3 inline ml-1 animate-spin text-[var(--text-muted,#6e7681)]" />}
                </label>
                <div className="space-y-1 max-h-44 overflow-y-auto border border-[rgba(255,255,255,0.07)] rounded-lg divide-y divide-[rgba(255,255,255,0.07)]">
                  {drivers.map(d => (
                    <label key={d.id}
                      className={`flex items-center gap-3 px-3 py-2.5 cursor-pointer transition-colors ${
                        selectedDriver?.id === d.id ? 'bg-[rgba(0,111,255,0.15)]' : 'hover:bg-[rgba(255,255,255,0.04)]'
                      }`}
                    >
                      <input
                        type="radio"
                        name="driver"
                        checked={selectedDriver?.id === d.id}
                        onChange={() => setSelectedDriver(d)}
                        className="text-[#006FFF]"
                      />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-[var(--text-primary,#e4e6ea)] truncate">{d.name}</p>
                        {d.version && <p className="text-xs text-[var(--text-muted,#6e7681)]">v{d.version}</p>}
                      </div>
                      {d.recommended && (
                        <span className="text-xs px-1.5 py-0.5 bg-[rgba(0,111,255,0.15)] text-[#006FFF] rounded font-medium flex-shrink-0">
                          Recommended
                        </span>
                      )}
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Step 3: Name & Confirm ── */}
          {step === 3 && probeResult && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1.5">Printer Name *</label>
                <input
                  value={printerName}
                  onChange={e => setPrinterName(e.target.value)}
                  className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                  style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
                  placeholder="e.g. Office-HP-LaserJet"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1.5">Location (optional)</label>
                <input
                  value={location}
                  onChange={e => setLocation(e.target.value)}
                  className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                  style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
                  placeholder="e.g. Open Office, 2nd Floor"
                />
              </div>

              {/* Multifunction toggle */}
              <div className="border border-[rgba(255,255,255,0.07)] rounded-lg p-3 space-y-2 bg-[rgba(0,111,255,0.1)]">
                <label className="flex items-center gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isMultifunction}
                    onChange={e => setIsMultifunction(e.target.checked)}
                    className="w-4 h-4 rounded text-[#006FFF] focus:ring-[#006FFF]"
                  />
                  <span className="text-sm font-medium text-[var(--text-secondary,#8b949e)]">This device also has a scanner</span>
                  {autoDetectedMF && (
                    <span className="text-xs text-[#3fb950] bg-[rgba(63,185,80,0.15)] px-1.5 py-0.5 rounded font-medium">Auto-detected</span>
                  )}
                </label>
                {isMultifunction && (
                  <div className="pl-6 space-y-1.5">
                    <p className="text-xs text-[var(--text-muted,#6e7681)]">Supported scan formats:</p>
                    <div className="flex gap-4">
                      {(['PDF', 'JPEG', 'TIFF', 'PNG'] as const).map(fmt => (
                        <label key={fmt} className="flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={scanFormats.includes(fmt)}
                            onChange={e => setScanFormats(prev =>
                              e.target.checked ? [...prev, fmt] : prev.filter(f => f !== fmt)
                            )}
                            className="w-3.5 h-3.5 rounded text-[#006FFF]"
                          />
                          <span className="text-xs text-[var(--text-secondary,#8b949e)]">{fmt}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Summary */}
              <div className="bg-[var(--bg-surface-raised,#1c2128)] rounded-lg p-4 space-y-1.5 text-xs">
                <p className="font-medium text-[var(--text-secondary,#8b949e)] mb-2">Summary</p>
                {[
                  ['Address',  probeResult.ip],
                  ['Model',    probeResult.model ?? '—'],
                  ['Protocol', selectedProtocol],
                  ['Driver',   selectedDriver?.name ?? '—'],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-[var(--text-muted,#6e7681)]">{k}</span>
                    <span className="text-[var(--text-primary,#e4e6ea)] font-medium truncate max-w-[220px]">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-[rgba(255,255,255,0.07)]">
          <button
            onClick={step === 1 ? onClose : () => setStep(s => (s - 1) as WizardStep)}
            className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] hover:text-[var(--text-primary,#e4e6ea)]"
          >
            {step === 1 ? 'Cancel' : <><ChevronLeftIcon className="w-4 h-4" /> Back</>}
          </button>

          {step === 1 && !manualMode && (
            <button
              onClick={handleProbe}
              disabled={probing || !ip.trim()}
              className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-50"
            >
              {probing ? <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Probing…</> : <>Next <ChevronRightIcon className="w-4 h-4" /></>}
            </button>
          )}
          {step === 1 && manualMode && (
            <button
              onClick={handleManualNext}
              disabled={!ip.trim()}
              className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-50"
            >
              Next <ChevronRightIcon className="w-4 h-4" />
            </button>
          )}

          {step === 2 && (
            <button
              onClick={() => setStep(3)}
              disabled={!selectedDriver}
              className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-50"
            >
              Next <ChevronRightIcon className="w-4 h-4" />
            </button>
          )}

          {step === 3 && (
            <button
              onClick={handleAddPrinter}
              disabled={saving || !printerName.trim()}
              className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-50"
            >
              {saving ? <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Adding…</> : 'Add Printer'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Scan Modal ───────────────────────────────────────────────────────────────

function ScanModal({ scanner, onClose }: { scanner: Scanner; onClose: () => void }) {
  const defaultProfile = scanner.profiles?.find(p => p.isDefault) ?? scanner.profiles?.[0];
  const [form, setForm] = useState({
    resolution: defaultProfile?.resolution ?? '300',
    color:      defaultProfile?.color      ?? 'color',
    format:     defaultProfile?.format     ?? (scanner.formats[0] ?? 'PDF'),
    destination: defaultProfile?.destination ?? '',
  });
  const [scanning, setScanning] = useState(false);
  const [activeProfileId, setActiveProfileId] = useState<string | null>(defaultProfile?.id ?? null);
  const [scanShares, setScanShares] = useState<{ id: string; name: string; path: string; server: string; protocol: string }[]>([]);

  useEffect(() => {
    fetch('/api/network/shares')
      .then(r => r.ok ? r.json() : { shares: [] })
      .then(data => {
        const shares = (data.shares ?? []).filter((s: any) => s.purpose?.includes('scan'));
        setScanShares(shares);
      })
      .catch(() => {});
  }, []);

  const applyProfile = (p: ScanProfile) => {
    setForm({ resolution: p.resolution, color: p.color, format: p.format, destination: p.destination });
    setActiveProfileId(p.id);
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.destination.trim()) { toast.error('Ziel (Ordner oder E-Mail) angeben'); return; }
    setScanning(true);
    try {
      await printerApi.startScan(scanner.id, form);
      toast.success('Scan gestartet');
      onClose();
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Scan fehlgeschlagen');
    } finally {
      setScanning(false);
    }
  };

  const profiles = scanner.profiles ?? [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[rgba(255,255,255,0.07)]">
          <div>
            <h2 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Scannen — {scanner.name}</h2>
            <p className="text-xs text-[var(--text-muted,#6e7681)] mt-0.5">{scanner.ip} · {scanner.model}</p>
          </div>
          <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Quick profile selector */}
        {profiles.length > 0 && (
          <div className="px-6 pt-4 pb-0">
            <p className="text-xs font-medium text-[var(--text-muted,#6e7681)] mb-2">Schnellauswahl</p>
            <div className="flex gap-2 flex-wrap">
              {profiles.map(p => (
                <button
                  key={p.id}
                  onClick={() => applyProfile(p)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                    activeProfileId === p.id
                      ? 'bg-[#006FFF] text-white border-[#006FFF]'
                      : 'text-[var(--text-secondary,#8b949e)] border-[rgba(255,255,255,0.07)] hover:border-[#006FFF] hover:text-[#006FFF]'
                  }`}
                  style={activeProfileId !== p.id ? { background: 'var(--bg-surface-raised,#1c2128)' } : undefined}
                >
                  {p.isDefault && <StarIconSolid className="w-3 h-3 text-yellow-400 flex-shrink-0" />}
                  <FolderIcon className="w-3 h-3 flex-shrink-0" />
                  {p.name}
                </button>
              ))}
            </div>
          </div>
        )}

        <form onSubmit={handleScan} className="p-6 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Auflösung</label>
              <select value={form.resolution}
                onChange={e => { setForm(f => ({ ...f, resolution: e.target.value })); setActiveProfileId(null); }}
                className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}>
                {['75', '150', '300', '600'].map(r => <option key={r} value={r}>{r} DPI</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Farbe</label>
              <select value={form.color}
                onChange={e => { setForm(f => ({ ...f, color: e.target.value })); setActiveProfileId(null); }}
                className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}>
                <option value="color">Farbe</option>
                <option value="grayscale">Schwarz/Weiss</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Format</label>
            <div className="flex gap-2">
              {scanner.formats.map(fmt => (
                <button key={fmt} type="button"
                  onClick={() => { setForm(f => ({ ...f, format: fmt })); setActiveProfileId(null); }}
                  className={`flex-1 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                    form.format === fmt ? 'bg-[#006FFF] text-white border-[#006FFF]' : 'text-[var(--text-secondary,#8b949e)] border-[rgba(255,255,255,0.07)] hover:bg-[rgba(255,255,255,0.04)]'
                  }`}
                  style={form.format !== fmt ? { background: 'var(--bg-surface-raised,#1c2128)' } : undefined}>
                  {fmt}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Zielordner oder E-Mail *</label>
            {scanShares.length > 0 ? (
              <select
                value={form.destination}
                onChange={e => { setForm(f => ({ ...f, destination: e.target.value })); setActiveProfileId(null); }}
                className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
                style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
              >
                <option value="">— Share auswählen oder Pfad eingeben —</option>
                {scanShares.map(s => {
                  const path = s.protocol === 'SMB' ? `\\\\${s.server}\\${s.path}` : s.protocol === 'NFS' ? `${s.server}:${s.path}` : s.path;
                  return <option key={s.id} value={path}>{s.name} ({path})</option>;
                })}
                <option value="__custom__">Eigenen Pfad eingeben…</option>
              </select>
            ) : null}
            {(scanShares.length === 0 || form.destination === '__custom__') && (
              <input
                value={form.destination === '__custom__' ? '' : form.destination}
                onChange={e => { setForm(f => ({ ...f, destination: e.target.value })); setActiveProfileId(null); }}
                className={`w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF] ${scanShares.length > 0 ? 'mt-2' : ''}`}
                style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
                placeholder="/scans/dokumente  oder  user@example.com"
                autoFocus={form.destination === '__custom__'}
              />
            )}
          </div>
          <div className="flex justify-end gap-3 pt-1">
            <button type="button" onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] bg-[rgba(255,255,255,0.08)] hover:bg-[rgba(255,255,255,0.12)] rounded-lg">
              Abbrechen
            </button>
            <button type="submit" disabled={scanning}
              className="px-4 py-2 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg disabled:opacity-50">
              {scanning ? 'Starte…' : 'Scan starten'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Scanner Settings Modal ───────────────────────────────────────────────────

const BLANK_PROFILE = (): Omit<ScanProfile, 'id'> => ({
  name: '', resolution: '300', color: 'color', format: 'PDF', destination: '', isDefault: false,
});

function ScannerSettingsModal({ scanner, onClose, onSaved }: {
  scanner: Scanner;
  onClose: () => void;
  onSaved: (updated: Scanner) => void;
}) {
  const [profiles, setProfiles]     = useState<ScanProfile[]>(scanner.profiles ?? []);
  const [editing,  setEditing]      = useState<(ScanProfile & { _new?: boolean }) | null>(null);
  const [saving,   setSaving]       = useState(false);

  const saveAll = async (next: ScanProfile[]) => {
    setSaving(true);
    try {
      await printerApi.updateScannerProfiles(scanner.id, next);
      onSaved({ ...scanner, profiles: next });
      toast.success('Profile gespeichert');
    } catch {
      toast.error('Speichern fehlgeschlagen');
    } finally {
      setSaving(false);
    }
  };

  const handleSetDefault = (id: string) => {
    const next = profiles.map(p => ({ ...p, isDefault: p.id === id }));
    setProfiles(next);
    saveAll(next);
  };

  const handleDelete = (id: string) => {
    const next = profiles.filter(p => p.id !== id);
    setProfiles(next);
    saveAll(next);
  };

  const handleSaveProfile = (form: typeof editing) => {
    if (!form) return;
    if (!form.name.trim()) { toast.error('Name angeben'); return; }
    let next: ScanProfile[];
    if (form._new) {
      const { _new, ...rest } = form;
      next = [...profiles, { ...rest, id: Date.now().toString(36) }];
    } else {
      next = profiles.map(p => p.id === form.id ? { ...form } : p);
    }
    setProfiles(next);
    setEditing(null);
    saveAll(next);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[var(--bg-surface,#161b22)] rounded-xl shadow-xl w-full max-w-lg mx-4 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[rgba(255,255,255,0.07)] flex-shrink-0">
          <div>
            <h2 className="text-base font-semibold text-[var(--text-primary,#e4e6ea)]">Scanner-Einstellungen</h2>
            <p className="text-xs text-[var(--text-muted,#6e7681)] mt-0.5">{scanner.name} · {scanner.ip}</p>
          </div>
          <button onClick={onClose} className="text-[var(--text-muted,#6e7681)] hover:text-[var(--text-secondary,#8b949e)]"><XMarkIcon className="w-5 h-5" /></button>
        </div>

        <div className="overflow-y-auto flex-1 p-6 space-y-4">
          {/* Profile list */}
          <div className="flex items-center justify-between mb-1">
            <p className="text-sm font-medium text-[var(--text-secondary,#8b949e)]">Scan-Profile ({profiles.length})</p>
            <button
              onClick={() => setEditing({ ...BLANK_PROFILE(), id: '', _new: true })}
              className="flex items-center gap-1.5 text-xs font-medium text-[#006FFF] hover:text-[#0056cc]"
            >
              <PlusIcon className="w-4 h-4" /> Profil hinzufügen
            </button>
          </div>

          {profiles.length === 0 && !editing && (
            <div className="text-center py-8 text-[var(--text-muted,#6e7681)]">
              <FolderIcon className="w-10 h-10 mx-auto mb-2 opacity-30" />
              <p className="text-sm">Noch keine Profile — erstelle das erste Profil</p>
            </div>
          )}

          <div className="space-y-2">
            {profiles.map(p => (
              <div key={p.id} className="border border-[rgba(255,255,255,0.07)] rounded-lg p-3 flex items-center gap-3 hover:bg-[rgba(255,255,255,0.04)]">
                <button onClick={() => handleSetDefault(p.id)} title="Als Standard setzen"
                  className={`flex-shrink-0 ${p.isDefault ? 'text-yellow-500' : 'text-[var(--text-muted,#6e7681)] hover:text-yellow-400'}`}>
                  {p.isDefault ? <StarIconSolid className="w-4 h-4" /> : <StarIcon className="w-4 h-4" />}
                </button>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-[var(--text-primary,#e4e6ea)] truncate">
                    {p.name}
                    {p.isDefault && <span className="ml-2 text-xs text-yellow-500 bg-[rgba(210,153,34,0.15)] px-1.5 py-0.5 rounded">Standard</span>}
                  </p>
                  <p className="text-xs text-[var(--text-muted,#6e7681)] truncate">
                    {p.resolution} DPI · {p.color === 'color' ? 'Farbe' : 'S/W'} · {p.format} → {p.destination || '—'}
                  </p>
                </div>
                <button onClick={() => setEditing(p)}
                  className="text-[var(--text-muted,#6e7681)] hover:text-[#006FFF] p-1 rounded transition-colors">
                  <PencilIcon className="w-4 h-4" />
                </button>
                <button onClick={() => handleDelete(p.id)}
                  className="text-[var(--text-muted,#6e7681)] hover:text-[#f85149] p-1 rounded transition-colors">
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>

          {/* Inline edit form */}
          {editing && (
            <ProfileEditForm
              value={editing}
              formats={scanner.formats}
              onSave={handleSaveProfile}
              onCancel={() => setEditing(null)}
            />
          )}
        </div>

        <div className="px-6 py-4 border-t border-[rgba(255,255,255,0.07)] flex justify-end flex-shrink-0">
          <button onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-[var(--text-secondary,#8b949e)] bg-[rgba(255,255,255,0.08)] hover:bg-[rgba(255,255,255,0.12)] rounded-lg">
            Schliessen
          </button>
        </div>
      </div>
    </div>
  );
}

function PencilIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125" />
    </svg>
  );
}

function ProfileEditForm({ value, formats, onSave, onCancel }: {
  value: ScanProfile & { _new?: boolean };
  formats: string[];
  onSave: (v: ScanProfile & { _new?: boolean }) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState(value);
  return (
    <div className="border-2 border-[rgba(0,111,255,0.3)] rounded-xl p-4 space-y-3 bg-[rgba(0,111,255,0.08)]">
      <p className="text-xs font-semibold text-[#006FFF] uppercase tracking-wide">
        {value._new ? 'Neues Profil' : 'Profil bearbeiten'}
      </p>
      <div>
        <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Profilname *</label>
        <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
          className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
          style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
          placeholder="z.B. Dokumente, Archiv, Schnellscan" autoFocus />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Auflösung</label>
          <select value={form.resolution} onChange={e => setForm(f => ({ ...f, resolution: e.target.value }))}
            className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
            style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}>
            <option value="75">75 DPI (Web)</option>
            <option value="150">150 DPI (Normal)</option>
            <option value="300">300 DPI (Druck)</option>
            <option value="600">600 DPI (Archiv)</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Farbe</label>
          <select value={form.color} onChange={e => setForm(f => ({ ...f, color: e.target.value }))}
            className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
            style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}>
            <option value="color">Farbe</option>
            <option value="grayscale">Schwarz/Weiss</option>
          </select>
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Format</label>
        <div className="flex gap-2">
          {(formats.length > 0 ? formats : ['PDF','JPEG','TIFF']).map(fmt => (
            <button key={fmt} type="button"
              onClick={() => setForm(f => ({ ...f, format: fmt }))}
              className={`flex-1 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                form.format === fmt ? 'bg-[#006FFF] text-white border-[#006FFF]' : 'text-[var(--text-secondary,#8b949e)] border-[rgba(255,255,255,0.07)] hover:bg-[rgba(255,255,255,0.04)]'
              }`}
              style={form.format !== fmt ? { background: 'var(--bg-surface-raised,#1c2128)' } : undefined}>
              {fmt}
            </button>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-[var(--text-secondary,#8b949e)] mb-1">Standardziel (Ordner oder E-Mail)</label>
        <input value={form.destination} onChange={e => setForm(f => ({ ...f, destination: e.target.value }))}
          className="w-full border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#006FFF]"
          style={{ background: 'var(--bg-surface-raised,#1c2128)', color: 'var(--text-primary,#e4e6ea)' }}
          placeholder="/scans/dokumente  oder  archiv@example.com" />
      </div>
      <label className="flex items-center gap-2 cursor-pointer">
        <input type="checkbox" checked={!!form.isDefault}
          onChange={e => setForm(f => ({ ...f, isDefault: e.target.checked }))}
          className="rounded text-[#006FFF]" />
        <span className="text-sm text-[var(--text-secondary,#8b949e)]">Als Standard-Profil setzen</span>
      </label>
      <div className="flex justify-end gap-2 pt-1">
        <button type="button" onClick={onCancel}
          className="px-3 py-1.5 text-sm text-[var(--text-secondary,#8b949e)] bg-[rgba(255,255,255,0.08)] hover:bg-[rgba(255,255,255,0.12)] rounded-lg">Abbrechen</button>
        <button type="button" onClick={() => onSave(form)}
          className="px-4 py-1.5 text-sm font-medium text-white bg-[#006FFF] hover:bg-[#0056cc] rounded-lg">Speichern</button>
      </div>
    </div>
  );
}

// ─── Print Server Info Modal ──────────────────────────────────────────────────

function PrintServerInfoModal({ printer, onClose }: { printer: { name: string }; onClose: () => void }) {
  const ippUrl    = `ipp://opendirectory.heusser.local/printers/${printer.name}`;
  const lpadmin   = `lpadmin -p "${printer.name}" -E -v "${ippUrl}" -m everywhere`;
  const powershell = `Add-Printer -ConnectionURI "http://192.168.1.245:631/ipp/print" -Name "${printer.name}"`;

  const copy = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <div
        className="rounded-xl shadow-xl w-full max-w-lg mx-4"
        style={{ background: 'var(--bg-surface, #161b22)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <InformationCircleIcon className="w-5 h-5 text-blue-500" />
            <h2 className="text-sm font-semibold text-gray-900">Print Server Connection</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* macOS / Linux */}
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">macOS / Linux</p>
            <div className="bg-blue-50 rounded-lg p-3 space-y-2">
              <div>
                <p className="text-[10px] text-blue-400 mb-0.5">Print Server URL</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-[11px] font-mono text-blue-800 break-all">{ippUrl}</code>
                  <button
                    onClick={() => copy(ippUrl)}
                    title="Copy URL"
                    className="flex-shrink-0 p-1 rounded hover:bg-blue-100 text-blue-400 hover:text-blue-600 transition-colors"
                  >
                    <ClipboardDocumentIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div className="border-t border-blue-100 pt-2">
                <p className="text-[10px] text-blue-400 mb-0.5">Terminal (lpadmin)</p>
                <div className="flex items-start gap-2">
                  <code className="flex-1 text-[10px] font-mono text-blue-700 break-all leading-relaxed">{lpadmin}</code>
                  <button
                    onClick={() => copy(lpadmin)}
                    title="Copy command"
                    className="flex-shrink-0 p-1 rounded hover:bg-blue-100 text-blue-400 hover:text-blue-600 transition-colors mt-0.5"
                  >
                    <ClipboardDocumentIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Windows */}
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Windows 10 / 11</p>
            <div className="bg-indigo-50 rounded-lg p-3 space-y-2">
              <div>
                <p className="text-[10px] text-indigo-400 mb-1">
                  Settings → Bluetooth &amp; devices → Printers &amp; scanners → Add device → Add manually
                  → <em>Add a printer using an IP address or hostname</em>
                </p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10px]">
                  <span className="text-indigo-400">Device type</span>
                  <span className="text-indigo-800 font-medium">IPP Device</span>
                  <span className="text-indigo-400">Hostname / IP</span>
                  <span className="text-indigo-800 font-mono">192.168.1.245</span>
                  <span className="text-indigo-400">Port</span>
                  <span className="text-indigo-800 font-mono">631</span>
                </div>
              </div>
              <div className="border-t border-indigo-100 pt-2">
                <p className="text-[10px] text-indigo-400 mb-0.5">PowerShell (als Administrator)</p>
                <div className="flex items-start gap-2">
                  <code className="flex-1 text-[10px] font-mono text-indigo-700 break-all leading-relaxed">{powershell}</code>
                  <button
                    onClick={() => copy(powershell)}
                    title="Copy command"
                    className="flex-shrink-0 p-1 rounded hover:bg-indigo-100 text-indigo-400 hover:text-indigo-600 transition-colors mt-0.5"
                  >
                    <ClipboardDocumentIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Empty State ──────────────────────────────────────────────────────────────

function EmptyState({ icon: Icon, title, description }: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center text-gray-400 space-y-2">
      <Icon className="w-12 h-12 opacity-30" />
      <p className="font-medium text-gray-600">{title}</p>
      <p className="text-sm max-w-xs">{description}</p>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function PrintersView() {
  const [activeTab, setActiveTab]   = useState<PrinterTab>('printers');
  const [printers,  setPrinters]    = useState<Printer[]>([]);
  const [scanners,  setScanners]    = useState<Scanner[]>([]);
  const [jobs,      setJobs]        = useState<PrintJob[]>([]);
  const [quotas,    setQuotas]      = useState<PrintQuota[]>([]);
  const [loading,   setLoading]     = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [showAddPrinter, setShowAddPrinter] = useState(false);
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [scanTarget, setScanTarget] = useState<Scanner | null>(null);
  const [scannerSettingsTarget, setScannerSettingsTarget] = useState<Scanner | null>(null);
  const [filterPrinter, setFilterPrinter] = useState<string | null>(null);
  const [testingPage, setTestingPage]   = useState<string | null>(null);
  const [testingScan, setTestingScan]   = useState<string | null>(null);
  const [editingQuota, setEditingQuota] = useState<{ userId: string; value: string } | null>(null);
  const [printServerInfo, setPrintServerInfo] = useState<Printer | null>(null);
  const [jobPeriod, setJobPeriod] = useState<'today' | 'week' | 'all'>('all');
  const jobTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Load ──────────────────────────────────────────────────────────────────

  const loadPrinters = useCallback(async () => {
    const res = await printerApi.getPrinters();
    setPrinters(res.data?.data ?? res.data ?? []);
  }, []);

  const loadScanners = useCallback(async () => {
    const res = await printerApi.getScanners();
    setScanners(res.data?.data ?? res.data ?? []);
  }, []);

  const loadJobs = useCallback(async () => {
    const res = await printerApi.getPrintJobs();
    setJobs(res.data?.data ?? res.data ?? []);
  }, []);

  const loadQuotas = useCallback(async () => {
    const res = await printerApi.getPrintQuotas();
    setQuotas(res.data?.data ?? res.data ?? []);
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.allSettled([loadPrinters(), loadScanners(), loadJobs(), loadQuotas()]);
      setLoading(false);
    })();
  }, [loadPrinters, loadScanners, loadJobs, loadQuotas]);

  // Auto-refresh jobs every 15 s
  useEffect(() => {
    jobTimerRef.current = setInterval(() => {
      loadJobs().catch(() => {});
    }, 15000);
    return () => { if (jobTimerRef.current) clearInterval(jobTimerRef.current); };
  }, [loadJobs]);

  // ── Actions ──────────────────────────────────────────────────────────────

  const handleDiscover = async () => {
    setDiscovering(true);
    try {
      const res = await printerApi.discoverPrinters();
      const found: Printer[] = res.data?.printers ?? res.data ?? [];
      if (found.length) {
        setPrinters(prev => {
          const ids = new Set(prev.map(p => p.id));
          return [...prev, ...found.filter((p: Printer) => !ids.has(p.id))];
        });
        toast.success(`Discovered ${found.length} printer(s)`);
      } else {
        toast('No new printers found on the network', { icon: 'ℹ️' });
      }
    } catch {
      toast.error('Network discovery unavailable — use "Add Printer" to add devices manually.');
    } finally {
      setDiscovering(false);
    }
  };

  const handleDeletePrinter = async (id: string, name: string) => {
    if (!confirm(`Remove printer "${name}"?`)) return;
    try {
      await printerApi.deletePrinter(id);
      setPrinters(prev => prev.filter(p => p.id !== id));
      toast.success(`Printer "${name}" removed`);
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Failed to remove printer');
    }
  };

  const handleCancelJob = async (id: string) => {
    try {
      await printerApi.cancelPrintJob(id);
      setJobs(prev => prev.map(j => j.id === id ? { ...j, status: 'cancelled' as JobStatus } : j));
      toast.success('Print job cancelled');
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Failed to cancel job');
    }
  };

  const handleSaveQuota = async (userId: string, newLimit: number) => {
    if (isNaN(newLimit) || newLimit < 1) { toast.error('Enter a valid quota limit'); return; }
    try {
      await printerApi.updatePrintQuota(userId, newLimit);
      setQuotas(prev => prev.map(q => q.userId === userId ? { ...q, limit: newLimit } : q));
      setEditingQuota(null);
      toast.success('Quota updated');
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Failed to update quota');
    }
  };

  const handleTestPage = async (printer: Printer) => {
    setTestingPage(printer.id);
    try {
      await printerApi.submitPrintJob({ printer_name: printer.name, document_name: 'Test Page', user_name: 'admin', pages: 1 });
      toast.success(`Test page sent to ${printer.name}`);
    } catch {
      toast.error('Could not send test page — printer service unavailable');
    } finally {
      setTestingPage(null);
    }
    // Refresh job list independently — don't let this fail silently affect the success toast
    loadJobs().catch(() => {});
  };

  const handleTestScan = async (sc: Scanner) => {
    setTestingScan(sc.id);
    try {
      const res = await printerApi.testScan(sc.ip, sc.name);
      const caps = res.data.capabilities;
      const modes = caps.colorModes?.join(', ') || '—';
      toast.success(
        `Scanner OK — ${caps.makeAndModel || sc.model}\nModes: ${modes}`,
        { duration: 5000 }
      );
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Test Scan fehlgeschlagen');
    } finally {
      setTestingScan(null);
    }
  };

  const handleScanFromPrinter = (printer: Printer) => {
    // Find the matching scanner entry by IP, or create a synthetic one
    const sc: Scanner = scanners.find(s => s.ip === printer.ip) ?? {
      id: printer.id,
      name: printer.name,
      ip: printer.ip,
      model: printer.model,
      status: printer.status,
      formats: printer.scanFormats?.length ? printer.scanFormats : ['PDF', 'JPEG'],
    };
    setScanTarget(sc);
  };

  // ── Tab bar ──────────────────────────────────────────────────────────────

  const TABS: { id: PrinterTab; label: string; count?: number }[] = [
    { id: 'printers',          label: 'Printers',           count: printers.length },
    { id: 'scanners',          label: 'Scanners',           count: scanners.length },
    { id: 'jobs',              label: 'Print Jobs',         count: jobs.length },
    { id: 'quotas',            label: 'Quotas',             count: quotas.length },
    { id: 'scan-destinations', label: 'Scan Destinations' },
    { id: 'print-pools',       label: 'Print Pools' },
  ];

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <ArrowPathIcon className="w-8 h-8 text-gray-400 animate-spin" />
      </div>
    );
  }

  const displayedJobs = (() => {
    let list = jobs;
    if (filterPrinter) list = list.filter(j => j.printer === filterPrinter);
    if (jobPeriod !== 'all') {
      const cutoff = new Date();
      if (jobPeriod === 'today') cutoff.setHours(0, 0, 0, 0);
      else cutoff.setDate(cutoff.getDate() - 7);
      list = list.filter(j => new Date(j.submitted) >= cutoff);
    }
    return list;
  })();

  // Per-user stats (from filtered jobs)
  const userStats = (() => {
    const map: Record<string, { pages: number; jobs: number }> = {};
    for (const j of displayedJobs) {
      const u = j.user || 'Unbekannt';
      if (!map[u]) map[u] = { pages: 0, jobs: 0 };
      map[u].pages += j.pages || 0;
      map[u].jobs  += 1;
    }
    return Object.entries(map).sort((a, b) => b[1].pages - a[1].pages);
  })();

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Printers &amp; Scanners</h1>
          <p className="text-sm text-gray-500 mt-1">Manage printers, scanners, print jobs and user quotas</p>
        </div>
        {activeTab === 'printers' && (
          <div className="flex gap-2">
            <button
              onClick={() => setShowSetupWizard(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-purple-700 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg transition-colors"
            >
              <SparklesIcon className="w-4 h-4" />
              Setup Wizard
            </button>
            <button
              onClick={handleDiscover}
              disabled={discovering}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 border border-[rgba(255,255,255,0.07)] hover:bg-[rgba(255,255,255,0.05)] rounded-lg disabled:opacity-50" style={{ background: 'var(--bg-surface-raised, #1c2128)' }}
            >
              <MagnifyingGlassIcon className="w-4 h-4" />
              {discovering ? 'Discovering…' : 'Discover'}
            </button>
            <button
              onClick={() => setShowAddPrinter(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg"
            >
              <PlusIcon className="w-4 h-4" />
              Add Printer
            </button>
          </div>
        )}
      </div>

      {/* Tab Bar */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-1 -mb-px">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900 hover:border-gray-300'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className={`ml-2 px-1.5 py-0.5 text-xs rounded-full ${
                  activeTab === tab.id ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-600'
                }`}>{tab.count}</span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ── PRINTERS TAB ───────────────────────────────────────────────────── */}
      {activeTab === 'printers' && (
        printers.length === 0
          ? <EmptyState
              icon={PrinterIcon}
              title="No printers configured"
              description="Click Add Printer to set up a network printer using the wizard, or use Discover to scan the network."
            />
          : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {printers.map(printer => (
                <div key={printer.id} className="border border-[rgba(255,255,255,0.07)] rounded-xl p-4 space-y-3 hover:shadow-sm transition-shadow" style={{ background: 'var(--bg-surface, #161b22)' }}>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <StatusDot status={printer.status} />
                      <span className="font-medium text-gray-900 text-sm">{printer.name}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {printer.isMultifunction && (
                        <span className="px-1.5 py-0.5 bg-purple-100 text-purple-700 rounded text-xs font-medium">MFP</span>
                      )}
                      <ProtocolBadge protocol={printer.protocol} />
                      <button
                        onClick={() => setPrintServerInfo(printer)}
                        title="Print Server Connection Info"
                        className="p-0.5 rounded text-gray-400 hover:text-blue-500 hover:bg-blue-50 transition-colors"
                      >
                        <InformationCircleIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                  <div className="space-y-1 text-xs text-gray-500">
                    <div className="flex justify-between">
                      <span>Model</span>
                      <span className="text-gray-700 font-medium truncate max-w-[180px]">{printer.model || '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>IP</span>
                      <span className="text-gray-700 font-mono">{printer.ip}</span>
                    </div>
                    {printer.location && (
                      <div className="flex justify-between">
                        <span>Location</span>
                        <span className="text-gray-700">{printer.location}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span>Queue</span>
                      <span className={`font-medium ${printer.queueDepth > 0 ? 'text-yellow-600' : 'text-green-600'}`}>
                        {printer.queueDepth} job{printer.queueDepth !== 1 ? 's' : ''}
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-1 pt-1 border-t border-gray-100">
                    <button
                      onClick={() => { setFilterPrinter(printer.name); setActiveTab('jobs'); }}
                      className="flex-1 text-xs py-1.5 px-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                    >
                      View Jobs
                    </button>
                    {printer.isMultifunction && (
                      <button
                        onClick={() => handleScanFromPrinter(printer)}
                        disabled={printer.status !== 'online'}
                        className="flex-1 text-xs py-1.5 px-2 text-purple-600 hover:bg-purple-50 rounded-lg transition-colors disabled:opacity-40"
                      >
                        Scan
                      </button>
                    )}
                    <button
                      onClick={() => handleTestPage(printer)}
                      disabled={testingPage === printer.id || printer.status !== 'online'}
                      className="flex-1 text-xs py-1.5 px-2 text-gray-600 hover:bg-gray-100 rounded-lg transition-colors disabled:opacity-40"
                    >
                      {testingPage === printer.id ? '…' : 'Test Page'}
                    </button>
                    <button
                      onClick={() => handleDeletePrinter(printer.id, printer.name)}
                      className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                    >
                      <TrashIcon className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )
      )}

      {/* ── SCANNERS TAB ───────────────────────────────────────────────────── */}
      {activeTab === 'scanners' && (
        scanners.length === 0
          ? <EmptyState
              icon={PrinterIcon}
              title="No scanners found"
              description="Scanner devices are auto-discovered from multifunction printers registered in the system."
            />
          : (
            <div className="border border-[rgba(255,255,255,0.07)] rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)' }}>
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    {['Status', 'Name', 'IP', 'Model', 'Formats', 'Actions'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {scanners.map(sc => (
                    <tr key={sc.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3"><StatusDot status={sc.status} /></td>
                      <td className="px-4 py-3 font-medium text-gray-900">{sc.name}</td>
                      <td className="px-4 py-3 font-mono text-gray-600">{sc.ip}</td>
                      <td className="px-4 py-3 text-gray-600">{sc.model}</td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1 flex-wrap">
                          {sc.formats.map(f => (
                            <span key={f} className="px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">{f}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setScanTarget(sc)}
                            disabled={sc.status !== 'online'}
                            className="px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-40"
                          >
                            Scan
                          </button>
                          <button
                            onClick={() => handleTestScan(sc)}
                            disabled={testingScan === sc.id || sc.status !== 'online'}
                            className="px-3 py-1.5 text-xs font-medium text-teal-700 bg-teal-50 hover:bg-teal-100 rounded-lg disabled:opacity-40 transition-colors"
                          >
                            {testingScan === sc.id ? '…' : 'Test Scan'}
                          </button>
                          <button
                            onClick={() => setScannerSettingsTarget(sc)}
                            className="p-1.5 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                            title="Scanner-Einstellungen"
                          >
                            <Cog6ToothIcon className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
      )}

      {/* ── PRINT JOBS TAB ─────────────────────────────────────────────────── */}
      {activeTab === 'jobs' && (
        <div className="space-y-4">

          {/* Filter bar */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Time period */}
            <div className="flex rounded-lg border border-gray-200 overflow-hidden text-xs font-medium">
              {(['today', 'week', 'all'] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setJobPeriod(p)}
                  className={`px-3 py-1.5 transition-colors ${jobPeriod === p ? 'bg-[#006FFF] text-white' : 'text-gray-400 hover:bg-[rgba(255,255,255,0.05)]'}`}
                >
                  {p === 'today' ? 'Heute' : p === 'week' ? 'Diese Woche' : 'Alle'}
                </button>
              ))}
            </div>

            {/* Printer filter chip */}
            {filterPrinter && (
              <div className="flex items-center gap-1.5 text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded-lg px-2.5 py-1.5">
                <span>{filterPrinter}</span>
                <button onClick={() => setFilterPrinter(null)} className="text-blue-400 hover:text-blue-600">
                  <XMarkIcon className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            <span className="ml-auto text-xs text-gray-400">{displayedJobs.length} Aufträge · Auto-refresh 15s</span>
          </div>

          {/* Per-user stats */}
          {userStats.length > 0 && (
            <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-3">Druckvolumen nach Benutzer</p>
              <div className="flex flex-wrap gap-3">
                {userStats.map(([user, { pages, jobs: jCount }]) => {
                  const maxPages = userStats[0][1].pages || 1;
                  const pct = Math.round((pages / maxPages) * 100);
                  return (
                    <div key={user} className="flex items-center gap-2 border border-[rgba(255,255,255,0.07)] rounded-lg px-3 py-2 min-w-[160px]" style={{ background: 'var(--bg-surface, #161b22)' }}>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-gray-800 truncate">{user}</p>
                        <div className="flex items-center gap-1.5 mt-1">
                          <div className="flex-1 bg-gray-200 rounded-full h-1.5">
                            <div className="bg-blue-500 h-1.5 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-gray-500 whitespace-nowrap">{pages} S. · {jCount} Job{jCount !== 1 ? 's' : ''}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Jobs table */}
          {displayedJobs.length === 0
            ? <EmptyState
                icon={PrinterIcon}
                title="Keine Druckaufträge"
                description={filterPrinter ? `Keine Aufträge für ${filterPrinter} im gewählten Zeitraum.` : 'Noch keine Druckaufträge im Verlauf.'}
              />
            : (
              <div className="border border-[rgba(255,255,255,0.07)] rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)' }}>
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      {['Dokument', 'Benutzer', 'Drucker', 'Seiten', 'Zeit', 'Status', ''].map(h => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {displayedJobs.map(job => (
                      <tr key={job.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-medium text-gray-900 max-w-[200px] truncate">{job.documentName}</td>
                        <td className="px-4 py-3 text-gray-600">
                          {job.user
                            ? <span className="inline-flex items-center gap-1">{job.user}</span>
                            : <span className="text-gray-400 italic">Unbekannt</span>
                          }
                        </td>
                        <td className="px-4 py-3 text-gray-600">{job.printer}</td>
                        <td className="px-4 py-3 text-gray-600">{job.pages ?? '—'}</td>
                        <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">{fmtDate(job.submitted)}</td>
                        <td className="px-4 py-3"><JobStatusBadge status={job.status} /></td>
                        <td className="px-4 py-3">
                          {(job.status === 'pending' || job.status === 'printing') && (
                            <button
                              onClick={() => handleCancelJob(job.id)}
                              className="px-2 py-1 text-xs text-red-600 bg-red-50 hover:bg-red-100 rounded-lg"
                            >
                              Abbrechen
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </div>
      )}

      {/* ── QUOTAS TAB ─────────────────────────────────────────────────────── */}
      {activeTab === 'quotas' && (
        quotas.length === 0
          ? <EmptyState
              icon={PrinterIcon}
              title="No quota records"
              description="Print quotas will appear here once configured in the printer management service."
            />
          : (
            <div className="border border-[rgba(255,255,255,0.07)] rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)' }}>
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    {['Username', 'Usage', 'Used / Limit', 'Reset Date', 'Actions'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {quotas.map(q => {
                    const pct = Math.min(100, Math.round((q.used / q.limit) * 100));
                    const barColor = pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-green-500';
                    const isEditing = editingQuota?.userId === q.userId;
                    return (
                      <tr key={q.userId} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-medium text-gray-900">{q.username}</td>
                        <td className="px-4 py-3 w-40">
                          <div className="w-full bg-gray-200 rounded-full h-2">
                            <div className={`${barColor} h-2 rounded-full`} style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-gray-500 mt-0.5 block">{pct}%</span>
                        </td>
                        <td className="px-4 py-3 text-gray-600">{q.used} / {q.limit} pages</td>
                        <td className="px-4 py-3 text-gray-500 text-xs">{q.resetDate}</td>
                        <td className="px-4 py-3">
                          {isEditing ? (
                            <div className="flex items-center gap-2">
                              <input
                                type="number" min="1"
                                value={editingQuota.value}
                                onChange={e => setEditingQuota({ userId: q.userId, value: e.target.value })}
                                className="w-20 border border-gray-300 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
                              />
                              <button
                                onClick={() => handleSaveQuota(q.userId, parseInt(editingQuota.value, 10))}
                                className="text-xs px-2 py-1 bg-blue-600 text-white rounded hover:bg-blue-700"
                              >Save</button>
                              <button
                                onClick={() => setEditingQuota(null)}
                                className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded hover:bg-gray-200"
                              >Cancel</button>
                            </div>
                          ) : (
                            <button
                              onClick={() => setEditingQuota({ userId: q.userId, value: String(q.limit) })}
                              className="text-xs px-3 py-1.5 text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg"
                            >Edit Limit</button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )
      )}

      {/* ── SCAN DESTINATIONS TAB ─────────────────────────────────────────── */}
      {activeTab === 'scan-destinations' && <ScanDestinationsTab />}

      {/* ── PRINT POOLS TAB ──────────────────────────────────────────────── */}
      {activeTab === 'print-pools' && <PrintPoolsTab />}

      {/* Modals */}
      {showAddPrinter && (
        <AddPrinterWizard
          onClose={() => setShowAddPrinter(false)}
          onAdded={p => {
            setPrinters(prev => [...prev, p]);
            if (p.isMultifunction) loadScanners();
          }}
        />
      )}
      {scanTarget && <ScanModal scanner={scanTarget} onClose={() => setScanTarget(null)} />}
      {printServerInfo && <PrintServerInfoModal printer={printServerInfo} onClose={() => setPrintServerInfo(null)} />}
      {scannerSettingsTarget && (
        <ScannerSettingsModal
          scanner={scannerSettingsTarget}
          onClose={() => setScannerSettingsTarget(null)}
          onSaved={updated => {
            setScanners(prev => prev.map(s => s.id === updated.id ? updated : s));
            setScannerSettingsTarget(updated);
          }}
        />
      )}
      {showSetupWizard && <PrinterSetupWizard onClose={() => setShowSetupWizard(false)} />}
    </div>
  );
}

// ─── Types for new features ──────────────────────────────────────────────────

interface ScanDestination {
  id: string;
  entityType: 'user' | 'group';
  entityId: string;
  type: string;
  smbServer?: string;
  smbShare?: string;
  smbPath?: string;
  smbUsername?: string;
  smbDomain?: string;
  localPath?: string;
  label?: string;
}

interface DestinationFormState {
  entityType: 'user' | 'group';
  entityId: string;
  type: 'smb' | 'local';
  smbServer: string;
  smbShare: string;
  smbPath: string;
  smbUsername: string;
  smbPassword: string;
  smbDomain: string;
  localPath: string;
  label: string;
}

const BLANK_DEST_FORM: DestinationFormState = {
  entityType: 'user',
  entityId: '',
  type: 'smb',
  smbServer: '',
  smbShare: '',
  smbPath: '',
  smbUsername: '',
  smbPassword: '',
  smbDomain: '',
  localPath: '',
  label: '',
};

interface PrintPool {
  id: string;
  name: string;
  display_name?: string;
  description?: string;
  algorithm: string;
  active: boolean;
  member_count: number;
}

interface PoolMember {
  id: string;
  pool_id: string;
  printer_id: string;
  printer_name?: string;
  printer_uri?: string;
  weight: number;
  priority: number;
  active: boolean;
  current_jobs: number;
  total_jobs: number;
  last_used_at?: string;
}

interface PoolWithMembers extends PrintPool {
  members: PoolMember[];
}

// ─── Scan Destinations Tab ───────────────────────────────────────────────────

export function ScanDestinationsTab() {
  const [destinations, setDestinations] = useState<ScanDestination[]>([]);
  const [loading, setLoading] = useState(true);
  const [showDialog, setShowDialog] = useState(false);
  const [editTarget, setEditTarget] = useState<ScanDestination | null>(null);
  const [form, setForm] = useState<DestinationFormState>(BLANK_DEST_FORM);
  const [saving, setSaving] = useState(false);

  const BASE = '/api/printer/scan-destinations';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(BASE);
      const data = await res.json();
      setDestinations(data.destinations ?? []);
    } catch {
      toast.error('Failed to load scan destinations');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const openAdd = () => {
    setEditTarget(null);
    setForm(BLANK_DEST_FORM);
    setShowDialog(true);
  };

  const openEdit = (dest: ScanDestination) => {
    setEditTarget(dest);
    setForm({
      entityType: dest.entityType,
      entityId:   dest.entityId,
      type:       (dest.type as 'smb' | 'local') || 'smb',
      smbServer:  dest.smbServer ?? '',
      smbShare:   dest.smbShare ?? '',
      smbPath:    dest.smbPath ?? '',
      smbUsername: dest.smbUsername ?? '',
      smbPassword: '',
      smbDomain:  dest.smbDomain ?? '',
      localPath:  dest.localPath ?? '',
      label:      dest.label ?? '',
    });
    setShowDialog(true);
  };

  const handleSave = async () => {
    if (!form.entityId.trim()) { toast.error('Entity ID is required'); return; }
    setSaving(true);
    try {
      const url = form.entityType === 'user'
        ? `${BASE}/user/${encodeURIComponent(form.entityId)}`
        : `${BASE}/group/${encodeURIComponent(form.entityId)}`;
      const body: Record<string, string> = {
        type: form.type,
        smbServer: form.smbServer,
        smbShare: form.smbShare,
        smbPath: form.smbPath,
        smbUsername: form.smbUsername,
        smbDomain: form.smbDomain,
        localPath: form.localPath,
        label: form.label,
      };
      if (form.smbPassword) body.smbPassword = form.smbPassword;
      const res = await fetch(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.json()).error ?? 'Save failed');
      toast.success('Destination saved');
      setShowDialog(false);
      load();
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (dest: ScanDestination) => {
    if (!confirm(`Delete destination for ${dest.entityType} "${dest.entityId}"?`)) return;
    try {
      const url = dest.entityType === 'user'
        ? `${BASE}/user/${encodeURIComponent(dest.entityId)}`
        : `${BASE}/group/${encodeURIComponent(dest.entityId)}`;
      const res = await fetch(url, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.json()).error ?? 'Delete failed');
      toast.success('Destination deleted');
      load();
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-40">
        <ArrowPathIcon className="w-6 h-6 text-gray-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">Configure per-user and per-group scan destinations (SMB or local).</p>
        <button
          onClick={openAdd}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg"
        >
          <PlusIcon className="w-4 h-4" />
          Add Destination
        </button>
      </div>

      {destinations.length === 0 ? (
        <EmptyState
          icon={FolderIcon}
          title="No scan destinations configured"
          description="Add per-user or per-group SMB / local destinations for scanned files."
        />
      ) : (
        <div className="border border-[rgba(255,255,255,0.07)] rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)' }}>
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                {['Type', 'Entity ID', 'Destination', 'Server / Share', 'Path', 'Label', 'Actions'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {destinations.map(dest => (
                <tr key={dest.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${dest.entityType === 'user' ? 'bg-blue-100 text-blue-700' : 'bg-purple-100 text-purple-700'}`}>
                      {dest.entityType}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-medium text-gray-900">{dest.entityId}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${dest.type === 'smb' ? 'bg-orange-100 text-orange-700' : 'bg-gray-100 text-gray-700'}`}>
                      {dest.type?.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-600 text-xs">
                    {dest.smbServer ? `//${dest.smbServer}/${dest.smbShare}` : dest.localPath ?? '—'}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">{dest.smbPath || '—'}</td>
                  <td className="px-4 py-3 text-gray-600">{dest.label || '—'}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => openEdit(dest)}
                        className="text-xs px-2 py-1 text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg"
                      >Edit</button>
                      <button
                        onClick={() => handleDelete(dest)}
                        className="p-1 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg"
                      >
                        <TrashIcon className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add / Edit Dialog */}
      {showDialog && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="rounded-2xl shadow-2xl w-full max-w-lg p-6 space-y-4" style={{ background: 'var(--bg-surface, #161b22)' }}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">{editTarget ? 'Edit' : 'Add'} Scan Destination</h2>
              <button onClick={() => setShowDialog(false)} className="p-1 rounded hover:bg-gray-100">
                <XMarkIcon className="w-5 h-5 text-gray-500" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {/* Entity Type */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Entity Type</label>
                <select
                  value={form.entityType}
                  onChange={e => setForm(f => ({ ...f, entityType: e.target.value as 'user' | 'group' }))}
                  disabled={!!editTarget}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
                >
                  <option value="user">User</option>
                  <option value="group">Group</option>
                </select>
              </div>

              {/* Entity ID */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Entity ID</label>
                <input
                  type="text"
                  placeholder="user@domain.com or group-name"
                  value={form.entityId}
                  onChange={e => setForm(f => ({ ...f, entityId: e.target.value }))}
                  disabled={!!editTarget}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
                />
              </div>

              {/* Destination Type */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Destination Type</label>
                <select
                  value={form.type}
                  onChange={e => setForm(f => ({ ...f, type: e.target.value as 'smb' | 'local' }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="smb">SMB</option>
                  <option value="local">Local</option>
                </select>
              </div>

              {/* Label */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Label</label>
                <input
                  type="text"
                  placeholder="e.g. Marketing Scans"
                  value={form.label}
                  onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {form.type === 'smb' && (
                <>
                  {/* SMB Server */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-gray-600">SMB Server</label>
                    <input
                      type="text"
                      placeholder="192.168.1.10"
                      value={form.smbServer}
                      onChange={e => setForm(f => ({ ...f, smbServer: e.target.value }))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  {/* SMB Share */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-gray-600">Share Name</label>
                    <input
                      type="text"
                      placeholder="scans"
                      value={form.smbShare}
                      onChange={e => setForm(f => ({ ...f, smbShare: e.target.value }))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  {/* SMB Path */}
                  <div className="space-y-1 col-span-2">
                    <label className="text-xs font-medium text-gray-600">Sub-path (optional)</label>
                    <input
                      type="text"
                      placeholder="Marketing/Incoming"
                      value={form.smbPath}
                      onChange={e => setForm(f => ({ ...f, smbPath: e.target.value }))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  {/* SMB Username */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-gray-600">Username</label>
                    <input
                      type="text"
                      placeholder="scanuser"
                      value={form.smbUsername}
                      onChange={e => setForm(f => ({ ...f, smbUsername: e.target.value }))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  {/* SMB Password */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-gray-600">Password{editTarget ? ' (leave blank to keep)' : ''}</label>
                    <input
                      type="password"
                      placeholder="••••••••"
                      value={form.smbPassword}
                      onChange={e => setForm(f => ({ ...f, smbPassword: e.target.value }))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  {/* SMB Domain */}
                  <div className="space-y-1 col-span-2">
                    <label className="text-xs font-medium text-gray-600">Domain (optional)</label>
                    <input
                      type="text"
                      placeholder="CORP"
                      value={form.smbDomain}
                      onChange={e => setForm(f => ({ ...f, smbDomain: e.target.value }))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </>
              )}

              {form.type === 'local' && (
                <div className="space-y-1 col-span-2">
                  <label className="text-xs font-medium text-gray-600">Local Path</label>
                  <input
                    type="text"
                    placeholder="/mnt/storage/scans"
                    value={form.localPath}
                    onChange={e => setForm(f => ({ ...f, localPath: e.target.value }))}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowDialog(false)}
                className="px-4 py-2 text-sm text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg"
              >Cancel</button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50"
              >{saving ? 'Saving…' : 'Save'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Print Pools Tab ─────────────────────────────────────────────────────────

export function PrintPoolsTab() {
  const [pools, setPools]               = useState<PrintPool[]>([]);
  const [loading, setLoading]           = useState(true);
  const [selectedPool, setSelectedPool] = useState<PoolWithMembers | null>(null);
  const [loadingPool, setLoadingPool]   = useState(false);
  const [showAddPool, setShowAddPool]   = useState(false);
  const [showAddMember, setShowAddMember] = useState(false);
  const [poolForm, setPoolForm] = useState({ name: '', displayName: '', algorithm: 'round_robin', description: '' });
  const [memberForm, setMemberForm] = useState({ printerId: '', printerName: '', printerUri: '', weight: '1', priority: '100' });
  const [saving, setSaving] = useState(false);

  const BASE = '/api/printer/print-pools';

  const loadPools = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(BASE);
      const data = await res.json();
      setPools(data.pools ?? []);
    } catch {
      toast.error('Failed to load print pools');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadPools(); }, [loadPools]);

  const loadPool = async (poolId: string) => {
    setLoadingPool(true);
    try {
      const res = await fetch(`${BASE}/${poolId}`);
      const data = await res.json();
      setSelectedPool(data.pool ?? null);
    } catch {
      toast.error('Failed to load pool details');
    } finally {
      setLoadingPool(false);
    }
  };

  const handleCreatePool = async () => {
    if (!poolForm.name.trim()) { toast.error('Pool name is required'); return; }
    setSaving(true);
    try {
      const res = await fetch(BASE, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(poolForm),
      });
      if (!res.ok) throw new Error((await res.json()).error ?? 'Create failed');
      toast.success('Pool created');
      setShowAddPool(false);
      setPoolForm({ name: '', displayName: '', algorithm: 'round_robin', description: '' });
      loadPools();
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDeletePool = async (pool: PrintPool) => {
    if (!confirm(`Delete pool "${pool.display_name || pool.name}"?`)) return;
    try {
      const res = await fetch(`${BASE}/${pool.id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.json()).error ?? 'Delete failed');
      toast.success('Pool deleted');
      if (selectedPool?.id === pool.id) setSelectedPool(null);
      loadPools();
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleAddMember = async () => {
    if (!selectedPool || !memberForm.printerId.trim()) { toast.error('Printer ID is required'); return; }
    setSaving(true);
    try {
      const body = {
        printerId: memberForm.printerId,
        printerName: memberForm.printerName,
        printerUri: memberForm.printerUri,
        weight: parseInt(memberForm.weight, 10) || 1,
        priority: parseInt(memberForm.priority, 10) || 100,
      };
      const res = await fetch(`${BASE}/${selectedPool.id}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.json()).error ?? 'Add member failed');
      toast.success('Member added');
      setShowAddMember(false);
      setMemberForm({ printerId: '', printerName: '', printerUri: '', weight: '1', priority: '100' });
      loadPool(selectedPool.id);
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveMember = async (member: PoolMember) => {
    if (!selectedPool || !confirm(`Remove "${member.printer_name || member.printer_id}" from pool?`)) return;
    try {
      const res = await fetch(`${BASE}/${selectedPool.id}/members/${encodeURIComponent(member.printer_id)}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.json()).error ?? 'Remove failed');
      toast.success('Member removed');
      loadPool(selectedPool.id);
      loadPools();
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleTestRoute = async (poolId: string) => {
    try {
      const res = await fetch(`${BASE}/${poolId}/test-route`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Route test failed');
      const m = data.selectedMember;
      toast.success(`Would route to: ${m.printer_name || m.printer_id}`, { duration: 4000 });
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const ALGO_LABELS: Record<string, string> = {
    round_robin: 'Round Robin',
    least_jobs:  'Least Jobs',
    priority:    'Priority',
    failover:    'Failover',
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-40">
        <ArrowPathIcon className="w-6 h-6 text-gray-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">Group printers into pools with automatic job routing algorithms.</p>
        <button
          onClick={() => setShowAddPool(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg"
        >
          <PlusIcon className="w-4 h-4" />
          Add Pool
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Pool list */}
        <div className="lg:col-span-1 space-y-2">
          {pools.length === 0 ? (
            <EmptyState
              icon={PrinterIcon}
              title="No print pools"
              description="Create a pool to group printers for load balancing or failover."
            />
          ) : (
            pools.map(pool => (
              <div
                key={pool.id}
                onClick={() => loadPool(pool.id)}
                className={`p-4 rounded-xl border cursor-pointer transition-shadow hover:shadow-sm ${
                  selectedPool?.id === pool.id ? 'border-blue-400' : 'border-[rgba(255,255,255,0.07)]'
                }`}
                style={{ background: selectedPool?.id === pool.id ? 'rgba(0,111,255,0.15)' : 'var(--bg-surface, #161b22)' }}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-medium text-gray-900 text-sm">{pool.display_name || pool.name}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{ALGO_LABELS[pool.algorithm] ?? pool.algorithm}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`inline-block w-2 h-2 rounded-full ${pool.active ? 'bg-green-500' : 'bg-gray-400'}`} />
                    <button
                      onClick={e => { e.stopPropagation(); handleTestRoute(pool.id); }}
                      className="text-xs px-2 py-1 text-teal-700 bg-teal-50 hover:bg-teal-100 rounded-lg"
                      title="Test routing"
                    >Test</button>
                    <button
                      onClick={e => { e.stopPropagation(); handleDeletePool(pool); }}
                      className="p-1 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg"
                    >
                      <TrashIcon className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <p className="text-xs text-gray-500 mt-1">{pool.member_count} member{pool.member_count !== 1 ? 's' : ''}</p>
              </div>
            ))
          )}
        </div>

        {/* Pool detail */}
        <div className="lg:col-span-2">
          {loadingPool ? (
            <div className="flex items-center justify-center h-40">
              <ArrowPathIcon className="w-6 h-6 text-gray-400 animate-spin" />
            </div>
          ) : selectedPool ? (
            <div className="border border-[rgba(255,255,255,0.07)] rounded-xl overflow-hidden" style={{ background: 'var(--bg-surface, #161b22)' }}>
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
                <h3 className="font-medium text-gray-900">{selectedPool.display_name || selectedPool.name}</h3>
                <button
                  onClick={() => setShowAddMember(true)}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg"
                >
                  <PlusIcon className="w-3.5 h-3.5" />
                  Add Member
                </button>
              </div>
              {selectedPool.members.length === 0 ? (
                <div className="p-8 text-center text-sm text-gray-500">No members yet. Add a printer to this pool.</div>
              ) : (
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      {['Printer', 'Weight', 'Priority', 'Current Jobs', 'Total Jobs', ''].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {selectedPool.members.map(m => (
                      <tr key={m.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3">
                          <p className="font-medium text-gray-900">{m.printer_name || m.printer_id}</p>
                          {m.printer_uri && <p className="text-xs text-gray-500 font-mono">{m.printer_uri}</p>}
                        </td>
                        <td className="px-4 py-3 text-gray-600">{m.weight}</td>
                        <td className="px-4 py-3 text-gray-600">{m.priority}</td>
                        <td className="px-4 py-3">
                          <span className={`font-medium ${m.current_jobs > 0 ? 'text-yellow-600' : 'text-green-600'}`}>
                            {m.current_jobs}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-600">{m.total_jobs}</td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => handleRemoveMember(m)}
                            className="p-1 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg"
                          >
                            <TrashIcon className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-40 text-sm text-gray-400">
              Select a pool to view its members.
            </div>
          )}
        </div>
      </div>

      {/* Add Pool Dialog */}
      {showAddPool && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="rounded-2xl shadow-2xl w-full max-w-md p-6 space-y-4" style={{ background: 'var(--bg-surface, #161b22)' }}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Add Print Pool</h2>
              <button onClick={() => setShowAddPool(false)} className="p-1 rounded hover:bg-gray-100">
                <XMarkIcon className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Name (unique identifier)</label>
                <input
                  type="text"
                  placeholder="floor2-pool"
                  value={poolForm.name}
                  onChange={e => setPoolForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Display Name</label>
                <input
                  type="text"
                  placeholder="Floor 2 Printer Pool"
                  value={poolForm.displayName}
                  onChange={e => setPoolForm(f => ({ ...f, displayName: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Algorithm</label>
                <select
                  value={poolForm.algorithm}
                  onChange={e => setPoolForm(f => ({ ...f, algorithm: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="round_robin">Round Robin</option>
                  <option value="least_jobs">Least Jobs</option>
                  <option value="priority">Priority</option>
                  <option value="failover">Failover</option>
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Description (optional)</label>
                <input
                  type="text"
                  placeholder="Printers on floor 2"
                  value={poolForm.description}
                  onChange={e => setPoolForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setShowAddPool(false)} className="px-4 py-2 text-sm text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">Cancel</button>
              <button
                onClick={handleCreatePool}
                disabled={saving}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50"
              >{saving ? 'Creating…' : 'Create Pool'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Member Dialog */}
      {showAddMember && selectedPool && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="rounded-2xl shadow-2xl w-full max-w-md p-6 space-y-4" style={{ background: 'var(--bg-surface, #161b22)' }}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Add Pool Member</h2>
              <button onClick={() => setShowAddMember(false)} className="p-1 rounded hover:bg-gray-100">
                <XMarkIcon className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Printer ID</label>
                <input
                  type="text"
                  placeholder="printer-uuid-or-cups-name"
                  value={memberForm.printerId}
                  onChange={e => setMemberForm(f => ({ ...f, printerId: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Printer Name (display)</label>
                <input
                  type="text"
                  placeholder="HP LaserJet 4100"
                  value={memberForm.printerName}
                  onChange={e => setMemberForm(f => ({ ...f, printerName: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-gray-600">Printer URI (optional)</label>
                <input
                  type="text"
                  placeholder="ipp://192.168.1.20/ipp/print"
                  value={memberForm.printerUri}
                  onChange={e => setMemberForm(f => ({ ...f, printerUri: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-gray-600">Weight</label>
                  <input
                    type="number" min="1"
                    value={memberForm.weight}
                    onChange={e => setMemberForm(f => ({ ...f, weight: e.target.value }))}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-medium text-gray-600">Priority</label>
                  <input
                    type="number" min="1"
                    value={memberForm.priority}
                    onChange={e => setMemberForm(f => ({ ...f, priority: e.target.value }))}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setShowAddMember(false)} className="px-4 py-2 text-sm text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">Cancel</button>
              <button
                onClick={handleAddMember}
                disabled={saving}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50"
              >{saving ? 'Adding…' : 'Add Member'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
