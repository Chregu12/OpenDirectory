'use client';

import React, { useState, useEffect } from 'react';
import {
  Cog6ToothIcon,
  CpuChipIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  PlayIcon,
  WifiIcon,
  ShieldCheckIcon,
  PrinterIcon,
  ComputerDesktopIcon,
  ChartBarIcon,
  CloudIcon,
  InformationCircleIcon,
  XMarkIcon,
  SparklesIcon,
  UserGroupIcon,
} from '@heroicons/react/24/outline';
import { gatewayApi, healthApi, configApi } from '@/lib/api';
import toast from 'react-hot-toast';
import SetupWizard from '@/components/setup/SetupWizard';
import MonitoringAlertingWizard from '@/components/setup/MonitoringAlertingWizard';
import SecuritySetupWizard from '@/components/setup/SecuritySetupWizard';
import NetworkConfigWizard from '@/components/setup/NetworkConfigWizard';
import DeviceEnrollmentWizard from '@/components/setup/DeviceEnrollmentWizard';
import UserManagementWizard from '@/components/setup/UserManagementWizard';
import PrinterSetupWizard from '@/components/setup/PrinterSetupWizard';

interface Service {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  port?: number;
  description?: string;
  lastCheck?: string;
  responseTime?: number;
}

interface Module {
  id: string;
  name: string;
  enabled: boolean;
  port: number;
  features: Record<string, boolean>;
  description?: string;
}

interface Props {
  enabledModules?: string[];
  onModuleChange?: (moduleId: string, enabled: boolean) => void;
}

type TabId = 'services' | 'setup' | 'mdm' | 'system';

// Modules that have a sidebar nav item and can be hidden
const HAS_NAV_ITEM = new Set([
  'monitoring-analytics', 'secrets-management', 'device-management', 'network-infrastructure', 'security-suite',
]);

// ─── MDM Settings Tab ──────────────────────────────────────────────────────────

function MdmSettingsTab() {
  const [apnsCert, setApnsCert] = useState('');
  const [apnsKey, setApnsKey] = useState('');
  const [apnsTopic, setApnsTopic] = useState('');
  const [mdmServerUrl, setMdmServerUrl] = useState('');
  const [mdmOrgName, setMdmOrgName] = useState('');
  const [saving, setSaving] = useState(false);
  const [mdmDevices, setMdmDevices] = useState<any[]>([]);
  const [devLoading, setDevLoading] = useState(true);

  useEffect(() => {
    // Load current MDM config
    fetch('/api/mdm/config').then(r => r.json()).then(d => {
      if (d.topic) setApnsTopic(d.topic);
      if (d.serverUrl) setMdmServerUrl(d.serverUrl);
      if (d.orgName) setMdmOrgName(d.orgName);
    }).catch(() => {});

    // Load enrolled Apple devices
    fetch('/api/mdm/devices').then(r => r.json()).then(d => {
      setMdmDevices(Array.isArray(d) ? d : d?.devices ?? []);
    }).catch(() => setMdmDevices([]))
      .finally(() => setDevLoading(false));
  }, []);

  const saveMdmConfig = async () => {
    setSaving(true);
    try {
      const body: Record<string, string> = { topic: apnsTopic, serverUrl: mdmServerUrl, orgName: mdmOrgName };
      if (apnsCert.trim()) body.apnsCert = btoa(apnsCert.trim());
      if (apnsKey.trim()) body.apnsKey = btoa(apnsKey.trim());
      const res = await fetch('/api/mdm/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) toast.success('MDM-Konfiguration gespeichert');
      else toast.error('Fehler beim Speichern');
    } catch {
      toast.error('Verbindungsfehler');
    }
    setSaving(false);
  };

  const pushDevice = async (udid: string) => {
    await fetch(`/api/mdm/devices/${udid}/push`, { method: 'POST' });
    toast.success('Push gesendet');
  };

  return (
    <div className="space-y-8 p-6">
      {/* APNs Certificate section */}
      <div>
        <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Apple MDM Push Certificate</h3>
        <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
          Apple MDM benötigt ein spezielles <strong>MDM Push Certificate</strong> — kein normales APNs-Zertifikat.{' '}
          Bezug über{' '}
          <span className="font-mono text-xs px-1 py-0.5 rounded" style={{ background: 'var(--bg-surface-raised)' }}>
            https://identity.apple.com/pushcert/
          </span>{' '}
          mit einer Apple-ID, die an deine Organisation gebunden ist.
        </p>

        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-5 text-sm text-amber-800">
          <strong>Voraussetzungen:</strong>
          <ol className="mt-2 ml-4 list-decimal space-y-1 text-amber-700">
            <li>Apple Developer Account oder Apple Business Manager</li>
            <li>CSR (Certificate Signing Request) von diesem Server generieren</li>
            <li>CSR auf identity.apple.com hochladen → MDM Push Certificate (.pem) herunterladen</li>
            <li>Zertifikat und Privaten Schlüssel hier eintragen</li>
          </ol>
        </div>

        <div className="grid grid-cols-1 gap-5">
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              APNs Topic (Bundle ID des MDM Push Certs)
            </label>
            <input
              value={apnsTopic}
              onChange={e => setApnsTopic(e.target.value)}
              placeholder="com.apple.mgmt.External.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="w-full border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: 'var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Im Zertifikat unter UID= zu finden</p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>MDM Server URL</label>
            <input
              value={mdmServerUrl}
              onChange={e => setMdmServerUrl(e.target.value)}
              placeholder="https://mdm.deine-domain.local"
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: 'var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Organisation</label>
            <input
              value={mdmOrgName}
              onChange={e => setMdmOrgName(e.target.value)}
              placeholder="Meine Firma GmbH"
              className="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: 'var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              MDM Push Certificate (.pem) — PEM-Inhalt einfügen
            </label>
            <textarea
              value={apnsCert}
              onChange={e => setApnsCert(e.target.value)}
              rows={5}
              placeholder={'-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----'}
              className="w-full border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: 'var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Privater Schlüssel (.key) — PEM-Inhalt einfügen
            </label>
            <textarea
              value={apnsKey}
              onChange={e => setApnsKey(e.target.value)}
              rows={5}
              placeholder={'-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----'}
              className="w-full border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{ borderColor: 'var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              Der Schlüssel wird Base64-verschlüsselt gespeichert und verlässt den Server nicht.
            </p>
          </div>

          <div>
            <button
              onClick={saveMdmConfig}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
            >
              {saving ? 'Speichern…' : 'MDM-Konfiguration speichern'}
            </button>
          </div>
        </div>
      </div>

      {/* Enrolled Apple Devices */}
      <div>
        <h3 className="text-base font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
          Eingeschriebene Apple-Geräte ({mdmDevices.length})
        </h3>
        {devLoading ? (
          <div className="space-y-2">{[...Array(3)].map((_, i) => <div key={i} className="h-10 rounded animate-pulse" style={{ background: 'var(--bg-surface-raised)' }} />)}</div>
        ) : mdmDevices.length === 0 ? (
          <div className="text-center py-8 text-sm rounded-lg" style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-strong)' }}>
            Noch keine Apple-Geräte via MDM eingeschrieben.{' '}
            Enrollment-Link: <span className="font-mono text-xs">/mdm/enroll</span>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg" style={{ border: '1px solid var(--border)' }}>
            <table className="w-full text-sm">
              <thead style={{ background: 'var(--bg-surface-raised)' }}>
                <tr className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  <th className="px-4 py-3 text-left">Gerät</th>
                  <th className="px-4 py-3 text-left">UDID</th>
                  <th className="px-4 py-3 text-left">OS</th>
                  <th className="px-4 py-3 text-left">Zuletzt gesehen</th>
                  <th className="px-4 py-3 text-left"></th>
                </tr>
              </thead>
              <tbody>
                {mdmDevices.map((d: any) => (
                  <tr key={d.udid} style={{ borderTop: '1px solid var(--border)' }}>
                    <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)' }}>{d.device_name ?? d.udid}</td>
                    <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{d.udid.slice(0, 16)}…</td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>{d.os_version ?? '—'}</td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                      {d.last_seen ? new Date(d.last_seen).toLocaleString('de-CH') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => pushDevice(d.udid)}
                        className="text-blue-600 hover:text-blue-800 text-xs font-medium"
                      >
                        Push
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Double-Confirm Disable Modal ──────────────────────────────────────────────

function DisableConfirmModal({ moduleName, step, onNext, onCancel }: {
  moduleName: string;
  step: 1 | 2;
  onNext: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onCancel}>
      <div className="rounded-xl shadow-xl max-w-md w-full" style={{ background: 'var(--bg-surface)' }} onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-lg bg-yellow-50 flex items-center justify-center flex-shrink-0">
                <ExclamationTriangleIcon className="w-5 h-5 text-yellow-600" />
              </div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
                {step === 1 ? 'Disable Module?' : 'Confirm Disable'}
              </h2>
            </div>
            <button onClick={onCancel} style={{ color: 'var(--text-muted)' }}>
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {step === 1 ? (
            <>
              <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
                You are about to disable <strong>{moduleName}</strong>.
              </p>
              <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
                This will <strong>hide it from the navigation</strong>. All settings and data
                are preserved — you can re-enable the module at any time from Settings.
              </p>
            </>
          ) : (
            <>
              <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
                Are you absolutely sure you want to disable <strong>{moduleName}</strong>?
              </p>
              <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
                The navigation item will disappear immediately. No data will be deleted.
              </p>
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg px-3 py-2 mb-4">
                <p className="text-xs text-yellow-800 font-medium">
                  This change takes effect immediately. Re-enable via Settings → Module Management.
                </p>
              </div>
            </>
          )}

          <div className="flex justify-end gap-3">
            <button onClick={onCancel}
              className="px-4 py-2 text-sm font-medium rounded-lg"
              style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)' }}>
              Cancel
            </button>
            <button onClick={onNext}
              className="px-4 py-2 text-sm font-medium text-white bg-yellow-600 hover:bg-yellow-700 rounded-lg">
              {step === 1 ? 'Continue →' : 'Yes, Disable Module'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function SettingsView({ enabledModules, onModuleChange }: Props) {
  const [activeTab, setActiveTab] = useState<TabId>('services');
  const [services, setServices]   = useState<Service[]>([]);
  const [modules, setModules]     = useState<Module[]>([]);
  const [healthData, setHealthData] = useState<any>(null);
  const [loading, setLoading]     = useState(true);

  // Double-confirmation state
  const [pendingDisable, setPendingDisable] = useState<Module | null>(null);
  const [confirmStep, setConfirmStep]       = useState<1 | 2>(1);

  // Wizard visibility state
  const [showSetupWizard, setShowSetupWizard]           = useState(false);
  const [showMonitoringWizard, setShowMonitoringWizard] = useState(false);
  const [showSecurityWizard, setShowSecurityWizard]     = useState(false);
  const [showNetworkWizard, setShowNetworkWizard]       = useState(false);
  const [showDeviceWizard, setShowDeviceWizard]         = useState(false);
  const [showUserWizard, setShowUserWizard]             = useState(false);
  const [showPrinterWizard, setShowPrinterWizard]       = useState(false);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [servicesRes, modulesRes, healthRes] = await Promise.all([
        gatewayApi.getServices(),
        configApi.getModules(),
        healthApi.getDetailedHealth(),
      ]);
      setServices(servicesRes.data || []);
      setModules(
        Object.entries(modulesRes.data || {}).map(([id, config]: [string, any]) => ({ id, ...config }))
      );
      setHealthData(healthRes.data);
    } catch {
      toast.error('Failed to load settings data');
    } finally {
      setLoading(false);
    }
  };

  // Called when user flips a toggle
  const handleToggleRequest = (module: Module, newEnabled: boolean) => {
    if (!newEnabled && HAS_NAV_ITEM.has(module.id)) {
      // Disabling a nav module → double confirmation
      setPendingDisable(module);
      setConfirmStep(1);
    } else {
      // Enabling, or disabling a module with no nav item → no confirmation needed
      executeToggle(module.id, newEnabled);
    }
  };

  const executeToggle = async (moduleId: string, enabled: boolean) => {
    try {
      await configApi.updateModule(moduleId, { enabled });
      toast.success(`Module ${enabled ? 'enabled' : 'disabled'}`);
      onModuleChange?.(moduleId, enabled);
      loadData();
    } catch {
      toast.error('Failed to update module');
    }
  };

  // Step through the double confirmation
  const handleConfirmNext = () => {
    if (confirmStep === 1) {
      setConfirmStep(2);
    } else {
      if (pendingDisable) {
        executeToggle(pendingDisable.id, false);
      }
      setPendingDisable(null);
      setConfirmStep(1);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':   return <CheckCircleIcon className="h-4 w-4 text-green-500" />;
      case 'unhealthy': return <XCircleIcon className="h-4 w-4 text-red-500" />;
      default:          return <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500" />;
    }
  };

  const getModuleIcon = (moduleId: string) => {
    const map: Record<string, React.ComponentType<any>> = {
      'network-infrastructure': WifiIcon,
      'security-suite':         ShieldCheckIcon,
      'printer-service':        PrinterIcon,
      'device-management':      ComputerDesktopIcon,
      'monitoring-analytics':   ChartBarIcon,
      'backup-disaster':        CloudIcon,
      'automation-workflows':   PlayIcon,
      'container-orchestration':CpuChipIcon,
      'ai-intelligence':        ChartBarIcon,
    };
    const Icon = map[moduleId] || CpuChipIcon;
    return <Icon className="h-5 w-5" />;
  };

  const isCoreModule = (id: string) =>
    id === 'authentication-service' || id === 'configuration-service';

  const healthyServices = services.filter(s => s.status === 'healthy').length;
  const uptime = (() => {
    const secs = healthData?.gateway?.uptime;
    if (!secs) return 'N/A';
    if (secs < 60)   return `${Math.floor(secs)}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
    return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
  })();

  const tabs: { key: TabId; label: string; icon: React.ComponentType<any> }[] = [
    { key: 'services', label: 'Services',        icon: CpuChipIcon },
    { key: 'setup',    label: 'Setup',           icon: SparklesIcon },
    { key: 'mdm',      label: 'MDM & Zertifikate', icon: ShieldCheckIcon },
    { key: 'system',   label: 'System',          icon: InformationCircleIcon },
  ];

  return (
    <>
      <div className="rounded-lg" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }}>
        {/* Header */}
        <div style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Cog6ToothIcon className="h-6 w-6 text-blue-600" />
                <h2 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>Settings</h2>
              </div>
              {!loading && (
                <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
                  {healthyServices}/{services.length} services healthy · Uptime {uptime}
                </div>
              )}
            </div>
          </div>
          <nav className="flex space-x-8 px-6" aria-label="Tabs">
            {tabs.map(tab => (
              <button key={tab.key} onClick={() => setActiveTab(tab.key)}
                className={`${
                  activeTab === tab.key
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent hover:border-gray-300'
                } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
                style={activeTab !== tab.key ? { color: 'var(--text-muted)' } : {}}>
                <tab.icon className="h-4 w-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {/* ── Services Tab ── */}
          {activeTab === 'services' && (
            <div className="space-y-6">
              {/* Summary cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-blue-50 rounded-lg p-4">
                  <p className="text-xs font-medium text-blue-600 uppercase tracking-wider">System Health</p>
                  <p className="text-2xl font-bold text-blue-900 mt-1">
                    {healthData?.status === 'healthy' ? 'Healthy' : healthData?.status === 'degraded' ? 'Degraded' : 'Unknown'}
                  </p>
                </div>
                <div className="bg-green-50 rounded-lg p-4">
                  <p className="text-xs font-medium text-green-600 uppercase tracking-wider">Active Services</p>
                  <p className="text-2xl font-bold text-green-900 mt-1">{healthyServices}/{services.length}</p>
                </div>
                <div className="bg-purple-50 rounded-lg p-4">
                  <p className="text-xs font-medium text-purple-600 uppercase tracking-wider">Enabled Modules</p>
                  <p className="text-2xl font-bold text-purple-900 mt-1">
                    {modules.filter(m => m.enabled).length}/{modules.length}
                  </p>
                </div>
                <div className="bg-orange-50 rounded-lg p-4">
                  <p className="text-xs font-medium text-orange-600 uppercase tracking-wider">Uptime</p>
                  <p className="text-2xl font-bold text-orange-900 mt-1">{uptime}</p>
                </div>
              </div>

              {/* Module Management */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Module Management</h3>
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Disabled modules are hidden from the navigation</p>
                </div>
                {loading ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {[...Array(6)].map((_, i) => (
                      <div key={i} className="rounded-lg p-4 animate-pulse" style={{ border: '1px solid var(--border)' }}>
                        <div className="h-4 rounded w-3/4 mb-2" style={{ background: 'var(--bg-surface-raised)' }} />
                        <div className="h-3 rounded w-1/2" style={{ background: 'var(--bg-surface-raised)' }} />
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {modules.map(module => {
                      const service = services.find(s => s.name === module.id);
                      const isCore = isCoreModule(module.id);
                      const hasNav = HAS_NAV_ITEM.has(module.id);
                      return (
                        <div key={module.id} className="rounded-lg p-4" style={{
                          border: '1px solid var(--border)',
                          background: module.enabled ? 'transparent' : 'var(--bg-surface-raised)',
                          opacity: module.enabled ? 1 : 0.75,
                        }}>
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-3">
                              <div className={`p-2 rounded-lg ${module.enabled ? 'bg-green-100 text-green-600' : 'text-gray-400'}`}
                                style={!module.enabled ? { background: 'var(--bg-overlay)' } : {}}>
                                {getModuleIcon(module.id)}
                              </div>
                              <div>
                                <h4 className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{module.name}</h4>
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Port {module.port}</p>
                                {service && (
                                  <div className="flex items-center space-x-1 mt-1">
                                    {getStatusIcon(service.status)}
                                    <span className="text-xs capitalize" style={{ color: 'var(--text-muted)' }}>{service.status}</span>
                                  </div>
                                )}
                                {hasNav && !module.enabled && (
                                  <p className="text-xs text-orange-600 mt-0.5">Hidden from navigation</p>
                                )}
                                {isCore && (
                                  <p className="text-xs text-blue-500 mt-0.5">Core module</p>
                                )}
                              </div>
                            </div>
                            <label className={`relative inline-flex items-center ${isCore ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}>
                              <input
                                type="checkbox"
                                className="sr-only peer"
                                checked={module.enabled}
                                disabled={isCore}
                                onChange={e => handleToggleRequest(module, e.target.checked)}
                              />
                              <div className="w-11 h-6 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"
                                style={{ background: module.enabled ? undefined : 'var(--bg-overlay)' }} />
                            </label>
                          </div>
                          {module.enabled && Object.keys(module.features || {}).length > 0 && (
                            <div className="mt-3 flex flex-wrap gap-1">
                              {Object.entries(module.features).slice(0, 3).map(([feat, on]) => (
                                <span key={feat} className="px-2 py-0.5 text-xs rounded-full" style={on
                                  ? { background: 'var(--success-light)', color: 'var(--success)' }
                                  : { background: 'var(--bg-overlay)', color: 'var(--text-muted)' }}>
                                  {feat}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Service Status Table */}
              {services.length > 0 && (
                <div>
                  <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--text-secondary)' }}>Service Status</h3>
                  <div className="overflow-hidden md:rounded-lg" style={{ boxShadow: 'var(--card-shadow)' }}>
                    <table className="min-w-full">
                      <thead style={{ background: 'var(--bg-surface-raised)' }}>
                        <tr>
                          {['Service', 'Status', 'Port', 'Response', 'Last Check'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody style={{ background: 'var(--bg-surface)' }}>
                        {services.map((svc, i) => (
                          <tr key={svc.name} style={{ borderTop: '1px solid var(--border)', background: i % 2 === 0 ? 'var(--bg-surface)' : 'var(--bg-surface-raised)' }}>
                            <td className="px-4 py-3 text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{svc.name}</td>
                            <td className="px-4 py-3">
                              <div className="flex items-center space-x-1">
                                {getStatusIcon(svc.status)}
                                <span className={`text-xs font-medium capitalize ${
                                  svc.status === 'healthy' ? 'text-green-600' :
                                  svc.status === 'unhealthy' ? 'text-red-600' : 'text-yellow-600'
                                }`}>{svc.status}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-muted)' }}>{svc.port || '—'}</td>
                            <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-muted)' }}>{svc.responseTime ? `${svc.responseTime}ms` : '—'}</td>
                            <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-muted)' }}>
                              {svc.lastCheck ? new Date(svc.lastCheck).toLocaleTimeString() : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Setup Tab ── */}
          {activeTab === 'setup' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Setup & Configuration Wizards</h3>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Verwende die Wizards um Module und Dienste nachträglich zu konfigurieren.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Initial Setup */}
                <div className="border-2 border-blue-200 bg-blue-50 rounded-xl p-5">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center flex-shrink-0">
                      <SparklesIcon className="w-5 h-5 text-blue-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Initial Setup Wizard</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Module aktivieren, Gerätezahlen anpassen, Organisationsname ändern.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowSetupWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                  >
                    <SparklesIcon className="w-4 h-4" /> Setup öffnen
                  </button>
                </div>

                {/* User Management */}
                <div className="rounded-xl p-5 transition-colors" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-indigo-100 flex items-center justify-center flex-shrink-0">
                      <PlayIcon className="w-5 h-5 text-indigo-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>User Management</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Benutzer und Gruppen anlegen, LDAP-Einstellungen konfigurieren.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowUserWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-indigo-700 bg-indigo-100 hover:bg-indigo-200 rounded-lg transition-colors"
                  >
                    <PlayIcon className="w-4 h-4" /> Wizard starten
                  </button>
                </div>

                {/* Device Enrollment */}
                <div className="rounded-xl p-5 transition-colors" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-teal-100 flex items-center justify-center flex-shrink-0">
                      <ComputerDesktopIcon className="w-5 h-5 text-teal-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Device Enrollment</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Geräte registrieren, Enrollment-Profile und Richtlinien einrichten.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowDeviceWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-teal-700 bg-teal-100 hover:bg-teal-200 rounded-lg transition-colors"
                  >
                    <PlayIcon className="w-4 h-4" /> Wizard starten
                  </button>
                </div>

                {/* Monitoring */}
                <div className="rounded-xl p-5 transition-colors" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-purple-100 flex items-center justify-center flex-shrink-0">
                      <ChartBarIcon className="w-5 h-5 text-purple-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Monitoring & Alerting</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Grafana-Dashboards, Prometheus-Alerts und Benachrichtigungen einrichten.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowMonitoringWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-purple-700 bg-purple-100 hover:bg-purple-200 rounded-lg transition-colors"
                  >
                    <PlayIcon className="w-4 h-4" /> Wizard starten
                  </button>
                </div>

                {/* Security */}
                <div className="rounded-xl p-5 transition-colors" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center flex-shrink-0">
                      <ShieldCheckIcon className="w-5 h-5 text-red-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Security Setup</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Wazuh, Vault, MFA und Sicherheitsrichtlinien konfigurieren.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowSecurityWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-red-700 bg-red-100 hover:bg-red-200 rounded-lg transition-colors"
                  >
                    <PlayIcon className="w-4 h-4" /> Wizard starten
                  </button>
                </div>

                {/* Network */}
                <div className="rounded-xl p-5 transition-colors" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-cyan-100 flex items-center justify-center flex-shrink-0">
                      <WifiIcon className="w-5 h-5 text-cyan-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Network Configuration</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>DNS, DHCP, VLANs und Netzwerkinfrastruktur einrichten.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowNetworkWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-cyan-700 bg-cyan-100 hover:bg-cyan-200 rounded-lg transition-colors"
                  >
                    <PlayIcon className="w-4 h-4" /> Wizard starten
                  </button>
                </div>

                {/* Printer */}
                <div className="rounded-xl p-5 transition-colors" style={{ border: '1px solid var(--border)' }}>
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-orange-100 flex items-center justify-center flex-shrink-0">
                      <PrinterIcon className="w-5 h-5 text-orange-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Printer Setup</h4>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Drucker hinzufügen, Protokolle konfigurieren und Treiber installieren.</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowPrinterWizard(true)}
                    className="mt-4 w-full flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium text-orange-700 bg-orange-100 hover:bg-orange-200 rounded-lg transition-colors"
                  >
                    <PlayIcon className="w-4 h-4" /> Wizard starten
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── MDM & Certificates Tab ── */}
          {activeTab === 'mdm' && <MdmSettingsTab />}

          {/* ── System Tab ── */}
          {activeTab === 'system' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="rounded-lg p-4" style={{ border: '1px solid var(--border)' }}>
                  <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--text-primary)' }}>Gateway</h3>
                  <dl className="space-y-2">
                    {[
                      { label: 'Status',      value: healthData?.status || '—' },
                      { label: 'Uptime',      value: uptime },
                      { label: 'Version',     value: healthData?.gateway?.version || '—' },
                      { label: 'Environment', value: healthData?.gateway?.environment || 'production' },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex justify-between text-sm">
                        <dt style={{ color: 'var(--text-muted)' }}>{label}</dt>
                        <dd className="font-medium capitalize" style={{ color: 'var(--text-primary)' }}>{value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
                <div className="rounded-lg p-4" style={{ border: '1px solid var(--border)' }}>
                  <h3 className="text-sm font-medium mb-3" style={{ color: 'var(--text-primary)' }}>About OpenDirectory</h3>
                  <dl className="space-y-2">
                    {[
                      { label: 'Version',   value: healthData?.gateway?.version || '1.0.0' },
                      { label: 'Platform',  value: process.env.NEXT_PUBLIC_DEPLOY_PLATFORM || 'Docker Compose' },
                      { label: 'Namespace', value: process.env.NEXT_PUBLIC_DEPLOY_NAMESPACE || 'opendirectory' },
                      { label: 'Host',      value: typeof window !== 'undefined' ? window.location.hostname : '—' },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex justify-between text-sm">
                        <dt style={{ color: 'var(--text-muted)' }}>{label}</dt>
                        <dd className="font-medium font-mono text-xs" style={{ color: 'var(--text-primary)' }}>{value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Double-confirmation modal */}
      {pendingDisable && (
        <DisableConfirmModal
          moduleName={pendingDisable.name}
          step={confirmStep}
          onNext={handleConfirmNext}
          onCancel={() => { setPendingDisable(null); setConfirmStep(1); }}
        />
      )}
      {showSetupWizard      && <SetupWizard              onComplete={() => setShowSetupWizard(false)} />}
      {showMonitoringWizard && <MonitoringAlertingWizard  onClose={() => setShowMonitoringWizard(false)} />}
      {showSecurityWizard   && <SecuritySetupWizard       onClose={() => setShowSecurityWizard(false)} />}
      {showNetworkWizard    && <NetworkConfigWizard        onClose={() => setShowNetworkWizard(false)} />}
      {showDeviceWizard     && <DeviceEnrollmentWizard    onClose={() => setShowDeviceWizard(false)} />}
      {showUserWizard       && <UserManagementWizard      onClose={() => setShowUserWizard(false)} />}
      {showPrinterWizard    && <PrinterSetupWizard        onClose={() => setShowPrinterWizard(false)} />}
    </>
  );
}
