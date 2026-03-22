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

type TabId = 'services' | 'setup' | 'system';

// Modules that have a sidebar nav item and can be hidden
const HAS_NAV_ITEM = new Set([
  'monitoring-analytics', 'secrets-management', 'device-management', 'network-infrastructure', 'security-suite',
]);

// ─── Double-Confirm Disable Modal ──────────────────────────────────────────────

function DisableConfirmModal({ moduleName, step, onNext, onCancel }: {
  moduleName: string;
  step: 1 | 2;
  onNext: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={onCancel}>
      <div className="bg-white rounded-xl shadow-xl max-w-md w-full" onClick={e => e.stopPropagation()}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-lg bg-yellow-50 flex items-center justify-center flex-shrink-0">
                <ExclamationTriangleIcon className="w-5 h-5 text-yellow-600" />
              </div>
              <h2 className="text-base font-semibold text-gray-900">
                {step === 1 ? 'Disable Module?' : 'Confirm Disable'}
              </h2>
            </div>
            <button onClick={onCancel} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {step === 1 ? (
            <>
              <p className="text-sm text-gray-700 mb-2">
                You are about to disable <strong>{moduleName}</strong>.
              </p>
              <p className="text-sm text-gray-500 mb-4">
                This will <strong>hide it from the navigation</strong>. All settings and data
                are preserved — you can re-enable the module at any time from Settings.
              </p>
            </>
          ) : (
            <>
              <p className="text-sm text-gray-700 mb-2">
                Are you absolutely sure you want to disable <strong>{moduleName}</strong>?
              </p>
              <p className="text-sm text-gray-500 mb-4">
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
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
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
    { key: 'services', label: 'Services',  icon: CpuChipIcon },
    { key: 'setup',    label: 'Setup',     icon: SparklesIcon },
    { key: 'system',   label: 'System',    icon: InformationCircleIcon },
  ];

  return (
    <>
      <div className="bg-white rounded-lg shadow">
        {/* Header */}
        <div className="border-b border-gray-200">
          <div className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Cog6ToothIcon className="h-6 w-6 text-blue-600" />
                <h2 className="text-lg font-medium text-gray-900">Settings</h2>
              </div>
              {!loading && (
                <div className="text-sm text-gray-500">
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
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}>
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
                  <h3 className="text-sm font-medium text-gray-700">Module Management</h3>
                  <p className="text-xs text-gray-400">Disabled modules are hidden from the navigation</p>
                </div>
                {loading ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {[...Array(6)].map((_, i) => (
                      <div key={i} className="border border-gray-200 rounded-lg p-4 animate-pulse">
                        <div className="h-4 bg-gray-200 rounded w-3/4 mb-2" />
                        <div className="h-3 bg-gray-200 rounded w-1/2" />
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
                        <div key={module.id} className={`border rounded-lg p-4 ${
                          module.enabled ? 'border-gray-200' : 'border-gray-100 bg-gray-50 opacity-75'
                        }`}>
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-3">
                              <div className={`p-2 rounded-lg ${module.enabled ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-400'}`}>
                                {getModuleIcon(module.id)}
                              </div>
                              <div>
                                <h4 className="text-sm font-medium text-gray-900">{module.name}</h4>
                                <p className="text-xs text-gray-500">Port {module.port}</p>
                                {service && (
                                  <div className="flex items-center space-x-1 mt-1">
                                    {getStatusIcon(service.status)}
                                    <span className="text-xs text-gray-500 capitalize">{service.status}</span>
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
                              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" />
                            </label>
                          </div>
                          {module.enabled && Object.keys(module.features || {}).length > 0 && (
                            <div className="mt-3 flex flex-wrap gap-1">
                              {Object.entries(module.features).slice(0, 3).map(([feat, on]) => (
                                <span key={feat} className={`px-2 py-0.5 text-xs rounded-full ${on ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
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
                  <h3 className="text-sm font-medium text-gray-700 mb-3">Service Status</h3>
                  <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
                    <table className="min-w-full divide-y divide-gray-300">
                      <thead className="bg-gray-50">
                        <tr>
                          {['Service', 'Status', 'Port', 'Response', 'Last Check'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {services.map((svc, i) => (
                          <tr key={svc.name} className={i % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{svc.name}</td>
                            <td className="px-4 py-3">
                              <div className="flex items-center space-x-1">
                                {getStatusIcon(svc.status)}
                                <span className={`text-xs font-medium capitalize ${
                                  svc.status === 'healthy' ? 'text-green-600' :
                                  svc.status === 'unhealthy' ? 'text-red-600' : 'text-yellow-600'
                                }`}>{svc.status}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">{svc.port || '—'}</td>
                            <td className="px-4 py-3 text-sm text-gray-500">{svc.responseTime ? `${svc.responseTime}ms` : '—'}</td>
                            <td className="px-4 py-3 text-sm text-gray-500">
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
                <h3 className="text-sm font-medium text-gray-700">Setup & Configuration Wizards</h3>
                <p className="text-xs text-gray-400 mt-0.5">Verwende die Wizards um Module und Dienste nachträglich zu konfigurieren.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Initial Setup */}
                <div className="border-2 border-blue-200 bg-blue-50 rounded-xl p-5">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center flex-shrink-0">
                      <SparklesIcon className="w-5 h-5 text-blue-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">Initial Setup Wizard</h4>
                      <p className="text-xs text-gray-500 mt-0.5">Module aktivieren, Gerätezahlen anpassen, Organisationsname ändern.</p>
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
                <div className="border border-gray-200 rounded-xl p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-indigo-100 flex items-center justify-center flex-shrink-0">
                      <PlayIcon className="w-5 h-5 text-indigo-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">User Management</h4>
                      <p className="text-xs text-gray-500 mt-0.5">Benutzer und Gruppen anlegen, LDAP-Einstellungen konfigurieren.</p>
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
                <div className="border border-gray-200 rounded-xl p-5 hover:border-teal-200 hover:bg-teal-50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-teal-100 flex items-center justify-center flex-shrink-0">
                      <ComputerDesktopIcon className="w-5 h-5 text-teal-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">Device Enrollment</h4>
                      <p className="text-xs text-gray-500 mt-0.5">Geräte registrieren, Enrollment-Profile und Richtlinien einrichten.</p>
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
                <div className="border border-gray-200 rounded-xl p-5 hover:border-purple-200 hover:bg-purple-50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-purple-100 flex items-center justify-center flex-shrink-0">
                      <ChartBarIcon className="w-5 h-5 text-purple-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">Monitoring & Alerting</h4>
                      <p className="text-xs text-gray-500 mt-0.5">Grafana-Dashboards, Prometheus-Alerts und Benachrichtigungen einrichten.</p>
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
                <div className="border border-gray-200 rounded-xl p-5 hover:border-red-200 hover:bg-red-50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center flex-shrink-0">
                      <ShieldCheckIcon className="w-5 h-5 text-red-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">Security Setup</h4>
                      <p className="text-xs text-gray-500 mt-0.5">Wazuh, Vault, MFA und Sicherheitsrichtlinien konfigurieren.</p>
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
                <div className="border border-gray-200 rounded-xl p-5 hover:border-cyan-200 hover:bg-cyan-50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-cyan-100 flex items-center justify-center flex-shrink-0">
                      <WifiIcon className="w-5 h-5 text-cyan-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">Network Configuration</h4>
                      <p className="text-xs text-gray-500 mt-0.5">DNS, DHCP, VLANs und Netzwerkinfrastruktur einrichten.</p>
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
                <div className="border border-gray-200 rounded-xl p-5 hover:border-orange-200 hover:bg-orange-50 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-orange-100 flex items-center justify-center flex-shrink-0">
                      <PrinterIcon className="w-5 h-5 text-orange-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-semibold text-gray-900">Printer Setup</h4>
                      <p className="text-xs text-gray-500 mt-0.5">Drucker hinzufügen, Protokolle konfigurieren und Treiber installieren.</p>
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

          {/* ── System Tab ── */}
          {activeTab === 'system' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="border border-gray-200 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-gray-900 mb-3">Gateway</h3>
                  <dl className="space-y-2">
                    {[
                      { label: 'Status',      value: healthData?.status || '—' },
                      { label: 'Uptime',      value: uptime },
                      { label: 'Version',     value: healthData?.gateway?.version || '—' },
                      { label: 'Environment', value: healthData?.gateway?.environment || 'production' },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex justify-between text-sm">
                        <dt className="text-gray-500">{label}</dt>
                        <dd className="font-medium text-gray-900 capitalize">{value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
                <div className="border border-gray-200 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-gray-900 mb-3">About OpenDirectory</h3>
                  <dl className="space-y-2">
                    {[
                      { label: 'Version',   value: '1.0.0' },
                      { label: 'Platform',  value: 'Kubernetes / k3s' },
                      { label: 'Namespace', value: 'opendirectory' },
                      { label: 'Host',      value: 'opendirectory.heusser.local' },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex justify-between text-sm">
                        <dt className="text-gray-500">{label}</dt>
                        <dd className="font-medium text-gray-900 font-mono text-xs">{value}</dd>
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
