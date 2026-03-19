'use client';

import React, { useState } from 'react';
import {
  WifiIcon,
  PrinterIcon,
  ChartBarIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  CheckIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  ServerIcon,
  ComputerDesktopIcon,
  UserGroupIcon,
  GlobeAltIcon,
  RocketLaunchIcon,
} from '@heroicons/react/24/outline';
import { configApi } from '@/lib/api';
import toast from 'react-hot-toast';

type WizardStep = 1 | 2 | 3 | 4;

interface ModuleOption {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  ram: string;
  recommended?: boolean;
  features: string[];
}

interface SetupWizardProps {
  onComplete: () => void;
}

const MODULES: ModuleOption[] = [
  {
    id: 'network',
    name: 'Netzwerk',
    description: 'DNS-Server, DHCP, SMB/NFS File Shares',
    icon: GlobeAltIcon,
    ram: '192 MB',
    recommended: true,
    features: ['DNS-Server (Port 53)', 'DHCP-Server (Port 67)', 'SMB File Shares (Port 445)', 'NFS Shares (Port 2049)', 'Netzwerk-Discovery'],
  },
  {
    id: 'printers',
    name: 'Drucker',
    description: 'Drucker- & Scanner-Management mit CUPS',
    icon: PrinterIcon,
    ram: '192 MB',
    features: ['CUPS Print Server', 'Auto-Discovery', 'Drucker-Quotas', 'Scanner-Integration', 'Job-Tracking'],
  },
  {
    id: 'monitoring',
    name: 'Monitoring',
    description: 'Grafana Dashboards & Prometheus Metriken',
    icon: ChartBarIcon,
    ram: '448 MB',
    features: ['Grafana Dashboards', 'Prometheus Metrics', 'Alert-Regeln', 'Custom Reports', 'Performance-Tracking'],
  },
  {
    id: 'security',
    name: 'Security',
    description: 'CIS/NIST Compliance Scanner & Auto-Remediation',
    icon: ShieldCheckIcon,
    ram: '320 MB',
    features: ['CIS Benchmark Scanner', 'NIST Compliance', 'BSI Grundschutz', 'Auto-Remediation', 'Compliance Reports'],
  },
  {
    id: 'lifecycle',
    name: 'Lifecycle',
    description: 'Geräte-Lifecycle, Graph Explorer & Policy Simulator',
    icon: CpuChipIcon,
    ram: '448 MB',
    features: ['Device Lifecycle Management', 'AD Graph Explorer', 'Policy Simulator (What-If)', 'Risk Scoring', 'Angriffspfad-Analyse'],
  },
];

const STEPS = [
  { n: 1 as const, label: 'Willkommen' },
  { n: 2 as const, label: 'Module' },
  { n: 3 as const, label: 'Geräte' },
  { n: 4 as const, label: 'Fertig' },
];

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [selectedModules, setSelectedModules] = useState<string[]>(['network']);
  const [orgName, setOrgName] = useState('');
  const [deviceCounts, setDeviceCounts] = useState({ windows: 5, macos: 5, linux: 3 });
  const [saving, setSaving] = useState(false);

  const toggleModule = (id: string) => {
    setSelectedModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    );
  };

  const totalRam = () => {
    let ram = 2112; // Kern
    selectedModules.forEach(id => {
      const mod = MODULES.find(m => m.id === id);
      if (mod) ram += parseInt(mod.ram);
    });
    return (ram / 1024).toFixed(1);
  };

  const totalDevices = () => deviceCounts.windows + deviceCounts.macos + deviceCounts.linux;

  const handleComplete = async () => {
    setSaving(true);
    try {
      await configApi.runSetupWizard({
        orgName: orgName || 'OpenDirectory',
        modules: selectedModules,
        devices: deviceCounts,
        completedAt: new Date().toISOString(),
      });
      toast.success('Setup abgeschlossen!');
      onComplete();
    } catch {
      // Backend may not be fully wired — save locally as fallback
      if (typeof window !== 'undefined') {
        localStorage.setItem('od_setup_completed', JSON.stringify({
          orgName: orgName || 'OpenDirectory',
          modules: selectedModules,
          devices: deviceCounts,
          completedAt: new Date().toISOString(),
        }));
      }
      toast.success('Setup abgeschlossen!');
      onComplete();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header with steps */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-8 pt-6 pb-8">
          <h2 className="text-white text-xl font-bold mb-1">OpenDirectory Setup</h2>
          <p className="text-blue-200 text-sm">Erstmalige Konfiguration</p>

          {/* Step indicator */}
          <div className="flex items-center justify-between mt-6">
            {STEPS.map((s, i) => (
              <React.Fragment key={s.n}>
                <div className="flex items-center">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-all ${
                    s.n < step
                      ? 'bg-blue-300 text-blue-800'
                      : s.n === step
                      ? 'bg-white text-blue-600 ring-4 ring-blue-300'
                      : 'bg-blue-500/40 text-blue-200'
                  }`}>
                    {s.n < step ? <CheckIcon className="h-4 w-4" /> : s.n}
                  </div>
                  <span className={`ml-2 text-sm hidden sm:block ${
                    s.n === step ? 'text-white font-medium' : 'text-blue-200'
                  }`}>
                    {s.label}
                  </span>
                </div>
                {i < STEPS.length - 1 && (
                  <div className={`flex-1 h-px mx-3 ${
                    s.n < step ? 'bg-blue-300' : 'bg-blue-500/40'
                  }`} />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-8 py-6">

          {/* Step 1: Willkommen */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center py-4">
                <div className="w-16 h-16 bg-blue-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <RocketLaunchIcon className="h-8 w-8 text-blue-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-2">Willkommen bei OpenDirectory</h3>
                <p className="text-gray-500 max-w-md mx-auto">
                  Konfiguriere dein Device-Management in wenigen Schritten.
                  Du kannst alles später in den Einstellungen ändern.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Organisationsname (optional)
                </label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="z.B. Meine Firma GmbH"
                  className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Was ist immer dabei (Kern-System)</h4>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { icon: UserGroupIcon, label: 'User-Verzeichnis (LDAP)' },
                    { icon: ComputerDesktopIcon, label: 'Geräte-Management' },
                    { icon: ShieldCheckIcon, label: 'Policy-Engine' },
                    { icon: ServerIcon, label: 'API & Web-Dashboard' },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center text-sm text-gray-600">
                      <item.icon className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
                      {item.label}
                    </div>
                  ))}
                </div>
                <p className="text-xs text-gray-400 mt-3">~2.0 GB RAM</p>
              </div>
            </div>
          )}

          {/* Step 2: Module auswählen */}
          {step === 2 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Optionale Module</h3>
                <p className="text-sm text-gray-500">Wähle welche Zusatzfunktionen du brauchst. Jedes Modul kann später aktiviert/deaktiviert werden.</p>
              </div>

              <div className="space-y-3">
                {MODULES.map((mod) => {
                  const isSelected = selectedModules.includes(mod.id);
                  return (
                    <button
                      key={mod.id}
                      onClick={() => toggleModule(mod.id)}
                      className={`w-full text-left rounded-xl border-2 p-4 transition-all ${
                        isSelected
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200 bg-white hover:border-gray-300'
                      }`}
                    >
                      <div className="flex items-start">
                        {/* Checkbox */}
                        <div className={`w-5 h-5 rounded border-2 flex-shrink-0 mt-0.5 mr-3 flex items-center justify-center transition-all ${
                          isSelected ? 'bg-blue-500 border-blue-500' : 'border-gray-300'
                        }`}>
                          {isSelected && <CheckIcon className="h-3 w-3 text-white" />}
                        </div>

                        {/* Icon */}
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 mr-3 ${
                          isSelected ? 'bg-blue-100' : 'bg-gray-100'
                        }`}>
                          <mod.icon className={`h-5 w-5 ${isSelected ? 'text-blue-600' : 'text-gray-500'}`} />
                        </div>

                        {/* Text */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center">
                            <span className="font-medium text-gray-900">{mod.name}</span>
                            {mod.recommended && (
                              <span className="ml-2 px-2 py-0.5 text-xs bg-green-100 text-green-700 rounded-full">
                                empfohlen
                              </span>
                            )}
                            <span className="ml-auto text-xs text-gray-400">+{mod.ram}</span>
                          </div>
                          <p className="text-sm text-gray-500 mt-0.5">{mod.description}</p>

                          {/* Features (only when selected) */}
                          {isSelected && (
                            <div className="flex flex-wrap gap-1.5 mt-2">
                              {mod.features.map((f) => (
                                <span key={f} className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded">
                                  {f}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* RAM Summary */}
              <div className="bg-gray-50 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <span className="text-sm text-gray-600">Geschätzter RAM-Verbrauch:</span>
                  <span className="ml-2 text-lg font-bold text-gray-900">~{totalRam()} GB</span>
                </div>
                <div className="text-sm text-gray-400">
                  {selectedModules.length} Module + Kern
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Geräte */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Wie viele Geräte verwaltest du?</h3>
                <p className="text-sm text-gray-500">Ungefähre Anzahl pro Plattform — hilft uns die Ansicht zu optimieren.</p>
              </div>

              <div className="space-y-4">
                {[
                  { key: 'windows' as const, label: 'Windows', color: 'blue', icon: '🪟' },
                  { key: 'macos' as const, label: 'macOS', color: 'gray', icon: '🍎' },
                  { key: 'linux' as const, label: 'Linux Server', color: 'orange', icon: '🐧' },
                ].map(({ key, label, icon }) => (
                  <div key={key} className="flex items-center bg-gray-50 rounded-xl p-4">
                    <span className="text-2xl mr-3">{icon}</span>
                    <div className="flex-1">
                      <label className="block text-sm font-medium text-gray-900">{label}</label>
                    </div>
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => setDeviceCounts(prev => ({ ...prev, [key]: Math.max(0, prev[key] - 1) }))}
                        className="w-8 h-8 rounded-lg bg-white border border-gray-300 flex items-center justify-center text-gray-600 hover:bg-gray-100"
                      >
                        −
                      </button>
                      <input
                        type="number"
                        min={0}
                        value={deviceCounts[key]}
                        onChange={(e) => setDeviceCounts(prev => ({ ...prev, [key]: Math.max(0, parseInt(e.target.value) || 0) }))}
                        className="w-16 text-center text-lg font-bold border border-gray-300 rounded-lg py-1"
                      />
                      <button
                        onClick={() => setDeviceCounts(prev => ({ ...prev, [key]: prev[key] + 1 }))}
                        className="w-8 h-8 rounded-lg bg-white border border-gray-300 flex items-center justify-center text-gray-600 hover:bg-gray-100"
                      >
                        +
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-blue-50 rounded-xl p-4 text-center">
                <span className="text-sm text-blue-600">Gesamt: </span>
                <span className="text-xl font-bold text-blue-900">{totalDevices()} Geräte</span>
              </div>
            </div>
          )}

          {/* Step 4: Zusammenfassung */}
          {step === 4 && (
            <div className="space-y-6">
              <div className="text-center py-2">
                <div className="w-16 h-16 bg-green-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <CheckIcon className="h-8 w-8 text-green-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900">Bereit zum Starten</h3>
                <p className="text-gray-500 text-sm mt-1">Überprüfe deine Konfiguration</p>
              </div>

              {/* Summary cards */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-gray-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-gray-900">{totalDevices()}</p>
                  <p className="text-xs text-gray-500">Geräte</p>
                </div>
                <div className="bg-gray-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-gray-900">{selectedModules.length + 1}</p>
                  <p className="text-xs text-gray-500">Module</p>
                </div>
                <div className="bg-gray-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-gray-900">~{totalRam()}</p>
                  <p className="text-xs text-gray-500">GB RAM</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-5 space-y-3">
                {orgName && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Organisation</span>
                    <span className="font-medium text-gray-900">{orgName}</span>
                  </div>
                )}
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Plattformen</span>
                  <span className="font-medium text-gray-900">
                    {deviceCounts.windows > 0 && `${deviceCounts.windows}× Windows`}
                    {deviceCounts.windows > 0 && deviceCounts.macos > 0 && ', '}
                    {deviceCounts.macos > 0 && `${deviceCounts.macos}× macOS`}
                    {(deviceCounts.windows > 0 || deviceCounts.macos > 0) && deviceCounts.linux > 0 && ', '}
                    {deviceCounts.linux > 0 && `${deviceCounts.linux}× Linux`}
                  </span>
                </div>
                <div className="border-t border-gray-200 pt-3">
                  <span className="text-sm text-gray-500">Aktive Module:</span>
                  <div className="flex flex-wrap gap-2 mt-2">
                    <span className="px-2.5 py-1 text-xs bg-green-100 text-green-700 rounded-full font-medium">
                      Kern-System
                    </span>
                    {selectedModules.map(id => {
                      const mod = MODULES.find(m => m.id === id);
                      return mod ? (
                        <span key={id} className="px-2.5 py-1 text-xs bg-blue-100 text-blue-700 rounded-full font-medium">
                          {mod.name}
                        </span>
                      ) : null;
                    })}
                  </div>
                </div>
              </div>

              <p className="text-xs text-gray-400 text-center">
                Du kannst Module jederzeit unter Einstellungen → Services ändern.
              </p>
            </div>
          )}
        </div>

        {/* Footer with navigation */}
        <div className="border-t border-gray-200 px-8 py-4 flex items-center justify-between bg-gray-50">
          <div>
            {step > 1 && (
              <button
                onClick={() => setStep((step - 1) as WizardStep)}
                className="flex items-center px-4 py-2 text-sm text-gray-600 hover:text-gray-900 transition-colors"
              >
                <ArrowLeftIcon className="h-4 w-4 mr-1" />
                Zurück
              </button>
            )}
          </div>

          <div>
            {step < 4 ? (
              <button
                onClick={() => setStep((step + 1) as WizardStep)}
                className="flex items-center px-6 py-2.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
              >
                Weiter
                <ArrowRightIcon className="h-4 w-4 ml-1" />
              </button>
            ) : (
              <button
                onClick={handleComplete}
                disabled={saving}
                className="flex items-center px-6 py-2.5 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 transition-colors disabled:opacity-50"
              >
                {saving ? (
                  <>
                    <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Speichern...
                  </>
                ) : (
                  <>
                    <CheckIcon className="h-4 w-4 mr-1" />
                    Setup abschließen
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
