'use client';

import React, { useState } from 'react';
import {
  PrinterIcon,
  ChartBarIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  CheckIcon,
  ServerIcon,
  ComputerDesktopIcon,
  UserGroupIcon,
  GlobeAltIcon,
  RocketLaunchIcon,
} from '@heroicons/react/24/outline';
import { configApi } from '@/lib/api';
import { MODULES as MODULE_REGISTRY, calculateRam } from '@/lib/modules';
import RamMeter from '@/components/shared/RamMeter';
import WizardLayout from '@/components/shared/WizardLayout';
import toast from 'react-hot-toast';

type WizardStep = 1 | 2 | 3 | 4;

interface SetupWizardProps {
  onComplete: () => void;
}

// Map icon names from module registry to actual components
const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  GlobeAltIcon,
  PrinterIcon,
  ChartBarIcon,
  ShieldCheckIcon,
  CpuChipIcon,
};

const STEPS = [
  { n: 1 as const, label: 'Willkommen' },
  { n: 2 as const, label: 'Module' },
  { n: 3 as const, label: 'Geräte' },
  { n: 4 as const, label: 'Fertig' },
];

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [selectedModules, setSelectedModules] = useState<string[]>(
    MODULE_REGISTRY.filter(m => m.recommended).map(m => m.id)
  );
  const [orgName, setOrgName] = useState('');
  const [deviceCounts, setDeviceCounts] = useState({ windows: 5, macos: 5, linux: 3 });
  const [saving, setSaving] = useState(false);

  const toggleModule = (id: string) => {
    setSelectedModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    );
  };

  const ram = calculateRam(selectedModules);
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
    <WizardLayout
      title="OpenDirectory Setup"
      subtitle="Erstmalige Konfiguration"
      color="blue"
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onComplete}
      onComplete={handleComplete}
      saving={saving}
      completeLabel="Setup abschließen"
      savingLabel="Speichern..."
      maxWidth="max-w-3xl"
    >
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
                {MODULE_REGISTRY.map((mod) => {
                  const isSelected = selectedModules.includes(mod.id);
                  const Icon = ICON_MAP[mod.iconName] || CpuChipIcon;
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
                          <Icon className={`h-5 w-5 ${isSelected ? 'text-blue-600' : 'text-gray-500'}`} />
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
                            <span className="ml-auto text-xs text-gray-400">+{mod.ramMB} MB</span>
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

              {/* Live RAM Meter */}
              <RamMeter
                enabledModules={selectedModules}
                compact={false}
                showBreakdown={false}
              />
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
                  { key: 'windows' as const, label: 'Windows', icon: '🪟' },
                  { key: 'macos' as const, label: 'macOS', icon: '🍎' },
                  { key: 'linux' as const, label: 'Linux Server', icon: '🐧' },
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
                  <p className="text-2xl font-bold text-gray-900">~{ram.totalGB}</p>
                  <p className="text-xs text-gray-500">GB RAM</p>
                </div>
              </div>

              {/* RAM visualization */}
              <RamMeter
                enabledModules={selectedModules}
                compact={false}
                showBreakdown={true}
              />

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
                      const mod = MODULE_REGISTRY.find(m => m.id === id);
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
    </WizardLayout>
  );
}
