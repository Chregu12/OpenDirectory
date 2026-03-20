'use client';

import React, { useState, useEffect } from 'react';
import {
  SquaresPlusIcon,
  MagnifyingGlassIcon,
  CheckIcon,
  UserGroupIcon,
  ComputerDesktopIcon,
  TagIcon,
} from '@heroicons/react/24/outline';
import { appStoreApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';
import WizardLayout from '@/components/shared/WizardLayout';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface AppDeploymentWizardProps {
  onClose: () => void;
}

interface AppItem {
  id: string;
  name: string;
  version: string;
  category: string;
  platform: string[];
  description?: string;
  selected: boolean;
  installType: 'required' | 'optional';
}

interface AssignmentTarget {
  id: string;
  name: string;
  type: 'domain' | 'ou' | 'group' | 'device';
}

const STEPS = [
  { n: 1 as const, label: 'Katalog' },
  { n: 2 as const, label: 'Apps wählen' },
  { n: 3 as const, label: 'Zielgruppen' },
  { n: 4 as const, label: 'Lizenzen' },
  { n: 5 as const, label: 'Deployment' },
];

const DEFAULT_TARGETS: AssignmentTarget[] = [
  { id: 'domain-all', name: 'Gesamte Domain', type: 'domain' },
  { id: 'ou-it', name: 'IT-Abteilung', type: 'ou' },
  { id: 'ou-dev', name: 'Entwicklung', type: 'ou' },
  { id: 'ou-hr', name: 'Personalabteilung', type: 'ou' },
  { id: 'group-admins', name: 'Administratoren', type: 'group' },
  { id: 'group-users', name: 'Standard-Benutzer', type: 'group' },
];

export default function AppDeploymentWizard({ onClose }: AppDeploymentWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);

  // Catalog
  const [catalogLoaded, setCatalogLoaded] = useState(false);
  const [catalogSeeding, setCatalogSeeding] = useState(false);
  const [categories, setCategories] = useState<string[]>([]);
  const [catalogCount, setCatalogCount] = useState(0);

  // Apps
  const [apps, setApps] = useState<AppItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterCategory, setFilterCategory] = useState('all');

  // Targets
  const [targets] = useState<AssignmentTarget[]>(DEFAULT_TARGETS);
  const [selectedTargets, setSelectedTargets] = useState<string[]>(['group-users']);

  // Licenses
  const [licenseType, setLicenseType] = useState<'unlimited' | 'per-device' | 'per-user'>('unlimited');
  const [licenseCount, setLicenseCount] = useState(100);

  useEffect(() => {
    loadCatalog();
  }, []);

  const loadCatalog = async () => {
    try {
      const [catalogRes, catRes, statsRes] = await Promise.all([
        appStoreApi.getCatalog().catch(() => ({ data: { apps: [] } })),
        appStoreApi.getCategories().catch(() => ({ data: { categories: [] } })),
        appStoreApi.getStats().catch(() => ({ data: { totalApps: 0 } })),
      ]);

      const rawApps = catalogRes.data?.apps || catalogRes.data?.data?.apps || [];
      setCatalogCount(rawApps.length || statsRes.data?.totalApps || 0);
      setCategories(catRes.data?.categories?.map((c: any) => c.name || c) || []);
      setCatalogLoaded(rawApps.length > 0);

      setApps(rawApps.map((a: any) => ({
        id: a.id || a._id,
        name: a.name,
        version: a.version || '–',
        category: a.category || 'Sonstiges',
        platform: a.platforms || a.platform || ['windows'],
        description: a.description,
        selected: false,
        installType: 'optional' as const,
      })));
    } catch {
      // keep defaults
    }
  };

  const seedCatalog = async () => {
    setCatalogSeeding(true);
    try {
      await appStoreApi.seedCatalog();
      toast.success('App-Katalog wurde befüllt!');
      await loadCatalog();
    } catch {
      toast.error('Katalog konnte nicht befüllt werden.');
    } finally {
      setCatalogSeeding(false);
    }
  };

  const toggleApp = (id: string) => {
    setApps(prev =>
      prev.map(a => a.id === id ? { ...a, selected: !a.selected } : a)
    );
  };

  const setAppInstallType = (id: string, type: 'required' | 'optional') => {
    setApps(prev =>
      prev.map(a => a.id === id ? { ...a, installType: type } : a)
    );
  };

  const toggleTarget = (id: string) => {
    setSelectedTargets(prev =>
      prev.includes(id) ? prev.filter(t => t !== id) : [...prev, id]
    );
  };

  const filteredApps = apps.filter(a => {
    const matchesSearch = !searchQuery || a.name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = filterCategory === 'all' || a.category === filterCategory;
    return matchesSearch && matchesCategory;
  });

  const selectedApps = apps.filter(a => a.selected);

  const handleComplete = async () => {
    setSaving(true);
    try {
      // Assign each selected app to selected targets
      for (const app of selectedApps) {
        await appStoreApi.assignApp(app.id, {
          targets: selectedTargets.map(tid => {
            const target = targets.find(t => t.id === tid);
            return {
              target_type: target?.type || 'group',
              target_id: tid,
              target_name: target?.name,
            };
          }),
          install_type: app.installType,
        }).catch(() => {});
      }
      toast.success('App-Verteilung konfiguriert!');
      onClose();
    } catch {
      if (typeof window !== 'undefined') {
        localStorage.setItem('od_app_deployment', JSON.stringify({
          apps: selectedApps.map(a => ({ id: a.id, name: a.name, installType: a.installType })),
          targets: selectedTargets,
          licenseType, licenseCount,
          completedAt: new Date().toISOString(),
        }));
      }
      toast.success('App-Verteilung konfiguriert!');
      onClose();
    }
  };

  return (
    <WizardLayout
      title="App-Verteilung"
      subtitle="App-Katalog befüllen und Software zuweisen"
      icon={<SquaresPlusIcon className="h-8 w-8" />}
      color="violet"
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onClose}
      onComplete={handleComplete}
      saving={saving}
      completeLabel="Apps verteilen"
      savingLabel="Verteilen..."
    >
          {/* Step 1: Catalog */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">App-Katalog</h3>
                <p className="text-sm text-gray-500">Ihr Software-Katalog für die verwaltete Verteilung.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-violet-50 border border-violet-200 rounded-xl p-4 text-center">
                  <SquaresPlusIcon className="h-8 w-8 text-violet-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-violet-700">{catalogCount}</p>
                  <p className="text-sm text-violet-600">Apps im Katalog</p>
                </div>
                <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-center">
                  <TagIcon className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-blue-700">{categories.length}</p>
                  <p className="text-sm text-blue-600">Kategorien</p>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center">
                  <ComputerDesktopIcon className="h-8 w-8 text-green-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-green-700">{selectedApps.length}</p>
                  <p className="text-sm text-green-600">Ausgewählt</p>
                </div>
              </div>

              {!catalogLoaded && (
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-6 text-center">
                  <SquaresPlusIcon className="h-12 w-12 text-amber-600 mx-auto mb-3" />
                  <h4 className="font-semibold text-gray-900 mb-2">Katalog ist leer</h4>
                  <p className="text-sm text-gray-600 mb-4">Befüllen Sie den Katalog mit Standard-Anwendungen.</p>
                  <button
                    onClick={seedCatalog}
                    disabled={catalogSeeding}
                    className="px-6 py-2.5 bg-violet-600 text-white rounded-lg hover:bg-violet-700 transition-colors text-sm font-medium disabled:opacity-50"
                  >
                    {catalogSeeding ? 'Wird befüllt...' : 'Standard-Katalog laden'}
                  </button>
                </div>
              )}

              {catalogLoaded && (
                <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center">
                  <CheckIcon className="h-8 w-8 text-green-600 mx-auto mb-2" />
                  <p className="font-semibold text-gray-900">Katalog bereit</p>
                  <p className="text-sm text-gray-600">Fahren Sie fort, um Apps auszuwählen.</p>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Select Apps */}
          {step === 2 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Apps auswählen</h3>
                <p className="text-sm text-gray-500">Wählen Sie die Apps die verteilt werden sollen.</p>
              </div>

              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <MagnifyingGlassIcon className="h-4 w-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Apps suchen..."
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500"
                  />
                </div>
                <select
                  value={filterCategory}
                  onChange={e => setFilterCategory(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500"
                >
                  <option value="all">Alle Kategorien</option>
                  {categories.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>

              <div className="space-y-2 max-h-[400px] overflow-y-auto">
                {filteredApps.length > 0 ? filteredApps.map(app => (
                  <div
                    key={app.id}
                    className={`flex items-center justify-between bg-white border rounded-lg px-4 py-3 transition-all cursor-pointer ${
                      app.selected ? 'border-violet-500 bg-violet-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => toggleApp(app.id)}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${app.selected ? 'bg-violet-600' : 'bg-gray-100'}`}>
                        {app.selected ? <CheckIcon className="h-4 w-4 text-white" /> : <SquaresPlusIcon className="h-4 w-4 text-gray-400" />}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">{app.name}</p>
                        <p className="text-xs text-gray-500">{app.category} · v{app.version}</p>
                      </div>
                    </div>
                    {app.selected && (
                      <select
                        value={app.installType}
                        onChange={e => { e.stopPropagation(); setAppInstallType(app.id, e.target.value as any); }}
                        onClick={e => e.stopPropagation()}
                        className="px-2 py-1 text-xs border border-violet-300 rounded bg-white focus:ring-2 focus:ring-violet-500"
                      >
                        <option value="optional">Optional</option>
                        <option value="required">Pflicht</option>
                      </select>
                    )}
                  </div>
                )) : (
                  <p className="text-sm text-gray-500 text-center py-8">Keine Apps gefunden. Befüllen Sie zuerst den Katalog.</p>
                )}
              </div>

              <p className="text-xs text-gray-400">{selectedApps.length} Apps ausgewählt ({selectedApps.filter(a => a.installType === 'required').length} Pflicht, {selectedApps.filter(a => a.installType === 'optional').length} Optional)</p>
            </div>
          )}

          {/* Step 3: Targets */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Zielgruppen</h3>
                <p className="text-sm text-gray-500">An wen sollen die Apps verteilt werden?</p>
              </div>

              <div className="space-y-2">
                {targets.map(target => (
                  <button
                    key={target.id}
                    onClick={() => toggleTarget(target.id)}
                    className={`w-full text-left flex items-center justify-between bg-white border rounded-lg px-4 py-3 transition-all ${
                      selectedTargets.includes(target.id) ? 'border-violet-500 bg-violet-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                        target.type === 'domain' ? 'bg-blue-100' : target.type === 'ou' ? 'bg-green-100' : target.type === 'group' ? 'bg-purple-100' : 'bg-gray-100'
                      }`}>
                        {target.type === 'domain' || target.type === 'ou' ? (
                          <ComputerDesktopIcon className={`h-4 w-4 ${target.type === 'domain' ? 'text-blue-600' : 'text-green-600'}`} />
                        ) : (
                          <UserGroupIcon className="h-4 w-4 text-purple-600" />
                        )}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">{target.name}</p>
                        <p className="text-xs text-gray-500 capitalize">{target.type}</p>
                      </div>
                    </div>
                    {selectedTargets.includes(target.id) && <CheckIcon className="h-5 w-5 text-violet-600" />}
                  </button>
                ))}
              </div>

              <p className="text-xs text-gray-400">{selectedTargets.length} Ziel(e) ausgewählt</p>
            </div>
          )}

          {/* Step 4: Licenses */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Lizenzverwaltung</h3>
                <p className="text-sm text-gray-500">Lizenztyp und -umfang für die ausgewählten Apps.</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Lizenztyp</label>
                <div className="grid grid-cols-3 gap-3">
                  {([
                    ['unlimited', 'Unbegrenzt', 'Keine Lizenzbeschränkung'],
                    ['per-device', 'Pro Gerät', 'Eine Lizenz pro Gerät'],
                    ['per-user', 'Pro Benutzer', 'Eine Lizenz pro Benutzer'],
                  ] as const).map(([val, label, desc]) => (
                    <button
                      key={val}
                      onClick={() => setLicenseType(val)}
                      className={`text-left p-3 rounded-lg border-2 transition-all ${licenseType === val ? 'border-violet-500 bg-violet-50' : 'border-gray-200 hover:border-gray-300'}`}
                    >
                      <p className="font-medium text-sm text-gray-900">{label}</p>
                      <p className="text-xs text-gray-500">{desc}</p>
                    </button>
                  ))}
                </div>
              </div>

              {licenseType !== 'unlimited' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Anzahl Lizenzen</label>
                  <input
                    type="number"
                    min={1}
                    value={licenseCount}
                    onChange={e => setLicenseCount(Number(e.target.value))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500"
                  />
                </div>
              )}

              <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                <h4 className="font-semibold text-gray-900 mb-3">Ausgewählte Apps</h4>
                {selectedApps.length > 0 ? (
                  <div className="space-y-2">
                    {selectedApps.map(app => (
                      <div key={app.id} className="flex items-center justify-between text-sm">
                        <span className="text-gray-700">{app.name}</span>
                        <span className={`px-2 py-0.5 rounded-full text-xs ${app.installType === 'required' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'}`}>
                          {app.installType === 'required' ? 'Pflicht' : 'Optional'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500">Keine Apps ausgewählt.</p>
                )}
              </div>
            </div>
          )}

          {/* Step 5: Summary */}
          {step === 5 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Deployment-Zusammenfassung</h3>
                <p className="text-sm text-gray-500">Überprüfen und starten Sie die Software-Verteilung.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-violet-50 border border-violet-200 rounded-xl p-4">
                  <SquaresPlusIcon className="h-6 w-6 text-violet-600 mb-2" />
                  <p className="font-semibold text-gray-900">Apps</p>
                  <p className="text-sm text-gray-600">{selectedApps.length} ausgewählt</p>
                  <p className="text-xs text-gray-500 mt-1">{selectedApps.filter(a => a.installType === 'required').length} Pflicht, {selectedApps.filter(a => a.installType === 'optional').length} Optional</p>
                </div>
                <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                  <UserGroupIcon className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-semibold text-gray-900">Zielgruppen</p>
                  <p className="text-sm text-gray-600">{selectedTargets.length} Ziel(e)</p>
                  <p className="text-xs text-gray-500 mt-1">{selectedTargets.map(id => targets.find(t => t.id === id)?.name).filter(Boolean).join(', ')}</p>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-xl p-4">
                  <TagIcon className="h-6 w-6 text-green-600 mb-2" />
                  <p className="font-semibold text-gray-900">Lizenzen</p>
                  <p className="text-sm text-gray-600">{licenseType === 'unlimited' ? 'Unbegrenzt' : `${licenseCount} ${licenseType === 'per-device' ? 'Geräte' : 'Benutzer'}`}</p>
                </div>
              </div>

              {selectedApps.length > 0 && (
                <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                  <h4 className="font-semibold text-gray-900 mb-2">Apps zur Verteilung</h4>
                  <div className="space-y-1">
                    {selectedApps.map(app => (
                      <div key={app.id} className="flex items-center justify-between text-sm py-1">
                        <span className="text-gray-700">{app.name} v{app.version}</span>
                        <span className="text-gray-500">{app.category}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
    </WizardLayout>
  );
}
