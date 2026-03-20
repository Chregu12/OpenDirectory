'use client';

import React, { useState, useEffect } from 'react';
import {
  PrinterIcon,
  MagnifyingGlassIcon,
  UserGroupIcon,
  RocketLaunchIcon,
  PlusIcon,
  TrashIcon,
  SignalIcon,
  ClipboardDocumentIcon,
  MapPinIcon,
} from '@heroicons/react/24/outline';
import { printerApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';
import WizardLayout from '@/components/shared/WizardLayout';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface PrinterSetupWizardProps {
  onClose: () => void;
}

interface Printer {
  id?: string;
  name: string;
  address: string;
  port: number;
  protocol: 'IPP' | 'LPD' | 'SMB' | 'RAW';
  location: string;
  driver: string;
  duplex: boolean;
  color: boolean;
  paperSize: string;
  group?: string;
}

interface PrinterGroup {
  name: string;
  printers: string[];
}

interface PrinterUserAssignment {
  groupName: string;
  printerGroups: string[];
  quota: number; // pages per month, 0 = unlimited
}

const PROTOCOLS = [
  { value: 'IPP', label: 'IPP (Internet Printing Protocol)', port: 631 },
  { value: 'LPD', label: 'LPD/LPR', port: 515 },
  { value: 'SMB', label: 'SMB/Windows', port: 445 },
  { value: 'RAW', label: 'Raw/Socket (Port 9100)', port: 9100 },
];

const PAPER_SIZES = ['A4', 'A3', 'Letter', 'Legal'];

const STEPS = [
  { n: 1 as const, label: 'Finden' },
  { n: 2 as const, label: 'Konfigurieren' },
  { n: 3 as const, label: 'Gruppen' },
  { n: 4 as const, label: 'Zuordnung' },
  { n: 5 as const, label: 'Deploy' },
];

export default function PrinterSetupWizard({ onClose }: PrinterSetupWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);

  // Discovery
  const [discovering, setDiscovering] = useState(false);
  const [discoveredPrinters, setDiscoveredPrinters] = useState<Partial<Printer>[]>([]);

  // Printers
  const [printers, setPrinters] = useState<Printer[]>([]);
  const [editingPrinter, setEditingPrinter] = useState<number | null>(null);
  const [newPrinter, setNewPrinter] = useState<Partial<Printer>>({
    protocol: 'IPP',
    port: 631,
    duplex: true,
    color: true,
    paperSize: 'A4',
    location: '',
    driver: 'auto',
  });

  // Groups
  const [printerGroups, setPrinterGroups] = useState<PrinterGroup[]>([]);
  const [newGroupName, setNewGroupName] = useState('');

  // User Assignments
  const [assignments, setAssignments] = useState<PrinterUserAssignment[]>([]);
  const [userGroups] = useState(['Administratoren', 'Benutzer', 'Gäste', 'IT-Abteilung', 'Management']);

  // Deploy
  const [deployPlatform, setDeployPlatform] = useState<'windows' | 'macos' | 'linux'>('windows');

  useEffect(() => {
    loadExistingPrinters();
  }, []);

  const loadExistingPrinters = async () => {
    try {
      const res = await printerApi.getPrinters();
      const existing = (res.data?.printers || []).map((p: any) => ({
        id: p.id,
        name: p.name || '',
        address: p.address || p.ip || '',
        port: p.port || 631,
        protocol: p.protocol || 'IPP',
        location: p.location || '',
        driver: p.driver || 'auto',
        duplex: p.duplex !== false,
        color: p.color !== false,
        paperSize: p.paperSize || 'A4',
        group: '',
      }));
      if (existing.length > 0) setPrinters(existing);
    } catch {
      // OK — wizard starts fresh
    }
  };

  const handleDiscovery = async () => {
    setDiscovering(true);
    try {
      const res = await printerApi.discoverPrinters();
      const found = res.data?.printers || res.data?.discovered || [];
      setDiscoveredPrinters(found);
      toast.success(`${found.length} Drucker gefunden`);
    } catch (error) {
      toast.error(`Discovery fehlgeschlagen: ${formatError(error)}`);
    } finally {
      setDiscovering(false);
    }
  };

  const addDiscoveredPrinter = (dp: Partial<Printer>) => {
    const printer: Printer = {
      name: dp.name || dp.address || 'Unbekannter Drucker',
      address: dp.address || '',
      port: dp.port || 631,
      protocol: dp.protocol || 'IPP',
      location: dp.location || '',
      driver: dp.driver || 'auto',
      duplex: dp.duplex !== false,
      color: dp.color !== false,
      paperSize: dp.paperSize || 'A4',
    };
    setPrinters(prev => [...prev, printer]);
    setDiscoveredPrinters(prev => prev.filter(p => p.address !== dp.address));
  };

  const addManualPrinter = () => {
    if (!newPrinter.name || !newPrinter.address) {
      toast.error('Name und IP-Adresse sind erforderlich');
      return;
    }
    const printer: Printer = {
      name: newPrinter.name!,
      address: newPrinter.address!,
      port: newPrinter.port || 631,
      protocol: (newPrinter.protocol as Printer['protocol']) || 'IPP',
      location: newPrinter.location || '',
      driver: newPrinter.driver || 'auto',
      duplex: newPrinter.duplex !== false,
      color: newPrinter.color !== false,
      paperSize: newPrinter.paperSize || 'A4',
    };
    setPrinters(prev => [...prev, printer]);
    setNewPrinter({
      protocol: 'IPP', port: 631, duplex: true, color: true, paperSize: 'A4', location: '', driver: 'auto',
    });
  };

  const removePrinter = (index: number) => {
    setPrinters(prev => prev.filter((_, i) => i !== index));
  };

  const updatePrinter = (index: number, updates: Partial<Printer>) => {
    setPrinters(prev => prev.map((p, i) => i === index ? { ...p, ...updates } : p));
  };

  const addPrinterGroup = () => {
    if (!newGroupName.trim()) return;
    if (printerGroups.some(g => g.name === newGroupName)) {
      toast.error('Gruppe existiert bereits');
      return;
    }
    setPrinterGroups(prev => [...prev, { name: newGroupName, printers: [] }]);
    setNewGroupName('');
  };

  const togglePrinterInGroup = (groupIndex: number, printerName: string) => {
    setPrinterGroups(prev => prev.map((g, i) => {
      if (i !== groupIndex) return g;
      const has = g.printers.includes(printerName);
      return { ...g, printers: has ? g.printers.filter(p => p !== printerName) : [...g.printers, printerName] };
    }));
  };

  const removePrinterGroup = (index: number) => {
    setPrinterGroups(prev => prev.filter((_, i) => i !== index));
  };

  const toggleAssignment = (userGroup: string, printerGroup: string) => {
    setAssignments(prev => {
      const existing = prev.find(a => a.groupName === userGroup);
      if (existing) {
        const has = existing.printerGroups.includes(printerGroup);
        return prev.map(a =>
          a.groupName === userGroup
            ? { ...a, printerGroups: has ? a.printerGroups.filter(pg => pg !== printerGroup) : [...a.printerGroups, printerGroup] }
            : a
        );
      }
      return [...prev, { groupName: userGroup, printerGroups: [printerGroup], quota: 0 }];
    });
  };

  const updateQuota = (userGroup: string, quota: number) => {
    setAssignments(prev => {
      const existing = prev.find(a => a.groupName === userGroup);
      if (existing) {
        return prev.map(a => a.groupName === userGroup ? { ...a, quota } : a);
      }
      return [...prev, { groupName: userGroup, printerGroups: [], quota }];
    });
  };

  const getAssignment = (userGroup: string) => assignments.find(a => a.groupName === userGroup);

  const getDeployScript = () => {
    const printerList = printers.map(p => `${p.name} (${p.address}:${p.port})`).join(', ');
    if (deployPlatform === 'windows') {
      return printers.map(p =>
        `# ${p.name}\nAdd-Printer -Name "${p.name}" -PortName "${p.protocol}_${p.address}" -DriverName "${p.driver === 'auto' ? 'Microsoft IPP Class Driver' : p.driver}"\nAdd-PrinterPort -Name "${p.protocol}_${p.address}" -PrinterHostAddress "${p.address}" -PortNumber ${p.port}`
      ).join('\n\n');
    } else if (deployPlatform === 'macos') {
      return printers.map(p =>
        `# ${p.name}\nlpadmin -p "${p.name}" -E -v "${p.protocol.toLowerCase()}://${p.address}:${p.port}/ipp/print" -L "${p.location}" -D "${p.name}" -m everywhere`
      ).join('\n\n');
    } else {
      return printers.map(p =>
        `# ${p.name}\nsudo lpadmin -p "${p.name}" -E -v "${p.protocol.toLowerCase()}://${p.address}:${p.port}/ipp/print" -L "${p.location}" -D "${p.name}" -m everywhere\nsudo cupsenable "${p.name}"\nsudo cupsaccept "${p.name}"`
      ).join('\n\n');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('In die Zwischenablage kopiert');
  };

  const handleDeploy = async () => {
    setSaving(true);
    try {
      for (const printer of printers) {
        await printerApi.addPrinter({
          name: printer.name,
          address: printer.address,
          port: printer.port,
          protocol: printer.protocol,
          location: printer.location,
          driver: printer.driver,
          capabilities: {
            duplex: printer.duplex,
            color: printer.color,
            paperSize: printer.paperSize,
          },
        }).catch(() => {});
      }
      toast.success(`${printers.length} Drucker bereitgestellt!`);
      onClose();
    } catch (error) {
      toast.error(`Fehler: ${formatError(error)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <WizardLayout
      title="Drucker-Setup"
      subtitle="Drucker finden, konfigurieren und bereitstellen"
      icon={<PrinterIcon className="h-8 w-8" />}
      color="orange"
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onClose}
      onComplete={handleDeploy}
      saving={saving}
      completeLabel="Drucker bereitstellen"
      savingLabel="Bereitstellen..."
    >
          {/* Step 1: Finden */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center py-4">
                <div className="w-16 h-16 bg-orange-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <PrinterIcon className="h-8 w-8 text-orange-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-2">Drucker finden</h3>
                <p className="text-gray-500 max-w-md mx-auto">
                  Suche automatisch nach Druckern im Netzwerk oder füge sie manuell hinzu.
                </p>
              </div>

              {/* Auto Discovery */}
              <div className="bg-orange-50 border border-orange-200 rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <SignalIcon className="h-5 w-5 text-orange-600 mr-3" />
                    <div>
                      <h4 className="text-sm font-medium text-orange-900">Auto-Discovery</h4>
                      <p className="text-xs text-orange-700">Sucht per mDNS/SNMP nach Druckern im lokalen Netzwerk</p>
                    </div>
                  </div>
                  <button
                    onClick={handleDiscovery}
                    disabled={discovering}
                    className="flex items-center px-4 py-2 bg-orange-600 text-white rounded-lg text-sm font-medium hover:bg-orange-700 disabled:opacity-50 transition-colors"
                  >
                    {discovering ? (
                      <>
                        <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Suche...
                      </>
                    ) : (
                      <>
                        <MagnifyingGlassIcon className="h-4 w-4 mr-2" />
                        Netzwerk scannen
                      </>
                    )}
                  </button>
                </div>

                {discoveredPrinters.length > 0 && (
                  <div className="mt-4 space-y-2">
                    {discoveredPrinters.map((dp, i) => (
                      <div key={i} className="flex items-center justify-between bg-white rounded-lg px-4 py-3">
                        <div>
                          <span className="font-medium text-gray-900 text-sm">{dp.name || dp.address}</span>
                          <span className="text-gray-500 text-sm ml-2">{dp.address}:{dp.port || 631}</span>
                        </div>
                        <button
                          onClick={() => addDiscoveredPrinter(dp)}
                          className="flex items-center px-3 py-1.5 bg-green-600 text-white rounded-lg text-xs font-medium hover:bg-green-700 transition-colors"
                        >
                          <PlusIcon className="h-3 w-3 mr-1" />
                          Übernehmen
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Manual add */}
              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Manuell hinzufügen</h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <input
                    type="text"
                    placeholder="Drucker-Name"
                    value={newPrinter.name || ''}
                    onChange={(e) => setNewPrinter({ ...newPrinter, name: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  />
                  <input
                    type="text"
                    placeholder="IP-Adresse (z.B. 192.168.1.50)"
                    value={newPrinter.address || ''}
                    onChange={(e) => setNewPrinter({ ...newPrinter, address: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  />
                  <select
                    value={newPrinter.protocol}
                    onChange={(e) => {
                      const proto = PROTOCOLS.find(p => p.value === e.target.value);
                      setNewPrinter({ ...newPrinter, protocol: e.target.value as any, port: proto?.port || 631 });
                    }}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  >
                    {PROTOCOLS.map(p => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>
                <button
                  onClick={addManualPrinter}
                  className="mt-3 flex items-center px-4 py-2 bg-orange-600 text-white rounded-lg text-sm font-medium hover:bg-orange-700 transition-colors"
                >
                  <PlusIcon className="h-4 w-4 mr-1" />
                  Drucker hinzufügen
                </button>
              </div>

              {/* Added printers */}
              {printers.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Drucker ({printers.length})</h4>
                  <div className="space-y-2">
                    {printers.map((p, index) => (
                      <div key={index} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3">
                        <div className="flex items-center">
                          <PrinterIcon className="h-4 w-4 text-orange-500 mr-3" />
                          <div>
                            <span className="font-medium text-gray-900 text-sm">{p.name}</span>
                            <span className="text-gray-500 text-sm ml-2">{p.address}:{p.port}</span>
                            <span className="ml-2 px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded">{p.protocol}</span>
                          </div>
                        </div>
                        <button onClick={() => removePrinter(index)} className="text-red-500 hover:text-red-700">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Konfigurieren */}
          {step === 2 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Drucker konfigurieren</h3>
                <p className="text-sm text-gray-500">Konfiguriere Standort, Treiber und Standardeinstellungen für jeden Drucker.</p>
              </div>

              {printers.length > 0 ? (
                <div className="space-y-4">
                  {printers.map((printer, index) => (
                    <div key={index} className="bg-white border border-gray-200 rounded-xl p-5">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center">
                          <PrinterIcon className="h-5 w-5 text-orange-500 mr-2" />
                          <h4 className="font-medium text-gray-900">{printer.name}</h4>
                          <span className="text-gray-500 text-sm ml-2">{printer.address}</span>
                        </div>
                        <button
                          onClick={() => setEditingPrinter(editingPrinter === index ? null : index)}
                          className="text-sm text-blue-600 hover:text-blue-800"
                        >
                          {editingPrinter === index ? 'Schließen' : 'Bearbeiten'}
                        </button>
                      </div>

                      {editingPrinter === index ? (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-3 border-t border-gray-100">
                          <div>
                            <label className="block text-xs text-gray-500 mb-1">Name</label>
                            <input
                              type="text"
                              value={printer.name}
                              onChange={(e) => updatePrinter(index, { name: e.target.value })}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-gray-500 mb-1">Standort</label>
                            <input
                              type="text"
                              value={printer.location}
                              placeholder="z.B. Büro EG, Flur 2. OG"
                              onChange={(e) => updatePrinter(index, { location: e.target.value })}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-gray-500 mb-1">Treiber</label>
                            <input
                              type="text"
                              value={printer.driver}
                              placeholder="auto"
                              onChange={(e) => updatePrinter(index, { driver: e.target.value })}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-gray-500 mb-1">Papierformat</label>
                            <select
                              value={printer.paperSize}
                              onChange={(e) => updatePrinter(index, { paperSize: e.target.value })}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500"
                            >
                              {PAPER_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
                            </select>
                          </div>
                          <div className="flex items-center space-x-6 col-span-2">
                            <label className="flex items-center space-x-2">
                              <input
                                type="checkbox"
                                checked={printer.duplex}
                                onChange={(e) => updatePrinter(index, { duplex: e.target.checked })}
                                className="rounded border-gray-300 text-orange-600 focus:ring-orange-500"
                              />
                              <span className="text-sm text-gray-700">Duplex (beidseitig)</span>
                            </label>
                            <label className="flex items-center space-x-2">
                              <input
                                type="checkbox"
                                checked={printer.color}
                                onChange={(e) => updatePrinter(index, { color: e.target.checked })}
                                className="rounded border-gray-300 text-orange-600 focus:ring-orange-500"
                              />
                              <span className="text-sm text-gray-700">Farbe</span>
                            </label>
                          </div>
                        </div>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          {printer.location && (
                            <span className="flex items-center px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded">
                              <MapPinIcon className="h-3 w-3 mr-1" />{printer.location}
                            </span>
                          )}
                          <span className="px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded">{printer.protocol}</span>
                          <span className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded">{printer.paperSize}</span>
                          {printer.duplex && <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded">Duplex</span>}
                          {printer.color && <span className="px-2 py-0.5 text-xs bg-green-100 text-green-700 rounded">Farbe</span>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Keine Drucker hinzugefügt. Gehe zurück und füge Drucker hinzu.
                </div>
              )}
            </div>
          )}

          {/* Step 3: Gruppen */}
          {step === 3 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Drucker-Gruppen</h3>
                <p className="text-sm text-gray-500">Organisiere Drucker in logische Gruppen (z.B. nach Standort oder Abteilung).</p>
              </div>

              <div className="bg-gray-50 rounded-xl p-5">
                <div className="flex items-center space-x-3">
                  <input
                    type="text"
                    placeholder="Gruppenname (z.B. Büro EG)"
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  />
                  <button
                    onClick={addPrinterGroup}
                    className="flex items-center px-4 py-2 bg-orange-600 text-white rounded-lg text-sm font-medium hover:bg-orange-700 transition-colors"
                  >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Gruppe erstellen
                  </button>
                </div>
              </div>

              {printerGroups.length > 0 ? (
                <div className="space-y-4">
                  {printerGroups.map((group, gi) => (
                    <div key={gi} className="bg-white border border-gray-200 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="font-medium text-gray-900 text-sm">{group.name}</h4>
                        <button onClick={() => removePrinterGroup(gi)} className="text-red-500 hover:text-red-700">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {printers.map(p => {
                          const inGroup = group.printers.includes(p.name);
                          return (
                            <button
                              key={p.name}
                              onClick={() => togglePrinterInGroup(gi, p.name)}
                              className={`flex items-center px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${
                                inGroup
                                  ? 'bg-orange-100 text-orange-800 border border-orange-300'
                                  : 'bg-gray-100 text-gray-600 border border-gray-200 hover:bg-gray-200'
                              }`}
                            >
                              <PrinterIcon className="h-3 w-3 mr-1" />
                              {inGroup && <span className="mr-1">✓</span>}
                              {p.name}
                            </button>
                          );
                        })}
                      </div>
                      {group.printers.length === 0 && (
                        <p className="text-xs text-gray-400 mt-1">Klicke auf Drucker um sie dieser Gruppe zuzuweisen.</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Noch keine Drucker-Gruppen. Optional — du kannst diesen Schritt überspringen.
                </div>
              )}
            </div>
          )}

          {/* Step 4: Benutzer-Zuordnung */}
          {step === 4 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Benutzer-Zuordnung</h3>
                <p className="text-sm text-gray-500">Definiere welche Benutzergruppen welche Drucker nutzen dürfen und setze Kontingente.</p>
              </div>

              {printerGroups.length > 0 ? (
                <div className="space-y-4">
                  {userGroups.map(ug => {
                    const assignment = getAssignment(ug);
                    return (
                      <div key={ug} className="bg-white border border-gray-200 rounded-xl p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center">
                            <UserGroupIcon className="h-4 w-4 text-indigo-500 mr-2" />
                            <h4 className="font-medium text-gray-900 text-sm">{ug}</h4>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-xs text-gray-500">Kontingent:</span>
                            <input
                              type="number"
                              min={0}
                              value={assignment?.quota || 0}
                              onChange={(e) => updateQuota(ug, parseInt(e.target.value) || 0)}
                              className="w-20 px-2 py-1 border border-gray-300 rounded text-sm text-center"
                            />
                            <span className="text-xs text-gray-400">Seiten/Monat (0 = unbegrenzt)</span>
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {printerGroups.map(pg => {
                            const active = assignment?.printerGroups.includes(pg.name);
                            return (
                              <button
                                key={pg.name}
                                onClick={() => toggleAssignment(ug, pg.name)}
                                className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${
                                  active
                                    ? 'bg-green-100 text-green-800 border border-green-300'
                                    : 'bg-gray-100 text-gray-600 border border-gray-200 hover:bg-gray-200'
                                }`}
                              >
                                {active && <span className="mr-1">✓</span>}
                                {pg.name} ({pg.printers.length} Drucker)
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Keine Drucker-Gruppen vorhanden. Erstelle im vorherigen Schritt Gruppen oder überspringe diesen Schritt.
                </div>
              )}
            </div>
          )}

          {/* Step 5: Deploy */}
          {step === 5 && (
            <div className="space-y-6">
              <div className="text-center py-2">
                <div className="w-16 h-16 bg-green-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <RocketLaunchIcon className="h-8 w-8 text-green-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900">Bereitstellung</h3>
                <p className="text-gray-500 text-sm mt-1">{printers.length} Drucker bereit zum Deployment</p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-orange-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-orange-900">{printers.length}</p>
                  <p className="text-xs text-orange-600">Drucker</p>
                </div>
                <div className="bg-blue-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-blue-900">{printerGroups.length}</p>
                  <p className="text-xs text-blue-600">Gruppen</p>
                </div>
                <div className="bg-green-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-green-900">{assignments.filter(a => a.printerGroups.length > 0).length}</p>
                  <p className="text-xs text-green-600">Zuordnungen</p>
                </div>
              </div>

              {/* Platform scripts */}
              {printers.length > 0 && (
                <div className="bg-gray-50 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-medium text-gray-900">Deployment-Script</h4>
                    <div className="flex space-x-1">
                      {(['windows', 'macos', 'linux'] as const).map(p => (
                        <button
                          key={p}
                          onClick={() => setDeployPlatform(p)}
                          className={`px-3 py-1 text-xs rounded-lg font-medium transition-colors ${
                            deployPlatform === p
                              ? 'bg-orange-600 text-white'
                              : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-100'
                          }`}
                        >
                          {p === 'windows' ? 'Windows' : p === 'macos' ? 'macOS' : 'Linux'}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="relative">
                    <pre className="bg-gray-900 text-green-400 rounded-lg p-4 text-xs overflow-x-auto max-h-48">
                      {getDeployScript()}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(getDeployScript())}
                      className="absolute top-2 right-2 p-1.5 bg-gray-700 rounded-md text-gray-300 hover:text-white hover:bg-gray-600 transition-colors"
                    >
                      <ClipboardDocumentIcon className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              )}

              {/* Printer summary */}
              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-700 mb-2">Drucker-Übersicht</h4>
                <div className="space-y-2">
                  {printers.map((p, i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <div className="flex items-center">
                        <PrinterIcon className="h-4 w-4 text-orange-500 mr-2" />
                        <span className="font-medium text-gray-900">{p.name}</span>
                        {p.location && <span className="text-gray-500 ml-2">({p.location})</span>}
                      </div>
                      <div className="flex gap-1">
                        <span className="px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded">{p.protocol}</span>
                        {p.color && <span className="px-2 py-0.5 text-xs bg-green-100 text-green-700 rounded">Farbe</span>}
                        {p.duplex && <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded">Duplex</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
    </WizardLayout>
  );
}
