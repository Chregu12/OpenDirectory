'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  UserGroupIcon,
  UsersIcon,
  UserPlusIcon,
  ShieldCheckIcon,
  CheckIcon,
  XMarkIcon,
  PlusIcon,
  TrashIcon,
  ArrowUpTrayIcon,
  DocumentArrowUpIcon,
  KeyIcon,
} from '@heroicons/react/24/outline';
import { lldapApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';
import WizardLayout from '@/components/shared/WizardLayout';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface UserManagementWizardProps {
  onClose: () => void;
}

interface NewUser {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  groups: string[];
}

interface NewGroup {
  name: string;
  description: string;
}

interface GroupTemplate {
  name: string;
  description: string;
  icon: string;
}

interface ServicePermission {
  groupName: string;
  services: string[];
}

const GROUP_TEMPLATES: GroupTemplate[] = [
  { name: 'Administratoren', description: 'Voller Zugriff auf alle Systeme', icon: '🔑' },
  { name: 'Benutzer', description: 'Standard-Zugriff', icon: '👤' },
  { name: 'Gäste', description: 'Eingeschränkter Zugriff', icon: '👋' },
  { name: 'IT-Abteilung', description: 'Zugriff auf IT-Infrastruktur', icon: '💻' },
  { name: 'Management', description: 'Zugriff auf Reports und Dashboards', icon: '📊' },
  { name: 'Extern', description: 'Temporärer externer Zugriff', icon: '🌐' },
];

const AVAILABLE_SERVICES = [
  'Dashboard', 'Geräte-Management', 'Netzwerk', 'Drucker', 'File Shares',
  'Monitoring', 'Policies', 'Security Scanner', 'App Store',
];

const STEPS = [
  { n: 1 as const, label: 'Übersicht' },
  { n: 2 as const, label: 'Gruppen' },
  { n: 3 as const, label: 'Benutzer' },
  { n: 4 as const, label: 'Berechtigungen' },
  { n: 5 as const, label: 'Fertig' },
];

const generatePassword = () => {
  const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%';
  return Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
};

export default function UserManagementWizard({ onClose }: UserManagementWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Stats
  const [stats, setStats] = useState({ total: 0, active: 0, groups: 0 });
  const [existingGroups, setExistingGroups] = useState<string[]>([]);

  // New Groups
  const [newGroups, setNewGroups] = useState<NewGroup[]>([]);
  const [newGroupInput, setNewGroupInput] = useState<NewGroup>({ name: '', description: '' });

  // New Users
  const [newUsers, setNewUsers] = useState<NewUser[]>([]);
  const [newUserInput, setNewUserInput] = useState<NewUser>({
    firstName: '', lastName: '', email: '', password: '', groups: [],
  });
  const [csvPreview, setCsvPreview] = useState<string[][]>([]);
  const [showCsvImport, setShowCsvImport] = useState(false);

  // Permissions
  const [permissions, setPermissions] = useState<ServicePermission[]>([]);

  useEffect(() => {
    loadExistingData();
  }, []);

  const loadExistingData = async () => {
    try {
      const [statsRes, groupsRes] = await Promise.all([
        lldapApi.getStats().catch(() => ({ data: { statistics: { total: 0, active: 0, groups: 0 } } })),
        lldapApi.getGroups().catch(() => ({ data: { groups: [] } })),
      ]);
      setStats(statsRes.data?.statistics || { total: 0, active: 0, groups: 0 });
      const groups = (groupsRes.data?.groups || []).map((g: any) => g.displayName || g.name);
      setExistingGroups(groups);
    } catch {
      // Wizard can still be used
    }
  };

  const allGroupNames = [...existingGroups, ...newGroups.map(g => g.name)];

  const addGroupFromTemplate = (template: GroupTemplate) => {
    if (allGroupNames.includes(template.name)) {
      toast.error(`Gruppe "${template.name}" existiert bereits`);
      return;
    }
    setNewGroups(prev => [...prev, { name: template.name, description: template.description }]);
  };

  const addCustomGroup = () => {
    if (!newGroupInput.name.trim()) {
      toast.error('Gruppenname ist erforderlich');
      return;
    }
    if (allGroupNames.includes(newGroupInput.name)) {
      toast.error(`Gruppe "${newGroupInput.name}" existiert bereits`);
      return;
    }
    setNewGroups(prev => [...prev, { ...newGroupInput }]);
    setNewGroupInput({ name: '', description: '' });
  };

  const removeGroup = (index: number) => {
    setNewGroups(prev => prev.filter((_, i) => i !== index));
  };

  const addUser = () => {
    if (!newUserInput.firstName || !newUserInput.email) {
      toast.error('Vorname und E-Mail sind erforderlich');
      return;
    }
    if (newUsers.some(u => u.email === newUserInput.email)) {
      toast.error('E-Mail-Adresse bereits vergeben');
      return;
    }
    const password = newUserInput.password || generatePassword();
    setNewUsers(prev => [...prev, { ...newUserInput, password }]);
    setNewUserInput({ firstName: '', lastName: '', email: '', password: '', groups: [] });
  };

  const removeUser = (index: number) => {
    setNewUsers(prev => prev.filter((_, i) => i !== index));
  };

  const toggleUserGroup = (group: string) => {
    setNewUserInput(prev => ({
      ...prev,
      groups: prev.groups.includes(group)
        ? prev.groups.filter(g => g !== group)
        : [...prev.groups, group],
    }));
  };

  const handleCsvFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      const lines = text.split('\n').filter(l => l.trim());
      const rows = lines.map(l => l.split(/[,;]/).map(c => c.trim().replace(/^"|"$/g, '')));
      setCsvPreview(rows);
      setShowCsvImport(true);
    };
    reader.readAsText(file);
  };

  const importCsvUsers = () => {
    // Assume first row is header: Vorname, Nachname, E-Mail, Gruppe(n)
    const [, ...dataRows] = csvPreview;
    const imported: NewUser[] = dataRows
      .filter(row => row.length >= 3 && row[2].includes('@'))
      .map(row => ({
        firstName: row[0] || '',
        lastName: row[1] || '',
        email: row[2] || '',
        password: generatePassword(),
        groups: row[3] ? row[3].split('|').map(g => g.trim()) : [],
      }));

    setNewUsers(prev => [...prev, ...imported]);
    setCsvPreview([]);
    setShowCsvImport(false);
    toast.success(`${imported.length} Benutzer importiert`);
  };

  const toggleServicePermission = (groupName: string, service: string) => {
    setPermissions(prev => {
      const existing = prev.find(p => p.groupName === groupName);
      if (existing) {
        const hasService = existing.services.includes(service);
        return prev.map(p =>
          p.groupName === groupName
            ? { ...p, services: hasService ? p.services.filter(s => s !== service) : [...p.services, service] }
            : p
        );
      } else {
        return [...prev, { groupName, services: [service] }];
      }
    });
  };

  const getGroupServices = (groupName: string) => {
    return permissions.find(p => p.groupName === groupName)?.services || [];
  };

  const handleApply = async () => {
    setSaving(true);
    try {
      // Create groups
      for (const group of newGroups) {
        await fetch('/api/lldap/groups', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(group),
        }).catch(() => {});
      }
      // Create users
      for (const user of newUsers) {
        await fetch('/api/lldap/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: user.email,
            displayName: `${user.firstName} ${user.lastName}`.trim(),
            firstName: user.firstName,
            lastName: user.lastName,
            password: user.password,
            groups: user.groups,
          }),
        }).catch(() => {});
      }
      toast.success(`${newGroups.length} Gruppen und ${newUsers.length} Benutzer erstellt!`);
      onClose();
    } catch (error) {
      toast.error(`Fehler: ${formatError(error)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <WizardLayout
      title="Benutzer-Verwaltung"
      subtitle="Gruppen und Benutzer einrichten"
      icon={<UserGroupIcon className="h-8 w-8" />}
      color="indigo"
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onClose}
      onComplete={handleApply}
      saving={saving}
      completeLabel="Benutzer & Gruppen erstellen"
      savingLabel="Erstellen..."
    >
          {/* Step 1: Übersicht */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center py-4">
                <div className="w-16 h-16 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <UserGroupIcon className="h-8 w-8 text-indigo-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-2">Verzeichnis-Übersicht</h3>
                <p className="text-gray-500 max-w-md mx-auto">
                  Erstelle Gruppen und Benutzer für dein Verzeichnis (LLDAP).
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-blue-50 rounded-xl p-4 text-center">
                  <UsersIcon className="h-6 w-6 text-blue-600 mx-auto mb-1" />
                  <p className="text-xl font-bold text-blue-900">{stats.total}</p>
                  <p className="text-xs text-blue-600">Benutzer gesamt</p>
                </div>
                <div className="bg-green-50 rounded-xl p-4 text-center">
                  <UsersIcon className="h-6 w-6 text-green-600 mx-auto mb-1" />
                  <p className="text-xl font-bold text-green-900">{stats.active}</p>
                  <p className="text-xs text-green-600">Aktive Benutzer</p>
                </div>
                <div className="bg-purple-50 rounded-xl p-4 text-center">
                  <UserGroupIcon className="h-6 w-6 text-purple-600 mx-auto mb-1" />
                  <p className="text-xl font-bold text-purple-900">{stats.groups}</p>
                  <p className="text-xs text-purple-600">Gruppen</p>
                </div>
              </div>

              {existingGroups.length > 0 && (
                <div className="bg-gray-50 rounded-xl p-5">
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Vorhandene Gruppen</h4>
                  <div className="flex flex-wrap gap-2">
                    {existingGroups.map(g => (
                      <span key={g} className="px-2.5 py-1 text-xs bg-indigo-100 text-indigo-700 rounded-full font-medium">
                        {g}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Gruppen */}
          {step === 2 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Gruppen erstellen</h3>
                <p className="text-sm text-gray-500">Wähle aus Vorlagen oder erstelle eigene Gruppen.</p>
              </div>

              {/* Templates */}
              <div>
                <h4 className="text-sm font-medium text-gray-700 mb-2">Vorlagen</h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {GROUP_TEMPLATES.map(t => {
                    const exists = allGroupNames.includes(t.name);
                    return (
                      <button
                        key={t.name}
                        onClick={() => addGroupFromTemplate(t)}
                        disabled={exists}
                        className={`text-left rounded-xl border-2 p-3 transition-all ${
                          exists
                            ? 'border-green-300 bg-green-50 opacity-60'
                            : 'border-gray-200 bg-white hover:border-indigo-300 hover:bg-indigo-50'
                        }`}
                      >
                        <div className="flex items-center">
                          <span className="text-lg mr-2">{t.icon}</span>
                          <div>
                            <p className="text-sm font-medium text-gray-900">{t.name}</p>
                            <p className="text-xs text-gray-500">{t.description}</p>
                          </div>
                          {exists && <CheckIcon className="h-4 w-4 text-green-600 ml-auto" />}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Custom group */}
              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Eigene Gruppe</h4>
                <div className="flex items-center space-x-3">
                  <input
                    type="text"
                    placeholder="Gruppenname"
                    value={newGroupInput.name}
                    onChange={(e) => setNewGroupInput({ ...newGroupInput, name: e.target.value })}
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <input
                    type="text"
                    placeholder="Beschreibung"
                    value={newGroupInput.description}
                    onChange={(e) => setNewGroupInput({ ...newGroupInput, description: e.target.value })}
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <button
                    onClick={addCustomGroup}
                    className="flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors"
                  >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Hinzufügen
                  </button>
                </div>
              </div>

              {/* Created groups list */}
              {newGroups.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Neue Gruppen ({newGroups.length})</h4>
                  <div className="space-y-2">
                    {newGroups.map((g, index) => (
                      <div key={index} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3">
                        <div>
                          <span className="font-medium text-gray-900 text-sm">{g.name}</span>
                          {g.description && <span className="text-gray-500 text-sm ml-2">— {g.description}</span>}
                        </div>
                        <button onClick={() => removeGroup(index)} className="text-red-500 hover:text-red-700">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Benutzer */}
          {step === 3 && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-gray-900">Benutzer anlegen</h3>
                  <p className="text-sm text-gray-500">Einzeln hinzufügen oder per CSV importieren.</p>
                </div>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center px-3 py-2 border border-gray-300 rounded-lg text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  <DocumentArrowUpIcon className="h-4 w-4 mr-2" />
                  CSV importieren
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,.txt"
                  onChange={handleCsvFile}
                  className="hidden"
                />
              </div>

              {/* CSV Preview Modal */}
              {showCsvImport && csvPreview.length > 0 && (
                <div className="bg-orange-50 border border-orange-200 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-medium text-orange-900">CSV-Vorschau ({csvPreview.length - 1} Einträge)</h4>
                    <button onClick={() => setShowCsvImport(false)} className="text-orange-500 hover:text-orange-700">
                      <XMarkIcon className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="max-h-40 overflow-y-auto">
                    <table className="min-w-full text-sm">
                      <thead>
                        <tr>
                          {csvPreview[0]?.map((h, i) => (
                            <th key={i} className="px-2 py-1 text-left text-xs font-medium text-orange-700 uppercase">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {csvPreview.slice(1, 6).map((row, i) => (
                          <tr key={i}>
                            {row.map((cell, j) => (
                              <td key={j} className="px-2 py-1 text-gray-700">{cell}</td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {csvPreview.length > 6 && (
                      <p className="text-xs text-orange-500 mt-1">... und {csvPreview.length - 6} weitere</p>
                    )}
                  </div>
                  <button
                    onClick={importCsvUsers}
                    className="mt-3 flex items-center px-4 py-2 bg-orange-600 text-white rounded-lg text-sm font-medium hover:bg-orange-700 transition-colors"
                  >
                    <ArrowUpTrayIcon className="h-4 w-4 mr-1" />
                    {csvPreview.length - 1} Benutzer importieren
                  </button>
                </div>
              )}

              {/* Add user form */}
              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Neuer Benutzer</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <input
                    type="text"
                    placeholder="Vorname"
                    value={newUserInput.firstName}
                    onChange={(e) => setNewUserInput({ ...newUserInput, firstName: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <input
                    type="text"
                    placeholder="Nachname"
                    value={newUserInput.lastName}
                    onChange={(e) => setNewUserInput({ ...newUserInput, lastName: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <input
                    type="email"
                    placeholder="E-Mail"
                    value={newUserInput.email}
                    onChange={(e) => setNewUserInput({ ...newUserInput, email: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      placeholder="Passwort (leer = generiert)"
                      value={newUserInput.password}
                      onChange={(e) => setNewUserInput({ ...newUserInput, password: e.target.value })}
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                    <button
                      onClick={() => setNewUserInput({ ...newUserInput, password: generatePassword() })}
                      className="px-3 py-2 border border-gray-300 rounded-lg text-gray-500 hover:bg-gray-100 transition-colors"
                      title="Passwort generieren"
                    >
                      <KeyIcon className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Group assignment */}
                {allGroupNames.length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs text-gray-500 mb-2">Gruppen zuweisen:</p>
                    <div className="flex flex-wrap gap-2">
                      {allGroupNames.map(g => (
                        <button
                          key={g}
                          onClick={() => toggleUserGroup(g)}
                          className={`px-2.5 py-1 text-xs rounded-full font-medium transition-colors ${
                            newUserInput.groups.includes(g)
                              ? 'bg-indigo-600 text-white'
                              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                          }`}
                        >
                          {g}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  onClick={addUser}
                  className="mt-3 flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors"
                >
                  <UserPlusIcon className="h-4 w-4 mr-1" />
                  Benutzer hinzufügen
                </button>
              </div>

              {/* Users list */}
              {newUsers.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Neue Benutzer ({newUsers.length})</h4>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {newUsers.map((u, index) => (
                      <div key={index} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center">
                            <span className="font-medium text-gray-900 text-sm">{u.firstName} {u.lastName}</span>
                            <span className="text-gray-500 text-sm ml-2">{u.email}</span>
                          </div>
                          {u.groups.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {u.groups.map(g => (
                                <span key={g} className="px-2 py-0.5 text-xs bg-indigo-100 text-indigo-700 rounded-full">{g}</span>
                              ))}
                            </div>
                          )}
                        </div>
                        <button onClick={() => removeUser(index)} className="text-red-500 hover:text-red-700 ml-2">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Berechtigungen */}
          {step === 4 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Berechtigungen</h3>
                <p className="text-sm text-gray-500">Definiere welche Gruppen auf welche Services zugreifen dürfen.</p>
              </div>

              {allGroupNames.length > 0 ? (
                <div className="space-y-4">
                  {allGroupNames.map(groupName => (
                    <div key={groupName} className="bg-white border border-gray-200 rounded-xl p-4">
                      <div className="flex items-center mb-3">
                        <ShieldCheckIcon className="h-4 w-4 text-indigo-500 mr-2" />
                        <h4 className="font-medium text-gray-900 text-sm">{groupName}</h4>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {AVAILABLE_SERVICES.map(service => {
                          const active = getGroupServices(groupName).includes(service);
                          return (
                            <button
                              key={service}
                              onClick={() => toggleServicePermission(groupName, service)}
                              className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${
                                active
                                  ? 'bg-green-100 text-green-800 border border-green-300'
                                  : 'bg-gray-100 text-gray-600 border border-gray-200 hover:bg-gray-200'
                              }`}
                            >
                              {active && <span className="mr-1">✓</span>}
                              {service}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Keine Gruppen vorhanden. Gehe zurück und erstelle zuerst Gruppen.
                </div>
              )}
            </div>
          )}

          {/* Step 5: Zusammenfassung */}
          {step === 5 && (
            <div className="space-y-6">
              <div className="text-center py-2">
                <div className="w-16 h-16 bg-green-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <CheckIcon className="h-8 w-8 text-green-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900">Zusammenfassung</h3>
                <p className="text-gray-500 text-sm mt-1">Überprüfe die Benutzer-Konfiguration</p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-indigo-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-indigo-900">{newGroups.length}</p>
                  <p className="text-xs text-indigo-600">Neue Gruppen</p>
                </div>
                <div className="bg-blue-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-blue-900">{newUsers.length}</p>
                  <p className="text-xs text-blue-600">Neue Benutzer</p>
                </div>
                <div className="bg-green-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-green-900">{permissions.length}</p>
                  <p className="text-xs text-green-600">Berechtigungsregeln</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-5 space-y-4">
                {newGroups.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">Neue Gruppen</h4>
                    <div className="flex flex-wrap gap-2">
                      {newGroups.map((g, i) => (
                        <span key={i} className="px-2.5 py-1 text-xs bg-indigo-100 text-indigo-700 rounded-full font-medium">
                          {g.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {newUsers.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">Neue Benutzer</h4>
                    <div className="flex flex-wrap gap-2">
                      {newUsers.map((u, i) => (
                        <span key={i} className="px-2.5 py-1 text-xs bg-blue-100 text-blue-700 rounded-full font-medium">
                          {u.firstName} {u.lastName} ({u.email})
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {permissions.filter(p => p.services.length > 0).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">Berechtigungen</h4>
                    {permissions.filter(p => p.services.length > 0).map((p, i) => (
                      <div key={i} className="text-sm text-gray-600 mb-1">
                        <span className="font-medium">{p.groupName}:</span> {p.services.join(', ')}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {newGroups.length === 0 && newUsers.length === 0 && (
                <p className="text-center text-gray-400 text-sm">
                  Keine Änderungen. Gehe zurück um Gruppen und Benutzer anzulegen.
                </p>
              )}
            </div>
          )}
    </WizardLayout>
  );
}
