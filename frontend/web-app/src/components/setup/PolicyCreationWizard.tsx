'use client';

import React, { useState, useEffect } from 'react';
import {
  DocumentCheckIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  UserGroupIcon,
  CheckIcon,
  LockClosedIcon,
  FireIcon,
  KeyIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline';
import { policyApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';
import WizardLayout from '@/components/shared/WizardLayout';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface PolicyCreationWizardProps {
  onClose: () => void;
}

interface PolicyTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  icon: string;
  defaults: Record<string, any>;
}

interface AssignmentTarget {
  id: string;
  name: string;
  type: 'domain' | 'ou' | 'group' | 'device';
}

const STEPS = [
  { n: 1 as const, label: 'Template' },
  { n: 2 as const, label: 'Konfiguration' },
  { n: 3 as const, label: 'Plattformen' },
  { n: 4 as const, label: 'Zuweisung' },
  { n: 5 as const, label: 'Aktivieren' },
];

const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'password', name: 'Passwort-Richtlinie', category: 'Security',
    description: 'Passwort-Komplexität, Alter, Historie und Sperrung',
    icon: 'key',
    defaults: { minLength: 12, maxAge: 90, history: 24, requireUppercase: true, requireLowercase: true, requireDigit: true, requireSymbol: true, lockoutAttempts: 5, lockoutDuration: 30 },
  },
  {
    id: 'screenlock', name: 'Bildschirmsperre', category: 'Security',
    description: 'Automatische Sperre nach Inaktivität',
    icon: 'lock',
    defaults: { timeout: 15, requirePassword: true, maxInactivity: 30 },
  },
  {
    id: 'firewall', name: 'Firewall-Regeln', category: 'Network',
    description: 'Ein-/Ausgehende Verbindungen, Ports, Protokolle',
    icon: 'fire',
    defaults: { defaultInbound: 'deny', defaultOutbound: 'allow', allowICMP: true, allowDHCP: true, allowDNS: true },
  },
  {
    id: 'encryption', name: 'Festplatten-Verschlüsselung', category: 'Security',
    description: 'BitLocker / FileVault / LUKS erzwingen',
    icon: 'shield',
    defaults: { enforce: true, algorithm: 'AES-256', recoveryKeyEscrow: true },
  },
  {
    id: 'software', name: 'Software-Einschränkung', category: 'Software',
    description: 'Erlaubte/Blockierte Anwendungen verwalten',
    icon: 'globe',
    defaults: { mode: 'blacklist', blockedApps: [], allowedApps: [] },
  },
  {
    id: 'update', name: 'Update-Richtlinie', category: 'Compliance',
    description: 'Windows Update / macOS Update Einstellungen',
    icon: 'shield',
    defaults: { autoInstall: true, deferDays: 7, maintenanceWindow: '02:00-06:00', restartPolicy: 'scheduled' },
  },
];

const DEFAULT_TARGETS: AssignmentTarget[] = [
  { id: 'domain-all', name: 'Gesamte Domain', type: 'domain' },
  { id: 'ou-it', name: 'IT-Abteilung', type: 'ou' },
  { id: 'ou-dev', name: 'Entwicklung', type: 'ou' },
  { id: 'ou-hr', name: 'Personalabteilung', type: 'ou' },
  { id: 'group-admins', name: 'Administratoren', type: 'group' },
  { id: 'group-users', name: 'Standard-Benutzer', type: 'group' },
  { id: 'group-servers', name: 'Server', type: 'group' },
];

const TEMPLATE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  key: KeyIcon,
  lock: LockClosedIcon,
  fire: FireIcon,
  shield: ShieldCheckIcon,
  globe: GlobeAltIcon,
};

export default function PolicyCreationWizard({ onClose }: PolicyCreationWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);

  // Template
  const [selectedTemplate, setSelectedTemplate] = useState<PolicyTemplate | null>(null);

  // Config
  const [policyName, setPolicyName] = useState('');
  const [settings, setSettings] = useState<Record<string, any>>({});

  // Platforms
  const [platforms, setPlatforms] = useState({ windows: true, macos: true, linux: true });

  // Assignment
  const [targets] = useState<AssignmentTarget[]>(DEFAULT_TARGETS);
  const [selectedTargets, setSelectedTargets] = useState<string[]>(['group-users']);
  const [priority, setPriority] = useState(100);

  // Activate
  const [activateImmediately, setActivateImmediately] = useState(true);

  const selectTemplate = (tpl: PolicyTemplate) => {
    setSelectedTemplate(tpl);
    setPolicyName(tpl.name);
    setSettings({ ...tpl.defaults });
  };

  const updateSetting = (key: string, value: any) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const togglePlatform = (p: 'windows' | 'macos' | 'linux') => {
    setPlatforms(prev => ({ ...prev, [p]: !prev[p] }));
  };

  const toggleTarget = (id: string) => {
    setSelectedTargets(prev =>
      prev.includes(id) ? prev.filter(t => t !== id) : [...prev, id]
    );
  };

  const selectedPlatforms = Object.entries(platforms).filter(([, v]) => v).map(([k]) => k);

  const handleComplete = async () => {
    setSaving(true);
    try {
      const result = await policyApi.createFromTemplate({
        templateId: selectedTemplate?.id,
        name: policyName,
        category: selectedTemplate?.category,
        settings,
        platforms: selectedPlatforms,
        priority,
      });

      const policyId = result.data?.id || result.data?.data?.id;

      if (policyId) {
        // Assign to targets
        for (const tid of selectedTargets) {
          const target = targets.find(t => t.id === tid);
          if (target) {
            await policyApi.linkPolicy(policyId, {
              targetType: target.type,
              targetId: tid,
              targetName: target.name,
            }).catch(() => {});
          }
        }
        // Activate if requested
        if (activateImmediately) {
          await policyApi.activatePolicy(policyId).catch(() => {});
        }
      }

      toast.success('Policy erstellt und zugewiesen!');
      onClose();
    } catch {
      if (typeof window !== 'undefined') {
        localStorage.setItem('od_policy_created', JSON.stringify({
          template: selectedTemplate?.id,
          name: policyName,
          settings,
          platforms: selectedPlatforms,
          targets: selectedTargets,
          priority,
          activateImmediately,
          completedAt: new Date().toISOString(),
        }));
      }
      toast.success('Policy-Konfiguration gespeichert!');
      onClose();
    }
  };

  // Render config fields dynamically based on selected template
  const renderConfigFields = () => {
    if (!selectedTemplate) return null;

    switch (selectedTemplate.id) {
      case 'password':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Mindestlänge</label>
                <input type="number" min={6} max={128} value={settings.minLength || 12} onChange={e => updateSetting('minLength', Number(e.target.value))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Max. Alter (Tage)</label>
                <input type="number" min={0} max={365} value={settings.maxAge || 90} onChange={e => updateSetting('maxAge', Number(e.target.value))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Passwort-Historie</label>
                <input type="number" min={0} max={50} value={settings.history || 24} onChange={e => updateSetting('history', Number(e.target.value))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Sperrversuche</label>
                <input type="number" min={1} max={20} value={settings.lockoutAttempts || 5} onChange={e => updateSetting('lockoutAttempts', Number(e.target.value))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500" />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Komplexitätsanforderungen</label>
              <div className="grid grid-cols-2 gap-2">
                {([
                  ['requireUppercase', 'Grossbuchstaben'],
                  ['requireLowercase', 'Kleinbuchstaben'],
                  ['requireDigit', 'Zahlen'],
                  ['requireSymbol', 'Sonderzeichen'],
                ] as const).map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => updateSetting(key, !settings[key])}
                    className={`text-left px-3 py-2 rounded-lg border text-sm transition-all ${settings[key] ? 'border-amber-500 bg-amber-50 text-amber-800' : 'border-gray-200 text-gray-600'}`}
                  >
                    {settings[key] ? <CheckIcon className="h-3.5 w-3.5 inline mr-1" /> : null}
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        );

      case 'screenlock':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Sperre nach (Minuten)</label>
              <div className="flex gap-3">
                {[5, 10, 15, 30, 60].map(m => (
                  <button
                    key={m}
                    onClick={() => updateSetting('timeout', m)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${settings.timeout === m ? 'bg-amber-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'}`}
                  >
                    {m} min
                  </button>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
              <div>
                <p className="font-semibold text-gray-900">Passwort bei Entsperrung</p>
                <p className="text-sm text-gray-500">Passwort/PIN zum Entsperren erforderlich</p>
              </div>
              <button
                onClick={() => updateSetting('requirePassword', !settings.requirePassword)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${settings.requirePassword ? 'bg-amber-600' : 'bg-gray-300'}`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.requirePassword ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          </div>
        );

      case 'firewall':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Eingehend (Default)</label>
                <select value={settings.defaultInbound || 'deny'} onChange={e => updateSetting('defaultInbound', e.target.value)} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                  <option value="deny">Blockieren</option>
                  <option value="allow">Erlauben</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Ausgehend (Default)</label>
                <select value={settings.defaultOutbound || 'allow'} onChange={e => updateSetting('defaultOutbound', e.target.value)} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                  <option value="allow">Erlauben</option>
                  <option value="deny">Blockieren</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Erlaubte Protokolle</label>
              <div className="grid grid-cols-3 gap-2">
                {([['allowICMP', 'ICMP (Ping)'], ['allowDHCP', 'DHCP'], ['allowDNS', 'DNS']] as const).map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => updateSetting(key, !settings[key])}
                    className={`px-3 py-2 rounded-lg border text-sm transition-all ${settings[key] ? 'border-amber-500 bg-amber-50' : 'border-gray-200'}`}
                  >
                    {settings[key] ? <CheckIcon className="h-3.5 w-3.5 inline mr-1" /> : null}
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        );

      case 'encryption':
        return (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
              <div>
                <p className="font-semibold text-gray-900">Verschlüsselung erzwingen</p>
                <p className="text-sm text-gray-500">BitLocker / FileVault / LUKS auf allen Geräten</p>
              </div>
              <button
                onClick={() => updateSetting('enforce', !settings.enforce)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${settings.enforce ? 'bg-amber-600' : 'bg-gray-300'}`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.enforce ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Algorithmus</label>
              <select value={settings.algorithm || 'AES-256'} onChange={e => updateSetting('algorithm', e.target.value)} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                <option value="AES-128">AES-128</option>
                <option value="AES-256">AES-256</option>
                <option value="XTS-AES-256">XTS-AES-256</option>
              </select>
            </div>
            <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
              <div>
                <p className="font-semibold text-gray-900">Recovery-Key Escrow</p>
                <p className="text-sm text-gray-500">Wiederherstellungsschlüssel zentral speichern</p>
              </div>
              <button
                onClick={() => updateSetting('recoveryKeyEscrow', !settings.recoveryKeyEscrow)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${settings.recoveryKeyEscrow ? 'bg-amber-600' : 'bg-gray-300'}`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.recoveryKeyEscrow ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          </div>
        );

      case 'update':
        return (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
              <div>
                <p className="font-semibold text-gray-900">Automatische Installation</p>
                <p className="text-sm text-gray-500">Updates automatisch installieren</p>
              </div>
              <button
                onClick={() => updateSetting('autoInstall', !settings.autoInstall)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${settings.autoInstall ? 'bg-amber-600' : 'bg-gray-300'}`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.autoInstall ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Verzögerung (Tage)</label>
                <input type="number" min={0} max={30} value={settings.deferDays || 7} onChange={e => updateSetting('deferDays', Number(e.target.value))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Wartungsfenster</label>
                <input type="text" value={settings.maintenanceWindow || '02:00-06:00'} onChange={e => updateSetting('maintenanceWindow', e.target.value)} placeholder="02:00-06:00" className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500" />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Neustart-Verhalten</label>
              <select value={settings.restartPolicy || 'scheduled'} onChange={e => updateSetting('restartPolicy', e.target.value)} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                <option value="immediate">Sofort</option>
                <option value="scheduled">Geplant (im Wartungsfenster)</option>
                <option value="user-choice">Benutzer entscheidet</option>
                <option value="never">Nie automatisch</option>
              </select>
            </div>
          </div>
        );

      default: // software
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Modus</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => updateSetting('mode', 'blacklist')}
                  className={`text-left p-3 rounded-lg border-2 transition-all ${settings.mode === 'blacklist' ? 'border-amber-500 bg-amber-50' : 'border-gray-200'}`}
                >
                  <p className="font-medium text-sm text-gray-900">Blacklist</p>
                  <p className="text-xs text-gray-500">Bestimmte Apps blockieren</p>
                </button>
                <button
                  onClick={() => updateSetting('mode', 'whitelist')}
                  className={`text-left p-3 rounded-lg border-2 transition-all ${settings.mode === 'whitelist' ? 'border-amber-500 bg-amber-50' : 'border-gray-200'}`}
                >
                  <p className="font-medium text-sm text-gray-900">Whitelist</p>
                  <p className="text-xs text-gray-500">Nur bestimmte Apps erlauben</p>
                </button>
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <WizardLayout
      title="Policy-Erstellung"
      subtitle="Richtlinien erstellen, konfigurieren und zuweisen"
      icon={<DocumentCheckIcon className="h-8 w-8" />}
      color="amber"
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onClose}
      onComplete={handleComplete}
      saving={saving}
      completeLabel={activateImmediately ? 'Policy erstellen & aktivieren' : 'Policy erstellen'}
      savingLabel="Erstellen..."
    >
          {/* Step 1: Template Selection */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Policy-Template wählen</h3>
                <p className="text-sm text-gray-500">Starten Sie mit einer vorgefertigten Vorlage.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {POLICY_TEMPLATES.map(tpl => {
                  const IconComp = TEMPLATE_ICONS[tpl.icon] || ShieldCheckIcon;
                  return (
                    <button
                      key={tpl.id}
                      onClick={() => selectTemplate(tpl)}
                      className={`text-left p-4 rounded-xl border-2 transition-all ${
                        selectedTemplate?.id === tpl.id ? 'border-amber-500 bg-amber-50' : 'border-gray-200 hover:border-gray-300'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${selectedTemplate?.id === tpl.id ? 'bg-amber-200' : 'bg-gray-100'}`}>
                          <IconComp className={`h-5 w-5 ${selectedTemplate?.id === tpl.id ? 'text-amber-700' : 'text-gray-500'}`} />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{tpl.name}</p>
                          <p className="text-xs text-gray-500 mt-0.5">{tpl.description}</p>
                          <span className="inline-block mt-1 text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full">{tpl.category}</span>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Step 2: Configuration */}
          {step === 2 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Konfiguration</h3>
                <p className="text-sm text-gray-500">Einstellungen für: {selectedTemplate?.name || '–'}</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Policy-Name</label>
                <input
                  type="text"
                  value={policyName}
                  onChange={e => setPolicyName(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500"
                />
              </div>

              {renderConfigFields()}
            </div>
          )}

          {/* Step 3: Platforms */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Ziel-Plattformen</h3>
                <p className="text-sm text-gray-500">Auf welchen Betriebssystemen soll die Policy gelten?</p>
              </div>

              <div className="grid grid-cols-3 gap-4">
                {([
                  ['windows', 'Windows', 'Windows 10/11 und Server'],
                  ['macos', 'macOS', 'macOS Ventura und neuer'],
                  ['linux', 'Linux', 'Ubuntu, Debian, RHEL etc.'],
                ] as const).map(([key, label, desc]) => (
                  <button
                    key={key}
                    onClick={() => togglePlatform(key)}
                    className={`text-left p-4 rounded-xl border-2 transition-all ${
                      platforms[key] ? 'border-amber-500 bg-amber-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <ComputerDesktopIcon className={`h-8 w-8 mb-2 ${platforms[key] ? 'text-amber-600' : 'text-gray-400'}`} />
                    <p className="font-medium text-gray-900">{label}</p>
                    <p className="text-xs text-gray-500">{desc}</p>
                    {platforms[key] && <CheckIcon className="h-5 w-5 text-amber-600 mt-2" />}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 4: Assignment */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Zuweisung</h3>
                <p className="text-sm text-gray-500">An wen soll die Policy zugewiesen werden?</p>
              </div>

              <div className="space-y-2">
                {targets.map(target => (
                  <button
                    key={target.id}
                    onClick={() => toggleTarget(target.id)}
                    className={`w-full text-left flex items-center justify-between bg-white border rounded-lg px-4 py-3 transition-all ${
                      selectedTargets.includes(target.id) ? 'border-amber-500 bg-amber-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                        target.type === 'domain' ? 'bg-blue-100' : target.type === 'ou' ? 'bg-green-100' : target.type === 'group' ? 'bg-purple-100' : 'bg-gray-100'
                      }`}>
                        {target.type === 'domain' || target.type === 'ou' ? (
                          <ComputerDesktopIcon className={`h-4 w-4 ${target.type === 'domain' ? 'text-blue-600' : 'text-green-600'}`} />
                        ) : target.type === 'group' ? (
                          <UserGroupIcon className="h-4 w-4 text-purple-600" />
                        ) : (
                          <ComputerDesktopIcon className="h-4 w-4 text-gray-600" />
                        )}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">{target.name}</p>
                        <p className="text-xs text-gray-500 capitalize">{target.type}</p>
                      </div>
                    </div>
                    {selectedTargets.includes(target.id) && <CheckIcon className="h-5 w-5 text-amber-600" />}
                  </button>
                ))}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Priorität (höher = stärker)</label>
                <input
                  type="number"
                  min={1}
                  max={999}
                  value={priority}
                  onChange={e => setPriority(Number(e.target.value))}
                  className="w-32 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-amber-500 focus:border-amber-500"
                />
              </div>
            </div>
          )}

          {/* Step 5: Review & Activate */}
          {step === 5 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Review & Aktivieren</h3>
                <p className="text-sm text-gray-500">Überprüfen Sie die Policy-Konfiguration.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                  <DocumentCheckIcon className="h-6 w-6 text-amber-600 mb-2" />
                  <p className="font-semibold text-gray-900">{policyName}</p>
                  <p className="text-sm text-gray-600">{selectedTemplate?.category}</p>
                </div>
                <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                  <ComputerDesktopIcon className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-semibold text-gray-900">Plattformen</p>
                  <p className="text-sm text-gray-600">{selectedPlatforms.join(', ')}</p>
                </div>
                <div className="bg-purple-50 border border-purple-200 rounded-xl p-4">
                  <UserGroupIcon className="h-6 w-6 text-purple-600 mb-2" />
                  <p className="font-semibold text-gray-900">Zuweisungen</p>
                  <p className="text-sm text-gray-600">{selectedTargets.length} Ziel(e), Prio {priority}</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                <h4 className="font-semibold text-gray-900 mb-2">Einstellungen</h4>
                <div className="space-y-1">
                  {Object.entries(settings).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between text-sm py-1">
                      <span className="text-gray-500">{key}</span>
                      <span className="text-gray-900 font-medium">{String(value)}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
                <div>
                  <p className="font-semibold text-gray-900">Sofort aktivieren</p>
                  <p className="text-sm text-gray-500">Policy nach Erstellung direkt anwenden</p>
                </div>
                <button
                  onClick={() => setActivateImmediately(!activateImmediately)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${activateImmediately ? 'bg-amber-600' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${activateImmediately ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>
            </div>
          )}
    </WizardLayout>
  );
}
