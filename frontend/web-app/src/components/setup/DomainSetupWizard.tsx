'use client';

import React, { useState, useEffect } from 'react';
import {
  ServerStackIcon,
  KeyIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import WizardLayout from '@/components/shared/WizardLayout';
import toast from 'react-hot-toast';

const SAMBA_URL = process.env.NEXT_PUBLIC_SAMBA_URL || 'http://samba-ad-dc:3010';

// ─── Types ────────────────────────────────────────────────────────────────────

type DnsBackend = 'SAMBA_INTERNAL' | 'BIND9_FLATFILE' | 'BIND9_DLZ';
type JoinPlatform = 'Linux' | 'macOS' | 'Windows';

interface ProvisionForm {
  realm: string;
  domain: string;
  adminPassword: string;
  adminPasswordConfirm: string;
  dnsBackend: DnsBackend;
}

interface DomainInfo {
  realm: string;
  domain: string;
  provisioned: boolean;
  provisionedAt?: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function passwordStrength(pw: string): { score: number; label: string; color: string } {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const levels = [
    { label: 'Zu kurz',    color: 'bg-red-500' },
    { label: 'Schwach',    color: 'bg-red-400' },
    { label: 'Mittel',     color: 'bg-amber-400' },
    { label: 'Gut',        color: 'bg-blue-500' },
    { label: 'Stark',      color: 'bg-green-500' },
    { label: 'Sehr stark', color: 'bg-green-600' },
  ];
  return { score, ...levels[Math.min(score, 5)] };
}

function joinScript(platform: JoinPlatform, realm: string): string {
  const domain = realm.toLowerCase();
  switch (platform) {
    case 'Windows':
      return `# PowerShell (als Administrator ausführen):\nAdd-Computer -DomainName "${realm}" -Credential (Get-Credential) -Restart`;
    case 'macOS':
      return `# Terminal (macOS 13+):\ndsconfigad -add ${domain} -username Administrator -password ""`;
    case 'Linux':
      return `# Ubuntu / Debian:\nsudo apt install -y realmd sssd sssd-tools adcli\nsudo realm join -U Administrator ${domain}`;
  }
}

// ─── Copy Button ──────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };
  return (
    <button onClick={copy} className="flex items-center gap-1 px-2 py-1 text-xs text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors">
      {copied ? <><CheckIcon className="w-3 h-3" />Kopiert</> : <><ClipboardDocumentIcon className="w-3 h-3" />Kopieren</>}
    </button>
  );
}

// ─── Step 1: Domain ───────────────────────────────────────────────────────────

function StepDomain({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  const handleRealm = (v: string) => {
    const realm = v.toUpperCase();
    const domain = realm.split('.')[0].slice(0, 15);
    onChange({ realm, domain });
  };

  const DNS_OPTIONS: { value: DnsBackend; label: string; desc: string }[] = [
    { value: 'SAMBA_INTERNAL', label: 'Samba Internal DNS', desc: 'Empfohlen — kein separater DNS-Server nötig' },
    { value: 'BIND9_FLATFILE', label: 'BIND9 Flat-File',    desc: 'BIND9 mit statischen Zonen-Dateien' },
    { value: 'BIND9_DLZ',      label: 'BIND9 DLZ',          desc: 'BIND9 liest Zonen direkt aus Samba AD' },
  ];

  return (
    <div className="space-y-6">
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
        <GlobeAltIcon className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-blue-800">
          <p className="font-medium mb-1">Was ist ein AD-Realm?</p>
          <p>Der Realm ist der vollqualifizierte Domainname (FQDN) deiner Active-Directory-Domain — z.B. <code className="bg-blue-100 px-1 rounded">CORP.LOCAL</code> oder <code className="bg-blue-100 px-1 rounded">FIRMA.INTERN</code>. Er muss in Grossbuchstaben angegeben werden.</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">AD Realm (FQDN) <span className="text-red-500">*</span></label>
          <input
            type="text"
            value={form.realm}
            onChange={e => handleRealm(e.target.value)}
            placeholder="CORP.LOCAL"
            className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 uppercase"
          />
          <p className="text-xs text-gray-500">Grossbuchstaben, z.B. CORP.LOCAL</p>
        </div>

        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">NetBIOS-Name <span className="text-red-500">*</span></label>
          <input
            type="text"
            value={form.domain}
            onChange={e => onChange({ domain: e.target.value.toUpperCase().slice(0, 15) })}
            placeholder="CORP"
            className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 uppercase"
          />
          <p className="text-xs text-gray-500">Max. 15 Zeichen, nur Buchstaben/Zahlen</p>
        </div>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">DNS-Backend</label>
        <div className="space-y-2">
          {DNS_OPTIONS.map(opt => (
            <label key={opt.value} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${form.dnsBackend === opt.value ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}>
              <input
                type="radio"
                name="dnsBackend"
                value={opt.value}
                checked={form.dnsBackend === opt.value}
                onChange={() => onChange({ dnsBackend: opt.value })}
                className="mt-0.5 text-blue-600"
              />
              <div>
                <div className="text-sm font-medium text-gray-900">{opt.label}</div>
                <div className="text-xs text-gray-500">{opt.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Step 2: Admin Password ───────────────────────────────────────────────────

function StepAdmin({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  const [show, setShow] = useState(false);
  const strength = passwordStrength(form.adminPassword);
  const match = form.adminPassword && form.adminPasswordConfirm && form.adminPassword === form.adminPasswordConfirm;
  const mismatch = form.adminPasswordConfirm && form.adminPassword !== form.adminPasswordConfirm;

  return (
    <div className="space-y-6">
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3">
        <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-amber-800">
          <p className="font-medium mb-1">Wichtig: Administrator-Passwort</p>
          <p>Das Domain-Admin-Passwort wird benötigt um Clients der Domain hinzuzufügen, Gruppenrichtlinien anzuwenden und LAPS zu verwalten. Bitte sicher aufbewahren.</p>
        </div>
      </div>

      <div className="max-w-sm space-y-4">
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">Administrator-Passwort <span className="text-red-500">*</span></label>
          <div className="relative">
            <input
              type={show ? 'text' : 'password'}
              value={form.adminPassword}
              onChange={e => onChange({ adminPassword: e.target.value })}
              placeholder="••••••••••••"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button type="button" onClick={() => setShow(s => !s)} className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600 text-xs">
              {show ? 'Verbergen' : 'Zeigen'}
            </button>
          </div>

          {/* Strength bar */}
          {form.adminPassword && (
            <div className="space-y-1">
              <div className="flex gap-1">
                {[0,1,2,3,4].map(i => (
                  <div key={i} className={`h-1.5 flex-1 rounded-full transition-colors ${i < strength.score ? strength.color : 'bg-gray-200'}`} />
                ))}
              </div>
              <p className="text-xs text-gray-500">Stärke: <span className="font-medium">{strength.label}</span></p>
            </div>
          )}
        </div>

        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">Passwort bestätigen <span className="text-red-500">*</span></label>
          <input
            type={show ? 'text' : 'password'}
            value={form.adminPasswordConfirm}
            onChange={e => onChange({ adminPasswordConfirm: e.target.value })}
            placeholder="••••••••••••"
            className={`w-full border rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 ${mismatch ? 'border-red-400 focus:ring-red-400' : match ? 'border-green-400 focus:ring-green-400' : 'border-gray-300 focus:ring-blue-500'}`}
          />
          {mismatch && <p className="text-xs text-red-600">Passwörter stimmen nicht überein</p>}
          {match    && <p className="text-xs text-green-600 flex items-center gap-1"><CheckIcon className="w-3 h-3" />Passwörter stimmen überein</p>}
        </div>
      </div>

      <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 text-sm text-gray-600 space-y-1">
        <p className="font-medium text-gray-700 mb-2">Passwort-Anforderungen (Windows AD-Kompatibilität):</p>
        {[
          [form.adminPassword.length >= 8,    'Mindestens 8 Zeichen'],
          [/[A-Z]/.test(form.adminPassword),  'Grossbuchstaben (A–Z)'],
          [/[a-z]/.test(form.adminPassword),  'Kleinbuchstaben (a–z)'],
          [/[0-9]/.test(form.adminPassword),  'Ziffern (0–9)'],
          [/[^A-Za-z0-9]/.test(form.adminPassword), 'Sonderzeichen (!@#$...)'],
        ].map(([ok, label], i) => (
          <p key={i} className="flex items-center gap-2">
            <span className={ok ? 'text-green-600' : 'text-gray-400'}>
              {ok ? '✓' : '○'}
            </span>
            <span className={ok ? 'text-gray-800' : 'text-gray-400'}>{label as string}</span>
          </p>
        ))}
      </div>
    </div>
  );
}

// ─── Step 3: Review ───────────────────────────────────────────────────────────

function StepReview({ form }: { form: ProvisionForm }) {
  const checks = [
    'Samba AD DC Dienst läuft',
    'Kerberos KDC wird konfiguriert',
    `DNS-Backend: ${form.dnsBackend}`,
    'SYSVOL / NETLOGON Shares werden erstellt',
    'SAM Datenbank wird initialisiert',
    `Forest-Level: Windows 2008 R2 (kompatibel mit allen Clients)`,
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2"><GlobeAltIcon className="w-4 h-4 text-blue-600" />Domain</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-gray-500">Realm (FQDN)</span><code className="font-mono text-gray-900">{form.realm || '—'}</code></div>
            <div className="flex justify-between"><span className="text-gray-500">NetBIOS-Name</span><code className="font-mono text-gray-900">{form.domain || '—'}</code></div>
            <div className="flex justify-between"><span className="text-gray-500">DNS-Backend</span><span className="text-gray-900">{form.dnsBackend}</span></div>
          </div>
        </div>

        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2"><KeyIcon className="w-4 h-4 text-blue-600" />Administrator</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-gray-500">Konto</span><code className="font-mono text-gray-900">Administrator</code></div>
            <div className="flex justify-between"><span className="text-gray-500">Passwort</span><span className="text-gray-900">{'•'.repeat(Math.min(form.adminPassword.length, 12))}</span></div>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700">Was wird eingerichtet:</h3>
        <div className="space-y-1.5">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-sm text-gray-600">
              <div className="w-4 h-4 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                <span className="text-blue-600 text-xs font-bold">{i + 1}</span>
              </div>
              {c}
            </div>
          ))}
        </div>
      </div>

      {(!form.realm || !form.domain || !form.adminPassword) && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-3 flex items-center gap-2 text-sm text-red-700">
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" />
          Bitte alle Pflichtfelder ausfüllen (Realm, NetBIOS-Name, Passwort).
        </div>
      )}
    </div>
  );
}

// ─── Step 4: Provisioning ─────────────────────────────────────────────────────

function StepProvision({ realm, success, error, log }: { realm: string; success: boolean; error: string | null; log: string[] }) {
  const [joinPlatform, setJoinPlatform] = useState<JoinPlatform>('Linux');

  if (success) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 p-4 bg-green-50 border border-green-200 rounded-xl">
          <div className="w-10 h-10 rounded-full bg-green-100 flex items-center justify-center flex-shrink-0">
            <CheckIcon className="w-6 h-6 text-green-600" />
          </div>
          <div>
            <p className="font-semibold text-green-800">Domain erfolgreich eingerichtet!</p>
            <p className="text-sm text-green-700"><code className="font-mono">{realm}</code> ist einsatzbereit.</p>
          </div>
        </div>

        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2">
            <ComputerDesktopIcon className="w-4 h-4 text-blue-600" />
            Clients der Domain hinzufügen
          </h3>
          <div className="flex gap-2">
            {(['Linux', 'macOS', 'Windows'] as JoinPlatform[]).map(p => (
              <button
                key={p}
                onClick={() => setJoinPlatform(p)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${joinPlatform === p ? 'bg-blue-600 text-white border-blue-600' : 'bg-white text-gray-600 border-gray-300 hover:border-gray-400'}`}
              >
                {p}
              </button>
            ))}
          </div>
          <div className="relative">
            <pre className="bg-gray-900 text-green-400 rounded-xl p-4 text-xs font-mono whitespace-pre-wrap overflow-x-auto">
              {joinScript(joinPlatform, realm)}
            </pre>
            <div className="absolute top-2 right-2">
              <CopyBtn text={joinScript(joinPlatform, realm)} />
            </div>
          </div>
          <p className="text-xs text-gray-500">Domain-Admin-Konto: <code className="font-mono">Administrator@{realm.toLowerCase()}</code></p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {error ? (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex gap-3">
          <ExclamationTriangleIcon className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-red-800 mb-1">Fehler beim Einrichten</p>
            <p className="text-sm text-red-700 font-mono">{error}</p>
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-3 p-4 bg-blue-50 border border-blue-200 rounded-xl">
          <svg className="animate-spin w-5 h-5 text-blue-600 flex-shrink-0" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <p className="text-sm text-blue-800 font-medium">Domain wird eingerichtet — bitte warten…</p>
        </div>
      )}

      {log.length > 0 && (
        <div className="bg-gray-900 rounded-xl p-4 max-h-48 overflow-y-auto">
          {log.map((line, i) => (
            <p key={i} className="text-xs font-mono text-green-400 leading-relaxed">{line}</p>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Wizard ──────────────────────────────────────────────────────────────

export interface DomainSetupWizardProps {
  onClose: () => void;
  onProvisioned?: (info: DomainInfo) => void;
}

const STEPS = [
  { n: 1, label: 'Domain' },
  { n: 2, label: 'Admin' },
  { n: 3, label: 'Prüfen' },
  { n: 4, label: 'Einrichten' },
];

const BLANK: ProvisionForm = {
  realm:               '',
  domain:              '',
  adminPassword:       '',
  adminPasswordConfirm:'',
  dnsBackend:          'SAMBA_INTERNAL',
};

export default function DomainSetupWizard({ onClose, onProvisioned }: DomainSetupWizardProps) {
  const [step,    setStep]    = useState(1);
  const [form,    setForm]    = useState<ProvisionForm>(BLANK);
  const [saving,  setSaving]  = useState(false);
  const [success, setSuccess] = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  const [log,     setLog]     = useState<string[]>([]);

  const patch = (f: Partial<ProvisionForm>) => setForm(prev => ({ ...prev, ...f }));

  const canAdvance = (s: number) => {
    if (s === 1) return !!(form.realm.trim() && form.domain.trim());
    if (s === 2) return !!(form.adminPassword && form.adminPassword === form.adminPasswordConfirm && form.adminPassword.length >= 8);
    if (s === 3) return !!(form.realm && form.domain && form.adminPassword);
    return true;
  };

  const handleStepChange = (next: number) => {
    if (next > step && !canAdvance(step)) {
      toast.error('Bitte alle Pflichtfelder ausfüllen.');
      return;
    }
    setStep(next);
  };

  const provision = async () => {
    setSaving(true);
    setError(null);
    setLog([]);
    setStep(4);

    const steps = [
      `Verbindung zu Samba AD DC (${SAMBA_URL})…`,
      `Realm: ${form.realm} / NetBIOS: ${form.domain}`,
      `DNS-Backend: ${form.dnsBackend}`,
      'Initialisiere SAM-Datenbank…',
      'Konfiguriere Kerberos KDC…',
      'Erstelle SYSVOL / NETLOGON Shares…',
      'Wende Forest-Einstellungen an…',
    ];

    // Simulate log output while waiting for API
    let i = 0;
    const ticker = setInterval(() => {
      if (i < steps.length) setLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${steps[i++]}`]);
    }, 600);

    try {
      const res = await fetch(`${SAMBA_URL}/api/samba/domain/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          realm:        form.realm.toUpperCase(),
          domain:       form.domain.toUpperCase(),
          adminPassword:form.adminPassword,
          dnsBackend:   form.dnsBackend,
        }),
      });
      clearInterval(ticker);
      const data = await res.json();

      if (!res.ok) {
        setError(data.error || `Fehler ${res.status}`);
        setSaving(false);
        return;
      }

      setLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ✓ Domain erfolgreich eingerichtet!`]);
      setSuccess(true);
      setSaving(false);
      onProvisioned?.({ realm: form.realm, domain: form.domain, provisioned: true });
      toast.success(`Domain ${form.realm} eingerichtet!`);
    } catch (err: any) {
      clearInterval(ticker);
      setError(err.message || 'Netzwerkfehler — ist der Samba-Service erreichbar?');
      setSaving(false);
    }
  };

  return (
    <WizardLayout
      title="Domain einrichten"
      subtitle="Active Directory Domain Controller mit Samba AD"
      icon={<ServerStackIcon className="h-7 w-7" />}
      color="blue"
      steps={STEPS}
      currentStep={step}
      onStepChange={handleStepChange}
      onClose={onClose}
      onComplete={step < 3 ? () => handleStepChange(step + 1) : provision}
      saving={saving}
      completeLabel={step === 3 ? 'Domain einrichten' : 'Weiter'}
      savingLabel="Wird eingerichtet…"
      maxWidth="max-w-2xl"
    >
      {step === 1 && <StepDomain form={form} onChange={patch} />}
      {step === 2 && <StepAdmin  form={form} onChange={patch} />}
      {step === 3 && <StepReview form={form} />}
      {step === 4 && <StepProvision realm={form.realm} success={success} error={error} log={log} />}
    </WizardLayout>
  );
}
