'use client';

import React, { useState } from 'react';
import {
  ServerStackIcon,
  KeyIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ComputerDesktopIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  SignalIcon,
  Cog6ToothIcon,
  UsersIcon,
} from '@heroicons/react/24/outline';
import WizardLayout from '@/components/shared/WizardLayout';
import toast from 'react-hot-toast';

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '').replace(/\/$/, '');

// ─── Types ────────────────────────────────────────────────────────────────────

type DnsBackend    = 'SAMBA_INTERNAL' | 'BIND9_FLATFILE' | 'BIND9_DLZ';
type ServerRole    = 'dc' | 'rodc' | 'standalone';
type FunctionLevel = '2000' | '2003' | '2008' | '2008_R2' | '2012' | '2012_R2' | '2016';
type JoinPlatform  = 'Linux' | 'macOS' | 'Windows';

interface ProvisionForm {
  // Step 1 — Domain & DC
  realm:       string;
  domain:      string;
  dcHostname:  string;
  dcIp:        string;
  exposedFqdn: string;
  // Step 2 — DNS
  dnsBackend:   DnsBackend;
  dnsInterface: string;
  dnsForwarders:string;
  // Step 3 — Optionen
  functionLevel:  FunctionLevel;
  enableLdaps:    boolean;
  enableRfc2307:  boolean;
  serverRole:     ServerRole;
  // Step 4 — Verwaltung
  usersEnabled:  boolean;
  groupsEnabled: boolean;
  // Step 5 — Admin
  adminPassword:       string;
  adminPasswordConfirm:string;
}

interface DomainInfo {
  realm: string; domain: string; provisioned: boolean; provisionedAt?: string;
}

// ─── Static data ──────────────────────────────────────────────────────────────

const FUNCTION_LEVELS: { value: FunctionLevel; label: string; compat: string }[] = [
  { value: '2016',    label: 'Windows Server 2016',         compat: 'Win 10+ / Server 2016+' },
  { value: '2012_R2', label: 'Windows Server 2012 R2',      compat: 'Win 8.1+ / Server 2012 R2+' },
  { value: '2012',    label: 'Windows Server 2012',         compat: 'Win 8+ / Server 2012+' },
  { value: '2008_R2', label: 'Windows Server 2008 R2 (Standard)', compat: 'Win Vista+ / Server 2008 R2+' },
  { value: '2008',    label: 'Windows Server 2008',         compat: 'Win Vista+ / Server 2008+' },
  { value: '2003',    label: 'Windows Server 2003',         compat: 'Win XP+ / Server 2003+' },
  { value: '2000',    label: 'Windows 2000',                compat: 'Win 2000+ (max. Kompatibilität)' },
];

const SERVER_ROLES: { value: ServerRole; label: string; desc: string }[] = [
  { value: 'dc',         label: 'Domain Controller (DC)',   desc: 'Vollständiger DC mit Read/Write-Zugriff auf das AD' },
  { value: 'rodc',       label: 'Read-Only DC (RODC)',      desc: 'Schreibgeschützter DC — ideal für Zweigstellen' },
  { value: 'standalone', label: 'Standalone-Server',        desc: 'Eigenständiger Server ohne Domain-Mitgliedschaft' },
];

const DNS_OPTIONS: { value: DnsBackend; label: string; desc: string }[] = [
  { value: 'SAMBA_INTERNAL', label: 'Samba Internal DNS', desc: 'Empfohlen — kein separater DNS-Server nötig' },
  { value: 'BIND9_FLATFILE', label: 'BIND9 Flat-File',    desc: 'BIND9 mit statischen Zonen-Dateien' },
  { value: 'BIND9_DLZ',      label: 'BIND9 DLZ',          desc: 'BIND9 liest Zonen direkt aus Samba AD' },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function passwordStrength(pw: string): { score: number; label: string; color: string } {
  let score = 0;
  if (pw.length >= 8)              score++;
  if (pw.length >= 12)             score++;
  if (/[A-Z]/.test(pw))           score++;
  if (/[0-9]/.test(pw))           score++;
  if (/[^A-Za-z0-9]/.test(pw))   score++;
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

// ─── Sub-components ───────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); }); }}
      className="flex items-center gap-1 px-2 py-1 text-xs text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors"
    >
      {copied
        ? <><CheckIcon className="w-3 h-3" />Kopiert</>
        : <><ClipboardDocumentIcon className="w-3 h-3" />Kopieren</>}
    </button>
  );
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${checked ? 'bg-blue-600' : 'bg-gray-300'}`}
    >
      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${checked ? 'translate-x-6' : 'translate-x-1'}`} />
    </button>
  );
}

// ─── Step 1: Domain & DC ──────────────────────────────────────────────────────

function StepDomain({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  const handleRealm = (v: string) => {
    const realm = v.toUpperCase();
    const domain = realm.split('.')[0].slice(0, 15);
    onChange({ realm, domain, exposedFqdn: form.exposedFqdn || realm.toLowerCase() });
  };

  return (
    <div className="space-y-5">
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
        <GlobeAltIcon className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-blue-800">
          Der AD-Realm ist der vollqualifizierte Domainname deiner Active-Directory-Domain — z.B.{' '}
          <code className="bg-blue-100 px-1 rounded">CORP.LOCAL</code>. Er muss in Grossbuchstaben angegeben werden.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">AD Realm (FQDN) <span className="text-red-500">*</span></label>
          <input
            type="text" value={form.realm}
            onChange={e => handleRealm(e.target.value)}
            placeholder="CORP.LOCAL"
            className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 uppercase"
          />
          <p className="text-xs text-gray-500">z.B. CORP.LOCAL oder FIRMA.INTERN</p>
        </div>
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">NetBIOS-Name <span className="text-red-500">*</span></label>
          <input
            type="text" value={form.domain}
            onChange={e => onChange({ domain: e.target.value.toUpperCase().slice(0, 15) })}
            placeholder="CORP"
            className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 uppercase"
          />
          <p className="text-xs text-gray-500">Max. 15 Zeichen (automatisch befüllt)</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">DC Hostname</label>
          <input
            type="text" value={form.dcHostname}
            onChange={e => onChange({ dcHostname: e.target.value })}
            placeholder="dc01"
            className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <p className="text-xs text-gray-500">Leer = Systemhostname verwenden</p>
        </div>
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">DC IP-Adresse</label>
          <input
            type="text" value={form.dcIp}
            onChange={e => onChange({ dcIp: e.target.value })}
            placeholder="192.168.1.10"
            className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <p className="text-xs text-gray-500">Leer = automatisch erkannt</p>
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="block text-sm font-medium text-gray-700">Öffentlicher FQDN (DNS-Name)</label>
        <input
          type="text" value={form.exposedFqdn}
          onChange={e => onChange({ exposedFqdn: e.target.value })}
          placeholder="corp.local"
          className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="text-xs text-gray-500">DNS-Name für externe Erreichbarkeit — wird automatisch aus dem Realm abgeleitet</p>
      </div>
    </div>
  );
}

// ─── Step 2: DNS ──────────────────────────────────────────────────────────────

function StepDns({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">DNS-Backend <span className="text-red-500">*</span></label>
        <div className="space-y-2">
          {DNS_OPTIONS.map(opt => (
            <label
              key={opt.value}
              className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${form.dnsBackend === opt.value ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}
            >
              <input type="radio" name="dnsBackend" value={opt.value} checked={form.dnsBackend === opt.value} onChange={() => onChange({ dnsBackend: opt.value })} className="mt-0.5 text-blue-600" />
              <div>
                <div className="text-sm font-medium text-gray-900">{opt.label}</div>
                <div className="text-xs text-gray-500">{opt.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="block text-sm font-medium text-gray-700">DNS-Schnittstellen</label>
        <input
          type="text" value={form.dnsInterface}
          onChange={e => onChange({ dnsInterface: e.target.value })}
          placeholder="lo eth0"
          className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="text-xs text-gray-500">Interfaces auf denen Samba-DNS lauscht (Leerzeichen-getrennt). Standard: <code className="bg-gray-100 px-1 rounded">lo eth0</code></p>
      </div>

      <div className="space-y-1.5">
        <label className="block text-sm font-medium text-gray-700">DNS-Forwarder</label>
        <input
          type="text" value={form.dnsForwarders}
          onChange={e => onChange({ dnsForwarders: e.target.value })}
          placeholder="8.8.8.8 8.8.4.4"
          className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="text-xs text-gray-500">IP-Adressen der übergeordneten DNS-Server (Leerzeichen-getrennt). Leer = kein Forwarding.</p>
      </div>
    </div>
  );
}

// ─── Step 3: Optionen ─────────────────────────────────────────────────────────

function StepOptions({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">Verwaltungsmodus (Server-Rolle)</label>
        <div className="space-y-2">
          {SERVER_ROLES.map(r => (
            <label
              key={r.value}
              className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${form.serverRole === r.value ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}
            >
              <input type="radio" name="serverRole" value={r.value} checked={form.serverRole === r.value} onChange={() => onChange({ serverRole: r.value })} className="mt-0.5 text-blue-600" />
              <div>
                <div className="text-sm font-medium text-gray-900">{r.label}</div>
                <div className="text-xs text-gray-500">{r.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="block text-sm font-medium text-gray-700">Funktionslevel (XP-Kompatibilität)</label>
        <select
          value={form.functionLevel}
          onChange={e => onChange({ functionLevel: e.target.value as FunctionLevel })}
          className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          {FUNCTION_LEVELS.map(l => (
            <option key={l.value} value={l.value}>{l.label} — {l.compat}</option>
          ))}
        </select>
        <p className="text-xs text-gray-500">Standard: 2008 R2. Für Windows XP-Kompatibilität «Windows Server 2003» oder «Windows 2000» wählen.</p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">Domain-Optionen</label>
        {([
          { key: 'enableLdaps',   label: 'LDAPS aktivieren (Zertifikat)', desc: 'TLS-verschlüsselte LDAP-Verbindungen (Port 636). Self-signed-Zertifikat wird automatisch erstellt.' },
          { key: 'enableRfc2307', label: 'RFC2307 Unix-Attribute',         desc: 'UID/GID-Attribute für Linux-Kompatibilität (NFS, PAM, SSSD).' },
        ] as const).map(opt => (
          <div key={opt.key} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200">
            <div>
              <div className="text-sm font-medium text-gray-900">{opt.label}</div>
              <div className="text-xs text-gray-500">{opt.desc}</div>
            </div>
            <Toggle checked={form[opt.key]} onChange={v => onChange({ [opt.key]: v })} />
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Step 4: Verwaltung ───────────────────────────────────────────────────────

function StepVerwaltung({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  return (
    <div className="space-y-6">
      <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 flex gap-3">
        <UsersIcon className="w-5 h-5 text-gray-600 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-gray-700">
          Lege fest, welche Verzeichnisse in der OpenDirectory-Oberfläche sichtbar sind. Diese Einstellungen beeinflussen nicht Samba selbst, sondern die Verwaltungsansicht.
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-gray-700">Verzeichnislisten</label>
        {([
          { key: 'usersEnabled',  label: 'Benutzerliste aktiviert',  desc: 'Domain-Benutzer in der Verwaltungsansicht anzeigen und verwalten.' },
          { key: 'groupsEnabled', label: 'Gruppenliste aktiviert',   desc: 'Domain-Gruppen in der Verwaltungsansicht anzeigen und verwalten.' },
        ] as const).map(opt => (
          <div key={opt.key} className="flex items-center justify-between p-4 bg-white rounded-xl border border-gray-200 shadow-sm">
            <div className="flex items-center gap-3">
              <UsersIcon className="w-5 h-5 text-blue-600" />
              <div>
                <div className="text-sm font-medium text-gray-900">{opt.label}</div>
                <div className="text-xs text-gray-500">{opt.desc}</div>
              </div>
            </div>
            <Toggle checked={form[opt.key]} onChange={v => onChange({ [opt.key]: v })} />
          </div>
        ))}
      </div>

      <div className="bg-blue-50 border border-blue-100 rounded-xl p-4 text-sm text-blue-700">
        <p className="font-medium mb-1">Automatischer Verwaltungsmodus</p>
        <p>OpenDirectory synchronisiert Benutzer und Gruppen automatisch aus der Samba-Domain. Änderungen im AD werden in der Verwaltungsansicht sofort reflektiert.</p>
      </div>
    </div>
  );
}

// ─── Step 5: Admin Password ───────────────────────────────────────────────────

function StepAdmin({ form, onChange }: { form: ProvisionForm; onChange: (f: Partial<ProvisionForm>) => void }) {
  const [show, setShow] = useState(false);
  const strength = passwordStrength(form.adminPassword);
  const match    = !!(form.adminPassword && form.adminPasswordConfirm && form.adminPassword === form.adminPasswordConfirm);
  const mismatch = !!(form.adminPasswordConfirm && form.adminPassword !== form.adminPasswordConfirm);

  return (
    <div className="space-y-6">
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3">
        <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-amber-800">
          <p className="font-medium mb-1">Wichtig: Administrator-Passwort</p>
          <p>Das Domain-Admin-Passwort wird benötigt um Clients der Domain hinzuzufügen und Gruppenrichtlinien anzuwenden. Bitte sicher aufbewahren.</p>
        </div>
      </div>

      <div className="max-w-sm space-y-4">
        <div className="space-y-1.5">
          <label className="block text-sm font-medium text-gray-700">Administrator-Passwort <span className="text-red-500">*</span></label>
          <div className="relative">
            <input
              type={show ? 'text' : 'password'} value={form.adminPassword}
              onChange={e => onChange({ adminPassword: e.target.value })}
              placeholder="••••••••••••"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 pr-20 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button type="button" onClick={() => setShow(s => !s)} className="absolute right-3 top-2.5 text-xs text-gray-400 hover:text-gray-600">
              {show ? 'Verbergen' : 'Zeigen'}
            </button>
          </div>
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
            type={show ? 'text' : 'password'} value={form.adminPasswordConfirm}
            onChange={e => onChange({ adminPasswordConfirm: e.target.value })}
            placeholder="••••••••••••"
            className={`w-full border rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 ${mismatch ? 'border-red-400 focus:ring-red-400' : match ? 'border-green-400 focus:ring-green-400' : 'border-gray-300 focus:ring-blue-500'}`}
          />
          {mismatch && <p className="text-xs text-red-600">Passwörter stimmen nicht überein</p>}
          {match    && <p className="text-xs text-green-600 flex items-center gap-1"><CheckIcon className="w-3 h-3" />Passwörter stimmen überein</p>}
        </div>
      </div>

      <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 text-sm text-gray-600 space-y-1">
        <p className="font-medium text-gray-700 mb-2">Passwort-Anforderungen:</p>
        {([
          [form.adminPassword.length >= 8,         'Mindestens 8 Zeichen'],
          [/[A-Z]/.test(form.adminPassword),        'Grossbuchstaben (A–Z)'],
          [/[a-z]/.test(form.adminPassword),        'Kleinbuchstaben (a–z)'],
          [/[0-9]/.test(form.adminPassword),        'Ziffern (0–9)'],
          [/[^A-Za-z0-9]/.test(form.adminPassword), 'Sonderzeichen (!@#$...)'],
        ] as [boolean, string][]).map(([ok, label], i) => (
          <p key={i} className="flex items-center gap-2">
            <span className={ok ? 'text-green-600' : 'text-gray-400'}>{ok ? '✓' : '○'}</span>
            <span className={ok ? 'text-gray-800' : 'text-gray-400'}>{label}</span>
          </p>
        ))}
      </div>
    </div>
  );
}

// ─── Step 6: Review ───────────────────────────────────────────────────────────

function StepReview({ form }: { form: ProvisionForm }) {
  const lvl  = FUNCTION_LEVELS.find(l => l.value === form.functionLevel);
  const role = SERVER_ROLES.find(r => r.value === form.serverRole);

  const ready = !!(form.realm && form.domain && form.adminPassword && form.adminPassword === form.adminPasswordConfirm);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2"><GlobeAltIcon className="w-4 h-4 text-blue-600" />Domain &amp; DC</h3>
          <div className="space-y-1.5 text-sm">
            <Row label="Realm"    value={form.realm}       />
            <Row label="NetBIOS"  value={form.domain}      />
            {form.dcHostname && <Row label="DC Hostname" value={form.dcHostname} mono />}
            {form.dcIp       && <Row label="DC IP"       value={form.dcIp}       mono />}
            {form.exposedFqdn && <Row label="DNS-Name"   value={form.exposedFqdn} mono />}
          </div>
        </div>

        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2"><SignalIcon className="w-4 h-4 text-blue-600" />DNS</h3>
          <div className="space-y-1.5 text-sm">
            <Row label="Backend"    value={form.dnsBackend} />
            <Row label="Interfaces" value={form.dnsInterface  || 'lo eth0'}  mono />
            <Row label="Forwarder"  value={form.dnsForwarders || '—'}         mono />
          </div>
        </div>

        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2"><Cog6ToothIcon className="w-4 h-4 text-blue-600" />Optionen</h3>
          <div className="space-y-1.5 text-sm">
            <Row label="Modus"         value={role?.label  || form.serverRole}   />
            <Row label="Funktionslevel" value={lvl?.label  || form.functionLevel} />
            <Row label="LDAPS"          value={form.enableLdaps   ? '✓ Aktiv' : 'Deaktiviert'} ok={form.enableLdaps}  />
            <Row label="RFC2307"        value={form.enableRfc2307 ? '✓ Aktiv' : 'Deaktiviert'} ok={form.enableRfc2307} />
          </div>
        </div>

        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-2"><KeyIcon className="w-4 h-4 text-blue-600" />Admin &amp; Verwaltung</h3>
          <div className="space-y-1.5 text-sm">
            <Row label="Konto"        value="Administrator" mono />
            <Row label="Passwort"     value={'•'.repeat(Math.min(form.adminPassword.length, 12))} />
            <Row label="Benutzerliste" value={form.usersEnabled  ? '✓ Aktiv' : 'Deaktiviert'} ok={form.usersEnabled}  />
            <Row label="Gruppenliste"  value={form.groupsEnabled ? '✓ Aktiv' : 'Deaktiviert'} ok={form.groupsEnabled} />
          </div>
        </div>
      </div>

      {!ready && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-3 flex items-center gap-2 text-sm text-red-700">
          <ExclamationTriangleIcon className="w-4 h-4 flex-shrink-0" />
          Bitte alle Pflichtfelder ausfüllen (Realm, NetBIOS-Name, übereinstimmende Passwörter).
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono, ok }: { label: string; value: string; mono?: boolean; ok?: boolean }) {
  const valClass = ok === true
    ? 'text-green-700 font-medium'
    : ok === false
    ? 'text-gray-400'
    : mono ? 'font-mono text-gray-900' : 'text-gray-900';
  return (
    <div className="flex justify-between gap-2 min-w-0">
      <span className="text-gray-500 shrink-0">{label}</span>
      <span className={`text-right truncate text-xs ${valClass}`}>{value || '—'}</span>
    </div>
  );
}

// ─── Step 7: Provisioning ─────────────────────────────────────────────────────

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
            <ComputerDesktopIcon className="w-4 h-4 text-blue-600" />Clients der Domain hinzufügen
          </h3>
          <div className="flex gap-2">
            {(['Linux', 'macOS', 'Windows'] as JoinPlatform[]).map(p => (
              <button
                key={p} onClick={() => setJoinPlatform(p)}
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
        <div className="bg-gray-900 rounded-xl p-4 max-h-52 overflow-y-auto">
          {log.map((line, i) => <p key={i} className="text-xs font-mono text-green-400 leading-relaxed">{line}</p>)}
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
  { n: 2, label: 'DNS' },
  { n: 3, label: 'Optionen' },
  { n: 4, label: 'Verwaltung' },
  { n: 5, label: 'Admin' },
  { n: 6, label: 'Prüfen' },
  { n: 7, label: 'Einrichten' },
];

const BLANK: ProvisionForm = {
  realm: '', domain: '', dcHostname: '', dcIp: '', exposedFqdn: '',
  dnsBackend: 'SAMBA_INTERNAL', dnsInterface: 'lo eth0', dnsForwarders: '8.8.8.8 8.8.4.4',
  functionLevel: '2008_R2', enableLdaps: true, enableRfc2307: true, serverRole: 'dc',
  usersEnabled: true, groupsEnabled: true,
  adminPassword: '', adminPasswordConfirm: '',
};

export default function DomainSetupWizard({ onClose, onProvisioned }: DomainSetupWizardProps) {
  const [step,    setStep]    = useState(1);
  const [form,    setForm]    = useState<ProvisionForm>(BLANK);
  const [saving,  setSaving]  = useState(false);
  const [success, setSuccess] = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  const [log,     setLog]     = useState<string[]>([]);

  const patch = (f: Partial<ProvisionForm>) => setForm(prev => ({ ...prev, ...f }));

  const canAdvance = (s: number): boolean => {
    if (s === 1) return !!(form.realm.trim() && form.domain.trim());
    if (s === 5) return !!(form.adminPassword && form.adminPassword === form.adminPasswordConfirm && form.adminPassword.length >= 8);
    if (s === 6) return !!(form.realm && form.domain && form.adminPassword && form.adminPassword === form.adminPasswordConfirm);
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
    setStep(7);

    const logSteps = [
      `Verbindung zu Samba AD DC via API-Gateway…`,
      `Realm: ${form.realm} / NetBIOS: ${form.domain}`,
      `DNS-Backend: ${form.dnsBackend} / Interfaces: ${form.dnsInterface}`,
      `Funktionslevel: ${form.functionLevel} / Rolle: ${form.serverRole}`,
      'Initialisiere SAM-Datenbank…',
      'Konfiguriere Kerberos KDC…',
      'Erstelle SYSVOL / NETLOGON-Shares…',
      ...(form.enableLdaps ? ['Generiere LDAPS-Zertifikat (self-signed)…'] : []),
      ...(form.dnsForwarders ? ['Konfiguriere DNS-Forwarder…'] : []),
      'Wende Forest-Einstellungen an…',
    ];

    let i = 0;
    const ticker = setInterval(() => {
      if (i < logSteps.length) setLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${logSteps[i++]}`]);
    }, 600);

    try {
      const res = await fetch(`${API_BASE}/api/samba/domain/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          realm:         form.realm.toUpperCase(),
          domain:        form.domain.toUpperCase(),
          adminPassword: form.adminPassword,
          dnsBackend:    form.dnsBackend,
          dcHostname:    form.dcHostname    || undefined,
          dcIp:          form.dcIp          || undefined,
          functionLevel: form.functionLevel,
          dnsInterface:  form.dnsInterface,
          dnsForwarders: form.dnsForwarders || undefined,
          enableLdaps:   form.enableLdaps,
          enableRfc2307: form.enableRfc2307,
          serverRole:    form.serverRole,
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
    } catch (err: unknown) {
      clearInterval(ticker);
      setError(err instanceof Error ? err.message : 'Netzwerkfehler — ist der samba-ad-dc Container gestartet?');
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
      onComplete={step === 6 ? provision : () => handleStepChange(step + 1)}
      saving={saving}
      completeLabel={step === 6 ? 'Domain einrichten' : 'Weiter'}
      savingLabel="Wird eingerichtet…"
      maxWidth="max-w-2xl"
    >
      {step === 1 && <StepDomain    form={form} onChange={patch} />}
      {step === 2 && <StepDns       form={form} onChange={patch} />}
      {step === 3 && <StepOptions   form={form} onChange={patch} />}
      {step === 4 && <StepVerwaltung form={form} onChange={patch} />}
      {step === 5 && <StepAdmin     form={form} onChange={patch} />}
      {step === 6 && <StepReview    form={form} />}
      {step === 7 && <StepProvision realm={form.realm} success={success} error={error} log={log} />}
    </WizardLayout>
  );
}
