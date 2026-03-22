'use client';

import React, { useState, useEffect } from 'react';
import { policyApi, api } from '@/lib/api';
import {
  ShieldCheckIcon,
  SparklesIcon,
  FolderIcon,
  FolderOpenIcon,
  DocumentTextIcon,
  PlusIcon,
  PencilIcon,
  TrashIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  CheckCircleIcon,
  XCircleIcon,
  LinkIcon,
  UserGroupIcon,
  ComputerDesktopIcon,
  LockClosedIcon,
  Cog6ToothIcon,
  CommandLineIcon,
  CubeIcon,
  XMarkIcon,
  GlobeAltIcon,
  WrenchScrewdriverIcon,
  ClipboardDocumentListIcon,
  ArrowDownTrayIcon,
  DocumentDuplicateIcon,
  CalculatorIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import PolicyCreationWizard from '@/components/setup/PolicyCreationWizard';

// ─── Types ─────────────────────────────────────────────────────────────────────

type GPOStatus = 'enabled' | 'disabled';
type SettingState = 'configured' | 'not_configured';
type GPOTab = 'general' | 'scope' | 'settings' | 'delegation';

interface PasswordSettings {
  enabled: boolean;
  minLength: number;
  complexity: boolean;
  history: number;
  expiryDays: number;
  lockoutAttempts: number;
  lockoutDuration: number;
}

interface DeviceSettings {
  enabled: boolean;
  requireEncryption: boolean;
  requireScreenLock: boolean;
  requireAV: boolean;
  minOsVersion: string;
  allowedPlatforms: string[];
}

interface SoftwareSettings {
  packages: { id: string; name: string; version: string; action: 'install' | 'uninstall' }[];
}

interface ScriptSettings {
  startup: string[];
  shutdown: string[];
  logon: string[];
  logoff: string[];
}

interface AccessSettings {
  allowed: string[];
  denied: string[];
  mfaRequired: boolean;
}

interface AuditSettings {
  enabled: boolean;
  logonEvents: boolean;
  accountManagement: boolean;
  policyChange: boolean;
  privilegeUse: boolean;
  objectAccess: boolean;
  processTracking: boolean;
  directoryAccess: boolean;
  systemEvents: boolean;
  logSize: number;
  retentionDays: number;
}

interface SecurityOptions {
  enabled: boolean;
  sshMaxAuthTries: number;
  sshPermitRootLogin: boolean;
  sshPasswordAuth: boolean;
  sshAllowGroups: string[];
  sessionTimeout: number;
  loginBannerText: string;
  blockUsbStorage: boolean;
  sudoNoPassword: string[];
  sudoWithPassword: string[];
  ntpServer: string;
}

interface FirewallRule {
  id: string;
  direction: 'inbound' | 'outbound';
  action: 'allow' | 'deny';
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  port: string;
  source: string;
  description: string;
  enabled: boolean;
}

interface FirewallSettings {
  enabled: boolean;
  defaultInbound: 'allow' | 'deny';
  defaultOutbound: 'allow' | 'deny';
  rules: FirewallRule[];
}

interface ServiceEntry {
  id: string;
  name: string;
  displayName: string;
  startupType: 'enabled' | 'disabled' | 'manual';
}

interface SystemServices {
  enabled: boolean;
  services: ServiceEntry[];
}

interface GPO {
  id: string;
  name: string;
  status: GPOStatus;
  linkedOUs: string[];
  description: string;
  createdAt: string;
  modifiedAt: string;
  version: number;
  password: PasswordSettings;
  device: DeviceSettings;
  software: SoftwareSettings;
  scripts: ScriptSettings;
  access: AccessSettings;
  audit: AuditSettings;
  securityOptions: SecurityOptions;
  firewall: FirewallSettings;
  systemServices: SystemServices;
}

interface OU {
  id: string;
  name: string;
  icon: 'domain' | 'ou' | 'group';
  linkedGPOs: string[];
  children?: OU[];
}

// ─── Initial Data ──────────────────────────────────────────────────────────────

const AD_DOMAIN = process.env.NEXT_PUBLIC_AD_DOMAIN || '';

function buildFallbackOuTree(domain: string): OU[] {
  return [
    {
      id: 'ou-root',
      name: domain || 'Domain',
      icon: 'domain',
      linkedGPOs: ['gpo-default-domain'],
      children: [
        {
          id: 'ou-servers',
          name: 'Servers',
          icon: 'ou',
          linkedGPOs: ['gpo-server-hardening'],
          children: [],
        },
        {
          id: 'ou-workstations',
          name: 'Workstations',
          icon: 'ou',
          linkedGPOs: ['gpo-workstation-standard', 'gpo-dev-tools'],
          children: [],
        },
        {
          id: 'ou-users',
          name: 'Users',
          icon: 'ou',
          linkedGPOs: [],
          children: [],
        },
        {
          id: 'ou-admins',
          name: 'Admins',
          icon: 'group',
          linkedGPOs: ['gpo-admin-mfa'],
          children: [],
        },
      ],
    },
  ];
}

// ─── Default AD-equivalent GPOs ────────────────────────────────────────────────

const FALLBACK_GPOS: GPO[] = [
  {
    id: 'gpo-default-domain',
    name: 'Default Domain Policy',
    status: 'enabled',
    linkedOUs: ['ou-root'],
    description: 'Default Domain Policy — enforces password policy and account lockout for all domain objects.',
    createdAt: '2024-01-01T00:00:00Z',
    modifiedAt: '2024-01-01T00:00:00Z',
    version: 3,
    password: {
      enabled: true, minLength: 12, complexity: true,
      history: 24, expiryDays: 90, lockoutAttempts: 5, lockoutDuration: 30,
    },
    device: { enabled: false, requireEncryption: false, requireScreenLock: false, requireAV: false, minOsVersion: '', allowedPlatforms: [] },
    software: { packages: [] },
    scripts: { startup: [], shutdown: [], logon: [], logoff: [] },
    access: { allowed: [], denied: [], mfaRequired: false },
    audit: {
      enabled: true, logonEvents: true, accountManagement: true, policyChange: true,
      privilegeUse: false, objectAccess: false, processTracking: false, directoryAccess: true,
      systemEvents: true, logSize: 200, retentionDays: 90,
    },
    securityOptions: {
      enabled: false, sshMaxAuthTries: 3, sshPermitRootLogin: false, sshPasswordAuth: false,
      sshAllowGroups: [], sessionTimeout: 30, loginBannerText: '', blockUsbStorage: false,
      sudoNoPassword: [], sudoWithPassword: [], ntpServer: '',
    },
    firewall: { enabled: false, defaultInbound: 'deny', defaultOutbound: 'allow', rules: [] },
    systemServices: { enabled: false, services: [] },
  },
  {
    id: 'gpo-server-hardening',
    name: 'Server Security Baseline CIS L1',
    status: 'enabled',
    linkedOUs: ['ou-servers'],
    description: 'CIS Level 1 hardening baseline for Linux servers — SSH restrictions, session timeouts, login banner, NTP.',
    createdAt: '2024-01-01T00:00:00Z',
    modifiedAt: '2024-01-01T00:00:00Z',
    version: 2,
    password: { enabled: false, minLength: 12, complexity: false, history: 0, expiryDays: 0, lockoutAttempts: 0, lockoutDuration: 0 },
    device: { enabled: true, requireEncryption: true, requireScreenLock: false, requireAV: false, minOsVersion: '', allowedPlatforms: ['linux'] },
    software: { packages: [] },
    scripts: { startup: [], shutdown: [], logon: [], logoff: [] },
    access: { allowed: [], denied: [], mfaRequired: false },
    audit: {
      enabled: true, logonEvents: true, accountManagement: true, policyChange: true,
      privilegeUse: true, objectAccess: true, processTracking: false, directoryAccess: true,
      systemEvents: true, logSize: 500, retentionDays: 180,
    },
    securityOptions: {
      enabled: true, sshMaxAuthTries: 3, sshPermitRootLogin: false, sshPasswordAuth: false,
      sshAllowGroups: ['sshusers', 'admins'], sessionTimeout: 15,
      loginBannerText: 'Authorized use only. All activity is monitored and logged.',
      blockUsbStorage: true, sudoNoPassword: [], sudoWithPassword: ['admins'], ntpServer: 'pool.ntp.org',
    },
    firewall: {
      enabled: true, defaultInbound: 'deny', defaultOutbound: 'allow',
      rules: [
        { id: 'r1', direction: 'inbound', action: 'allow', protocol: 'tcp', port: '22', source: '10.0.0.0/8', description: 'SSH from internal', enabled: true },
        { id: 'r2', direction: 'inbound', action: 'allow', protocol: 'tcp', port: '443', source: 'any', description: 'HTTPS', enabled: true },
        { id: 'r3', direction: 'inbound', action: 'allow', protocol: 'icmp', port: 'any', source: '10.0.0.0/8', description: 'ICMP from internal', enabled: true },
      ],
    },
    systemServices: {
      enabled: true,
      services: [
        { id: 'svc1', name: 'ufw', displayName: 'Uncomplicated Firewall', startupType: 'enabled' },
        { id: 'svc2', name: 'fail2ban', displayName: 'Fail2Ban', startupType: 'enabled' },
        { id: 'svc3', name: 'auditd', displayName: 'Linux Audit Daemon', startupType: 'enabled' },
        { id: 'svc4', name: 'rpcbind', displayName: 'RPC Bind', startupType: 'disabled' },
        { id: 'svc5', name: 'avahi-daemon', displayName: 'Avahi mDNS', startupType: 'disabled' },
      ],
    },
  },
  {
    id: 'gpo-workstation-standard',
    name: 'Workstation Standard',
    status: 'enabled',
    linkedOUs: ['ou-workstations'],
    description: 'Standard workstation policy — disk encryption, screen lock, endpoint security baseline.',
    createdAt: '2024-01-01T00:00:00Z',
    modifiedAt: '2024-01-01T00:00:00Z',
    version: 2,
    password: { enabled: false, minLength: 12, complexity: false, history: 0, expiryDays: 0, lockoutAttempts: 0, lockoutDuration: 0 },
    device: { enabled: true, requireEncryption: true, requireScreenLock: true, requireAV: true, minOsVersion: '', allowedPlatforms: ['linux', 'macos', 'windows'] },
    software: {
      packages: [
        { id: 'pkg1', name: 'ufw', version: 'latest', action: 'install' },
        { id: 'pkg2', name: 'clamav', version: 'latest', action: 'install' },
      ],
    },
    scripts: { startup: [], shutdown: [], logon: [], logoff: [] },
    access: { allowed: [], denied: [], mfaRequired: false },
    audit: {
      enabled: true, logonEvents: true, accountManagement: false, policyChange: false,
      privilegeUse: false, objectAccess: false, processTracking: false, directoryAccess: false,
      systemEvents: false, logSize: 100, retentionDays: 30,
    },
    securityOptions: {
      enabled: true, sshMaxAuthTries: 3, sshPermitRootLogin: false, sshPasswordAuth: false,
      sshAllowGroups: [], sessionTimeout: 30, loginBannerText: '', blockUsbStorage: false,
      sudoNoPassword: [], sudoWithPassword: [], ntpServer: '',
    },
    firewall: { enabled: false, defaultInbound: 'deny', defaultOutbound: 'allow', rules: [] },
    systemServices: { enabled: false, services: [] },
  },
  {
    id: 'gpo-dev-tools',
    name: 'Developer Workstation',
    status: 'enabled',
    linkedOUs: ['ou-workstations'],
    description: 'Additional tooling for developer workstations — Docker, Git, VSCode, build tools.',
    createdAt: '2024-01-01T00:00:00Z',
    modifiedAt: '2024-01-01T00:00:00Z',
    version: 1,
    password: { enabled: false, minLength: 12, complexity: false, history: 0, expiryDays: 0, lockoutAttempts: 0, lockoutDuration: 0 },
    device: { enabled: false, requireEncryption: false, requireScreenLock: false, requireAV: false, minOsVersion: '', allowedPlatforms: [] },
    software: {
      packages: [
        { id: 'pkg1', name: 'docker.io', version: 'latest', action: 'install' },
        { id: 'pkg2', name: 'git', version: 'latest', action: 'install' },
        { id: 'pkg3', name: 'build-essential', version: 'latest', action: 'install' },
        { id: 'pkg4', name: 'python3', version: 'latest', action: 'install' },
        { id: 'pkg5', name: 'nodejs', version: '20.x', action: 'install' },
      ],
    },
    scripts: {
      startup: ['systemctl enable docker', 'usermod -aG docker $USER'],
      shutdown: [], logon: [], logoff: [],
    },
    access: { allowed: [], denied: [], mfaRequired: false },
    audit: { enabled: false, logonEvents: false, accountManagement: false, policyChange: false, privilegeUse: false, objectAccess: false, processTracking: false, directoryAccess: false, systemEvents: false, logSize: 100, retentionDays: 30 },
    securityOptions: { enabled: false, sshMaxAuthTries: 3, sshPermitRootLogin: false, sshPasswordAuth: false, sshAllowGroups: [], sessionTimeout: 60, loginBannerText: '', blockUsbStorage: false, sudoNoPassword: ['docker'], sudoWithPassword: [], ntpServer: '' },
    firewall: { enabled: false, defaultInbound: 'deny', defaultOutbound: 'allow', rules: [] },
    systemServices: {
      enabled: true,
      services: [
        { id: 'svc1', name: 'docker', displayName: 'Docker Engine', startupType: 'enabled' },
      ],
    },
  },
  {
    id: 'gpo-admin-mfa',
    name: 'Admin MFA Enforcement',
    status: 'enabled',
    linkedOUs: ['ou-admins'],
    description: 'Enforces MFA for all administrator accounts. Restricts admin access to approved groups only.',
    createdAt: '2024-01-01T00:00:00Z',
    modifiedAt: '2024-01-01T00:00:00Z',
    version: 1,
    password: {
      enabled: true, minLength: 16, complexity: true,
      history: 24, expiryDays: 60, lockoutAttempts: 3, lockoutDuration: 60,
    },
    device: { enabled: false, requireEncryption: false, requireScreenLock: false, requireAV: false, minOsVersion: '', allowedPlatforms: [] },
    software: { packages: [] },
    scripts: { startup: [], shutdown: [], logon: [], logoff: [] },
    access: { allowed: ['admins', 'domain-admins'], denied: [], mfaRequired: true },
    audit: {
      enabled: true, logonEvents: true, accountManagement: true, policyChange: true,
      privilegeUse: true, objectAccess: true, processTracking: true, directoryAccess: true,
      systemEvents: true, logSize: 1000, retentionDays: 365,
    },
    securityOptions: {
      enabled: true, sshMaxAuthTries: 2, sshPermitRootLogin: false, sshPasswordAuth: false,
      sshAllowGroups: ['admins', 'domain-admins'], sessionTimeout: 10,
      loginBannerText: 'ADMIN ACCESS — All actions are logged and audited.',
      blockUsbStorage: true, sudoNoPassword: [], sudoWithPassword: ['admins'], ntpServer: '',
    },
    firewall: { enabled: false, defaultInbound: 'deny', defaultOutbound: 'allow', rules: [] },
    systemServices: { enabled: false, services: [] },
  },
];

// ─── API Normalization ─────────────────────────────────────────────────────────

function normalizeGPO(raw: any): GPO {
  return {
    id:          raw.id || raw._id || String(Math.random()),
    name:        raw.name || raw.displayName || 'Unnamed Policy',
    status:      raw.status === 'disabled' ? 'disabled' : 'enabled',
    linkedOUs:   raw.linkedOUs || raw.linked_ous || [],
    description: raw.description || '',
    createdAt:   raw.createdAt || raw.created_at || new Date().toISOString(),
    modifiedAt:  raw.modifiedAt || raw.updated_at || new Date().toISOString(),
    version:     raw.version || 1,
    password: {
      enabled:          raw.password?.enabled          ?? false,
      minLength:        raw.password?.minLength        ?? 12,
      complexity:       raw.password?.complexity       ?? false,
      history:          raw.password?.history          ?? 0,
      expiryDays:       raw.password?.expiryDays       ?? 0,
      lockoutAttempts:  raw.password?.lockoutAttempts  ?? 0,
      lockoutDuration:  raw.password?.lockoutDuration  ?? 0,
    },
    device: {
      enabled:            raw.device?.enabled            ?? false,
      requireEncryption:  raw.device?.requireEncryption  ?? false,
      requireScreenLock:  raw.device?.requireScreenLock  ?? false,
      requireAV:          raw.device?.requireAV          ?? false,
      minOsVersion:       raw.device?.minOsVersion       ?? '',
      allowedPlatforms:   raw.device?.allowedPlatforms   ?? ['linux', 'macos', 'windows'],
    },
    software: {
      packages: raw.software?.packages || [],
    },
    scripts: {
      startup:  raw.scripts?.startup  || [],
      shutdown: raw.scripts?.shutdown || [],
      logon:    raw.scripts?.logon    || [],
      logoff:   raw.scripts?.logoff   || [],
    },
    access: {
      allowed:     raw.access?.allowed     || [],
      denied:      raw.access?.denied      || [],
      mfaRequired: raw.access?.mfaRequired ?? false,
    },
    audit: {
      enabled:           raw.audit?.enabled           ?? false,
      logonEvents:       raw.audit?.logonEvents       ?? false,
      accountManagement: raw.audit?.accountManagement ?? false,
      policyChange:      raw.audit?.policyChange      ?? false,
      privilegeUse:      raw.audit?.privilegeUse      ?? false,
      objectAccess:      raw.audit?.objectAccess      ?? false,
      processTracking:   raw.audit?.processTracking   ?? false,
      directoryAccess:   raw.audit?.directoryAccess   ?? false,
      systemEvents:      raw.audit?.systemEvents      ?? false,
      logSize:           raw.audit?.logSize           ?? 100,
      retentionDays:     raw.audit?.retentionDays     ?? 30,
    },
    securityOptions: {
      enabled:            raw.securityOptions?.enabled            ?? false,
      sshMaxAuthTries:    raw.securityOptions?.sshMaxAuthTries    ?? 3,
      sshPermitRootLogin: raw.securityOptions?.sshPermitRootLogin ?? false,
      sshPasswordAuth:    raw.securityOptions?.sshPasswordAuth    ?? false,
      sshAllowGroups:     raw.securityOptions?.sshAllowGroups     ?? [],
      sessionTimeout:     raw.securityOptions?.sessionTimeout     ?? 30,
      loginBannerText:    raw.securityOptions?.loginBannerText    ?? '',
      blockUsbStorage:    raw.securityOptions?.blockUsbStorage    ?? false,
      sudoNoPassword:     raw.securityOptions?.sudoNoPassword     ?? [],
      sudoWithPassword:   raw.securityOptions?.sudoWithPassword   ?? [],
      ntpServer:          raw.securityOptions?.ntpServer          ?? '',
    },
    firewall: {
      enabled:        raw.firewall?.enabled        ?? false,
      defaultInbound: raw.firewall?.defaultInbound ?? 'deny',
      defaultOutbound:raw.firewall?.defaultOutbound?? 'allow',
      rules:          raw.firewall?.rules          ?? [],
    },
    systemServices: {
      enabled:  raw.systemServices?.enabled  ?? false,
      services: raw.systemServices?.services ?? [],
    },
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(ds: string) {
  if (!ds) return '—';
  return new Date(ds).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function countSettings(gpo: GPO): number {
  let n = 0;
  if (gpo.password.enabled) n += 6;
  if (gpo.device.enabled) n += Object.values(gpo.device).filter(v => v === true).length;
  n += gpo.software.packages.length;
  n += gpo.scripts.startup.length + gpo.scripts.shutdown.length + gpo.scripts.logon.length + gpo.scripts.logoff.length;
  if (gpo.access.mfaRequired) n++;
  n += gpo.access.denied.length;
  if (gpo.audit?.enabled) n += Object.values(gpo.audit).filter(v => v === true).length;
  if (gpo.securityOptions?.enabled) n += 1;
  n += gpo.firewall?.rules?.length ?? 0;
  n += gpo.systemServices?.services?.filter(s => s.startupType !== 'manual').length ?? 0;
  return n;
}

// ─── Tree Item ─────────────────────────────────────────────────────────────────

function TreeItem({ ou, gpos, selectedGPO, onSelectGPO, depth = 0 }: {
  ou: OU;
  gpos: GPO[];
  selectedGPO: GPO | null;
  onSelectGPO: (g: GPO) => void;
  depth?: number;
}) {
  const [open, setOpen] = useState(true);
  const hasChildren = (ou.children?.length || 0) > 0 || ou.linkedGPOs.length > 0;

  const OUIcon = ou.icon === 'domain' ? ShieldCheckIcon :
    ou.icon === 'group' ? UserGroupIcon : FolderOpenIcon;

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 w-full text-left px-2 py-1 rounded hover:bg-gray-100 transition-colors group"
        style={{ paddingLeft: 8 + depth * 16 }}
      >
        {hasChildren ? (
          open ? <ChevronDownIcon className="w-3 h-3 text-gray-400 flex-shrink-0" />
               : <ChevronRightIcon className="w-3 h-3 text-gray-400 flex-shrink-0" />
        ) : <span className="w-3" />}
        <OUIcon className={`w-4 h-4 flex-shrink-0 ${
          ou.icon === 'domain' ? 'text-blue-600' :
          ou.icon === 'group' ? 'text-purple-500' : 'text-yellow-500'
        }`} />
        <span className="text-xs text-gray-700 truncate">{ou.name}</span>
        {(() => {
          const existingCount = ou.linkedGPOs.filter(gid => gpos.some(g => g.id === gid)).length;
          return existingCount > 0 ? (
            <span className="ml-auto flex-shrink-0 text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded-full">
              {existingCount}
            </span>
          ) : null;
        })()}
      </button>

      {open && (
        <div>
          {/* Linked GPOs */}
          {ou.linkedGPOs.map(gid => {
            const gpo = gpos.find(g => g.id === gid);
            if (!gpo) return null;
            const isSelected = selectedGPO?.id === gpo.id;
            return (
              <button
                key={gid}
                onClick={() => onSelectGPO(gpo)}
                className={`flex items-center gap-1.5 w-full text-left px-2 py-1 rounded transition-colors ${
                  isSelected
                    ? 'bg-blue-50 text-blue-700'
                    : 'hover:bg-gray-100 text-gray-600'
                }`}
                style={{ paddingLeft: 8 + (depth + 1) * 16 }}
              >
                <span className="w-3" />
                <DocumentTextIcon className={`w-4 h-4 flex-shrink-0 ${
                  gpo.status === 'disabled' ? 'text-gray-300' : isSelected ? 'text-blue-500' : 'text-blue-400'
                }`} />
                <span className={`text-xs truncate ${gpo.status === 'disabled' ? 'text-gray-400 line-through' : ''}`}>
                  {gpo.name}
                </span>
              </button>
            );
          })}
          {/* Child OUs */}
          {ou.children?.map(child => (
            <TreeItem
              key={child.id}
              ou={child}
              gpos={gpos}
              selectedGPO={selectedGPO}
              onSelectGPO={onSelectGPO}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Settings Tree ─────────────────────────────────────────────────────────────

function TreeSection({ title, icon: Icon, children, defaultOpen = true }: {
  title: string;
  icon: React.ComponentType<any>;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <button onClick={() => setOpen(!open)}
        className="flex items-center gap-2 w-full text-left py-2 hover:bg-gray-50 rounded px-2 transition-colors">
        {open ? <ChevronDownIcon className="w-3.5 h-3.5 text-gray-400" /> : <ChevronRightIcon className="w-3.5 h-3.5 text-gray-400" />}
        <Icon className="w-4 h-4 text-gray-500" />
        <span className="text-sm font-medium text-gray-700">{title}</span>
      </button>
      {open && <div className="ml-6 border-l border-gray-100 pl-3 mb-2">{children}</div>}
    </div>
  );
}

function SettingRow({ label, value, configured = true }: { label: string; value: React.ReactNode; configured?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1.5 px-2 hover:bg-gray-50 rounded text-sm">
      <span className="text-gray-600">{label}</span>
      <span className={`font-medium ${configured ? 'text-gray-900' : 'text-gray-400 italic'}`}>
        {configured ? value : 'Not Configured'}
      </span>
    </div>
  );
}

function BoolRow({ label, value }: { label: string; value: boolean }) {
  return (
    <div className="flex items-center justify-between py-1.5 px-2 hover:bg-gray-50 rounded text-sm">
      <span className="text-gray-600">{label}</span>
      {value
        ? <span className="flex items-center gap-1 text-green-600 font-medium"><CheckCircleIcon className="w-4 h-4" />Enabled</span>
        : <span className="flex items-center gap-1 text-gray-400 italic"><XCircleIcon className="w-4 h-4" />Disabled</span>
      }
    </div>
  );
}

// ─── GPO Settings Editor ───────────────────────────────────────────────────────

type EditTab = 'password' | 'device' | 'software' | 'scripts' | 'access' | 'audit' | 'security' | 'firewall' | 'services';

function GPOEditModal({ gpo, onClose, onSave }: {
  gpo: GPO;
  onClose: () => void;
  onSave: (updated: GPO) => void;
}) {
  const [tab, setTab] = useState<EditTab>('password');
  const [draft, setDraft] = useState<GPO>(JSON.parse(JSON.stringify(gpo)));
  const [newPkg, setNewPkg] = useState({ name: '', version: '', action: 'install' as 'install' | 'uninstall' });
  const [scriptInputs, setScriptInputs] = useState({ startup: '', shutdown: '', logon: '', logoff: '' });
  const [allowedInput, setAllowedInput] = useState('');
  const [deniedInput, setDeniedInput] = useState('');

  // New tab state
  const [sshGroupInput, setSshGroupInput] = useState('');
  const [sudoNoPwdInput, setSudoNoPwdInput] = useState('');
  const [sudoWithPwdInput, setSudoWithPwdInput] = useState('');
  const [newRule, setNewRule] = useState<Omit<FirewallRule, 'id'>>({
    direction: 'inbound', action: 'allow', protocol: 'tcp', port: '', source: '*', description: '', enabled: true,
  });
  const [newSvc, setNewSvc] = useState({ name: '', displayName: '', startupType: 'enabled' as ServiceEntry['startupType'] });

  const setPassword = (u: Partial<PasswordSettings>) =>
    setDraft(d => ({ ...d, password: { ...d.password, ...u } }));
  const setDevice = (u: Partial<DeviceSettings>) =>
    setDraft(d => ({ ...d, device: { ...d.device, ...u } }));
  const setAudit = (u: Partial<AuditSettings>) =>
    setDraft(d => ({ ...d, audit: { ...d.audit, ...u } }));
  const setSecOpts = (u: Partial<SecurityOptions>) =>
    setDraft(d => ({ ...d, securityOptions: { ...d.securityOptions, ...u } }));
  const setFirewall = (u: Partial<FirewallSettings>) =>
    setDraft(d => ({ ...d, firewall: { ...d.firewall, ...u } }));

  const addPackage = () => {
    if (!newPkg.name.trim()) return;
    setDraft(d => ({ ...d, software: { packages: [...d.software.packages, { id: String(Date.now()), ...newPkg }] } }));
    setNewPkg({ name: '', version: '', action: 'install' });
  };
  const removePkg = (id: string) =>
    setDraft(d => ({ ...d, software: { packages: d.software.packages.filter(p => p.id !== id) } }));

  const addScript = (type: keyof ScriptSettings) => {
    const value = scriptInputs[type].trim();
    if (!value) return;
    setDraft(d => ({ ...d, scripts: { ...d.scripts, [type]: [...d.scripts[type], value] } }));
    setScriptInputs(s => ({ ...s, [type]: '' }));
  };
  const removeScript = (type: keyof ScriptSettings, s: string) =>
    setDraft(d => ({ ...d, scripts: { ...d.scripts, [type]: d.scripts[type].filter(x => x !== s) } }));

  const addAllowed = () => {
    if (!allowedInput.trim()) return;
    setDraft(d => ({ ...d, access: { ...d.access, allowed: [...d.access.allowed, allowedInput.trim()] } }));
    setAllowedInput('');
  };
  const addDenied = () => {
    if (!deniedInput.trim()) return;
    setDraft(d => ({ ...d, access: { ...d.access, denied: [...d.access.denied, deniedInput.trim()] } }));
    setDeniedInput('');
  };
  const removeGroup = (type: 'allowed' | 'denied', g: string) =>
    setDraft(d => ({ ...d, access: { ...d.access, [type]: d.access[type].filter(x => x !== g) } }));

  const handleSave = () => {
    onSave({ ...draft, modifiedAt: new Date().toISOString(), version: draft.version + 1 });
    toast.success('GPO settings saved');
    onClose();
  };

  const editTabs: { key: EditTab; label: string }[] = [
    { key: 'password', label: 'Password Policy' },
    { key: 'device',   label: 'Device Compliance' },
    { key: 'software', label: 'Software' },
    { key: 'scripts',  label: 'Scripts' },
    { key: 'access',   label: 'Access Control' },
    { key: 'audit',    label: 'Audit Policy' },
    { key: 'security', label: 'Security Options' },
    { key: 'firewall', label: 'Firewall Rules' },
    { key: 'services', label: 'System Services' },
  ];

  // Default Linux services list
  const DEFAULT_SERVICES: Omit<ServiceEntry, 'startupType'>[] = [
    { id: 'svc-ssh',       name: 'ssh',          displayName: 'OpenSSH Server' },
    { id: 'svc-ufw',       name: 'ufw',          displayName: 'Uncomplicated Firewall' },
    { id: 'svc-fail2ban',  name: 'fail2ban',     displayName: 'Fail2Ban IDS' },
    { id: 'svc-clamav',    name: 'clamav-daemon',displayName: 'ClamAV Antivirus' },
    { id: 'svc-wazuh',     name: 'wazuh-agent',  displayName: 'Wazuh Security Agent' },
    { id: 'svc-auditd',    name: 'auditd',       displayName: 'Linux Audit Daemon' },
    { id: 'svc-ntp',       name: 'chrony',       displayName: 'Time Sync (chrony)' },
    { id: 'svc-rsyslog',   name: 'rsyslog',      displayName: 'System Logging' },
    { id: 'svc-snapd',     name: 'snapd',        displayName: 'Snap Package Manager' },
    { id: 'svc-cups',      name: 'cups',         displayName: 'Print Server' },
  ];

  const getServiceStartup = (id: string): ServiceEntry['startupType'] =>
    draft.systemServices.services.find(s => s.id === id)?.startupType ?? 'manual';

  const setServiceStartup = (svcId: string, svcName: string, svcDisplay: string, startupType: ServiceEntry['startupType']) => {
    setDraft(d => {
      const existing = d.systemServices.services.find(s => s.id === svcId);
      if (existing) {
        return { ...d, systemServices: { ...d.systemServices, services: d.systemServices.services.map(s => s.id === svcId ? { ...s, startupType } : s) } };
      }
      return { ...d, systemServices: { ...d.systemServices, services: [...d.systemServices.services, { id: svcId, name: svcName, displayName: svcDisplay, startupType }] } };
    });
  };

  const addFirewallRule = () => {
    if (!newRule.port.trim()) return;
    setDraft(d => ({ ...d, firewall: { ...d.firewall, rules: [...d.firewall.rules, { ...newRule, id: 'rule-' + Date.now() }] } }));
    setNewRule({ direction: 'inbound', action: 'allow', protocol: 'tcp', port: '', source: '*', description: '', enabled: true });
  };

  const removeFirewallRule = (id: string) =>
    setDraft(d => ({ ...d, firewall: { ...d.firewall, rules: d.firewall.rules.filter(r => r.id !== id) } }));

  const toggleFirewallRule = (id: string) =>
    setDraft(d => ({ ...d, firewall: { ...d.firewall, rules: d.firewall.rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r) } }));

  const addCustomService = () => {
    if (!newSvc.name.trim()) return;
    setDraft(d => ({ ...d, systemServices: { ...d.systemServices, services: [...d.systemServices.services, { id: 'svc-' + Date.now(), ...newSvc }] } }));
    setNewSvc({ name: '', displayName: '', startupType: 'enabled' });
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-[60]" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-3xl w-full max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 flex-shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Edit GPO Settings</h2>
            <p className="text-sm text-gray-500">{gpo.name}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        {/* Two-column body: left nav + right content */}
        <div className="flex flex-1 overflow-hidden">

          {/* Left sidebar nav */}
          <nav className="w-44 flex-shrink-0 border-r border-gray-100 overflow-y-auto py-2">
            {editTabs.map(t => (
              <button key={t.key} onClick={() => setTab(t.key)}
                className={`w-full text-left px-4 py-2 text-sm font-medium transition-colors ${
                  tab === t.key
                    ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                }`}>
                {t.label}
              </button>
            ))}
          </nav>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">

          {/* ── Password Policy ── */}
          {tab === 'password' && (
            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <span className="text-sm font-medium text-gray-700">Password Policy Active</span>
                <input type="checkbox" checked={draft.password.enabled}
                  onChange={e => setPassword({ enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>
              <div className={`space-y-3 ${!draft.password.enabled ? 'opacity-40 pointer-events-none' : ''}`}>
                {([
                  { label: 'Minimum Password Length',     key: 'minLength',       suffix: 'characters', min: 1,  max: 128 },
                  { label: 'Password History',            key: 'history',         suffix: 'remembered', min: 0,  max: 24 },
                  { label: 'Maximum Password Age',        key: 'expiryDays',      suffix: 'days (0 = never)', min: 0, max: 365 },
                  { label: 'Account Lockout Threshold',   key: 'lockoutAttempts', suffix: 'attempts (0 = never)', min: 0, max: 20 },
                  { label: 'Lockout Duration',            key: 'lockoutDuration', suffix: 'minutes', min: 0, max: 1440 },
                ] as { label: string; key: keyof PasswordSettings; suffix: string; min: number; max: number }[]).map(({ label, key, suffix, min, max }) => (
                  <div key={String(key)} className="flex items-center justify-between py-1">
                    <span className="text-sm text-gray-700">{label}</span>
                    <div className="flex items-center gap-2">
                      <input type="number" min={min} max={max}
                        value={draft.password[key] as number}
                        onChange={e => setPassword({ [key]: parseInt(e.target.value) || 0 })}
                        className="w-20 border border-gray-200 rounded px-2 py-1 text-sm text-center focus:outline-none focus:ring-1 focus:ring-blue-500" />
                      <span className="text-xs text-gray-400 w-36">{suffix}</span>
                    </div>
                  </div>
                ))}
                <label className="flex items-center justify-between py-1 cursor-pointer">
                  <span className="text-sm text-gray-700">Enforce Password Complexity</span>
                  <input type="checkbox" checked={draft.password.complexity}
                    onChange={e => setPassword({ complexity: e.target.checked })}
                    className="w-4 h-4 rounded text-blue-600" />
                </label>
              </div>
            </div>
          )}

          {/* ── Device Compliance ── */}
          {tab === 'device' && (
            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <span className="text-sm font-medium text-gray-700">Device Compliance Active</span>
                <input type="checkbox" checked={draft.device.enabled}
                  onChange={e => setDevice({ enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>
              <div className={`space-y-3 ${!draft.device.enabled ? 'opacity-40 pointer-events-none' : ''}`}>
                {([
                  { label: 'Require Disk Encryption',  key: 'requireEncryption' },
                  { label: 'Require Screen Lock / PIN',key: 'requireScreenLock' },
                  { label: 'Require Antivirus / EDR',  key: 'requireAV' },
                ] as { label: string; key: keyof DeviceSettings }[]).map(({ label, key }) => (
                  <label key={String(key)} className="flex items-center justify-between py-1 cursor-pointer">
                    <span className="text-sm text-gray-700">{label}</span>
                    <input type="checkbox" checked={draft.device[key] as boolean}
                      onChange={e => setDevice({ [key]: e.target.checked })}
                      className="w-4 h-4 rounded text-blue-600" />
                  </label>
                ))}
                <div>
                  <label className="block text-sm text-gray-700 mb-1">Minimum OS Version</label>
                  <input value={draft.device.minOsVersion}
                    onChange={e => setDevice({ minOsVersion: e.target.value })}
                    placeholder="e.g. Ubuntu 22.04"
                    className="w-full border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                </div>
                <div>
                  <p className="text-sm text-gray-700 mb-2">Supported Platforms</p>
                  <div className="flex items-center gap-2">
                    {(['Windows', 'Linux', 'macOS'] as const).map(p => (
                      <span key={p} className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-50 text-blue-700 text-xs font-medium rounded-full border border-blue-100">
                        {p}
                      </span>
                    ))}
                    <span className="text-xs text-gray-400 ml-1">Policy applies to all platforms</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── Software ── */}
          {tab === 'software' && (
            <div className="space-y-4">
              <div className="space-y-1.5">
                {draft.software.packages.length === 0 && (
                  <p className="text-sm text-gray-400 italic px-1">No packages configured</p>
                )}
                {draft.software.packages.map(pkg => (
                  <div key={pkg.id} className="flex items-center justify-between px-3 py-2 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0 ${
                        pkg.action === 'install' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                      }`}>{pkg.action}</span>
                      <span className="text-sm font-medium text-gray-800 truncate">{pkg.name}</span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                      <span className="text-xs text-gray-400">v{pkg.version}</span>
                      <select value={pkg.action}
                        onChange={e => setDraft(d => ({
                          ...d,
                          software: { packages: d.software.packages.map(p =>
                            p.id === pkg.id ? { ...p, action: e.target.value as 'install' | 'uninstall' } : p
                          )},
                        }))}
                        className="text-xs border border-gray-200 rounded px-1.5 py-0.5 focus:outline-none">
                        <option value="install">install</option>
                        <option value="uninstall">uninstall</option>
                      </select>
                      <button onClick={() => removePkg(pkg.id)} className="text-gray-400 hover:text-red-500">
                        <XMarkIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              <div className="border-t border-gray-100 pt-3">
                <p className="text-xs font-medium text-gray-500 mb-2">Add Package</p>
                <div className="flex items-center gap-2">
                  <input value={newPkg.name} onChange={e => setNewPkg(p => ({ ...p, name: e.target.value }))}
                    onKeyDown={e => { if (e.key === 'Enter') addPackage(); }}
                    placeholder="Package name"
                    className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                  <input value={newPkg.version} onChange={e => setNewPkg(p => ({ ...p, version: e.target.value }))}
                    onKeyDown={e => { if (e.key === 'Enter') addPackage(); }}
                    placeholder="Version"
                    className="w-24 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                  <select value={newPkg.action} onChange={e => setNewPkg(p => ({ ...p, action: e.target.value as 'install' | 'uninstall' }))}
                    className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none">
                    <option value="install">install</option>
                    <option value="uninstall">uninstall</option>
                  </select>
                  <button onClick={addPackage}
                    className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg">
                    Add
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── Scripts ── */}
          {tab === 'scripts' && (
            <div className="space-y-5">
              {(['startup', 'shutdown', 'logon', 'logoff'] as const).map(type => (
                <div key={type}>
                  <p className="text-sm font-medium text-gray-700 mb-2 capitalize">{type} Scripts</p>
                  <div className="space-y-1 mb-2">
                    {draft.scripts[type].length === 0 && (
                      <p className="text-xs text-gray-400 italic px-1">No scripts</p>
                    )}
                    {draft.scripts[type].map(s => (
                      <div key={s} className="flex items-center justify-between px-3 py-1.5 bg-gray-50 rounded text-sm group">
                        <span className="font-mono text-xs text-gray-700">{s}</span>
                        <button onClick={() => removeScript(type, s)} className="text-gray-300 hover:text-red-500 group-hover:text-gray-400">
                          <XMarkIcon className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                  <div className="flex items-center gap-2">
                    <input value={scriptInputs[type]}
                      onChange={e => setScriptInputs(s => ({ ...s, [type]: e.target.value }))}
                      onKeyDown={e => { if (e.key === 'Enter') addScript(type); }}
                      placeholder={`${type}-script.sh`}
                      className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-500" />
                    <button onClick={() => addScript(type)} disabled={!scriptInputs[type].trim()}
                      className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-40">
                      Add
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Access Control ── */}
          {tab === 'access' && (
            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <div>
                  <p className="text-sm font-medium text-gray-700">Require Multi-Factor Authentication</p>
                  <p className="text-xs text-gray-400 mt-0.5">Users must verify with a second factor</p>
                </div>
                <input type="checkbox" checked={draft.access.mfaRequired}
                  onChange={e => setDraft(d => ({ ...d, access: { ...d.access, mfaRequired: e.target.checked } }))}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>

              {/* Allowed groups */}
              <div>
                <p className="text-sm font-medium text-gray-700 mb-2">Allowed Groups</p>
                <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
                  {draft.access.allowed.map(g => (
                    <span key={g} className="flex items-center gap-1 bg-green-50 border border-green-200 text-green-700 text-xs px-2.5 py-1 rounded-full">
                      {g === '*' ? 'Authenticated Users (All)' : g}
                      <button onClick={() => removeGroup('allowed', g)} className="hover:text-red-500 ml-0.5">
                        <XMarkIcon className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                  {draft.access.allowed.length === 0 && <p className="text-xs text-gray-400 italic">None</p>}
                </div>
                <div className="flex items-center gap-2">
                  <input value={allowedInput} onChange={e => setAllowedInput(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') addAllowed(); }}
                    placeholder="Group name or * for all"
                    className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                  <button onClick={addAllowed} disabled={!allowedInput.trim()}
                    className="px-3 py-1.5 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-40">
                    Allow
                  </button>
                </div>
              </div>

              {/* Denied groups */}
              <div>
                <p className="text-sm font-medium text-gray-700 mb-2">Denied Groups</p>
                <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
                  {draft.access.denied.map(g => (
                    <span key={g} className="flex items-center gap-1 bg-red-50 border border-red-200 text-red-700 text-xs px-2.5 py-1 rounded-full">
                      {g}
                      <button onClick={() => removeGroup('denied', g)} className="hover:text-red-700 ml-0.5">
                        <XMarkIcon className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                  {draft.access.denied.length === 0 && <p className="text-xs text-gray-400 italic">None</p>}
                </div>
                <div className="flex items-center gap-2">
                  <input value={deniedInput} onChange={e => setDeniedInput(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') addDenied(); }}
                    placeholder="Group name to deny"
                    className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                  <button onClick={addDenied} disabled={!deniedInput.trim()}
                    className="px-3 py-1.5 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg disabled:opacity-40">
                    Deny
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── Audit Policy ── */}
          {tab === 'audit' && (
            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <span className="text-sm font-medium text-gray-700">Audit Policy Active</span>
                <input type="checkbox" checked={draft.audit.enabled}
                  onChange={e => setAudit({ enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>
              <div className={`space-y-3 ${!draft.audit.enabled ? 'opacity-40 pointer-events-none' : ''}`}>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Audit Event Types</p>
                {([
                  { label: 'Logon / Logoff Events',       key: 'logonEvents' },
                  { label: 'Account Management',           key: 'accountManagement' },
                  { label: 'Policy Change',                key: 'policyChange' },
                  { label: 'Privilege Use',                key: 'privilegeUse' },
                  { label: 'Object Access',                key: 'objectAccess' },
                  { label: 'Process Tracking',             key: 'processTracking' },
                  { label: 'Directory Service Access',     key: 'directoryAccess' },
                  { label: 'System Events',                key: 'systemEvents' },
                ] as { label: string; key: keyof AuditSettings }[]).map(({ label, key }) => (
                  <label key={String(key)} className="flex items-center justify-between py-1 cursor-pointer">
                    <span className="text-sm text-gray-700">{label}</span>
                    <input type="checkbox" checked={draft.audit[key] as boolean}
                      onChange={e => setAudit({ [key]: e.target.checked })}
                      className="w-4 h-4 rounded text-blue-600" />
                  </label>
                ))}
                <div className="border-t border-gray-100 pt-3 space-y-3">
                  <div className="flex items-center justify-between py-1">
                    <span className="text-sm text-gray-700">Log Size (MB)</span>
                    <div className="flex items-center gap-2">
                      <input type="number" min={10} max={4096} value={draft.audit.logSize}
                        onChange={e => setAudit({ logSize: parseInt(e.target.value) || 100 })}
                        className="w-24 border border-gray-200 rounded px-2 py-1 text-sm text-center focus:outline-none focus:ring-1 focus:ring-blue-500" />
                      <span className="text-xs text-gray-400 w-20">MB (10–4096)</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between py-1">
                    <span className="text-sm text-gray-700">Retention (days)</span>
                    <div className="flex items-center gap-2">
                      <input type="number" min={0} max={365} value={draft.audit.retentionDays}
                        onChange={e => setAudit({ retentionDays: parseInt(e.target.value) || 0 })}
                        className="w-24 border border-gray-200 rounded px-2 py-1 text-sm text-center focus:outline-none focus:ring-1 focus:ring-blue-500" />
                      <span className="text-xs text-gray-400 w-20">days (0 = never)</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── Security Options ── */}
          {tab === 'security' && (
            <div className="space-y-5">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <span className="text-sm font-medium text-gray-700">Security Options Active</span>
                <input type="checkbox" checked={draft.securityOptions.enabled}
                  onChange={e => setSecOpts({ enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>
              <div className={`space-y-5 ${!draft.securityOptions.enabled ? 'opacity-40 pointer-events-none' : ''}`}>

                {/* SSH Hardening */}
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">SSH Hardening</p>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between py-1">
                      <span className="text-sm text-gray-700">Max Auth Tries</span>
                      <div className="flex items-center gap-2">
                        <input type="number" min={1} max={10} value={draft.securityOptions.sshMaxAuthTries}
                          onChange={e => setSecOpts({ sshMaxAuthTries: parseInt(e.target.value) || 3 })}
                          className="w-20 border border-gray-200 rounded px-2 py-1 text-sm text-center focus:outline-none focus:ring-1 focus:ring-blue-500" />
                        <span className="text-xs text-gray-400 w-16">attempts</span>
                      </div>
                    </div>
                    <label className="flex items-center justify-between py-1 cursor-pointer">
                      <span className="text-sm text-gray-700">Permit Root Login</span>
                      <input type="checkbox" checked={draft.securityOptions.sshPermitRootLogin}
                        onChange={e => setSecOpts({ sshPermitRootLogin: e.target.checked })}
                        className="w-4 h-4 rounded text-blue-600" />
                    </label>
                    <label className="flex items-center justify-between py-1 cursor-pointer">
                      <div>
                        <span className="text-sm text-gray-700">Allow Password Auth</span>
                        <p className="text-xs text-gray-400">Uncheck to enforce key-only authentication</p>
                      </div>
                      <input type="checkbox" checked={draft.securityOptions.sshPasswordAuth}
                        onChange={e => setSecOpts({ sshPasswordAuth: e.target.checked })}
                        className="w-4 h-4 rounded text-blue-600" />
                    </label>
                    <div>
                      <p className="text-sm text-gray-700 mb-2">SSH Allowed Groups</p>
                      <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
                        {draft.securityOptions.sshAllowGroups.map(g => (
                          <span key={g} className="flex items-center gap-1 bg-blue-50 border border-blue-200 text-blue-700 text-xs px-2.5 py-1 rounded-full">
                            {g}
                            <button onClick={() => setSecOpts({ sshAllowGroups: draft.securityOptions.sshAllowGroups.filter(x => x !== g) })} className="hover:text-red-500 ml-0.5">
                              <XMarkIcon className="w-3 h-3" />
                            </button>
                          </span>
                        ))}
                        {draft.securityOptions.sshAllowGroups.length === 0 && <p className="text-xs text-gray-400 italic">None (all groups allowed)</p>}
                      </div>
                      <div className="flex items-center gap-2">
                        <input value={sshGroupInput} onChange={e => setSshGroupInput(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter' && sshGroupInput.trim()) { setSecOpts({ sshAllowGroups: [...draft.securityOptions.sshAllowGroups, sshGroupInput.trim()] }); setSshGroupInput(''); } }}
                          placeholder="Group name"
                          className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                        <button onClick={() => { if (!sshGroupInput.trim()) return; setSecOpts({ sshAllowGroups: [...draft.securityOptions.sshAllowGroups, sshGroupInput.trim()] }); setSshGroupInput(''); }}
                          disabled={!sshGroupInput.trim()}
                          className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-40">
                          Add
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Session & Banner */}
                <div className="border-t border-gray-100 pt-4">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Session &amp; Banner</p>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between py-1">
                      <span className="text-sm text-gray-700">Session Timeout</span>
                      <div className="flex items-center gap-2">
                        <input type="number" min={0} max={480} value={draft.securityOptions.sessionTimeout}
                          onChange={e => setSecOpts({ sessionTimeout: parseInt(e.target.value) || 0 })}
                          className="w-20 border border-gray-200 rounded px-2 py-1 text-sm text-center focus:outline-none focus:ring-1 focus:ring-blue-500" />
                        <span className="text-xs text-gray-400 w-24">min (0 = never)</span>
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm text-gray-700 mb-1">Login Banner / MOTD</label>
                      <textarea value={draft.securityOptions.loginBannerText}
                        onChange={e => setSecOpts({ loginBannerText: e.target.value })}
                        rows={3}
                        placeholder="Authorized users only. All activity is monitored."
                        className="w-full border border-gray-200 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-500 resize-none" />
                    </div>
                  </div>
                </div>

                {/* Device Control */}
                <div className="border-t border-gray-100 pt-4">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Device Control</p>
                  <label className="flex items-center justify-between py-1 cursor-pointer">
                    <div>
                      <span className="text-sm text-gray-700">Block USB Storage Devices</span>
                      <p className="text-xs text-gray-400">Prevent mounting of removable USB drives</p>
                    </div>
                    <input type="checkbox" checked={draft.securityOptions.blockUsbStorage}
                      onChange={e => setSecOpts({ blockUsbStorage: e.target.checked })}
                      className="w-4 h-4 rounded text-blue-600" />
                  </label>
                </div>

                {/* Sudo Policy */}
                <div className="border-t border-gray-100 pt-4">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Sudo Policy</p>
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm text-gray-700 mb-2">NOPASSWD Groups</p>
                      <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
                        {draft.securityOptions.sudoNoPassword.map(g => (
                          <span key={g} className="flex items-center gap-1 bg-orange-50 border border-orange-200 text-orange-700 text-xs px-2.5 py-1 rounded-full">
                            {g}
                            <button onClick={() => setSecOpts({ sudoNoPassword: draft.securityOptions.sudoNoPassword.filter(x => x !== g) })} className="hover:text-red-500 ml-0.5">
                              <XMarkIcon className="w-3 h-3" />
                            </button>
                          </span>
                        ))}
                        {draft.securityOptions.sudoNoPassword.length === 0 && <p className="text-xs text-gray-400 italic">None</p>}
                      </div>
                      <div className="flex items-center gap-2">
                        <input value={sudoNoPwdInput} onChange={e => setSudoNoPwdInput(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter' && sudoNoPwdInput.trim()) { setSecOpts({ sudoNoPassword: [...draft.securityOptions.sudoNoPassword, sudoNoPwdInput.trim()] }); setSudoNoPwdInput(''); } }}
                          placeholder="Group name"
                          className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                        <button onClick={() => { if (!sudoNoPwdInput.trim()) return; setSecOpts({ sudoNoPassword: [...draft.securityOptions.sudoNoPassword, sudoNoPwdInput.trim()] }); setSudoNoPwdInput(''); }}
                          disabled={!sudoNoPwdInput.trim()}
                          className="px-3 py-1.5 text-sm font-medium text-white bg-orange-500 hover:bg-orange-600 rounded-lg disabled:opacity-40">
                          Add
                        </button>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm text-gray-700 mb-2">Password Required Groups</p>
                      <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
                        {draft.securityOptions.sudoWithPassword.map(g => (
                          <span key={g} className="flex items-center gap-1 bg-purple-50 border border-purple-200 text-purple-700 text-xs px-2.5 py-1 rounded-full">
                            {g}
                            <button onClick={() => setSecOpts({ sudoWithPassword: draft.securityOptions.sudoWithPassword.filter(x => x !== g) })} className="hover:text-red-500 ml-0.5">
                              <XMarkIcon className="w-3 h-3" />
                            </button>
                          </span>
                        ))}
                        {draft.securityOptions.sudoWithPassword.length === 0 && <p className="text-xs text-gray-400 italic">None</p>}
                      </div>
                      <div className="flex items-center gap-2">
                        <input value={sudoWithPwdInput} onChange={e => setSudoWithPwdInput(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter' && sudoWithPwdInput.trim()) { setSecOpts({ sudoWithPassword: [...draft.securityOptions.sudoWithPassword, sudoWithPwdInput.trim()] }); setSudoWithPwdInput(''); } }}
                          placeholder="Group name"
                          className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                        <button onClick={() => { if (!sudoWithPwdInput.trim()) return; setSecOpts({ sudoWithPassword: [...draft.securityOptions.sudoWithPassword, sudoWithPwdInput.trim()] }); setSudoWithPwdInput(''); }}
                          disabled={!sudoWithPwdInput.trim()}
                          className="px-3 py-1.5 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg disabled:opacity-40">
                          Add
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Time Sync */}
                <div className="border-t border-gray-100 pt-4">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Time Sync</p>
                  <div>
                    <label className="block text-sm text-gray-700 mb-1">NTP Server</label>
                    <input value={draft.securityOptions.ntpServer}
                      onChange={e => setSecOpts({ ntpServer: e.target.value })}
                      placeholder={AD_DOMAIN ? `ntp.${AD_DOMAIN}` : 'e.g. ntp.example.local'}
                      className="w-full border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── Firewall Rules ── */}
          {tab === 'firewall' && (
            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <span className="text-sm font-medium text-gray-700">Firewall Rules Active</span>
                <input type="checkbox" checked={draft.firewall.enabled}
                  onChange={e => setFirewall({ enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>
              <div className={`space-y-4 ${!draft.firewall.enabled ? 'opacity-40 pointer-events-none' : ''}`}>

                {/* Default policy */}
                <div className="flex items-center gap-4 p-3 bg-gray-50 rounded-lg">
                  <span className="text-sm font-medium text-gray-700 flex-shrink-0">Default Policy:</span>
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-500">Inbound</label>
                    <select value={draft.firewall.defaultInbound}
                      onChange={e => setFirewall({ defaultInbound: e.target.value as 'allow' | 'deny' })}
                      className="border border-gray-200 rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                      <option value="allow">Allow</option>
                      <option value="deny">Deny</option>
                    </select>
                  </div>
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-500">Outbound</label>
                    <select value={draft.firewall.defaultOutbound}
                      onChange={e => setFirewall({ defaultOutbound: e.target.value as 'allow' | 'deny' })}
                      className="border border-gray-200 rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                      <option value="allow">Allow</option>
                      <option value="deny">Deny</option>
                    </select>
                  </div>
                </div>

                {/* Rules list */}
                <div className="space-y-1.5">
                  {draft.firewall.rules.length === 0 && (
                    <p className="text-sm text-gray-400 italic px-1">No rules configured</p>
                  )}
                  {draft.firewall.rules.map(rule => (
                    <div key={rule.id} className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${rule.enabled ? 'bg-white border-gray-200' : 'bg-gray-50 border-gray-100 opacity-60'}`}>
                      <span className={`px-1.5 py-0.5 rounded font-medium flex-shrink-0 ${rule.direction === 'inbound' ? 'bg-blue-100 text-blue-700' : 'bg-purple-100 text-purple-700'}`}>
                        {rule.direction}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded font-medium flex-shrink-0 ${rule.action === 'allow' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                        {rule.action}
                      </span>
                      <span className="text-gray-500 flex-shrink-0">{rule.protocol}</span>
                      <span className="font-mono text-gray-700 flex-shrink-0">:{rule.port}</span>
                      <span className="text-gray-400 flex-shrink-0">from {rule.source}</span>
                      <span className="text-gray-500 truncate flex-1">{rule.description}</span>
                      <button onClick={() => toggleFirewallRule(rule.id)} className={`flex-shrink-0 ${rule.enabled ? 'text-green-500' : 'text-gray-300'} hover:text-blue-500`} title="Toggle rule">
                        <CheckCircleIcon className="w-4 h-4" />
                      </button>
                      <button onClick={() => removeFirewallRule(rule.id)} className="flex-shrink-0 text-gray-300 hover:text-red-500">
                        <XMarkIcon className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>

                {/* Add rule form */}
                <div className="border-t border-gray-100 pt-3">
                  <p className="text-xs font-medium text-gray-500 mb-2">Add Rule</p>
                  <div className="grid grid-cols-2 gap-2 mb-2">
                    <select value={newRule.direction} onChange={e => setNewRule(r => ({ ...r, direction: e.target.value as FirewallRule['direction'] }))}
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                      <option value="inbound">Inbound</option>
                      <option value="outbound">Outbound</option>
                    </select>
                    <select value={newRule.action} onChange={e => setNewRule(r => ({ ...r, action: e.target.value as FirewallRule['action'] }))}
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                      <option value="allow">Allow</option>
                      <option value="deny">Deny</option>
                    </select>
                    <select value={newRule.protocol} onChange={e => setNewRule(r => ({ ...r, protocol: e.target.value as FirewallRule['protocol'] }))}
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      <option value="icmp">ICMP</option>
                      <option value="any">Any</option>
                    </select>
                    <input value={newRule.port} onChange={e => setNewRule(r => ({ ...r, port: e.target.value }))}
                      placeholder='Port (e.g. "22" or "80,443")'
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                    <input value={newRule.source} onChange={e => setNewRule(r => ({ ...r, source: e.target.value }))}
                      placeholder='Source IP/CIDR or "*"'
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                    <input value={newRule.description} onChange={e => setNewRule(r => ({ ...r, description: e.target.value }))}
                      placeholder="Description"
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                  </div>
                  <button onClick={addFirewallRule} disabled={!newRule.port.trim()}
                    className="w-full px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-40">
                    Add Rule
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── System Services ── */}
          {tab === 'services' && (
            <div className="space-y-4">
              <label className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer">
                <span className="text-sm font-medium text-gray-700">System Services Active</span>
                <input type="checkbox" checked={draft.systemServices.enabled}
                  onChange={e => setDraft(d => ({ ...d, systemServices: { ...d.systemServices, enabled: e.target.checked } }))}
                  className="w-4 h-4 rounded text-blue-600" />
              </label>
              <div className={`space-y-1.5 ${!draft.systemServices.enabled ? 'opacity-40 pointer-events-none' : ''}`}>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider px-1">Common Services</p>
                {DEFAULT_SERVICES.map(svc => (
                  <div key={svc.id} className="flex items-center justify-between px-3 py-2 bg-gray-50 rounded-lg">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-gray-800">{svc.displayName}</p>
                      <p className="text-xs text-gray-400 font-mono">{svc.name}</p>
                    </div>
                    <select value={getServiceStartup(svc.id)}
                      onChange={e => setServiceStartup(svc.id, svc.name, svc.displayName, e.target.value as ServiceEntry['startupType'])}
                      className="ml-4 border border-gray-200 rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 flex-shrink-0">
                      <option value="manual">Manual (no change)</option>
                      <option value="enabled">Enabled (start on boot)</option>
                      <option value="disabled">Disabled (stop + disable)</option>
                    </select>
                  </div>
                ))}

                {/* Custom services */}
                {draft.systemServices.services.filter(s => !DEFAULT_SERVICES.find(d => d.id === s.id)).map(svc => (
                  <div key={svc.id} className="flex items-center justify-between px-3 py-2 bg-blue-50 rounded-lg">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-gray-800">{svc.displayName}</p>
                      <p className="text-xs text-gray-400 font-mono">{svc.name}</p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                      <select value={svc.startupType}
                        onChange={e => setDraft(d => ({ ...d, systemServices: { ...d.systemServices, services: d.systemServices.services.map(x => x.id === svc.id ? { ...x, startupType: e.target.value as ServiceEntry['startupType'] } : x) } }))}
                        className="border border-gray-200 rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                        <option value="manual">Manual</option>
                        <option value="enabled">Enabled</option>
                        <option value="disabled">Disabled</option>
                      </select>
                      <button onClick={() => setDraft(d => ({ ...d, systemServices: { ...d.systemServices, services: d.systemServices.services.filter(x => x.id !== svc.id) } }))} className="text-gray-400 hover:text-red-500">
                        <XMarkIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}

                {/* Add custom service */}
                <div className="border-t border-gray-100 pt-3">
                  <p className="text-xs font-medium text-gray-500 mb-2">Add Custom Service</p>
                  <div className="flex items-center gap-2">
                    <input value={newSvc.name} onChange={e => setNewSvc(s => ({ ...s, name: e.target.value }))}
                      placeholder="Service name (systemd)"
                      className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-500" />
                    <input value={newSvc.displayName} onChange={e => setNewSvc(s => ({ ...s, displayName: e.target.value }))}
                      placeholder="Display name"
                      className="flex-1 border border-gray-200 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                    <select value={newSvc.startupType} onChange={e => setNewSvc(s => ({ ...s, startupType: e.target.value as ServiceEntry['startupType'] }))}
                      className="border border-gray-200 rounded px-2 py-1.5 text-sm focus:outline-none">
                      <option value="enabled">Enabled</option>
                      <option value="disabled">Disabled</option>
                      <option value="manual">Manual</option>
                    </select>
                    <button onClick={addCustomService} disabled={!newSvc.name.trim()}
                      className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-40">
                      Add
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
        </div>{/* end two-column body */}

        {/* Footer */}
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-gray-100 flex-shrink-0">
          <button onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
            Cancel
          </button>
          <button onClick={handleSave}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg">
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── GPO Templates ─────────────────────────────────────────────────────────────

interface GPOTemplate {
  id: string;
  name: string;
  description: string;
  category: 'security' | 'compliance' | 'software' | 'access' | 'blank';
  color: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  tags: string[];
  defaults: {
    password?: Partial<PasswordSettings>;
    device?: Partial<DeviceSettings>;
    software?: SoftwareSettings;
    scripts?: Partial<ScriptSettings>;
    access?: Partial<AccessSettings>;
  };
}

const CATEGORY_CHIP: Record<string, string> = {
  security:   'bg-red-50 text-red-700 border-red-100',
  compliance: 'bg-indigo-50 text-indigo-700 border-indigo-100',
  software:   'bg-emerald-50 text-emerald-700 border-emerald-100',
  access:     'bg-purple-50 text-purple-700 border-purple-100',
  blank:      'bg-gray-50 text-gray-600 border-gray-200',
};

const GPO_TEMPLATES: GPOTemplate[] = [
  {
    id: 'tpl-blank',
    name: 'Blank Policy',
    description: 'Start from scratch — no pre-configured settings.',
    category: 'blank',
    color: 'bg-gray-200',
    icon: DocumentTextIcon,
    tags: [],
    defaults: {},
  },
  {
    id: 'tpl-default-domain',
    name: 'Default Domain Policy',
    description: 'Standard domain-wide password + lockout policy — equivalent to AD Default Domain Policy.',
    category: 'security',
    color: 'bg-blue-600',
    icon: ShieldCheckIcon,
    tags: ['Password', 'Lockout', 'Domain-wide'],
    defaults: {
      password: { enabled: true, minLength: 12, complexity: true, history: 10, expiryDays: 90, lockoutAttempts: 5, lockoutDuration: 30 },
      access:   { allowed: ['*'], denied: [], mfaRequired: false },
    },
  },
  {
    id: 'tpl-server-hardening',
    name: 'Server Hardening (CIS L1)',
    description: 'CIS Benchmark Level 1 for Linux servers: strong passwords, disk encryption, AV, hardening script.',
    category: 'security',
    color: 'bg-red-600',
    icon: LockClosedIcon,
    tags: ['CIS', 'Servers', 'Encryption', 'AV'],
    defaults: {
      password: { enabled: true, minLength: 14, complexity: true, history: 12, expiryDays: 90, lockoutAttempts: 3, lockoutDuration: 30 },
      device:   { enabled: true, requireEncryption: true, requireScreenLock: true, requireAV: true, minOsVersion: '', allowedPlatforms: ['linux'] },
      scripts:  { startup: ['/etc/security/cis-apply.sh'], shutdown: [], logon: [], logoff: [] },
    },
  },
  {
    id: 'tpl-workstation-standard',
    name: 'Workstation Standard',
    description: 'Baseline for all workstations: password policy, screen lock, disk encryption.',
    category: 'compliance',
    color: 'bg-indigo-600',
    icon: ComputerDesktopIcon,
    tags: ['Workstations', 'Screen Lock', 'Encryption'],
    defaults: {
      password: { enabled: true, minLength: 10, complexity: true, history: 5, expiryDays: 90, lockoutAttempts: 5, lockoutDuration: 15 },
      device:   { enabled: true, requireEncryption: true, requireScreenLock: true, requireAV: false, minOsVersion: '', allowedPlatforms: ['linux', 'macos', 'windows'] },
      access:   { allowed: ['*'], denied: [], mfaRequired: false },
    },
  },
  {
    id: 'tpl-developer',
    name: 'Developer Workstation',
    description: 'Pre-installs git, Docker, VS Code and Node.js. Disk encryption required.',
    category: 'software',
    color: 'bg-emerald-600',
    icon: CommandLineIcon,
    tags: ['Dev Tools', 'Docker', 'Node.js'],
    defaults: {
      device:   { enabled: true, requireEncryption: true, requireScreenLock: false, requireAV: false, minOsVersion: '', allowedPlatforms: ['linux', 'macos'] },
      software: { packages: [
        { id: 'tpl-git',    name: 'git',       version: 'latest', action: 'install' },
        { id: 'tpl-docker', name: 'docker-ce', version: 'latest', action: 'install' },
        { id: 'tpl-vsc',    name: 'vscode',    version: 'latest', action: 'install' },
        { id: 'tpl-node',   name: 'nodejs',    version: '20.x',   action: 'install' },
      ]},
      access: { allowed: ['developers', 'admins'], denied: [], mfaRequired: false },
    },
  },
  {
    id: 'tpl-admin-mfa',
    name: 'Admin MFA Enforcement',
    description: 'Forces MFA and strong 16-char passwords for all administrator accounts. No expiry.',
    category: 'access',
    color: 'bg-purple-600',
    icon: UserGroupIcon,
    tags: ['MFA', 'Admins', 'High Security'],
    defaults: {
      password: { enabled: true, minLength: 16, complexity: true, history: 15, expiryDays: 0, lockoutAttempts: 3, lockoutDuration: 60 },
      access:   { allowed: ['admins', 'Domain Admins'], denied: [], mfaRequired: true },
    },
  },
  {
    id: 'tpl-endpoint-security',
    name: 'Endpoint Security (EDR)',
    description: 'Deploys Wazuh Agent + ClamAV. Enforces encryption, screen lock and AV compliance.',
    category: 'security',
    color: 'bg-orange-500',
    icon: ShieldCheckIcon,
    tags: ['EDR', 'Wazuh', 'ClamAV'],
    defaults: {
      device:   { enabled: true, requireEncryption: true, requireScreenLock: true, requireAV: true, minOsVersion: '', allowedPlatforms: ['linux', 'macos', 'windows'] },
      software: { packages: [
        { id: 'tpl-wazuh',  name: 'wazuh-agent', version: '4.8.0', action: 'install' },
        { id: 'tpl-clamav', name: 'clamav',       version: '1.4.0', action: 'install' },
      ]},
      access: { allowed: ['*'], denied: [], mfaRequired: false },
    },
  },
  {
    id: 'tpl-software-base',
    name: 'Base Software Deployment',
    description: 'Installs common productivity apps: Firefox, LibreOffice, KeePassXC, Virt-Manager.',
    category: 'software',
    color: 'bg-teal-600',
    icon: CubeIcon,
    tags: ['Firefox', 'LibreOffice', 'KeePass'],
    defaults: {
      software: { packages: [
        { id: 'tpl-ff', name: 'firefox',      version: 'latest', action: 'install' },
        { id: 'tpl-lo', name: 'libreoffice',  version: '7.6',    action: 'install' },
        { id: 'tpl-kp', name: 'keepassxc',    version: 'latest', action: 'install' },
        { id: 'tpl-vm', name: 'virt-manager', version: 'latest', action: 'install' },
      ]},
    },
  },
  {
    id: 'tpl-remote-access',
    name: 'Remote Access Policy',
    description: 'Enforces MFA and 60-day password expiry for VPN / remote workers.',
    category: 'access',
    color: 'bg-cyan-600',
    icon: Cog6ToothIcon,
    tags: ['VPN', 'MFA', 'Remote Workers'],
    defaults: {
      password: { enabled: true, minLength: 12, complexity: true, history: 10, expiryDays: 60, lockoutAttempts: 5, lockoutDuration: 30 },
      access:   { allowed: ['vpn-users', 'admins'], denied: [], mfaRequired: true },
    },
  },
];

// Helper: create a blank GPO skeleton
function blankGPO(name: string, desc: string, linkedOU: string): GPO {
  return {
    id: 'gpo-' + Date.now(),
    name,
    description: desc,
    status: 'enabled',
    linkedOUs: linkedOU ? [linkedOU] : [],
    createdAt: new Date().toISOString(),
    modifiedAt: new Date().toISOString(),
    version: 1,
    password: { enabled: false, minLength: 12, complexity: true, history: 10, expiryDays: 90, lockoutAttempts: 5, lockoutDuration: 30 },
    device:   { enabled: false, requireEncryption: false, requireScreenLock: false, requireAV: false, minOsVersion: '', allowedPlatforms: ['linux', 'macos', 'windows'] },
    software: { packages: [] },
    scripts:  { startup: [], shutdown: [], logon: [], logoff: [] },
    access:   { allowed: [], denied: [], mfaRequired: false },
    audit:    { enabled: false, logonEvents: false, accountManagement: false, policyChange: false, privilegeUse: false, objectAccess: false, processTracking: false, directoryAccess: false, systemEvents: false, logSize: 100, retentionDays: 30 },
    securityOptions: { enabled: false, sshMaxAuthTries: 3, sshPermitRootLogin: false, sshPasswordAuth: false, sshAllowGroups: [], sessionTimeout: 30, loginBannerText: '', blockUsbStorage: false, sudoNoPassword: [], sudoWithPassword: [], ntpServer: '' },
    firewall: { enabled: false, defaultInbound: 'deny', defaultOutbound: 'allow', rules: [] },
    systemServices: { enabled: false, services: [] },
  };
}

// Merge template defaults onto a blank GPO
function applyTemplate(base: GPO, tmpl: GPOTemplate): GPO {
  const d = tmpl.defaults;
  return {
    ...base,
    password: d.password ? { ...base.password, ...d.password } : base.password,
    device:   d.device   ? { ...base.device,   ...d.device   } : base.device,
    software: d.software ?? base.software,
    scripts:  d.scripts  ? { ...base.scripts,  ...d.scripts  } : base.scripts,
    access:   d.access   ? { ...base.access,   ...d.access   } : base.access,
  };
}

// Human-readable summary lines for a template
function templatePreviewLines(tmpl: GPOTemplate): string[] {
  const d = tmpl.defaults;
  const lines: string[] = [];
  if (d.password?.enabled) {
    lines.push(`Password: ≥${d.password.minLength} chars, ${d.password.expiryDays === 0 ? 'no expiry' : `${d.password.expiryDays}d expiry`}, lockout after ${d.password.lockoutAttempts} attempts`);
  }
  if (d.device?.enabled) {
    const parts: string[] = [];
    if (d.device.requireEncryption) parts.push('disk encryption');
    if (d.device.requireScreenLock) parts.push('screen lock');
    if (d.device.requireAV)         parts.push('AV/EDR required');
    if (parts.length) lines.push(`Device compliance: ${parts.join(', ')}`);
  }
  if (d.software?.packages?.length) {
    lines.push(`Software: ${d.software.packages.map(p => p.name).join(', ')}`);
  }
  if (d.scripts?.startup?.length) {
    lines.push(`Startup script: ${d.scripts.startup[0]}`);
  }
  if (d.access?.mfaRequired) lines.push('MFA required for all users');
  if (d.access?.allowed?.length && d.access.allowed[0] !== '*') {
    lines.push(`Allowed groups: ${d.access.allowed.join(', ')}`);
  }
  return lines;
}

// ─── GPO Creation Wizard ────────────────────────────────────────────────────────

function GPOWizard({ ous, onClose, onSave }: {
  ous: OU[];
  onClose: () => void;
  onSave: (gpo: GPO) => void;
}) {
  const [step, setStep]         = useState(1);
  const [template, setTemplate] = useState<GPOTemplate | null>(null);
  const [name, setName]         = useState('');
  const [desc, setDesc]         = useState('');
  const [linkedOU, setLinkedOU] = useState('');

  const flatOUs = (list: OU[]): OU[] =>
    list.flatMap(o => [o, ...(o.children ? flatOUs(o.children) : [])]);
  const allOUs = flatOUs(ous);

  const pickTemplate = (tmpl: GPOTemplate) => {
    const isBlank  = tmpl.id === 'tpl-blank';
    const oldName  = template && template.id !== 'tpl-blank' ? template.name        : '';
    const oldDesc  = template && template.id !== 'tpl-blank' ? template.description : '';
    if (!name || name === oldName) setName(isBlank ? '' : tmpl.name);
    if (!desc || desc === oldDesc) setDesc(isBlank ? '' : tmpl.description);
    setTemplate(tmpl);
    setStep(2);
  };

  const handleCreate = () => {
    if (!name.trim()) { toast.error('GPO name is required'); return; }
    const base = blankGPO(name.trim(), desc, linkedOU);
    const gpo  = template ? applyTemplate(base, template) : base;
    onSave(gpo);
    onClose();
  };

  const STEP_LABELS = ['Template', 'Configure', 'Review'];
  const previewLines = template ? templatePreviewLines(template) : [];
  // Compute icon component once (must be capitalized for JSX)
  const TplIcon = template && template.id !== 'tpl-blank' ? template.icon : null;

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-50"
         onClick={onClose}>
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col"
           onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 flex-shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">New Group Policy Object</h2>
            <p className="text-sm text-gray-500">
              {step === 1 ? 'Choose a template to start from'
             : step === 2 ? 'Name and link your policy'
             :              'Review settings before creating'}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center px-6 py-3 bg-gray-50 border-b border-gray-100 flex-shrink-0">
          {STEP_LABELS.map((label, i) => {
            const n      = i + 1;
            const active = step === n;
            const done   = step > n;
            return (
              <React.Fragment key={label}>
                <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                  active ? 'bg-blue-600 text-white'
                : done   ? 'bg-green-100 text-green-700'
                :          'text-gray-400'
                }`}>
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center text-xs leading-none font-bold ${
                    active ? 'bg-white text-blue-600'
                  : done   ? 'bg-green-500 text-white'
                  :          'bg-gray-200 text-gray-500'
                  }`}>
                    {done ? '✓' : n}
                  </span>
                  {label}
                </div>
                {i < 2 && (
                  <div className={`flex-1 h-px mx-2 ${step > n ? 'bg-green-300' : 'bg-gray-200'}`} />
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">

          {/* ── Step 1: Template Grid ── */}
          {step === 1 && (
            <div className="p-6 grid grid-cols-3 gap-3">
              {GPO_TEMPLATES.map(tmpl => {
                const Icon     = tmpl.icon;
                const isBlank  = tmpl.id === 'tpl-blank';
                const selected = template?.id === tmpl.id;
                return (
                  <button
                    key={tmpl.id}
                    onClick={() => pickTemplate(tmpl)}
                    className={`text-left rounded-xl border-2 overflow-hidden transition-all hover:shadow-md ${
                      selected
                        ? 'border-blue-500 shadow-md ring-2 ring-blue-100'
                        : 'border-gray-100 hover:border-blue-200'
                    }`}
                  >
                    <div className={`px-4 py-3 flex items-center gap-2 ${isBlank ? 'bg-gray-100' : tmpl.color}`}>
                      <Icon className={`w-5 h-5 flex-shrink-0 ${isBlank ? 'text-gray-500' : 'text-white'}`} />
                      <span className={`text-sm font-semibold truncate ${isBlank ? 'text-gray-700' : 'text-white'}`}>
                        {tmpl.name}
                      </span>
                    </div>
                    <div className="px-4 py-3 bg-white min-h-[80px]">
                      <p className="text-xs text-gray-500 leading-relaxed mb-2 line-clamp-2">
                        {tmpl.description}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {tmpl.tags.slice(0, 3).map(t => (
                          <span key={t}
                            className={`text-xs px-1.5 py-0.5 rounded border ${CATEGORY_CHIP[tmpl.category]}`}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}

          {/* ── Step 2: Configure ── */}
          {step === 2 && (
            <div className="p-6">
              <div className="max-w-lg mx-auto space-y-5">

                {/* Template badge */}
                {TplIcon && template && (
                  <div className={`flex items-start gap-3 p-3 rounded-lg border ${CATEGORY_CHIP[template.category]}`}>
                    <TplIcon className="w-5 h-5 flex-shrink-0 mt-0.5" />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold">{template.name}</p>
                      {previewLines.length > 0 && (
                        <p className="text-xs opacity-75 mt-0.5 leading-relaxed">
                          {previewLines.slice(0, 2).join(' · ')}
                        </p>
                      )}
                    </div>
                    <button onClick={() => setStep(1)}
                      className="flex-shrink-0 text-xs underline opacity-60 hover:opacity-100">
                      Change
                    </button>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                    GPO Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    value={name}
                    onChange={e => setName(e.target.value)}
                    autoFocus
                    placeholder="e.g. Marketing Department Policy"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                    Description
                  </label>
                  <textarea
                    value={desc}
                    onChange={e => setDesc(e.target.value)}
                    rows={2}
                    placeholder="Describe the purpose of this policy…"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                    Link to OU / Group
                  </label>
                  <select
                    value={linkedOU}
                    onChange={e => setLinkedOU(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">— Not linked —</option>
                    {allOUs.map(ou => (
                      <option key={ou.id} value={ou.id}>{ou.name}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* ── Step 3: Review ── */}
          {step === 3 && (
            <div className="p-6">
              <div className="max-w-lg mx-auto space-y-4">

                {/* Summary grid */}
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: 'GPO Name',  value: name },
                    { label: 'Template',  value: template?.name ?? 'Blank' },
                    { label: 'Status',    value: 'Enabled' },
                    { label: 'Linked OU', value: allOUs.find(o => o.id === linkedOU)?.name || '— Not linked —' },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-gray-50 rounded-lg px-3 py-2.5 border border-gray-100">
                      <p className="text-xs text-gray-400 mb-0.5">{label}</p>
                      <p className="text-sm font-semibold text-gray-900 truncate">{value}</p>
                    </div>
                  ))}
                </div>

                {desc && (
                  <div className="bg-gray-50 rounded-lg px-3 py-2.5 border border-gray-100">
                    <p className="text-xs text-gray-400 mb-0.5">Description</p>
                    <p className="text-sm text-gray-700">{desc}</p>
                  </div>
                )}

                {/* Pre-configured settings */}
                {previewLines.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                      Pre-configured Settings
                    </p>
                    <div className="space-y-1.5">
                      {previewLines.map((line, i) => (
                        <div key={i} className="flex items-start gap-2 px-3 py-2 bg-blue-50 rounded-lg">
                          <CheckCircleIcon className="w-4 h-4 text-blue-500 flex-shrink-0 mt-0.5" />
                          <span className="text-sm text-blue-800">{line}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Software packages */}
                {(template?.defaults.software?.packages?.length ?? 0) > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                      Software Packages
                    </p>
                    <div className="space-y-1">
                      {template!.defaults.software!.packages.map(pkg => (
                        <div key={pkg.id} className="flex items-center gap-2 px-3 py-2 bg-emerald-50 rounded-lg">
                          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                            pkg.action === 'install'
                              ? 'bg-emerald-200 text-emerald-800'
                              : 'bg-red-100 text-red-700'
                          }`}>
                            {pkg.action}
                          </span>
                          <span className="text-sm font-medium text-emerald-900">{pkg.name}</span>
                          <span className="text-xs text-emerald-600 ml-auto">{pkg.version}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <p className="text-xs text-gray-400 text-center pt-1">
                  All settings can be fine-tuned after creation via the Edit button.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-100 flex-shrink-0">
          <button
            onClick={step === 1 ? onClose : () => setStep(s => s - 1)}
            className="px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-800 transition-colors"
          >
            {step === 1 ? 'Cancel' : '← Back'}
          </button>
          <div className="flex items-center gap-3">
            {step === 2 && (
              <button
                onClick={() => setStep(3)}
                disabled={!name.trim()}
                className="px-5 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg
                           disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Review →
              </button>
            )}
            {step === 3 && (
              <button
                onClick={handleCreate}
                className="px-5 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg transition-colors"
              >
                Create GPO
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── GPO Detail Panel ──────────────────────────────────────────────────────────

function GPODetail({ gpo, ous, onToggle, onDelete, onEdit, onCopy, onExport, onRSoP }: {
  gpo: GPO;
  ous: OU[];
  onToggle: () => void;
  onDelete: () => void;
  onEdit: () => void;
  onCopy: () => void;
  onExport: () => void;
  onRSoP: () => void;
}) {
  const [tab, setTab] = useState<GPOTab>('settings');

  const flatOUs = (list: OU[]): OU[] => list.flatMap(o => [o, ...(o.children ? flatOUs(o.children) : [])]);
  const allOUs = flatOUs(ous);
  const linkedOUNames = gpo.linkedOUs.map(id => allOUs.find(o => o.id === id)?.name || id);

  const tabs: { key: GPOTab; label: string }[] = [
    { key: 'general', label: 'General' },
    { key: 'scope', label: 'Scope' },
    { key: 'settings', label: 'Settings' },
    { key: 'delegation', label: 'Delegation' },
  ];

  return (
    <div className="flex flex-col h-full">
      {/* GPO Header */}
      <div className="flex items-start justify-between p-4 border-b border-gray-100">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
            gpo.status === 'enabled' ? 'bg-blue-50' : 'bg-gray-100'
          }`}>
            <DocumentTextIcon className={`w-6 h-6 ${gpo.status === 'enabled' ? 'text-blue-600' : 'text-gray-400'}`} />
          </div>
          <div>
            <h3 className="text-base font-semibold text-gray-900">{gpo.name}</h3>
            <div className="flex items-center gap-2 mt-0.5">
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                gpo.status === 'enabled' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
              }`}>
                {gpo.status === 'enabled' ? <CheckCircleIcon className="w-3 h-3" /> : <XCircleIcon className="w-3 h-3" />}
                {gpo.status === 'enabled' ? 'Enabled' : 'Disabled'}
              </span>
              <span className="text-xs text-gray-500">v{gpo.version} · {countSettings(gpo)} settings</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1 flex-wrap">
          <button onClick={onToggle}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              gpo.status === 'enabled'
                ? 'text-yellow-700 bg-yellow-50 hover:bg-yellow-100'
                : 'text-green-700 bg-green-50 hover:bg-green-100'
            }`}>
            {gpo.status === 'enabled' ? 'Disable' : 'Enable'}
          </button>
          <button onClick={onEdit}
            className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg"
            title="Edit GPO settings">
            <PencilIcon className="w-3.5 h-3.5" />
          </button>
          <button onClick={onCopy}
            className="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg"
            title="Copy GPO">
            <DocumentDuplicateIcon className="w-3.5 h-3.5" />
          </button>
          <button onClick={onExport}
            className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg"
            title="Export GPO as JSON">
            <ArrowDownTrayIcon className="w-3.5 h-3.5" />
          </button>
          <button onClick={onRSoP}
            className="px-3 py-1.5 text-xs font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg flex items-center gap-1"
            title="Resultant Set of Policy">
            <CalculatorIcon className="w-3.5 h-3.5" />
            <span>RSoP</span>
          </button>
          <button onClick={onDelete}
            className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg">
            <TrashIcon className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-100 px-4">
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`py-2 px-3 text-sm font-medium border-b-2 transition-colors ${
              tab === t.key ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-4">
        {/* ── General ── */}
        {tab === 'general' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'GPO Name', value: gpo.name },
                { label: 'Status', value: gpo.status === 'enabled' ? 'Enabled' : 'Disabled' },
                { label: 'Version', value: String(gpo.version) },
                { label: 'Settings', value: String(countSettings(gpo)) },
                { label: 'Created', value: fmtDate(gpo.createdAt) },
                { label: 'Last Modified', value: fmtDate(gpo.modifiedAt) },
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-50 rounded-lg px-3 py-2.5">
                  <p className="text-xs text-gray-500 mb-0.5">{label}</p>
                  <p className="text-sm font-medium text-gray-900">{value}</p>
                </div>
              ))}
            </div>
            {gpo.description && (
              <div className="bg-gray-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-gray-500 mb-0.5">Description</p>
                <p className="text-sm text-gray-700">{gpo.description}</p>
              </div>
            )}
          </div>
        )}

        {/* ── Scope ── */}
        {tab === 'scope' && (
          <div className="space-y-4">
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
                <LinkIcon className="w-3.5 h-3.5" /> Links
              </p>
              {linkedOUNames.length > 0 ? (
                <div className="space-y-1">
                  {linkedOUNames.map(name => (
                    <div key={name} className="flex items-center gap-2 px-3 py-2 bg-blue-50 border border-blue-100 rounded-lg">
                      <FolderOpenIcon className="w-4 h-4 text-blue-500" />
                      <span className="text-sm text-blue-800">{name}</span>
                      <span className="ml-auto text-xs text-blue-500">Linked</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-gray-400 italic">This GPO is not linked to any OU or group.</p>
              )}
            </div>
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Security Filtering</p>
              <div className="space-y-1">
                {gpo.access.allowed.map(g => (
                  <div key={g} className="flex items-center gap-2 px-3 py-2 bg-green-50 border border-green-100 rounded-lg">
                    <UserGroupIcon className="w-4 h-4 text-green-600" />
                    <span className="text-sm text-green-800">{g === '*' ? 'Authenticated Users (All)' : g}</span>
                    <span className="ml-auto text-xs text-green-600">Allow</span>
                  </div>
                ))}
                {gpo.access.denied.map(g => (
                  <div key={g} className="flex items-center gap-2 px-3 py-2 bg-red-50 border border-red-100 rounded-lg">
                    <UserGroupIcon className="w-4 h-4 text-red-500" />
                    <span className="text-sm text-red-700">{g}</span>
                    <span className="ml-auto text-xs text-red-500">Deny</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Settings ── */}
        {tab === 'settings' && (
          <div className="space-y-1">
            {/* Computer Configuration */}
            <TreeSection title="Computer Configuration" icon={ComputerDesktopIcon}>
              <TreeSection title="Software Settings" icon={CubeIcon} defaultOpen={gpo.software.packages.length > 0}>
                <div className="py-1">
                  <p className="text-xs font-medium text-gray-500 px-2 mb-1">Software Installation</p>
                  {gpo.software.packages.length > 0 ? (
                    gpo.software.packages.map(pkg => (
                      <div key={pkg.id} className="flex items-center justify-between py-1.5 px-2 hover:bg-gray-50 rounded text-sm">
                        <span className="text-gray-600">{pkg.name}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                          pkg.action === 'install' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                        }`}>{pkg.action} v{pkg.version}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-gray-400 italic px-2">No packages configured</p>
                  )}
                </div>
              </TreeSection>

              <TreeSection title="System Settings" icon={Cog6ToothIcon}>
                <TreeSection title="Security Settings" icon={ShieldCheckIcon} defaultOpen={gpo.password.enabled}>
                  <TreeSection title="Account Policies" icon={LockClosedIcon} defaultOpen={gpo.password.enabled}>
                    <div className="ml-2">
                      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-2 py-1">Password Policy</p>
                      <BoolRow label="Password Policy" value={gpo.password.enabled} />
                      {gpo.password.enabled && (<>
                        <SettingRow label="Minimum password length" value={`${gpo.password.minLength} characters`} />
                        <SettingRow label="Enforce password history" value={`${gpo.password.history} passwords`} />
                        <SettingRow label="Password complexity" value={gpo.password.complexity ? 'Enabled' : 'Disabled'} />
                        <SettingRow label="Maximum password age" value={gpo.password.expiryDays > 0 ? `${gpo.password.expiryDays} days` : 'Never'} />
                        <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-2 py-1 mt-1">Account Lockout Policy</p>
                        <SettingRow label="Account lockout threshold" value={`${gpo.password.lockoutAttempts} attempts`} />
                        <SettingRow label="Lockout duration" value={`${gpo.password.lockoutDuration} minutes`} />
                      </>)}
                    </div>
                  </TreeSection>
                  <TreeSection title="Device Compliance" icon={ComputerDesktopIcon} defaultOpen={gpo.device.enabled}>
                    <BoolRow label="Device Compliance Policy" value={gpo.device.enabled} />
                    {gpo.device.enabled && (<>
                      <BoolRow label="Require disk encryption" value={gpo.device.requireEncryption} />
                      <BoolRow label="Require screen lock / PIN" value={gpo.device.requireScreenLock} />
                      <BoolRow label="Require antivirus / EDR" value={gpo.device.requireAV} />
                      <SettingRow label="Minimum OS version"
                        value={gpo.device.minOsVersion || '—'}
                        configured={!!gpo.device.minOsVersion} />
                    </>)}
                  </TreeSection>
                </TreeSection>

                <TreeSection title="Scripts (Startup/Shutdown)" icon={CommandLineIcon}
                  defaultOpen={gpo.scripts.startup.length > 0 || gpo.scripts.shutdown.length > 0}>
                  {gpo.scripts.startup.length > 0
                    ? gpo.scripts.startup.map(s => <SettingRow key={s} label="Startup" value={s} />)
                    : <SettingRow label="Startup scripts" value="" configured={false} />}
                  {gpo.scripts.shutdown.length > 0
                    ? gpo.scripts.shutdown.map(s => <SettingRow key={s} label="Shutdown" value={s} />)
                    : <SettingRow label="Shutdown scripts" value="" configured={false} />}
                </TreeSection>

                <TreeSection title="Administrative Templates" icon={Cog6ToothIcon} defaultOpen={false}>
                  <SettingRow label="System settings" value="" configured={false} />
                  <SettingRow label="Network settings" value="" configured={false} />
                </TreeSection>

                <TreeSection title="Audit Policy" icon={ClipboardDocumentListIcon} defaultOpen={gpo.audit?.enabled}>
                  <BoolRow label="Audit Policy Active" value={gpo.audit?.enabled ?? false} />
                  {gpo.audit?.enabled && (<>
                    <BoolRow label="Logon / Logoff Events"      value={gpo.audit.logonEvents} />
                    <BoolRow label="Account Management"          value={gpo.audit.accountManagement} />
                    <BoolRow label="Policy Change"               value={gpo.audit.policyChange} />
                    <BoolRow label="Privilege Use"               value={gpo.audit.privilegeUse} />
                    <BoolRow label="Object Access"               value={gpo.audit.objectAccess} />
                    <BoolRow label="Process Tracking"            value={gpo.audit.processTracking} />
                    <BoolRow label="Directory Service Access"    value={gpo.audit.directoryAccess} />
                    <BoolRow label="System Events"               value={gpo.audit.systemEvents} />
                    <SettingRow label="Log Size"          value={`${gpo.audit.logSize} MB`} />
                    <SettingRow label="Retention"         value={gpo.audit.retentionDays === 0 ? 'Never delete' : `${gpo.audit.retentionDays} days`} />
                  </>)}
                </TreeSection>

                <TreeSection title="Security Options" icon={LockClosedIcon} defaultOpen={gpo.securityOptions?.enabled}>
                  <BoolRow label="Security Options Active" value={gpo.securityOptions?.enabled ?? false} />
                  {gpo.securityOptions?.enabled && (<>
                    <SettingRow label="SSH Max Auth Tries"  value={String(gpo.securityOptions.sshMaxAuthTries)} />
                    <BoolRow label="SSH Permit Root Login"  value={gpo.securityOptions.sshPermitRootLogin} />
                    <BoolRow label="SSH Password Auth"      value={gpo.securityOptions.sshPasswordAuth} />
                    <SettingRow label="Session Timeout"     value={gpo.securityOptions.sessionTimeout === 0 ? 'Never' : `${gpo.securityOptions.sessionTimeout} min`} />
                    <BoolRow label="Block USB Storage"      value={gpo.securityOptions.blockUsbStorage} />
                    {gpo.securityOptions.ntpServer && (
                      <SettingRow label="NTP Server" value={gpo.securityOptions.ntpServer} />
                    )}
                    {gpo.securityOptions.loginBannerText && (
                      <SettingRow label="Login Banner" value="Configured" />
                    )}
                  </>)}
                </TreeSection>

                <TreeSection title="Firewall Rules" icon={GlobeAltIcon} defaultOpen={gpo.firewall?.enabled}>
                  <BoolRow label="Firewall Active" value={gpo.firewall?.enabled ?? false} />
                  {gpo.firewall?.enabled && (<>
                    <SettingRow label="Default Inbound"  value={gpo.firewall.defaultInbound} />
                    <SettingRow label="Default Outbound" value={gpo.firewall.defaultOutbound} />
                    <SettingRow label="Total Rules"      value={String(gpo.firewall.rules.length)} configured={gpo.firewall.rules.length > 0} />
                    {gpo.firewall.rules.slice(0, 3).map(rule => (
                      <div key={rule.id} className="flex items-center gap-1.5 py-1.5 px-2 text-xs hover:bg-gray-50 rounded">
                        <span className={`px-1.5 py-0.5 rounded font-medium ${rule.action === 'allow' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{rule.action}</span>
                        <span className="text-gray-500">{rule.direction}</span>
                        <span className="font-mono text-gray-700">{rule.protocol}:{rule.port}</span>
                        <span className="text-gray-400 truncate">{rule.description || rule.source}</span>
                      </div>
                    ))}
                    {gpo.firewall.rules.length > 3 && (
                      <p className="text-xs text-gray-400 italic px-2">…and {gpo.firewall.rules.length - 3} more rules</p>
                    )}
                  </>)}
                </TreeSection>

                <TreeSection title="System Services" icon={WrenchScrewdriverIcon} defaultOpen={gpo.systemServices?.enabled}>
                  <BoolRow label="Service Management Active" value={gpo.systemServices?.enabled ?? false} />
                  {gpo.systemServices?.enabled && gpo.systemServices.services.filter(s => s.startupType !== 'manual').map(svc => (
                    <div key={svc.id} className="flex items-center justify-between py-1.5 px-2 hover:bg-gray-50 rounded text-sm">
                      <span className="text-gray-600">{svc.displayName || svc.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                        svc.startupType === 'enabled' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                      }`}>{svc.startupType}</span>
                    </div>
                  ))}
                  {gpo.systemServices?.enabled && gpo.systemServices.services.filter(s => s.startupType !== 'manual').length === 0 && (
                    <p className="text-sm text-gray-400 italic px-2">No service overrides configured</p>
                  )}
                </TreeSection>
              </TreeSection>
            </TreeSection>

            {/* User Configuration */}
            <TreeSection title="User Configuration" icon={UserGroupIcon}>
              <TreeSection title="Login Scripts" icon={CommandLineIcon}
                defaultOpen={gpo.scripts.logon.length > 0 || gpo.scripts.logoff.length > 0}>
                {gpo.scripts.logon.length > 0
                  ? gpo.scripts.logon.map(s => <SettingRow key={s} label="Logon" value={s} />)
                  : <SettingRow label="Logon scripts" value="" configured={false} />}
                {gpo.scripts.logoff.length > 0
                  ? gpo.scripts.logoff.map(s => <SettingRow key={s} label="Logoff" value={s} />)
                  : <SettingRow label="Logoff scripts" value="" configured={false} />}
              </TreeSection>
              <TreeSection title="Access Control" icon={ShieldCheckIcon} defaultOpen={gpo.access.mfaRequired}>
                <BoolRow label="Require MFA" value={gpo.access.mfaRequired} />
                <SettingRow label="Allowed groups" value={gpo.access.allowed.join(', ') || '—'}
                  configured={gpo.access.allowed.length > 0} />
                <SettingRow label="Denied groups" value={gpo.access.denied.join(', ') || 'None'}
                  configured={gpo.access.denied.length > 0} />
              </TreeSection>
              <TreeSection title="Administrative Templates" icon={Cog6ToothIcon} defaultOpen={false}>
                <SettingRow label="Desktop restrictions" value="" configured={false} />
                <SettingRow label="Application restrictions" value="" configured={false} />
              </TreeSection>
            </TreeSection>
          </div>
        )}

        {/* ── Delegation ── */}
        {tab === 'delegation' && (
          <div className="space-y-3">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Delegated Permissions</p>
            {[
              { group: 'Domain Admins', perm: 'Edit settings, delete, modify security' },
              { group: 'admins',        perm: 'Edit settings' },
              { group: 'Authenticated Users', perm: 'Read (Apply Group Policy)' },
            ].map(({ group, perm }) => (
              <div key={group} className="flex items-center justify-between px-3 py-2.5 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2">
                  <UserGroupIcon className="w-4 h-4 text-gray-400" />
                  <span className="text-sm font-medium text-gray-800">{group}</span>
                </div>
                <span className="text-xs text-gray-500">{perm}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── RSoP Modal ────────────────────────────────────────────────────────────────

function RSoPModal({ gpos, ouTree, onClose }: {
  gpos: GPO[];
  ouTree: OU[];
  onClose: () => void;
}) {
  const [targetOU, setTargetOU] = useState('');
  const [calculated, setCalculated] = useState(false);

  const flatOUs = (list: OU[]): OU[] => list.flatMap(o => [o, ...(o.children ? flatOUs(o.children) : [])]);
  const allOUs = flatOUs(ouTree);

  // Collect ancestor OU ids (including self) for a given OU id
  const getAncestorIds = (targetId: string): string[] => {
    const result: string[] = [];
    const find = (list: OU[], path: string[]): boolean => {
      for (const ou of list) {
        const newPath = [...path, ou.id];
        if (ou.id === targetId) { result.push(...newPath); return true; }
        if (ou.children && find(ou.children, newPath)) return true;
      }
      return false;
    };
    find(ouTree, []);
    return result;
  };

  const applicableGPOs: GPO[] = (() => {
    if (!targetOU) return [];
    const ancestorIds = getAncestorIds(targetOU);
    const seen = new Set<string>();
    const result: GPO[] = [];
    // higher OUs first (root to leaf order), then reverse for precedence
    for (const ouId of ancestorIds) {
      const ou = allOUs.find(o => o.id === ouId);
      if (!ou) continue;
      for (const gpoId of ou.linkedGPOs) {
        if (seen.has(gpoId)) continue;
        seen.add(gpoId);
        const gpo = gpos.find(g => g.id === gpoId && g.status === 'enabled');
        if (gpo) result.push(gpo);
      }
    }
    return result;
  })();

  // Merge effective settings (last writer wins = lowest OU = highest precedence)
  const effectivePassword = applicableGPOs.reduce<Partial<PasswordSettings>>((acc, g) => {
    if (g.password.enabled) return { ...acc, ...g.password };
    return acc;
  }, {});
  const effectiveMfa = applicableGPOs.some(g => g.access.mfaRequired);
  const effectiveFirewallRules = applicableGPOs.flatMap(g => g.firewall?.rules ?? []);
  const effectiveAuditEnabled = applicableGPOs.some(g => g.audit?.enabled);

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-60 flex items-center justify-center p-4 z-[70]" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 flex-shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Resultant Set of Policy (RSoP)</h2>
            <p className="text-sm text-gray-500">
              Effektive Richtlinien für eine Ziel-OU simulieren
              {AD_DOMAIN && <span className="ml-1 font-mono text-gray-400 text-xs">({AD_DOMAIN})</span>}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                Target OU / Group
              </label>
              <select value={targetOU} onChange={e => { setTargetOU(e.target.value); setCalculated(false); }}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                <option value="">— Select an OU or Group —</option>
                {allOUs.map(ou => (
                  <option key={ou.id} value={ou.id}>{ou.name}</option>
                ))}
              </select>
            </div>
            <button onClick={() => { if (targetOU) setCalculated(true); }}
              disabled={!targetOU}
              className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-40 flex-shrink-0">
              Calculate
            </button>
          </div>

          {calculated && (
            <div className="space-y-4">
              {/* Applied GPOs */}
              <div>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                  GPOs Applied ({applicableGPOs.length}) — in precedence order
                </p>
                {applicableGPOs.length === 0 ? (
                  <p className="text-sm text-gray-400 italic">No enabled GPOs apply to this target.</p>
                ) : (
                  <div className="space-y-1">
                    {applicableGPOs.map((g, i) => (
                      <div key={g.id} className="flex items-center gap-2 px-3 py-2 bg-indigo-50 border border-indigo-100 rounded-lg">
                        <span className="text-xs text-indigo-400 font-mono w-6 text-right">{i + 1}</span>
                        <DocumentTextIcon className="w-4 h-4 text-indigo-500" />
                        <span className="text-sm font-medium text-indigo-900">{g.name}</span>
                        <span className="ml-auto text-xs text-indigo-500">{countSettings(g)} settings</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Effective settings summary */}
              {applicableGPOs.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Effective Settings</p>
                  <div className="bg-gray-50 rounded-lg p-3 space-y-2 text-sm">
                    {effectivePassword.enabled ? (
                      <div className="flex items-center gap-2">
                        <CheckCircleIcon className="w-4 h-4 text-green-500 flex-shrink-0" />
                        <span className="text-gray-700">Password Policy: min {effectivePassword.minLength} chars, {effectivePassword.expiryDays === 0 ? 'no expiry' : `${effectivePassword.expiryDays}d expiry`}, lockout after {effectivePassword.lockoutAttempts} attempts</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <XCircleIcon className="w-4 h-4 text-gray-300 flex-shrink-0" />
                        <span className="text-gray-400">Password Policy: not configured</span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      {effectiveMfa
                        ? <><CheckCircleIcon className="w-4 h-4 text-green-500 flex-shrink-0" /><span className="text-gray-700">MFA: Required</span></>
                        : <><XCircleIcon className="w-4 h-4 text-gray-300 flex-shrink-0" /><span className="text-gray-400">MFA: Not required</span></>
                      }
                    </div>
                    <div className="flex items-center gap-2">
                      {effectiveAuditEnabled
                        ? <><CheckCircleIcon className="w-4 h-4 text-green-500 flex-shrink-0" /><span className="text-gray-700">Audit Policy: Active</span></>
                        : <><XCircleIcon className="w-4 h-4 text-gray-300 flex-shrink-0" /><span className="text-gray-400">Audit Policy: Not configured</span></>
                      }
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircleIcon className={`w-4 h-4 flex-shrink-0 ${effectiveFirewallRules.length > 0 ? 'text-green-500' : 'text-gray-300'}`} />
                      <span className={effectiveFirewallRules.length > 0 ? 'text-gray-700' : 'text-gray-400'}>
                        Firewall Rules: {effectiveFirewallRules.length} rule{effectiveFirewallRules.length !== 1 ? 's' : ''} applied
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-400 ml-6">
                        Total software packages: {applicableGPOs.reduce((n, g) => n + g.software.packages.length, 0)}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex justify-end px-6 py-4 border-t border-gray-100 flex-shrink-0">
          <button onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main View ─────────────────────────────────────────────────────────────────

export default function PolicyView() {
  const [gpos, setGPOs]         = useState<GPO[]>([]);
  const [ouTree, setOuTree]     = useState<OU[]>(() => buildFallbackOuTree(AD_DOMAIN));
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [selectedGPO, setSelectedGPO] = useState<GPO | null>(null);
  const [showNewGPO, setShowNewGPO] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [editingGPO, setEditingGPO] = useState<GPO | null>(null);
  const [listTab, setListTab] = useState<'tree' | 'all'>('tree');
  const [showRSoP, setShowRSoP] = useState(false);

  useEffect(() => {
    Promise.all([
      policyApi.getPolicies().catch(() => ({ data: null })),
      policyApi.getOUTree().catch(() => ({ data: null })),
    ]).then(([policiesRes, ouRes]) => {
      const policies = policiesRes.data?.data || policiesRes.data?.policies || policiesRes.data?.gpos || [];
      if (Array.isArray(policies) && policies.length > 0) {
        setGPOs(policies.map(normalizeGPO));
      } else {
        // Backend returned no policies — pre-populate with AD-equivalent defaults
        setGPOs(FALLBACK_GPOS);
      }

      const ouData = ouRes.data?.data || ouRes.data?.tree || ouRes.data?.ou_tree;
      if (Array.isArray(ouData) && ouData.length > 0) {
        setOuTree(ouData);
      }
      // else: ouTree stays as fallback built from AD_DOMAIN
    }).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="p-6 animate-pulse space-y-4">
        <div className="h-8 bg-gray-200 rounded w-1/3" />
        <div className="h-64 bg-gray-200 rounded-xl" />
      </div>
    );
  }

  const enabledCount = gpos.filter(g => g.status === 'enabled').length;

  const toggleGPO = (id: string) => {
    setGPOs(prev => prev.map(g =>
      g.id === id ? { ...g, status: g.status === 'enabled' ? 'disabled' : 'enabled' } : g
    ));
    setSelectedGPO(prev => prev?.id === id
      ? { ...prev, status: prev.status === 'enabled' ? 'disabled' : 'enabled' }
      : prev
    );
    toast.success('GPO status updated');
  };

  const deleteGPO = async (id: string) => {
    if (!confirm('Delete this GPO? This action cannot be undone.')) return;
    setGPOs(prev => prev.filter(g => g.id !== id));
    if (selectedGPO?.id === id) setSelectedGPO(gpos.find(g => g.id !== id) || null);
    toast.success('GPO deleted');
    try { await policyApi.deletePolicy(id); } catch {}
  };

  const addGPO = async (gpo: GPO) => {
    setGPOs(prev => [...prev, gpo]);
    setSelectedGPO(gpo);
    toast.success('GPO created');
    try { await policyApi.createPolicy(gpo); } catch {}
  };

  const saveEditedGPO = async (updated: GPO) => {
    setGPOs(prev => prev.map(g => g.id === updated.id ? updated : g));
    setSelectedGPO(updated);
    try { await policyApi.updatePolicy(updated.id, updated); } catch {}
  };

  const copyGPO = (gpo: GPO) => {
    const copy: GPO = {
      ...JSON.parse(JSON.stringify(gpo)),
      id: 'gpo-' + Date.now(),
      name: 'Copy of ' + gpo.name,
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      version: 1,
    };
    addGPO(copy);
  };

  const exportGPO = (gpo: GPO) => {
    const blob = new Blob([JSON.stringify(gpo, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${gpo.name.replace(/\s+/g, '_')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('GPO exported');
  };

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Group Policy Management</h1>
          <p className="text-sm text-gray-500 mt-1">
            {enabledCount} of {gpos.length} policies active
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-purple-700 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg transition-colors"
          >
            <SparklesIcon className="w-4 h-4" />
            Policy Wizard
          </button>
          <button
            onClick={() => setShowRSoP(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-lg transition-colors"
          >
            <CalculatorIcon className="w-4 h-4" />
            RSoP
          </button>
          <button
            onClick={() => setShowNewGPO(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
          >
            <PlusIcon className="w-4 h-4" />
            New GPO
          </button>
        </div>
      </div>

      {/* Main layout — left tree + right detail */}
      <div className="flex gap-4 h-[calc(100vh-220px)]">

        {/* Left panel */}
        <div className="w-72 flex-shrink-0 bg-white rounded-xl border border-gray-100 shadow-sm flex flex-col overflow-hidden">
          <div className="flex border-b border-gray-100">
            {(['tree', 'all'] as const).map(t => (
              <button key={t} onClick={() => setListTab(t)}
                className={`flex-1 py-2 text-xs font-medium transition-colors ${
                  listTab === t ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-500' : 'text-gray-500 hover:text-gray-700'
                }`}>
                {t === 'tree' ? 'Domain Tree' : `All GPOs (${gpos.length})`}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-2">
            {listTab === 'tree' ? (
              ouTree.map(ou => (
                <TreeItem key={ou.id} ou={ou} gpos={gpos} selectedGPO={selectedGPO} onSelectGPO={setSelectedGPO} />
              ))
            ) : (
              <div className="space-y-0.5">
                {gpos.map(gpo => (
                  <button key={gpo.id} onClick={() => setSelectedGPO(gpo)}
                    className={`flex items-center gap-2 w-full text-left px-3 py-2 rounded-lg transition-colors ${
                      selectedGPO?.id === gpo.id ? 'bg-blue-50 text-blue-700' : 'hover:bg-gray-50 text-gray-700'
                    }`}>
                    <DocumentTextIcon className={`w-4 h-4 flex-shrink-0 ${
                      gpo.status === 'disabled' ? 'text-gray-300' : 'text-blue-400'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className={`text-xs font-medium truncate ${gpo.status === 'disabled' ? 'text-gray-400' : ''}`}>
                        {gpo.name}
                      </p>
                      <p className="text-xs text-gray-400">{countSettings(gpo)} settings</p>
                    </div>
                    <span className={`flex-shrink-0 w-2 h-2 rounded-full ${
                      gpo.status === 'enabled' ? 'bg-green-500' : 'bg-gray-300'
                    }`} />
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right panel */}
        <div className="flex-1 bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          {selectedGPO ? (
            <GPODetail
              gpo={selectedGPO}
              ous={ouTree}
              onToggle={() => toggleGPO(selectedGPO.id)}
              onDelete={() => deleteGPO(selectedGPO.id)}
              onEdit={() => setEditingGPO(selectedGPO)}
              onCopy={() => copyGPO(selectedGPO)}
              onExport={() => exportGPO(selectedGPO)}
              onRSoP={() => setShowRSoP(true)}
            />
          ) : gpos.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-gray-400 h-full">
              <div className="text-center">
                <DocumentTextIcon className="w-10 h-10 mx-auto mb-2 text-gray-300" />
                <p className="text-sm">No policies found</p>
                <p className="text-xs mt-1">Create a new GPO to get started</p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-gray-400">
              <DocumentTextIcon className="w-12 h-12 mb-3" />
              <p className="text-sm">Select a GPO from the left panel</p>
            </div>
          )}
        </div>
      </div>

      {showNewGPO && (
        <GPOWizard ous={ouTree} onClose={() => setShowNewGPO(false)} onSave={addGPO} />
      )}
      {editingGPO && (
        <GPOEditModal
          gpo={editingGPO}
          onClose={() => setEditingGPO(null)}
          onSave={saveEditedGPO}
        />
      )}
      {showRSoP && (
        <RSoPModal gpos={gpos} ouTree={ouTree} onClose={() => setShowRSoP(false)} />
      )}
      {showWizard && <PolicyCreationWizard onClose={() => setShowWizard(false)} />}
    </div>
  );
}
