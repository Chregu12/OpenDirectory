'use client';

import React, { useState, useEffect } from 'react';
import {
  GlobeAltIcon,
  ServerIcon,
  FolderIcon,
  MagnifyingGlassIcon,
  ChartBarIcon,
  PlusIcon,
  TrashIcon,
  WifiIcon,
  ComputerDesktopIcon,
  LockClosedIcon,
  EyeIcon,
  SparklesIcon,
  EyeSlashIcon,
  XMarkIcon,
  CheckIcon,
  ChevronRightIcon,
  UserGroupIcon,
  UserIcon,
  CloudIcon,
  ChevronLeftIcon,
  ClipboardDocumentIcon,
  ArrowDownTrayIcon,
  ComputerDesktopIcon as WindowsIcon,
} from '@heroicons/react/24/outline';

type NewDevice = { ip: string; hostname: string; mac: string; vendor: string; type: string };
import toast from 'react-hot-toast';
import NetworkConfigWizard from '@/components/setup/NetworkConfigWizard';

interface NetworkDevice {
  ip: string;
  hostname?: string;
  mac?: string;
  vendor?: string;
  type?: string;
  os?: string;
  ports?: number[];
  lastSeen: string;
}

interface DNSRecord {
  name: string;
  type: string;
  value: string;
  ttl: number;
}

interface DHCPScope {
  name: string;
  startIP: string;
  endIP: string;
  subnet: string;
  gateway: string;
  dnsServers: string[];
  leaseTime: number;
  enabled: boolean;
}

interface FileShare {
  id: string;
  name: string;
  protocol: 'SMB' | 'NFS' | 'S3';
  server: string;
  path: string;
  permissions: 'rw' | 'ro';
  enabled: boolean;
  username?: string;
  has_credentials?: boolean;
  drive_letter?: string;
  allowed_groups: string[];
  allowed_users: string[];
  created_at: string;
}

interface LdapGroup { id: string; displayName: string; members: string[] }
interface LdapUser  { id: string; displayName: string; email: string; groups: string[] }

type TabId = 'dns' | 'dhcp' | 'shares' | 'discovery' | 'statistics';
type WizardStep = 1 | 2 | 3;
type Protocol = 'SMB' | 'NFS' | 'S3';

const PROTOCOLS: { id: Protocol; label: string; sub: string; icon: React.ElementType; color: string }[] = [
  { id: 'SMB', label: 'SMB / CIFS', sub: 'Windows-Netzlaufwerk, NAS (Synology, QNAP)', icon: ServerIcon,  color: 'blue'   },
  { id: 'NFS', label: 'NFS',        sub: 'Linux/Unix, Container-Storage',               icon: FolderIcon, color: 'green'  },
  { id: 'S3',  label: 'S3 / Object Storage', sub: 'AWS S3, MinIO, Synology C2',         icon: CloudIcon,  color: 'orange' },
];

const PORTAL = 'https://opendirectory.heusser.local';

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={copy} className="ml-2 flex-shrink-0 text-gray-400 hover:text-gray-600" title="Kopieren">
      {copied ? <CheckIcon className="h-3.5 w-3.5 text-green-500" /> : <ClipboardDocumentIcon className="h-3.5 w-3.5" />}
    </button>
  );
}

function AutoMountSetup() {
  const winCmd   = `irm ${PORTAL}/api/network/install-script/windows | iex`;
  const macCmd   = `bash <(curl -sk ${PORTAL}/api/network/install-script/macos)`;
  const linuxCmd = `sudo bash <(curl -sk ${PORTAL}/api/network/install-script/linux)`;

  const platforms = [
    {
      label: 'Windows',
      color: 'blue',
      icon: '🪟',
      cmd: winCmd,
      dl: `${PORTAL}/api/network/install-script/windows`,
      dlLabel: 'Install-ODMounts.ps1',
      note: 'PowerShell als Administrator — mappt Laufwerke per Scheduled Task bei jedem Login',
    },
    {
      label: 'macOS',
      color: 'gray',
      icon: '🍎',
      cmd: macCmd,
      dl: `${PORTAL}/api/network/install-script/macos`,
      dlLabel: 'install-od-mounts.sh',
      note: 'Terminal — installiert LaunchAgent, Shares erscheinen beim Login im Finder',
    },
    {
      label: 'Linux',
      color: 'orange',
      icon: '🐧',
      cmd: linuxCmd,
      dl: `${PORTAL}/api/network/install-script/linux`,
      dlLabel: 'install-od-mounts.sh',
      note: 'Root-Terminal — konfiguriert PAM-Session-Hook, Shares unter ~/mnt/ gemountet',
    },
  ];

  return (
    <div className="border border-purple-100 bg-purple-50 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <ArrowDownTrayIcon className="h-5 w-5 text-purple-600" />
        <h3 className="text-sm font-semibold text-purple-900">Auto-Mount einrichten</h3>
        <span className="text-xs text-purple-500">Einmalig pro Gerät — danach automatisch bei jedem Login</span>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        {platforms.map(p => (
          <div key={p.label} className="bg-white rounded-lg p-3 border border-purple-100">
            <div className="flex items-center gap-1.5 mb-2">
              <span className="text-base">{p.icon}</span>
              <span className="text-xs font-semibold text-gray-800">{p.label}</span>
            </div>
            <div className="flex items-start bg-gray-50 rounded px-2 py-1.5 mb-2">
              <code className="text-xs text-gray-700 break-all flex-1">{p.cmd}</code>
              <CopyButton text={p.cmd} />
            </div>
            <p className="text-xs text-gray-500 mb-2">{p.note}</p>
            <a
              href={p.dl}
              download={p.dlLabel}
              className="inline-flex items-center gap-1 text-xs text-purple-600 hover:text-purple-800"
            >
              <ArrowDownTrayIcon className="h-3 w-3" />
              Script herunterladen
            </a>
          </div>
        ))}
      </div>

      <p className="text-xs text-purple-500 mt-3">
        Die Scripts fragen beim Login <code className="bg-purple-100 px-1 rounded">/api/network/shares/for-user/&#123;username&#125;</code> ab
        und mounten automatisch die Shares, auf die der User Zugriff hat.
      </p>
    </div>
  );
}

export default function NetworkInfrastructureIntegration() {
  const [activeTab, setActiveTab] = useState<TabId>('dns');
  const [loading, setLoading]     = useState(false);
  const [showNetworkWizard, setShowNetworkWizard] = useState(false);

  const [dnsRecords, setDnsRecords]   = useState<DNSRecord[]>([]);
  const [newDNSRecord, setNewDNSRecord] = useState<Partial<DNSRecord>>({ type: 'A', ttl: 300 });

  const [dhcpScopes, setDhcpScopes]   = useState<DHCPScope[]>([]);
  const [newDHCPScope, setNewDHCPScope] = useState<Partial<DHCPScope>>({
    leaseTime: 86400, enabled: true, dnsServers: ['8.8.8.8', '8.8.4.4'],
  });

  const [fileShares, setFileShares] = useState<FileShare[]>([]);

  // Wizard state
  const [showWizard, setShowWizard]           = useState(false);
  const [wizardStep, setWizardStep]           = useState<WizardStep>(1);
  const [wizardSaving, setWizardSaving]       = useState(false);
  const [showWizardPw, setShowWizardPw]       = useState(false);
  const [ldapGroups, setLdapGroups]           = useState<LdapGroup[]>([]);
  const [ldapUsers, setLdapUsers]             = useState<LdapUser[]>([]);
  const [wizardShare, setWizardShare]         = useState<{
    protocol: Protocol;
    name: string;
    server: string;
    path: string;
    permissions: 'rw' | 'ro';
    username: string;
    password: string;
    driveLetter: string;
    // S3
    bucket: string;
    region: string;
    endpoint: string;
    accessKey: string;
    secretKey: string;
    // NFS options
    nfsOptions: string;
    // access control
    allowedGroups: string[];
    allowedUsers: string[];
  }>({
    protocol: 'SMB', name: '', server: '', path: '', permissions: 'rw',
    username: '', password: '', driveLetter: 'Z',
    bucket: '', region: 'eu-west-1', endpoint: '', accessKey: '', secretKey: '',
    nfsOptions: 'rw,async',
    allowedGroups: [], allowedUsers: [],
  });

  const [networkDevices, setNetworkDevices] = useState<NetworkDevice[]>([]);
  const [newDevice, setNewDevice]           = useState<NewDevice>({ ip: '', hostname: '', mac: '', vendor: '', type: '' });

  useEffect(() => { loadNetworkData(); }, []);

  const loadNetworkData = async () => {
    setLoading(true);
    try {
      await Promise.all([loadDNSRecords(), loadDHCPScopes(), loadFileShares(), loadNetworkDevices()]);
    } catch { toast.error('Failed to load network data'); }
    finally  { setLoading(false); }
  };

  const loadDNSRecords = async () => {
    try { const r = await fetch('/api/network/dns/records'); if (r.ok) setDnsRecords((await r.json()).records || []); } catch {}
  };
  const loadDHCPScopes = async () => {
    try { const r = await fetch('/api/network/dhcp/scopes'); if (r.ok) setDhcpScopes((await r.json()).scopes || []); } catch {}
  };
  const loadFileShares = async () => {
    try { const r = await fetch('/api/network/shares'); if (r.ok) setFileShares((await r.json()).shares || []); } catch {}
  };
  const loadNetworkDevices = async () => {
    try { const r = await fetch('/api/network/devices'); if (r.ok) setNetworkDevices((await r.json()).devices || []); } catch {}
  };

  const handleDNSRecordAdd = async () => {
    if (!newDNSRecord.name || !newDNSRecord.value) { toast.error('Name and value are required'); return; }
    try {
      const r = await fetch('/api/network/dns/records', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newDNSRecord) });
      if (r.ok) { toast.success('DNS record added'); setNewDNSRecord({ type: 'A', ttl: 300 }); loadDNSRecords(); }
      else       { toast.error('Failed to add DNS record'); }
    } catch { toast.error('Error adding DNS record'); }
  };

  const handleDHCPScopeAdd = async () => {
    if (!newDHCPScope.name || !newDHCPScope.startIP || !newDHCPScope.endIP) { toast.error('Name, start IP, and end IP are required'); return; }
    try {
      const r = await fetch('/api/network/dhcp/scopes', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newDHCPScope) });
      if (r.ok) { toast.success('DHCP scope added'); setNewDHCPScope({ leaseTime: 86400, enabled: true, dnsServers: ['8.8.8.8', '8.8.4.4'] }); loadDHCPScopes(); }
      else       { toast.error('Failed to add DHCP scope'); }
    } catch { toast.error('Error adding DHCP scope'); }
  };

  const handleFileShareDelete = async (id: string) => {
    try {
      const r = await fetch(`/api/network/shares/${id}`, { method: 'DELETE' });
      if (r.ok) { setFileShares(prev => prev.filter(s => s.id !== id)); toast.success('Share removed'); }
      else       { toast.error('Failed to remove share'); }
    } catch { toast.error('Error removing share'); }
  };

  const openWizard = async () => {
    setWizardStep(1);
    setWizardShare({ protocol: 'SMB', name: '', server: '', path: '', permissions: 'rw', username: '', password: '', driveLetter: 'Z', bucket: '', region: 'eu-west-1', endpoint: '', accessKey: '', secretKey: '', nfsOptions: 'rw,async', allowedGroups: [], allowedUsers: [] });
    setShowWizardPw(false);
    // Prefetch groups/users for step 3
    try {
      const [gr, ur] = await Promise.all([fetch('/api/lldap/groups'), fetch('/api/lldap/users')]);
      if (gr.ok) setLdapGroups((await gr.json()).groups || []);
      if (ur.ok) setLdapUsers((await ur.json()).users  || []);
    } catch {}
    setShowWizard(true);
  };

  const closeWizard = () => setShowWizard(false);

  const wizardNext = () => setWizardStep(s => (s < 3 ? (s + 1) as WizardStep : s));
  const wizardBack = () => setWizardStep(s => (s > 1 ? (s - 1) as WizardStep : s));

  const wizardStep2Valid = () => {
    const w = wizardShare;
    if (!w.name) return false;
    if (w.protocol === 'SMB') return !!w.server && !!w.path;
    if (w.protocol === 'NFS') return !!w.server && !!w.path;
    if (w.protocol === 'S3')  return !!w.bucket;
    return false;
  };

  const handleWizardSubmit = async () => {
    setWizardSaving(true);
    const w = wizardShare;
    try {
      const hasCredentials =
        (w.protocol === 'SMB' && !!w.username && !!w.password) ||
        (w.protocol === 'S3'  && !!w.accessKey && !!w.secretKey);

      // 1. Save credentials to Vault
      if (w.protocol === 'SMB' && w.username && w.password) {
        await fetch(`/api/vault/secrets/smb-shares/${w.name}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: w.username, password: w.password, server: w.server, path: w.path }),
        });
      }
      if (w.protocol === 'S3' && w.accessKey && w.secretKey) {
        await fetch(`/api/vault/secrets/s3-shares/${w.name}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ access_key: w.accessKey, secret_key: w.secretKey, bucket: w.bucket, region: w.region, endpoint: w.endpoint }),
        });
      }

      // 2. Create share record (no secrets)
      const payload = {
        name:            w.name,
        protocol:        w.protocol,
        server:          w.protocol === 'S3' ? (w.endpoint || 'aws') : w.server,
        path:            w.protocol === 'S3' ? w.bucket : w.path,
        permissions:     w.permissions,
        enabled:         true,
        username:        w.username || '',
        has_credentials: hasCredentials,
        drive_letter:    w.protocol === 'SMB' ? (w.driveLetter || '') : '',
        allowed_groups:  w.allowedGroups,
        allowed_users:   w.allowedUsers,
      };
      const r = await fetch('/api/network/shares', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (r.ok) {
        toast.success(hasCredentials ? `Share "${w.name}" hinzugefügt — Credentials in Vault gespeichert` : `Share "${w.name}" hinzugefügt`);
        closeWizard();
        loadFileShares();
      } else {
        const err = await r.json().catch(() => ({}));
        toast.error(err.error || 'Failed to add file share');
      }
    } catch { toast.error('Error saving file share'); }
    finally  { setWizardSaving(false); }
  };

  const handleAddDevice = async () => {
    if (!newDevice.ip) { toast.error('IP address is required'); return; }
    try {
      const r = await fetch('/api/network/devices', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...newDevice, lastSeen: new Date().toISOString() }) });
      if (r.ok) { toast.success('Device added'); setNewDevice({ ip: '', hostname: '', mac: '', vendor: '', type: '' }); loadNetworkDevices(); }
      else {
        setNetworkDevices(prev => [...prev, { ...newDevice, lastSeen: new Date().toISOString() }]);
        setNewDevice({ ip: '', hostname: '', mac: '', vendor: '', type: '' });
        toast.success('Device added locally');
      }
    } catch {
      setNetworkDevices(prev => [...prev, { ...newDevice, lastSeen: new Date().toISOString() }]);
      setNewDevice({ ip: '', hostname: '', mac: '', vendor: '', type: '' });
      toast.success('Device added locally');
    }
  };

  // ── helpers ────────────────────────────────────────────────────────────────
  const toggleGroup = (g: string) =>
    setWizardShare(s => ({
      ...s,
      allowedGroups: s.allowedGroups.includes(g)
        ? s.allowedGroups.filter(x => x !== g)
        : [...s.allowedGroups, g],
    }));
  const toggleUser = (u: string) =>
    setWizardShare(s => ({
      ...s,
      allowedUsers: s.allowedUsers.includes(u)
        ? s.allowedUsers.filter(x => x !== u)
        : [...s.allowedUsers, u],
    }));

  const protocolColor = (p: string) => {
    if (p === 'SMB') return 'bg-blue-100 text-blue-800';
    if (p === 'NFS') return 'bg-green-100 text-green-800';
    if (p === 'S3')  return 'bg-orange-100 text-orange-800';
    return 'bg-gray-100 text-gray-800';
  };

  const tabs: { key: TabId; label: string; icon: React.ElementType }[] = [
    { key: 'dns',        label: 'DNS',          icon: GlobeAltIcon },
    { key: 'dhcp',       label: 'DHCP',         icon: ServerIcon },
    { key: 'shares',     label: 'File Shares',  icon: FolderIcon },
    { key: 'discovery',  label: 'Discovery',    icon: MagnifyingGlassIcon },
    { key: 'statistics', label: 'Statistics',   icon: ChartBarIcon },
  ];

  const statSummary = [
    `${dnsRecords.length} DNS`,
    `${dhcpScopes.length} DHCP`,
    `${fileShares.length} Shares`,
    `${networkDevices.length} Devices`,
  ].join(' • ');

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="h-4 bg-gray-200 rounded"></div>
          <div className="h-4 bg-gray-200 rounded w-5/6"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      {/* Header */}
      <div className="border-b border-gray-200">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <WifiIcon className="h-6 w-6 text-blue-600" />
            <h2 className="text-lg font-medium text-gray-900">Network Infrastructure</h2>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-500">{statSummary}</span>
            <button
              onClick={() => setShowNetworkWizard(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-cyan-700 bg-cyan-50 hover:bg-cyan-100 border border-cyan-200 rounded-lg transition-colors"
            >
              <SparklesIcon className="w-4 h-4" />
              Network Wizard
            </button>
          </div>
        </div>
        <nav className="flex space-x-8 px-6" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`${
                activeTab === tab.key
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
            >
              <tab.icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="p-6">

        {/* DNS Tab */}
        {activeTab === 'dns' && (
          <div className="space-y-6">
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-700 mb-3">Add DNS Record</h3>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                <input type="text" placeholder="Name (e.g., www)" value={newDNSRecord.name || ''} onChange={(e) => setNewDNSRecord({ ...newDNSRecord, name: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <select value={newDNSRecord.type} onChange={(e) => setNewDNSRecord({ ...newDNSRecord, type: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                  {['A','AAAA','CNAME','MX','TXT'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <input type="text" placeholder="Value (e.g., 192.168.1.100)" value={newDNSRecord.value || ''} onChange={(e) => setNewDNSRecord({ ...newDNSRecord, value: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="number" placeholder="TTL" value={newDNSRecord.ttl || ''} onChange={(e) => setNewDNSRecord({ ...newDNSRecord, ttl: parseInt(e.target.value) })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <button onClick={handleDNSRecordAdd} className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center justify-center text-sm"><PlusIcon className="h-4 w-4 mr-1" />Add</button>
              </div>
            </div>
            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
              <table className="min-w-full divide-y divide-gray-300">
                <thead className="bg-gray-50">
                  <tr>
                    {['Name','Type','Value','TTL','Actions'].map(h => <th key={h} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>)}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {dnsRecords.map((record, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{record.name}</td>
                      <td className="px-6 py-4"><span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">{record.type}</span></td>
                      <td className="px-6 py-4 text-sm text-gray-500">{record.value}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{record.ttl}s</td>
                      <td className="px-6 py-4"><button className="text-red-400 hover:text-red-600"><TrashIcon className="h-4 w-4" /></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {dnsRecords.length === 0 && <div className="text-center py-8 text-gray-500 text-sm">No DNS records found</div>}
            </div>
          </div>
        )}

        {/* DHCP Tab */}
        {activeTab === 'dhcp' && (
          <div className="space-y-6">
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-700 mb-3">Add DHCP Scope</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <input type="text" placeholder="Scope Name" value={newDHCPScope.name || ''} onChange={(e) => setNewDHCPScope({ ...newDHCPScope, name: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="Start IP" value={newDHCPScope.startIP || ''} onChange={(e) => setNewDHCPScope({ ...newDHCPScope, startIP: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="End IP" value={newDHCPScope.endIP || ''} onChange={(e) => setNewDHCPScope({ ...newDHCPScope, endIP: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="Subnet (e.g., 255.255.255.0)" value={newDHCPScope.subnet || ''} onChange={(e) => setNewDHCPScope({ ...newDHCPScope, subnet: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="Gateway" value={newDHCPScope.gateway || ''} onChange={(e) => setNewDHCPScope({ ...newDHCPScope, gateway: e.target.value })} className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <button onClick={handleDHCPScopeAdd} className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 flex items-center justify-center text-sm"><PlusIcon className="h-4 w-4 mr-1" />Add Scope</button>
              </div>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {dhcpScopes.map((scope, i) => (
                <div key={i} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="text-sm font-medium text-gray-900">{scope.name}</h4>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${scope.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>{scope.enabled ? 'Enabled' : 'Disabled'}</span>
                      <button className="text-red-400 hover:text-red-600"><TrashIcon className="h-4 w-4" /></button>
                    </div>
                  </div>
                  <div className="space-y-1 text-xs text-gray-500">
                    <p>Range: {scope.startIP} – {scope.endIP}</p>
                    <p>Subnet: {scope.subnet}</p>
                    <p>Gateway: {scope.gateway}</p>
                  </div>
                </div>
              ))}
            </div>
            {dhcpScopes.length === 0 && <div className="text-center py-8 text-gray-500 text-sm">No DHCP scopes configured</div>}
          </div>
        )}

        {/* File Shares Tab */}
        {activeTab === 'shares' && (
          <div className="space-y-6">
            {/* Header row */}
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-700">
                {fileShares.length === 0 ? 'Keine Shares konfiguriert' : `${fileShares.length} Share${fileShares.length !== 1 ? 's' : ''} konfiguriert`}
              </h3>
              <button
                onClick={openWizard}
                className="bg-purple-600 text-white px-4 py-2 rounded-md hover:bg-purple-700 flex items-center space-x-2 text-sm"
              >
                <PlusIcon className="h-4 w-4" />
                <span>Share hinzufügen</span>
              </button>
            </div>

            {/* Share cards */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {fileShares.map((share) => (
                <div key={share.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-sm transition-shadow">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <FolderIcon className="h-5 w-5 text-purple-500 flex-shrink-0" />
                      <h4 className="text-sm font-medium text-gray-900 truncate">{share.name}</h4>
                    </div>
                    <button onClick={() => handleFileShareDelete(share.id)} className="text-red-400 hover:text-red-600 flex-shrink-0 ml-2">
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </div>

                  <div className="space-y-1.5 text-xs text-gray-600">
                    {/* Protocol + status */}
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${protocolColor(share.protocol)}`}>{share.protocol}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${share.permissions === 'rw' ? 'bg-blue-50 text-blue-700' : 'bg-gray-100 text-gray-600'}`}>{share.permissions === 'rw' ? 'Read/Write' : 'Read-only'}</span>
                      {share.drive_letter && (
                        <span className="px-1.5 py-0.5 rounded text-xs font-mono font-medium bg-indigo-100 text-indigo-700">{share.drive_letter}:</span>
                      )}
                      {share.has_credentials && (
                        <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700">
                          <LockClosedIcon className="h-3 w-3" /> Vault
                        </span>
                      )}
                    </div>

                    {/* Server + path */}
                    {share.server && (
                      <p className="font-mono text-gray-500 truncate">
                        {share.protocol === 'SMB' ? `\\\\${share.server}\\${share.path}` :
                         share.protocol === 'NFS' ? `${share.server}:${share.path}` :
                         share.server}
                      </p>
                    )}
                    {!share.server && share.path && <p className="font-mono text-gray-500 truncate">{share.path}</p>}

                    {/* Username */}
                    {share.username && <p className="text-gray-500">Benutzer: <span className="font-mono">{share.username}</span></p>}

                    {/* Access control */}
                    {(share.allowed_groups?.length > 0 || share.allowed_users?.length > 0) && (
                      <div className="pt-1 border-t border-gray-100">
                        {share.allowed_groups?.length > 0 && (
                          <div className="flex items-start gap-1 mt-1">
                            <UserGroupIcon className="h-3.5 w-3.5 text-gray-400 flex-shrink-0 mt-0.5" />
                            <span className="text-gray-500">{share.allowed_groups.join(', ')}</span>
                          </div>
                        )}
                        {share.allowed_users?.length > 0 && (
                          <div className="flex items-start gap-1 mt-1">
                            <UserIcon className="h-3.5 w-3.5 text-gray-400 flex-shrink-0 mt-0.5" />
                            <span className="text-gray-500">{share.allowed_users.join(', ')}</span>
                          </div>
                        )}
                      </div>
                    )}
                    {(!share.allowed_groups?.length && !share.allowed_users?.length) && (
                      <p className="text-gray-400 italic">Alle Benutzer (kein ACL)</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
            {fileShares.length === 0 && (
              <div className="text-center py-12 text-gray-500 text-sm border-2 border-dashed border-gray-200 rounded-lg">
                <FolderIcon className="h-10 w-10 mx-auto text-gray-300 mb-3" />
                <p>Noch keine File Shares konfiguriert</p>
                <p className="text-gray-400 mt-1">Klicke auf «Share hinzufügen» um SMB, NFS oder S3 einzurichten</p>
              </div>
            )}

            {/* Auto-Mount Setup */}
            <AutoMountSetup />

          </div>
        )}

        {/* Discovery Tab */}
        {activeTab === 'discovery' && (
          <div className="space-y-6">
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-700 mb-3">Add Network Device</h3>
              <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
                <input type="text" placeholder="IP Address *" value={newDevice.ip} onChange={e => setNewDevice(d => ({ ...d, ip: e.target.value }))} className="md:col-span-1 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="Hostname" value={newDevice.hostname} onChange={e => setNewDevice(d => ({ ...d, hostname: e.target.value }))} className="md:col-span-1 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="MAC Address" value={newDevice.mac} onChange={e => setNewDevice(d => ({ ...d, mac: e.target.value }))} className="md:col-span-1 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <input type="text" placeholder="Vendor" value={newDevice.vendor} onChange={e => setNewDevice(d => ({ ...d, vendor: e.target.value }))} className="md:col-span-1 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
                <select value={newDevice.type} onChange={e => setNewDevice(d => ({ ...d, type: e.target.value }))} className="md:col-span-1 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500">
                  <option value="">Type…</option>
                  {['router','switch','ap','server','workstation','printer','nas','other'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <button onClick={handleAddDevice} className="md:col-span-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center justify-center text-sm"><PlusIcon className="h-4 w-4 mr-1" />Add</button>
              </div>
            </div>
            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
              <div className="px-6 py-3 border-b border-gray-200 bg-gray-50">
                <span className="text-sm font-medium text-gray-700">Network Devices ({networkDevices.length})</span>
              </div>
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['IP Address','Hostname','MAC','Vendor','Type','Last Seen'].map(h => <th key={h} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>)}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {networkDevices.map((device, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm font-medium text-gray-900 font-mono">{device.ip}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{device.hostname || '—'}</td>
                      <td className="px-6 py-4 text-sm text-gray-500 font-mono">{device.mac || '—'}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{device.vendor || '—'}</td>
                      <td className="px-6 py-4 text-sm text-gray-500 capitalize">{device.type || '—'}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{new Date(device.lastSeen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {networkDevices.length === 0 && <div className="text-center py-8 text-gray-500 text-sm">No devices added yet</div>}
            </div>
          </div>
        )}

        {/* Statistics Tab */}
        {activeTab === 'statistics' && (
          <div className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              {[
                { label: 'DNS Records', value: dnsRecords.length, color: 'blue',   icon: GlobeAltIcon,       sub: `${dnsRecords.filter(r=>r.type==='A').length} A • ${dnsRecords.filter(r=>r.type==='CNAME').length} CNAME` },
                { label: 'DHCP Scopes', value: dhcpScopes.length, color: 'green',  icon: ServerIcon,          sub: `${dhcpScopes.filter(s=>s.enabled).length} active` },
                { label: 'File Shares', value: fileShares.length, color: 'purple', icon: FolderIcon,          sub: `${fileShares.filter(s=>s.protocol==='SMB').length} SMB • ${fileShares.filter(s=>s.protocol==='NFS').length} NFS • ${fileShares.filter(s=>s.protocol==='S3').length} S3` },
                { label: 'Devices',     value: networkDevices.length, color: 'orange', icon: ComputerDesktopIcon, sub: 'Discovered via network scan' },
              ].map(({ label, value, color, icon: Icon, sub }) => (
                <div key={label} className={`bg-${color}-50 rounded-lg p-6`}>
                  <div className="flex items-center">
                    <div className="flex-1">
                      <p className={`text-sm font-medium text-${color}-600`}>{label}</p>
                      <p className={`text-3xl font-bold text-${color}-900`}>{value}</p>
                    </div>
                    <Icon className={`h-8 w-8 text-${color}-400`} />
                  </div>
                  <p className={`text-xs text-${color}-600 mt-2`}>{sub}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Wizard Modal ──────────────────────────────────────────────────────── */}
      {showWizard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[90vh]">

            {/* Modal header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">File Share hinzufügen</h2>
                <p className="text-xs text-gray-500 mt-0.5">Schritt {wizardStep} von 3</p>
              </div>
              <button onClick={closeWizard} className="text-gray-400 hover:text-gray-600">
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>

            {/* Progress bar */}
            <div className="px-6 py-3 bg-gray-50 border-b border-gray-100">
              <div className="flex items-center space-x-2">
                {[1, 2, 3].map((s) => (
                  <React.Fragment key={s}>
                    <div className={`flex items-center justify-center w-7 h-7 rounded-full text-xs font-medium ${
                      wizardStep > s ? 'bg-purple-600 text-white' :
                      wizardStep === s ? 'bg-purple-600 text-white ring-2 ring-purple-200' :
                      'bg-gray-200 text-gray-500'
                    }`}>
                      {wizardStep > s ? <CheckIcon className="h-4 w-4" /> : s}
                    </div>
                    <span className={`text-xs ${wizardStep >= s ? 'text-purple-700 font-medium' : 'text-gray-400'}`}>
                      {s === 1 ? 'Protokoll' : s === 2 ? 'Verbindung' : 'Zugriffsrechte'}
                    </span>
                    {s < 3 && <ChevronRightIcon className="h-4 w-4 text-gray-300 flex-shrink-0" />}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Modal body */}
            <div className="flex-1 overflow-y-auto px-6 py-5">

              {/* ── Step 1: Protocol ── */}
              {wizardStep === 1 && (
                <div className="space-y-3">
                  <p className="text-sm text-gray-600 mb-4">Wähle den Storage-Typ für diesen Share:</p>
                  {PROTOCOLS.map((p) => {
                    const Icon = p.icon;
                    const selected = wizardShare.protocol === p.id;
                    return (
                      <button
                        key={p.id}
                        onClick={() => setWizardShare(s => ({ ...s, protocol: p.id }))}
                        className={`w-full flex items-center gap-4 p-4 rounded-lg border-2 text-left transition-all ${
                          selected
                            ? `border-purple-500 bg-purple-50`
                            : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                        }`}
                      >
                        <div className={`flex-shrink-0 p-2.5 rounded-lg ${selected ? 'bg-purple-100' : 'bg-gray-100'}`}>
                          <Icon className={`h-6 w-6 ${selected ? 'text-purple-600' : 'text-gray-500'}`} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className={`text-sm font-medium ${selected ? 'text-purple-900' : 'text-gray-900'}`}>{p.label}</p>
                          <p className={`text-xs mt-0.5 ${selected ? 'text-purple-600' : 'text-gray-500'}`}>{p.sub}</p>
                        </div>
                        {selected && <CheckIcon className="h-5 w-5 text-purple-600 flex-shrink-0" />}
                      </button>
                    );
                  })}
                </div>
              )}

              {/* ── Step 2: Connection Details ── */}
              {wizardStep === 2 && (
                <div className="space-y-4">
                  {/* Common: display name */}
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Share-Name (Anzeigename) *</label>
                    <input
                      type="text"
                      placeholder="z.B. Docker Volumes, Heimlaufwerk, Fotos"
                      value={wizardShare.name}
                      onChange={e => setWizardShare(s => ({ ...s, name: e.target.value }))}
                      className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                      autoFocus
                    />
                  </div>

                  {/* SMB/NFS: server + path */}
                  {(wizardShare.protocol === 'SMB' || wizardShare.protocol === 'NFS') && (
                    <>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">
                            Server (IP oder Hostname) *
                          </label>
                          <input
                            type="text"
                            placeholder="z.B. 192.168.1.7"
                            value={wizardShare.server}
                            onChange={e => setWizardShare(s => ({ ...s, server: e.target.value }))}
                            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">
                            {wizardShare.protocol === 'SMB' ? 'Freigabe-Pfad *' : 'Export-Pfad *'}
                          </label>
                          <input
                            type="text"
                            placeholder={wizardShare.protocol === 'SMB' ? 'z.B. volume2/docker' : 'z.B. /volume2/docker'}
                            value={wizardShare.path}
                            onChange={e => setWizardShare(s => ({ ...s, path: e.target.value }))}
                            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                          />
                        </div>
                      </div>

                      {/* UNC preview */}
                      {wizardShare.server && wizardShare.path && (
                        <div className="bg-gray-50 rounded-md px-3 py-2 text-xs font-mono text-gray-600">
                          {wizardShare.protocol === 'SMB'
                            ? `\\\\${wizardShare.server}\\${wizardShare.path}`
                            : `${wizardShare.server}:${wizardShare.path}`}
                        </div>
                      )}

                      {/* Permissions */}
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Berechtigung</label>
                        <div className="flex gap-2">
                          {[{ v: 'rw', l: 'Lesen & Schreiben' }, { v: 'ro', l: 'Nur Lesen' }].map(({ v, l }) => (
                            <button
                              key={v}
                              onClick={() => setWizardShare(s => ({ ...s, permissions: v as 'rw' | 'ro' }))}
                              className={`flex-1 py-2 px-3 rounded-md text-xs font-medium border transition-all ${wizardShare.permissions === v ? 'border-purple-500 bg-purple-50 text-purple-700' : 'border-gray-200 text-gray-600 hover:border-gray-300'}`}
                            >
                              {l}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Windows drive letter */}
                      {wizardShare.protocol === 'SMB' && (
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">
                            Windows Laufwerksbuchstabe
                          </label>
                          <div className="flex items-center gap-2">
                            <select
                              value={wizardShare.driveLetter}
                              onChange={e => setWizardShare(s => ({ ...s, driveLetter: e.target.value }))}
                              className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                            >
                              <option value="">(kein Laufwerk)</option>
                              {['D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'].map(l => (
                                <option key={l} value={l}>{l}:</option>
                              ))}
                            </select>
                            {wizardShare.driveLetter && wizardShare.server && wizardShare.path && (
                              <span className="text-xs font-mono text-gray-500 bg-gray-100 px-2 py-1 rounded">
                                {wizardShare.driveLetter}: → \\{wizardShare.server}\{wizardShare.path}
                              </span>
                            )}
                          </div>
                        </div>
                      )}

                      {/* SMB credentials */}
                      {wizardShare.protocol === 'SMB' && (
                        <div className="border border-gray-200 rounded-lg p-3 space-y-3">
                          <div className="flex items-center gap-1.5">
                            <LockClosedIcon className="h-3.5 w-3.5 text-purple-500" />
                            <span className="text-xs font-medium text-gray-700">SMB-Zugangsdaten</span>
                            <span className="text-xs text-gray-400">(optional — werden in Vault gespeichert)</span>
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            <input
                              type="text"
                              placeholder="Benutzername"
                              value={wizardShare.username}
                              onChange={e => setWizardShare(s => ({ ...s, username: e.target.value }))}
                              className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                              autoComplete="off"
                            />
                            <div className="relative">
                              <input
                                type={showWizardPw ? 'text' : 'password'}
                                placeholder="Passwort"
                                value={wizardShare.password}
                                onChange={e => setWizardShare(s => ({ ...s, password: e.target.value }))}
                                className="w-full border border-gray-300 rounded-md px-3 py-2 pr-9 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                                autoComplete="new-password"
                              />
                              <button type="button" onClick={() => setShowWizardPw(v => !v)} className="absolute inset-y-0 right-2 flex items-center text-gray-400 hover:text-gray-600">
                                {showWizardPw ? <EyeSlashIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                              </button>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* NFS options */}
                      {wizardShare.protocol === 'NFS' && (
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">Mount-Optionen</label>
                          <input
                            type="text"
                            value={wizardShare.nfsOptions}
                            onChange={e => setWizardShare(s => ({ ...s, nfsOptions: e.target.value }))}
                            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                          />
                        </div>
                      )}
                    </>
                  )}

                  {/* S3 */}
                  {wizardShare.protocol === 'S3' && (
                    <>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">Bucket-Name *</label>
                          <input type="text" placeholder="mein-bucket" value={wizardShare.bucket} onChange={e => setWizardShare(s => ({ ...s, bucket: e.target.value }))} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500" />
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">Region</label>
                          <input type="text" placeholder="eu-west-1" value={wizardShare.region} onChange={e => setWizardShare(s => ({ ...s, region: e.target.value }))} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500" />
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Endpoint URL (leer lassen für AWS)</label>
                        <input type="text" placeholder="https://s3.synology.com oder http://minio:9000" value={wizardShare.endpoint} onChange={e => setWizardShare(s => ({ ...s, endpoint: e.target.value }))} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500" />
                      </div>
                      <div className="border border-gray-200 rounded-lg p-3 space-y-3">
                        <div className="flex items-center gap-1.5">
                          <LockClosedIcon className="h-3.5 w-3.5 text-orange-500" />
                          <span className="text-xs font-medium text-gray-700">S3-Zugangsdaten</span>
                          <span className="text-xs text-gray-400">(werden in Vault gespeichert)</span>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <input type="text" placeholder="Access Key ID" value={wizardShare.accessKey} onChange={e => setWizardShare(s => ({ ...s, accessKey: e.target.value }))} className="border border-gray-300 rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-orange-500" autoComplete="off" />
                          <div className="relative">
                            <input type={showWizardPw ? 'text' : 'password'} placeholder="Secret Access Key" value={wizardShare.secretKey} onChange={e => setWizardShare(s => ({ ...s, secretKey: e.target.value }))} className="w-full border border-gray-300 rounded-md px-3 py-2 pr-9 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-orange-500" autoComplete="new-password" />
                            <button type="button" onClick={() => setShowWizardPw(v => !v)} className="absolute inset-y-0 right-2 flex items-center text-gray-400 hover:text-gray-600">
                              {showWizardPw ? <EyeSlashIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                            </button>
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* ── Step 3: Access Control ── */}
              {wizardStep === 3 && (
                <div className="space-y-5">
                  <p className="text-sm text-gray-600">
                    Lege fest, wer auf <span className="font-medium text-gray-900">«{wizardShare.name}»</span> zugreifen darf.
                    Wenn keine Auswahl getroffen wird, haben alle Benutzer Zugriff.
                  </p>

                  {/* Groups */}
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <UserGroupIcon className="h-4 w-4 text-gray-500" />
                      <h4 className="text-sm font-medium text-gray-700">Gruppen</h4>
                    </div>
                    {ldapGroups.length === 0
                      ? <p className="text-xs text-gray-400 italic">Keine Gruppen verfügbar</p>
                      : (
                        <div className="grid grid-cols-2 gap-2">
                          {ldapGroups.map((g) => {
                            const sel = wizardShare.allowedGroups.includes(g.displayName);
                            return (
                              <button
                                key={g.id}
                                onClick={() => toggleGroup(g.displayName)}
                                className={`flex items-center gap-2 p-2.5 rounded-lg border text-left transition-all text-xs ${sel ? 'border-purple-400 bg-purple-50 text-purple-800' : 'border-gray-200 text-gray-600 hover:border-gray-300'}`}
                              >
                                <div className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 ${sel ? 'bg-purple-600' : 'border border-gray-300'}`}>
                                  {sel && <CheckIcon className="h-3 w-3 text-white" />}
                                </div>
                                <div className="min-w-0">
                                  <p className="font-medium truncate">{g.displayName}</p>
                                  <p className="text-gray-400">{g.members.length} Mitglieder</p>
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                  </div>

                  {/* Users */}
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <UserIcon className="h-4 w-4 text-gray-500" />
                      <h4 className="text-sm font-medium text-gray-700">Einzelne Benutzer</h4>
                    </div>
                    {ldapUsers.length === 0
                      ? <p className="text-xs text-gray-400 italic">Keine Benutzer verfügbar</p>
                      : (
                        <div className="grid grid-cols-2 gap-2">
                          {ldapUsers.map((u) => {
                            const sel = wizardShare.allowedUsers.includes(u.displayName);
                            return (
                              <button
                                key={u.id}
                                onClick={() => toggleUser(u.displayName)}
                                className={`flex items-center gap-2 p-2.5 rounded-lg border text-left transition-all text-xs ${sel ? 'border-purple-400 bg-purple-50 text-purple-800' : 'border-gray-200 text-gray-600 hover:border-gray-300'}`}
                              >
                                <div className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 ${sel ? 'bg-purple-600' : 'border border-gray-300'}`}>
                                  {sel && <CheckIcon className="h-3 w-3 text-white" />}
                                </div>
                                <div className="min-w-0">
                                  <p className="font-medium truncate">{u.displayName}</p>
                                  <p className="text-gray-400 truncate">{u.email}</p>
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                  </div>

                  {/* Summary */}
                  {(wizardShare.allowedGroups.length > 0 || wizardShare.allowedUsers.length > 0) && (
                    <div className="bg-purple-50 border border-purple-100 rounded-lg p-3 text-xs text-purple-700">
                      Zugriff für: {[...wizardShare.allowedGroups.map(g => `Gruppe «${g}»`), ...wizardShare.allowedUsers.map(u => u)].join(', ')}
                    </div>
                  )}
                  {wizardShare.allowedGroups.length === 0 && wizardShare.allowedUsers.length === 0 && (
                    <div className="bg-amber-50 border border-amber-100 rounded-lg p-3 text-xs text-amber-700">
                      Kein ACL konfiguriert — alle authentifizierten Benutzer haben Zugriff
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Modal footer */}
            <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-xl">
              <button
                onClick={wizardStep === 1 ? closeWizard : wizardBack}
                className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-800"
              >
                {wizardStep > 1 && <ChevronLeftIcon className="h-4 w-4" />}
                {wizardStep === 1 ? 'Abbrechen' : 'Zurück'}
              </button>

              {wizardStep < 3 ? (
                <button
                  onClick={wizardNext}
                  disabled={wizardStep === 2 && !wizardStep2Valid()}
                  className="flex items-center gap-1 bg-purple-600 text-white px-5 py-2 rounded-md text-sm font-medium hover:bg-purple-700 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Weiter <ChevronRightIcon className="h-4 w-4" />
                </button>
              ) : (
                <button
                  onClick={handleWizardSubmit}
                  disabled={wizardSaving}
                  className="flex items-center gap-1 bg-purple-600 text-white px-5 py-2 rounded-md text-sm font-medium hover:bg-purple-700 disabled:opacity-60"
                >
                  {wizardSaving ? 'Speichern…' : 'Share erstellen'}
                  {!wizardSaving && <CheckIcon className="h-4 w-4" />}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
      {showNetworkWizard && <NetworkConfigWizard onClose={() => setShowNetworkWizard(false)} />}
    </div>
  );
}
