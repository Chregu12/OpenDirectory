'use client';

import React, { useState, useEffect } from 'react';
import {
  GlobeAltIcon,
  ServerIcon,
  FolderIcon,
  MagnifyingGlassIcon,
  CheckIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  PlusIcon,
  TrashIcon,
  WifiIcon,
  XMarkIcon,
  BoltIcon,
} from '@heroicons/react/24/outline';
import { networkApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface NetworkConfigWizardProps {
  onClose: () => void;
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
  name: string;
  path: string;
  protocol: 'SMB' | 'NFS' | 'AFP';
  permissions: string;
  enabled: boolean;
}

interface NetworkDevice {
  ip: string;
  hostname?: string;
  mac?: string;
  vendor?: string;
  type?: string;
  lastSeen: string;
}

const STEPS = [
  { n: 1 as const, label: 'Übersicht' },
  { n: 2 as const, label: 'DNS' },
  { n: 3 as const, label: 'DHCP' },
  { n: 4 as const, label: 'File Shares' },
  { n: 5 as const, label: 'Fertig' },
];

// Simple IP validation
const isValidIP = (ip: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(o => parseInt(o) <= 255);
const isValidSubnet = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^\/\d{1,2}$/.test(s);

export default function NetworkConfigWizard({ onClose }: NetworkConfigWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);

  // Overview / Discovery
  const [networkDevices, setNetworkDevices] = useState<NetworkDevice[]>([]);
  const [discoveryRange, setDiscoveryRange] = useState('192.168.1.0/24');
  const [discovering, setDiscovering] = useState(false);

  // DNS
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([]);
  const [newDNS, setNewDNS] = useState<Partial<DNSRecord>>({ type: 'A', ttl: 300 });

  // DHCP
  const [dhcpScopes, setDhcpScopes] = useState<DHCPScope[]>([]);
  const [newDHCP, setNewDHCP] = useState<Partial<DHCPScope>>({
    leaseTime: 86400,
    enabled: true,
    dnsServers: ['8.8.8.8', '8.8.4.4'],
  });

  // File Shares
  const [fileShares, setFileShares] = useState<FileShare[]>([]);
  const [newShare, setNewShare] = useState<Partial<FileShare>>({
    protocol: 'SMB',
    permissions: 'rw',
    enabled: true,
  });

  // Quick Setup
  const [quickSetupSubnet, setQuickSetupSubnet] = useState('192.168.1');

  useEffect(() => {
    loadExistingData();
  }, []);

  const loadExistingData = async () => {
    try {
      const [dnsRes, dhcpRes, sharesRes] = await Promise.all([
        networkApi.getDNSRecords().catch(() => ({ data: { records: [] } })),
        networkApi.getDHCPScopes().catch(() => ({ data: { scopes: [] } })),
        networkApi.getFileShares().catch(() => ({ data: { shares: [] } })),
      ]);
      setDnsRecords(dnsRes.data?.records || []);
      setDhcpScopes(dhcpRes.data?.scopes || []);
      setFileShares(sharesRes.data?.shares || []);
    } catch {
      // Silently fail — wizard can still be used to create new config
    }
  };

  const handleDiscovery = async () => {
    setDiscovering(true);
    try {
      await networkApi.startNetworkScan(discoveryRange);
      // Wait briefly then fetch discovered devices
      await new Promise(r => setTimeout(r, 3000));
      const res = await networkApi.getDiscoveredDevices();
      setNetworkDevices(res.data?.devices || []);
      toast.success(`${res.data?.devices?.length || 0} Geräte gefunden`);
    } catch (error) {
      toast.error(`Scan fehlgeschlagen: ${formatError(error)}`);
    } finally {
      setDiscovering(false);
    }
  };

  const handleQuickSetup = () => {
    const base = quickSetupSubnet;
    // Auto-create DNS + DHCP based on subnet
    setDnsRecords(prev => [
      ...prev,
      { name: 'gateway', type: 'A', value: `${base}.1`, ttl: 300 },
      { name: 'dns', type: 'A', value: `${base}.1`, ttl: 300 },
    ]);
    setDhcpScopes(prev => [
      ...prev,
      {
        name: `${base}.0/24`,
        startIP: `${base}.100`,
        endIP: `${base}.200`,
        subnet: '255.255.255.0',
        gateway: `${base}.1`,
        dnsServers: [`${base}.1`, '8.8.8.8'],
        leaseTime: 86400,
        enabled: true,
      },
    ]);
    toast.success('Quick Setup: DNS + DHCP vorkonfiguriert');
    setStep(5); // Jump to summary
  };

  const addDNSRecord = () => {
    if (!newDNS.name || !newDNS.value) {
      toast.error('Name und Wert sind erforderlich');
      return;
    }
    setDnsRecords(prev => [...prev, { name: newDNS.name!, type: newDNS.type || 'A', value: newDNS.value!, ttl: newDNS.ttl || 300 }]);
    setNewDNS({ type: 'A', ttl: 300 });
  };

  const removeDNSRecord = (index: number) => {
    setDnsRecords(prev => prev.filter((_, i) => i !== index));
  };

  const addDHCPScope = () => {
    if (!newDHCP.name || !newDHCP.startIP || !newDHCP.endIP) {
      toast.error('Name, Start-IP und End-IP sind erforderlich');
      return;
    }
    if (!isValidIP(newDHCP.startIP) || !isValidIP(newDHCP.endIP)) {
      toast.error('Ungültige IP-Adresse');
      return;
    }
    setDhcpScopes(prev => [
      ...prev,
      {
        name: newDHCP.name!,
        startIP: newDHCP.startIP!,
        endIP: newDHCP.endIP!,
        subnet: newDHCP.subnet || '255.255.255.0',
        gateway: newDHCP.gateway || '',
        dnsServers: newDHCP.dnsServers || ['8.8.8.8'],
        leaseTime: newDHCP.leaseTime || 86400,
        enabled: newDHCP.enabled !== false,
      },
    ]);
    setNewDHCP({ leaseTime: 86400, enabled: true, dnsServers: ['8.8.8.8', '8.8.4.4'] });
  };

  const removeDHCPScope = (index: number) => {
    setDhcpScopes(prev => prev.filter((_, i) => i !== index));
  };

  const addFileShare = () => {
    if (!newShare.name || !newShare.path) {
      toast.error('Name und Pfad sind erforderlich');
      return;
    }
    setFileShares(prev => [
      ...prev,
      {
        name: newShare.name!,
        path: newShare.path!,
        protocol: newShare.protocol || 'SMB',
        permissions: newShare.permissions || 'rw',
        enabled: newShare.enabled !== false,
      },
    ]);
    setNewShare({ protocol: 'SMB', permissions: 'rw', enabled: true });
  };

  const removeFileShare = (index: number) => {
    setFileShares(prev => prev.filter((_, i) => i !== index));
  };

  const handleApply = async () => {
    setSaving(true);
    try {
      // Submit DNS records
      for (const record of dnsRecords) {
        await networkApi.createDNSRecord(record).catch(() => {});
      }
      // Submit DHCP scopes
      for (const scope of dhcpScopes) {
        await networkApi.createDHCPScope(scope).catch(() => {});
      }
      // Submit file shares
      for (const share of fileShares) {
        await networkApi.createFileShare(share).catch(() => {});
      }
      toast.success('Netzwerk-Konfiguration angewendet!');
      onClose();
    } catch (error) {
      toast.error(`Fehler beim Anwenden: ${formatError(error)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-cyan-600 px-8 pt-6 pb-8">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-white text-xl font-bold mb-1">Netzwerk-Konfiguration</h2>
              <p className="text-blue-200 text-sm">DNS, DHCP und File Shares einrichten</p>
            </div>
            <button onClick={onClose} className="text-white/60 hover:text-white transition-colors">
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

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
                  <div className={`flex-1 h-px mx-3 ${s.n < step ? 'bg-blue-300' : 'bg-blue-500/40'}`} />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-8 py-6">

          {/* Step 1: Übersicht */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center py-4">
                <div className="w-16 h-16 bg-blue-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <WifiIcon className="h-8 w-8 text-blue-600" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-2">Netzwerk-Übersicht</h3>
                <p className="text-gray-500 max-w-md mx-auto">
                  Scanne dein Netzwerk um vorhandene Geräte zu finden, oder nutze das Quick Setup.
                </p>
              </div>

              {/* Quick Setup */}
              <div className="bg-green-50 border border-green-200 rounded-xl p-5">
                <div className="flex items-start">
                  <BoltIcon className="h-5 w-5 text-green-600 mt-0.5 mr-3 flex-shrink-0" />
                  <div className="flex-1">
                    <h4 className="text-sm font-medium text-green-900 mb-2">Quick Setup</h4>
                    <p className="text-sm text-green-700 mb-3">
                      Gib dein Subnet ein — DNS und DHCP werden automatisch konfiguriert.
                    </p>
                    <div className="flex items-center space-x-3">
                      <div className="flex items-center">
                        <input
                          type="text"
                          value={quickSetupSubnet}
                          onChange={(e) => setQuickSetupSubnet(e.target.value)}
                          placeholder="192.168.1"
                          className="w-40 px-3 py-2 border border-green-300 rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                        />
                        <span className="text-sm text-green-600 ml-2">.0/24</span>
                      </div>
                      <button
                        onClick={handleQuickSetup}
                        className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 transition-colors"
                      >
                        Auto-Konfigurieren
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Network Scan */}
              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Netzwerk-Scan</h4>
                <div className="flex items-center space-x-3">
                  <input
                    type="text"
                    value={discoveryRange}
                    onChange={(e) => setDiscoveryRange(e.target.value)}
                    placeholder="192.168.1.0/24"
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <button
                    onClick={handleDiscovery}
                    disabled={discovering}
                    className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
                  >
                    {discovering ? (
                      <>
                        <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Scanne...
                      </>
                    ) : (
                      <>
                        <MagnifyingGlassIcon className="h-4 w-4 mr-2" />
                        Scannen
                      </>
                    )}
                  </button>
                </div>

                {networkDevices.length > 0 && (
                  <div className="mt-4">
                    <p className="text-sm text-gray-600 mb-2">{networkDevices.length} Geräte gefunden:</p>
                    <div className="max-h-40 overflow-y-auto space-y-1">
                      {networkDevices.map((d, i) => (
                        <div key={i} className="flex items-center justify-between text-sm bg-white rounded-lg px-3 py-2">
                          <span className="font-medium text-gray-900">{d.ip}</span>
                          <span className="text-gray-500">{d.hostname || d.vendor || '-'}</span>
                          <span className="text-xs text-gray-400">{d.type || 'Unbekannt'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Current stats */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-blue-50 rounded-xl p-4 text-center">
                  <GlobeAltIcon className="h-6 w-6 text-blue-600 mx-auto mb-1" />
                  <p className="text-xl font-bold text-blue-900">{dnsRecords.length}</p>
                  <p className="text-xs text-blue-600">DNS Records</p>
                </div>
                <div className="bg-green-50 rounded-xl p-4 text-center">
                  <ServerIcon className="h-6 w-6 text-green-600 mx-auto mb-1" />
                  <p className="text-xl font-bold text-green-900">{dhcpScopes.length}</p>
                  <p className="text-xs text-green-600">DHCP Scopes</p>
                </div>
                <div className="bg-purple-50 rounded-xl p-4 text-center">
                  <FolderIcon className="h-6 w-6 text-purple-600 mx-auto mb-1" />
                  <p className="text-xl font-bold text-purple-900">{fileShares.length}</p>
                  <p className="text-xs text-purple-600">File Shares</p>
                </div>
              </div>
            </div>
          )}

          {/* Step 2: DNS */}
          {step === 2 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">DNS konfigurieren</h3>
                <p className="text-sm text-gray-500">DNS-Records für dein internes Netzwerk erstellen.</p>
              </div>

              {/* Add form */}
              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Neuer DNS-Record</h4>
                <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
                  <input
                    type="text"
                    placeholder="Name (z.B. www)"
                    value={newDNS.name || ''}
                    onChange={(e) => setNewDNS({ ...newDNS, name: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <select
                    value={newDNS.type}
                    onChange={(e) => setNewDNS({ ...newDNS, type: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="A">A</option>
                    <option value="AAAA">AAAA</option>
                    <option value="CNAME">CNAME</option>
                    <option value="MX">MX</option>
                    <option value="TXT">TXT</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Wert (z.B. 192.168.1.10)"
                    value={newDNS.value || ''}
                    onChange={(e) => setNewDNS({ ...newDNS, value: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <input
                    type="number"
                    placeholder="TTL"
                    value={newDNS.ttl || ''}
                    onChange={(e) => setNewDNS({ ...newDNS, ttl: parseInt(e.target.value) || 300 })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <button
                    onClick={addDNSRecord}
                    className="flex items-center justify-center px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
                  >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Hinzufügen
                  </button>
                </div>
              </div>

              {/* Records list */}
              {dnsRecords.length > 0 ? (
                <div className="space-y-2">
                  {dnsRecords.map((record, index) => (
                    <div key={index} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3">
                      <div className="flex items-center space-x-4">
                        <span className="px-2 py-0.5 text-xs font-medium bg-blue-100 text-blue-700 rounded">{record.type}</span>
                        <span className="font-medium text-gray-900 text-sm">{record.name}</span>
                        <span className="text-gray-500 text-sm">{record.value}</span>
                        <span className="text-gray-400 text-xs">TTL: {record.ttl}</span>
                      </div>
                      <button onClick={() => removeDNSRecord(index)} className="text-red-500 hover:text-red-700">
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Noch keine DNS-Records. Füge oben welche hinzu.
                </div>
              )}
            </div>
          )}

          {/* Step 3: DHCP */}
          {step === 3 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">DHCP konfigurieren</h3>
                <p className="text-sm text-gray-500">IP-Adressbereiche für automatische Zuweisung definieren.</p>
              </div>

              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Neuer DHCP-Scope</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <input
                    type="text"
                    placeholder="Scope-Name"
                    value={newDHCP.name || ''}
                    onChange={(e) => setNewDHCP({ ...newDHCP, name: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                  />
                  <input
                    type="text"
                    placeholder="Start-IP (z.B. 192.168.1.100)"
                    value={newDHCP.startIP || ''}
                    onChange={(e) => setNewDHCP({ ...newDHCP, startIP: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                  />
                  <input
                    type="text"
                    placeholder="End-IP (z.B. 192.168.1.200)"
                    value={newDHCP.endIP || ''}
                    onChange={(e) => setNewDHCP({ ...newDHCP, endIP: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                  />
                  <input
                    type="text"
                    placeholder="Subnet (z.B. 255.255.255.0)"
                    value={newDHCP.subnet || ''}
                    onChange={(e) => setNewDHCP({ ...newDHCP, subnet: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                  />
                  <input
                    type="text"
                    placeholder="Gateway (z.B. 192.168.1.1)"
                    value={newDHCP.gateway || ''}
                    onChange={(e) => setNewDHCP({ ...newDHCP, gateway: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                  />
                  <button
                    onClick={addDHCPScope}
                    className="flex items-center justify-center px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 transition-colors"
                  >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Scope hinzufügen
                  </button>
                </div>
              </div>

              {dhcpScopes.length > 0 ? (
                <div className="space-y-3">
                  {dhcpScopes.map((scope, index) => (
                    <div key={index} className="bg-white border border-gray-200 rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center space-x-2">
                            <h4 className="font-medium text-gray-900 text-sm">{scope.name}</h4>
                            <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                              scope.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                            }`}>
                              {scope.enabled ? 'Aktiv' : 'Inaktiv'}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500 mt-1">
                            {scope.startIP} — {scope.endIP} | Subnet: {scope.subnet}
                          </p>
                          {scope.gateway && (
                            <p className="text-xs text-gray-400">Gateway: {scope.gateway}</p>
                          )}
                        </div>
                        <button onClick={() => removeDHCPScope(index)} className="text-red-500 hover:text-red-700">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Noch keine DHCP-Scopes. Füge oben welche hinzu.
                </div>
              )}
            </div>
          )}

          {/* Step 4: File Shares */}
          {step === 4 && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">File Shares einrichten</h3>
                <p className="text-sm text-gray-500">Netzwerk-Freigaben für gemeinsamen Dateizugriff konfigurieren.</p>
              </div>

              <div className="bg-gray-50 rounded-xl p-5">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Neue Freigabe</h4>
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                  <input
                    type="text"
                    placeholder="Name (z.B. Dokumente)"
                    value={newShare.name || ''}
                    onChange={(e) => setNewShare({ ...newShare, name: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                  />
                  <input
                    type="text"
                    placeholder="Pfad (z.B. /srv/shares/docs)"
                    value={newShare.path || ''}
                    onChange={(e) => setNewShare({ ...newShare, path: e.target.value })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                  />
                  <select
                    value={newShare.protocol}
                    onChange={(e) => setNewShare({ ...newShare, protocol: e.target.value as 'SMB' | 'NFS' | 'AFP' })}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                  >
                    <option value="SMB">SMB/CIFS</option>
                    <option value="NFS">NFS</option>
                    <option value="AFP">AFP</option>
                  </select>
                  <button
                    onClick={addFileShare}
                    className="flex items-center justify-center px-4 py-2 bg-purple-600 text-white rounded-lg text-sm font-medium hover:bg-purple-700 transition-colors"
                  >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Hinzufügen
                  </button>
                </div>
              </div>

              {fileShares.length > 0 ? (
                <div className="space-y-3">
                  {fileShares.map((share, index) => (
                    <div key={index} className="bg-white border border-gray-200 rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center space-x-2">
                            <FolderIcon className="h-4 w-4 text-purple-500" />
                            <h4 className="font-medium text-gray-900 text-sm">{share.name}</h4>
                            <span className="px-2 py-0.5 text-xs font-medium bg-purple-100 text-purple-700 rounded">{share.protocol}</span>
                          </div>
                          <p className="text-sm text-gray-500 mt-1">{share.path}</p>
                          <p className="text-xs text-gray-400">Berechtigungen: {share.permissions}</p>
                        </div>
                        <button onClick={() => removeFileShare(index)} className="text-red-500 hover:text-red-700">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400 text-sm">
                  Noch keine File Shares. Füge oben welche hinzu.
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
                <p className="text-gray-500 text-sm mt-1">Überprüfe deine Netzwerk-Konfiguration</p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-blue-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-blue-900">{dnsRecords.length}</p>
                  <p className="text-xs text-blue-600">DNS Records</p>
                </div>
                <div className="bg-green-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-green-900">{dhcpScopes.length}</p>
                  <p className="text-xs text-green-600">DHCP Scopes</p>
                </div>
                <div className="bg-purple-50 rounded-xl p-4 text-center">
                  <p className="text-2xl font-bold text-purple-900">{fileShares.length}</p>
                  <p className="text-xs text-purple-600">File Shares</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-5 space-y-4">
                {dnsRecords.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">DNS Records</h4>
                    <div className="flex flex-wrap gap-2">
                      {dnsRecords.map((r, i) => (
                        <span key={i} className="px-2.5 py-1 text-xs bg-blue-100 text-blue-700 rounded-full font-medium">
                          {r.type} {r.name} → {r.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {dhcpScopes.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">DHCP Scopes</h4>
                    <div className="flex flex-wrap gap-2">
                      {dhcpScopes.map((s, i) => (
                        <span key={i} className="px-2.5 py-1 text-xs bg-green-100 text-green-700 rounded-full font-medium">
                          {s.name}: {s.startIP}–{s.endIP}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {fileShares.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">File Shares</h4>
                    <div className="flex flex-wrap gap-2">
                      {fileShares.map((s, i) => (
                        <span key={i} className="px-2.5 py-1 text-xs bg-purple-100 text-purple-700 rounded-full font-medium">
                          {s.protocol} {s.name} ({s.path})
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {dnsRecords.length === 0 && dhcpScopes.length === 0 && fileShares.length === 0 && (
                <p className="text-center text-gray-400 text-sm">
                  Keine Konfiguration hinzugefügt. Gehe zurück um Einstellungen vorzunehmen.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
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
            {step < 5 ? (
              <button
                onClick={() => setStep((step + 1) as WizardStep)}
                className="flex items-center px-6 py-2.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
              >
                Weiter
                <ArrowRightIcon className="h-4 w-4 ml-1" />
              </button>
            ) : (
              <button
                onClick={handleApply}
                disabled={saving || (dnsRecords.length === 0 && dhcpScopes.length === 0 && fileShares.length === 0)}
                className="flex items-center px-6 py-2.5 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 transition-colors disabled:opacity-50"
              >
                {saving ? (
                  <>
                    <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Anwenden...
                  </>
                ) : (
                  <>
                    <CheckIcon className="h-4 w-4 mr-1" />
                    Konfiguration anwenden
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
