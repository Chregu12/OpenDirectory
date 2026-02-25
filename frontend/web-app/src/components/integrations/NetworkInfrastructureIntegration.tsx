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
  ComputerDesktopIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

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
  name: string;
  path: string;
  protocol: 'SMB' | 'NFS' | 'AFP';
  permissions: string;
  enabled: boolean;
}

export default function NetworkInfrastructureIntegration() {
  const [activeView, setActiveView] = useState('overview');
  const [loading, setLoading] = useState(false);
  
  // DNS Management State
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([]);
  const [newDNSRecord, setNewDNSRecord] = useState<Partial<DNSRecord>>({
    type: 'A',
    ttl: 300
  });

  // DHCP Management State
  const [dhcpScopes, setDhcpScopes] = useState<DHCPScope[]>([]);
  const [newDHCPScope, setNewDHCPScope] = useState<Partial<DHCPScope>>({
    leaseTime: 86400,
    enabled: true,
    dnsServers: ['8.8.8.8', '8.8.4.4']
  });

  // File Share Management State
  const [fileShares, setFileShares] = useState<FileShare[]>([]);
  const [newFileShare, setNewFileShare] = useState<Partial<FileShare>>({
    protocol: 'SMB',
    permissions: 'rw',
    enabled: true
  });

  // Network Discovery State
  const [networkDevices, setNetworkDevices] = useState<NetworkDevice[]>([]);
  const [discoveryRange, setDiscoveryRange] = useState('192.168.1.0/24');
  const [discovering, setDiscovering] = useState(false);

  useEffect(() => {
    loadNetworkData();
  }, []);

  const loadNetworkData = async () => {
    setLoading(true);
    try {
      await Promise.all([
        loadDNSRecords(),
        loadDHCPScopes(),
        loadFileShares(),
        loadNetworkDevices()
      ]);
    } catch (error) {
      console.error('Failed to load network data:', error);
      toast.error('Failed to load network data');
    } finally {
      setLoading(false);
    }
  };

  const loadDNSRecords = async () => {
    try {
      const response = await fetch('/api/network/dns/records');
      if (response.ok) {
        const data = await response.json();
        setDnsRecords(data.records || []);
      }
    } catch (error) {
      console.error('Failed to load DNS records:', error);
    }
  };

  const loadDHCPScopes = async () => {
    try {
      const response = await fetch('/api/network/dhcp/scopes');
      if (response.ok) {
        const data = await response.json();
        setDhcpScopes(data.scopes || []);
      }
    } catch (error) {
      console.error('Failed to load DHCP scopes:', error);
    }
  };

  const loadFileShares = async () => {
    try {
      const response = await fetch('/api/network/shares');
      if (response.ok) {
        const data = await response.json();
        setFileShares(data.shares || []);
      }
    } catch (error) {
      console.error('Failed to load file shares:', error);
    }
  };

  const loadNetworkDevices = async () => {
    try {
      const response = await fetch('/api/network/devices');
      if (response.ok) {
        const data = await response.json();
        setNetworkDevices(data.devices || []);
      }
    } catch (error) {
      console.error('Failed to load network devices:', error);
    }
  };

  const handleDNSRecordAdd = async () => {
    if (!newDNSRecord.name || !newDNSRecord.value) {
      toast.error('Name and value are required');
      return;
    }

    try {
      const response = await fetch('/api/network/dns/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newDNSRecord)
      });

      if (response.ok) {
        toast.success('DNS record added successfully');
        setNewDNSRecord({ type: 'A', ttl: 300 });
        loadDNSRecords();
      } else {
        toast.error('Failed to add DNS record');
      }
    } catch (error) {
      toast.error('Error adding DNS record');
    }
  };

  const handleDHCPScopeAdd = async () => {
    if (!newDHCPScope.name || !newDHCPScope.startIP || !newDHCPScope.endIP) {
      toast.error('Name, start IP, and end IP are required');
      return;
    }

    try {
      const response = await fetch('/api/network/dhcp/scopes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newDHCPScope)
      });

      if (response.ok) {
        toast.success('DHCP scope added successfully');
        setNewDHCPScope({ leaseTime: 86400, enabled: true, dnsServers: ['8.8.8.8', '8.8.4.4'] });
        loadDHCPScopes();
      } else {
        toast.error('Failed to add DHCP scope');
      }
    } catch (error) {
      toast.error('Error adding DHCP scope');
    }
  };

  const handleFileShareAdd = async () => {
    if (!newFileShare.name || !newFileShare.path) {
      toast.error('Name and path are required');
      return;
    }

    try {
      const response = await fetch('/api/network/shares', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newFileShare)
      });

      if (response.ok) {
        toast.success('File share added successfully');
        setNewFileShare({ protocol: 'SMB', permissions: 'rw', enabled: true });
        loadFileShares();
      } else {
        toast.error('Failed to add file share');
      }
    } catch (error) {
      toast.error('Error adding file share');
    }
  };

  const handleNetworkDiscovery = async () => {
    setDiscovering(true);
    try {
      const response = await fetch('/api/network/discovery/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ range: discoveryRange })
      });

      if (response.ok) {
        toast.success('Network discovery started');
        setTimeout(loadNetworkDevices, 5000); // Refresh after 5 seconds
      } else {
        toast.error('Failed to start network discovery');
      }
    } catch (error) {
      toast.error('Error starting network discovery');
    } finally {
      setDiscovering(false);
    }
  };

  const views = [
    { id: 'overview', label: 'Overview', icon: WifiIcon },
    { id: 'dns', label: 'DNS Management', icon: GlobeAltIcon },
    { id: 'dhcp', label: 'DHCP Management', icon: ServerIcon },
    { id: 'shares', label: 'File Shares', icon: FolderIcon },
    { id: 'discovery', label: 'Network Discovery', icon: MagnifyingGlassIcon },
    { id: 'monitoring', label: 'Network Monitoring', icon: ChartBarIcon }
  ];

  return (
    <div className="space-y-6">
      {/* Navigation */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8">
          {views.map((view) => (
            <button
              key={view.id}
              onClick={() => setActiveView(view.id)}
              className={`${
                activeView === view.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
            >
              <view.icon className="h-5 w-5" />
              <span>{view.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Overview */}
      {activeView === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <GlobeAltIcon className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-blue-600">DNS</p>
                <p className="text-lg font-bold text-blue-900">{dnsRecords.length} Records</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <ServerIcon className="h-8 w-8 text-green-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-green-600">DHCP</p>
                <p className="text-lg font-bold text-green-900">{dhcpScopes.length} Scopes</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <FolderIcon className="h-8 w-8 text-purple-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-purple-600">File Shares</p>
                <p className="text-lg font-bold text-purple-900">{fileShares.length} Shares</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <ComputerDesktopIcon className="h-8 w-8 text-orange-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-orange-600">Devices</p>
                <p className="text-lg font-bold text-orange-900">{networkDevices.length} Found</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DNS Management */}
      {activeView === 'dns' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Add DNS Record</h3>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <input
                type="text"
                placeholder="Name (e.g., www)"
                value={newDNSRecord.name || ''}
                onChange={(e) => setNewDNSRecord({...newDNSRecord, name: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <select
                value={newDNSRecord.type}
                onChange={(e) => setNewDNSRecord({...newDNSRecord, type: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              >
                <option value="A">A</option>
                <option value="AAAA">AAAA</option>
                <option value="CNAME">CNAME</option>
                <option value="MX">MX</option>
                <option value="TXT">TXT</option>
              </select>
              <input
                type="text"
                placeholder="Value (e.g., 192.168.1.100)"
                value={newDNSRecord.value || ''}
                onChange={(e) => setNewDNSRecord({...newDNSRecord, value: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <input
                type="number"
                placeholder="TTL"
                value={newDNSRecord.ttl || ''}
                onChange={(e) => setNewDNSRecord({...newDNSRecord, ttl: parseInt(e.target.value)})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <button
                onClick={handleDNSRecordAdd}
                className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center justify-center"
              >
                <PlusIcon className="h-5 w-5 mr-2" />
                Add
              </button>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">DNS Records</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Value</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">TTL</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {dnsRecords.map((record, index) => (
                    <tr key={index}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{record.name}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{record.type}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{record.value}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{record.ttl}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <button className="text-red-600 hover:text-red-900">
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* DHCP Management */}
      {activeView === 'dhcp' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Add DHCP Scope</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <input
                type="text"
                placeholder="Scope Name"
                value={newDHCPScope.name || ''}
                onChange={(e) => setNewDHCPScope({...newDHCPScope, name: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <input
                type="text"
                placeholder="Start IP"
                value={newDHCPScope.startIP || ''}
                onChange={(e) => setNewDHCPScope({...newDHCPScope, startIP: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <input
                type="text"
                placeholder="End IP"
                value={newDHCPScope.endIP || ''}
                onChange={(e) => setNewDHCPScope({...newDHCPScope, endIP: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <input
                type="text"
                placeholder="Subnet (e.g., 255.255.255.0)"
                value={newDHCPScope.subnet || ''}
                onChange={(e) => setNewDHCPScope({...newDHCPScope, subnet: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <input
                type="text"
                placeholder="Gateway"
                value={newDHCPScope.gateway || ''}
                onChange={(e) => setNewDHCPScope({...newDHCPScope, gateway: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <button
                onClick={handleDHCPScopeAdd}
                className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 flex items-center justify-center"
              >
                <PlusIcon className="h-5 w-5 mr-2" />
                Add Scope
              </button>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">DHCP Scopes</h3>
            </div>
            <div className="space-y-4 p-6">
              {dhcpScopes.map((scope, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h4 className="text-lg font-medium text-gray-900">{scope.name}</h4>
                      <p className="text-sm text-gray-600">Range: {scope.startIP} - {scope.endIP}</p>
                      <p className="text-sm text-gray-600">Subnet: {scope.subnet}</p>
                      <p className="text-sm text-gray-600">Gateway: {scope.gateway}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                        scope.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {scope.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                      <button className="text-red-600 hover:text-red-900">
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* File Shares */}
      {activeView === 'shares' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Add File Share</h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <input
                type="text"
                placeholder="Share Name"
                value={newFileShare.name || ''}
                onChange={(e) => setNewFileShare({...newFileShare, name: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <input
                type="text"
                placeholder="Path"
                value={newFileShare.path || ''}
                onChange={(e) => setNewFileShare({...newFileShare, path: e.target.value})}
                className="border border-gray-300 rounded-md px-3 py-2"
              />
              <select
                value={newFileShare.protocol}
                onChange={(e) => setNewFileShare({...newFileShare, protocol: e.target.value as any})}
                className="border border-gray-300 rounded-md px-3 py-2"
              >
                <option value="SMB">SMB/CIFS</option>
                <option value="NFS">NFS</option>
                <option value="AFP">AFP</option>
              </select>
              <button
                onClick={handleFileShareAdd}
                className="bg-purple-600 text-white px-4 py-2 rounded-md hover:bg-purple-700 flex items-center justify-center"
              >
                <PlusIcon className="h-5 w-5 mr-2" />
                Add Share
              </button>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">File Shares</h3>
            </div>
            <div className="space-y-4 p-6">
              {fileShares.map((share, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h4 className="text-lg font-medium text-gray-900">{share.name}</h4>
                      <p className="text-sm text-gray-600">Path: {share.path}</p>
                      <p className="text-sm text-gray-600">Protocol: {share.protocol}</p>
                      <p className="text-sm text-gray-600">Permissions: {share.permissions}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                        share.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {share.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                      <button className="text-red-600 hover:text-red-900">
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Network Discovery */}
      {activeView === 'discovery' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Network Discovery</h3>
            <div className="flex space-x-4">
              <input
                type="text"
                placeholder="IP Range (e.g., 192.168.1.0/24)"
                value={discoveryRange}
                onChange={(e) => setDiscoveryRange(e.target.value)}
                className="flex-1 border border-gray-300 rounded-md px-3 py-2"
              />
              <button
                onClick={handleNetworkDiscovery}
                disabled={discovering}
                className="bg-orange-600 text-white px-4 py-2 rounded-md hover:bg-orange-700 disabled:opacity-50 flex items-center"
              >
                <MagnifyingGlassIcon className="h-5 w-5 mr-2" />
                {discovering ? 'Discovering...' : 'Scan Network'}
              </button>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Discovered Devices ({networkDevices.length})</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hostname</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">MAC Address</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vendor</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {networkDevices.map((device, index) => (
                    <tr key={index}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{device.ip}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{device.hostname || '-'}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{device.mac || '-'}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{device.vendor || '-'}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{device.type || '-'}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(device.lastSeen).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Network Monitoring */}
      {activeView === 'monitoring' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Network Monitoring</h3>
            <p className="text-gray-600">Real-time network monitoring and alerting system.</p>
            <div className="mt-4">
              <button className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                View Detailed Monitoring
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}