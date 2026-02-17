'use client';

import React, { useState, useEffect } from 'react';
import { 
  KeyIcon, 
  FolderIcon, 
  PlusIcon, 
  TrashIcon, 
  EyeIcon, 
  EyeSlashIcon,
  ShieldCheckIcon 
} from '@heroicons/react/24/outline';
import { vaultApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';

interface Secret {
  path: string;
  data: Record<string, any>;
  metadata: {
    created_time: string;
    version: number;
  };
}

interface HealthStatus {
  initialized: boolean;
  sealed: boolean;
  standby: boolean;
  version: string;
}

export default function VaultIntegration() {
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [selectedSecret, setSelectedSecret] = useState<Secret | null>(null);
  const [healthStatus, setHealthStatus] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [showSecretModal, setShowSecretModal] = useState(false);
  const [newSecretPath, setNewSecretPath] = useState('');
  const [newSecretData, setNewSecretData] = useState<Record<string, string>>({});
  const [visibleSecrets, setVisibleSecrets] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<'secrets' | 'service-creds' | 'api-keys' | 'health'>('secrets');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [secretsResponse, healthResponse] = await Promise.all([
        vaultApi.getSecrets(),
        vaultApi.getHealth().catch(() => null),
      ]);

      // Fetch individual secret details
      const secretPaths = secretsResponse.data.secrets || [];
      const secretDetails = await Promise.all(
        secretPaths.map(async (path: string) => {
          try {
            const response = await vaultApi.getSecret(path);
            return response.data;
          } catch {
            return null;
          }
        })
      );

      setSecrets(secretDetails.filter(Boolean));
      setHealthStatus(healthResponse?.data || null);
    } catch (error) {
      toast.error(`Failed to fetch Vault data: ${formatError(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const createSecret = async () => {
    if (!newSecretPath.trim()) {
      toast.error('Secret path is required');
      return;
    }

    if (Object.keys(newSecretData).length === 0) {
      toast.error('At least one key-value pair is required');
      return;
    }

    try {
      await vaultApi.putSecret(newSecretPath, newSecretData);
      toast.success('Secret created successfully');
      setShowSecretModal(false);
      setNewSecretPath('');
      setNewSecretData({});
      fetchData();
    } catch (error) {
      toast.error(`Failed to create secret: ${formatError(error)}`);
    }
  };

  const deleteSecret = async (path: string) => {
    if (!confirm(`Are you sure you want to delete the secret at "${path}"?`)) {
      return;
    }

    try {
      await vaultApi.deleteSecret(path);
      toast.success('Secret deleted successfully');
      setSecrets(secrets.filter(s => s.path !== path));
      if (selectedSecret?.path === path) {
        setSelectedSecret(null);
      }
    } catch (error) {
      toast.error(`Failed to delete secret: ${formatError(error)}`);
    }
  };

  const toggleSecretVisibility = (path: string) => {
    const newVisibleSecrets = new Set(visibleSecrets);
    if (newVisibleSecrets.has(path)) {
      newVisibleSecrets.delete(path);
    } else {
      newVisibleSecrets.add(path);
    }
    setVisibleSecrets(newVisibleSecrets);
  };

  const addSecretKeyValue = () => {
    const key = prompt('Enter key name:');
    if (key && !newSecretData[key]) {
      const value = prompt('Enter value:');
      if (value !== null) {
        setNewSecretData({ ...newSecretData, [key]: value });
      }
    }
  };

  const removeSecretKeyValue = (key: string) => {
    const { [key]: removed, ...rest } = newSecretData;
    setNewSecretData(rest);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-2">
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded w-5/6"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldCheckIcon className="h-6 w-6 text-yellow-600" />
              <h2 className="text-lg font-medium text-gray-900">Secrets (Vault)</h2>
            </div>
            {healthStatus && (
              <div className="flex items-center space-x-2 text-sm">
                <div className={`w-3 h-3 rounded-full ${
                  healthStatus.sealed ? 'bg-red-500' : 'bg-green-500'
                }`}></div>
                <span className="text-gray-600">
                  {healthStatus.sealed ? 'Sealed' : 'Unsealed'} • v{healthStatus.version}
                </span>
              </div>
            )}
          </div>
        </div>
        
        <nav className="flex space-x-8 px-6" aria-label="Tabs">
          {[
            { key: 'secrets' as const, label: 'Secrets', icon: KeyIcon },
            { key: 'service-creds' as const, label: 'Service Credentials', icon: FolderIcon },
            { key: 'api-keys' as const, label: 'API Keys', icon: KeyIcon },
            { key: 'health' as const, label: 'Health', icon: ShieldCheckIcon },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`${
                activeTab === tab.key
                  ? 'border-yellow-500 text-yellow-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
            >
              <tab.icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      <div className="p-6">
        {activeTab === 'secrets' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-medium text-gray-900">Secret Management</h3>
              <button
                onClick={() => setShowSecretModal(true)}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500"
              >
                <PlusIcon className="h-4 w-4 mr-2" />
                Add Secret
              </button>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              {secrets.map((secret) => (
                <div key={secret.path} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <KeyIcon className="h-5 w-5 text-yellow-600" />
                      <h4 className="text-sm font-medium text-gray-900">{secret.path}</h4>
                    </div>
                    <div className="flex space-x-1">
                      <button
                        onClick={() => toggleSecretVisibility(secret.path)}
                        className="p-1 text-gray-400 hover:text-gray-600"
                        title={visibleSecrets.has(secret.path) ? 'Hide values' : 'Show values'}
                      >
                        {visibleSecrets.has(secret.path) ? (
                          <EyeSlashIcon className="h-4 w-4" />
                        ) : (
                          <EyeIcon className="h-4 w-4" />
                        )}
                      </button>
                      <button
                        onClick={() => deleteSecret(secret.path)}
                        className="p-1 text-gray-400 hover:text-red-600"
                        title="Delete secret"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1 mb-2">
                    {Object.entries(secret.data).map(([key, value]) => (
                      <div key={key} className="flex justify-between text-xs">
                        <span className="text-gray-600">{key}:</span>
                        <span className="text-gray-900 font-mono">
                          {visibleSecrets.has(secret.path) ? 
                            (typeof value === 'string' ? value : JSON.stringify(value)) : 
                            '••••••••'
                          }
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="text-xs text-gray-500">
                    Version {secret.metadata.version} • 
                    Created {formatDate(secret.metadata.created_time)}
                  </div>
                </div>
              ))}
            </div>

            {secrets.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <KeyIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No secrets found</h3>
                <p>Create your first secret to get started.</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'service-creds' && (
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-gray-900">Service Credentials</h3>
            <div className="bg-gray-50 rounded-lg p-4">
              <p className="text-sm text-gray-600">
                Manage credentials for OpenDirectory services. These are automatically used by the integration service.
              </p>
            </div>
            
            {/* Placeholder for service credentials management */}
            <div className="grid gap-4 md:grid-cols-2">
              {['LLDAP', 'Grafana', 'Prometheus'].map((service) => (
                <div key={service} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-gray-900">{service}</h4>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                      Configured
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Credentials stored and managed automatically
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'api-keys' && (
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-gray-900">API Keys</h3>
            <div className="bg-gray-50 rounded-lg p-4">
              <p className="text-sm text-gray-600">
                Store and manage API keys for external services and integrations.
              </p>
            </div>
            
            {/* Placeholder for API keys management */}
            <div className="text-center py-8 text-gray-500">
              <KeyIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No API keys configured</h3>
              <p>API keys will be managed here.</p>
            </div>
          </div>
        )}

        {activeTab === 'health' && healthStatus && (
          <div className="space-y-6">
            <h3 className="text-lg font-medium text-gray-900">Vault Health Status</h3>
            
            <div className="grid gap-6 md:grid-cols-2">
              <div className="bg-gray-50 rounded-lg p-6">
                <div className="flex items-center">
                  <div className={`w-4 h-4 rounded-full mr-3 ${
                    healthStatus.sealed ? 'bg-red-500' : 'bg-green-500'
                  }`}></div>
                  <div>
                    <p className="text-sm font-medium text-gray-600">Seal Status</p>
                    <p className="text-lg font-bold text-gray-900">
                      {healthStatus.sealed ? 'Sealed' : 'Unsealed'}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-6">
                <div className="flex items-center">
                  <div className={`w-4 h-4 rounded-full mr-3 ${
                    healthStatus.initialized ? 'bg-green-500' : 'bg-red-500'
                  }`}></div>
                  <div>
                    <p className="text-sm font-medium text-gray-600">Initialization</p>
                    <p className="text-lg font-bold text-gray-900">
                      {healthStatus.initialized ? 'Initialized' : 'Not Initialized'}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-6">
                <div>
                  <p className="text-sm font-medium text-gray-600">Version</p>
                  <p className="text-lg font-bold text-gray-900">{healthStatus.version}</p>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-6">
                <div>
                  <p className="text-sm font-medium text-gray-600">Mode</p>
                  <p className="text-lg font-bold text-gray-900">
                    {healthStatus.standby ? 'Standby' : 'Active'}
                  </p>
                </div>
              </div>
            </div>

            <div className="flex justify-center">
              <a
                href={process.env.NEXT_PUBLIC_VAULT_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
              >
                Open Vault UI →
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Add Secret Modal */}
      {showSecretModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Add New Secret</h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Secret Path</label>
                  <input
                    type="text"
                    value={newSecretPath}
                    onChange={(e) => setNewSecretPath(e.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-yellow-500 focus:ring-yellow-500"
                    placeholder="e.g., my-app/database"
                  />
                </div>
                
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <label className="block text-sm font-medium text-gray-700">Key-Value Pairs</label>
                    <button
                      onClick={addSecretKeyValue}
                      className="text-sm text-yellow-600 hover:text-yellow-700"
                    >
                      + Add Pair
                    </button>
                  </div>
                  
                  {Object.entries(newSecretData).map(([key, value]) => (
                    <div key={key} className="flex space-x-2 mb-2">
                      <input
                        type="text"
                        value={key}
                        readOnly
                        className="flex-1 rounded-md border-gray-300 shadow-sm bg-gray-50"
                      />
                      <input
                        type="text"
                        value={value}
                        onChange={(e) => setNewSecretData({ ...newSecretData, [key]: e.target.value })}
                        className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-yellow-500 focus:ring-yellow-500"
                      />
                      <button
                        onClick={() => removeSecretKeyValue(key)}
                        className="px-2 py-1 text-red-600 hover:text-red-700"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                  
                  {Object.keys(newSecretData).length === 0 && (
                    <p className="text-sm text-gray-500">No key-value pairs added yet.</p>
                  )}
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => {
                    setShowSecretModal(false);
                    setNewSecretPath('');
                    setNewSecretData({});
                  }}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={createSecret}
                  className="px-4 py-2 text-sm font-medium text-white bg-yellow-600 border border-transparent rounded-md hover:bg-yellow-700"
                >
                  Create Secret
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}