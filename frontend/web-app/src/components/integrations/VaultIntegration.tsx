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
      <div className="rounded-lg p-6 animate-pulse" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)' }}>
        <div className="h-4 rounded w-1/4 mb-4" style={{ background: 'var(--bg-surface-raised)' }}></div>
        <div className="space-y-2">
          <div className="h-4 rounded" style={{ background: 'var(--bg-surface-raised)' }}></div>
          <div className="h-4 rounded w-5/6" style={{ background: 'var(--bg-surface-raised)' }}></div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg" style={{ background: 'var(--bg-surface)', boxShadow: 'var(--card-shadow)', border: '1px solid var(--border)' }}>
      <div style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldCheckIcon className="h-6 w-6 text-yellow-500" />
              <h2 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>Secrets (Vault)</h2>
            </div>
            {healthStatus && (
              <div className="flex items-center space-x-2 text-sm">
                <div className={`w-3 h-3 rounded-full ${
                  healthStatus.sealed ? 'bg-red-500' : 'bg-green-500'
                }`}></div>
                <span style={{ color: 'var(--text-secondary)' }}>
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
              className={`whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                activeTab === tab.key
                  ? 'border-yellow-500'
                  : 'border-transparent'
              }`}
              style={{ color: activeTab === tab.key ? '#d29922' : 'var(--text-muted)' }}
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
              <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>Secret Management</h3>
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
                <div key={secret.path} className="rounded-lg p-4" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <KeyIcon className="h-5 w-5 text-yellow-500" />
                      <h4 className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{secret.path}</h4>
                    </div>
                    <div className="flex space-x-1">
                      <button
                        onClick={() => toggleSecretVisibility(secret.path)}
                        className="p-1 transition-colors"
                        style={{ color: 'var(--text-muted)' }}
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
                        className="p-1 transition-colors hover:text-red-500"
                        style={{ color: 'var(--text-muted)' }}
                        title="Delete secret"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1 mb-2">
                    {Object.entries(secret.data).map(([key, value]) => (
                      <div key={key} className="flex justify-between text-xs">
                        <span style={{ color: 'var(--text-secondary)' }}>{key}:</span>
                        <span className="font-mono" style={{ color: 'var(--text-primary)' }}>
                          {visibleSecrets.has(secret.path) ?
                            (typeof value === 'string' ? value : JSON.stringify(value)) :
                            '••••••••'
                          }
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    Version {secret.metadata.version} •
                    Created {formatDate(secret.metadata.created_time)}
                  </div>
                </div>
              ))}
            </div>

            {secrets.length === 0 && (
              <div className="text-center py-8" style={{ color: 'var(--text-muted)' }}>
                <KeyIcon className="mx-auto h-12 w-12 mb-4" style={{ color: 'var(--text-muted)' }} />
                <h3 className="text-lg font-medium mb-2" style={{ color: 'var(--text-primary)' }}>No secrets found</h3>
                <p>Create your first secret to get started.</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'service-creds' && (
          <div className="space-y-4">
            <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>Service Credentials</h3>
            <div className="rounded-lg p-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                Manage credentials for OpenDirectory services. These are automatically used by the integration service.
              </p>
            </div>

            {/* Placeholder for service credentials management */}
            <div className="grid gap-4 md:grid-cols-2">
              {['LLDAP', 'Grafana', 'Prometheus'].map((service) => (
                <div key={service} className="rounded-lg p-4" style={{ border: '1px solid var(--border)', background: 'var(--bg-surface-raised)' }}>
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{service}</h4>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium" style={{ background: 'var(--success-light)', color: 'var(--success)' }}>
                      Configured
                    </span>
                  </div>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    Credentials stored and managed automatically
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'api-keys' && (
          <div className="space-y-4">
            <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>API Keys</h3>
            <div className="rounded-lg p-4" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                Store and manage API keys for external services and integrations.
              </p>
            </div>

            {/* Placeholder for API keys management */}
            <div className="text-center py-8" style={{ color: 'var(--text-muted)' }}>
              <KeyIcon className="mx-auto h-12 w-12 mb-4" style={{ color: 'var(--text-muted)' }} />
              <h3 className="text-lg font-medium mb-2" style={{ color: 'var(--text-primary)' }}>No API keys configured</h3>
              <p>API keys will be managed here.</p>
            </div>
          </div>
        )}

        {activeTab === 'health' && healthStatus && (
          <div className="space-y-6">
            <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>Vault Health Status</h3>

            <div className="grid gap-6 md:grid-cols-2">
              <div className="rounded-lg p-6" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div className="flex items-center">
                  <div className={`w-4 h-4 rounded-full mr-3 ${
                    healthStatus.sealed ? 'bg-red-500' : 'bg-green-500'
                  }`}></div>
                  <div>
                    <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Seal Status</p>
                    <p className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
                      {healthStatus.sealed ? 'Sealed' : 'Unsealed'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-lg p-6" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div className="flex items-center">
                  <div className={`w-4 h-4 rounded-full mr-3 ${
                    healthStatus.initialized ? 'bg-green-500' : 'bg-red-500'
                  }`}></div>
                  <div>
                    <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Initialization</p>
                    <p className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
                      {healthStatus.initialized ? 'Initialized' : 'Not Initialized'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-lg p-6" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div>
                  <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Version</p>
                  <p className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>{healthStatus.version}</p>
                </div>
              </div>

              <div className="rounded-lg p-6" style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}>
                <div>
                  <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Mode</p>
                  <p className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
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
                className="inline-flex items-center px-4 py-2 text-sm font-medium rounded-md transition-colors"
                style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}
              >
                Open Vault UI →
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Add Secret Modal */}
      {showSecretModal && (
        <div className="fixed inset-0 overflow-y-auto h-full w-full z-50" style={{ background: 'rgba(0,0,0,0.6)' }}>
          <div className="relative top-20 mx-auto p-5 w-96 rounded-md shadow-lg" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-strong)' }}>
            <div className="mt-3">
              <h3 className="text-lg font-medium mb-4" style={{ color: 'var(--text-primary)' }}>Add New Secret</h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Secret Path</label>
                  <input
                    type="text"
                    value={newSecretPath}
                    onChange={(e) => setNewSecretPath(e.target.value)}
                    className="mt-1 block w-full rounded-md focus:outline-none focus:ring-1 focus:ring-yellow-500"
                    style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 12px' }}
                    placeholder="e.g., my-app/database"
                  />
                </div>

                <div>
                  <div className="flex justify-between items-center mb-2">
                    <label className="block text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Key-Value Pairs</label>
                    <button
                      onClick={addSecretKeyValue}
                      className="text-sm text-yellow-500 hover:text-yellow-400"
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
                        className="flex-1 rounded-md"
                        style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '6px 10px' }}
                      />
                      <input
                        type="text"
                        value={value}
                        onChange={(e) => setNewSecretData({ ...newSecretData, [key]: e.target.value })}
                        className="flex-1 rounded-md focus:outline-none focus:ring-1 focus:ring-yellow-500"
                        style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '6px 10px' }}
                      />
                      <button
                        onClick={() => removeSecretKeyValue(key)}
                        className="px-2 py-1 text-red-500 hover:text-red-400"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  ))}

                  {Object.keys(newSecretData).length === 0 && (
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No key-value pairs added yet.</p>
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
                  className="px-4 py-2 text-sm font-medium rounded-md transition-colors"
                  style={{ color: 'var(--text-secondary)', background: 'var(--bg-surface-raised)', border: '1px solid var(--border)' }}
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
