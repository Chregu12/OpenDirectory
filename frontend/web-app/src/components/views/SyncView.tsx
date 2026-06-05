'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ArrowPathIcon,
  PlusIcon,
  TrashIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ServerStackIcon,
  XMarkIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { api } from '@/lib/api';

// ── Types ──────────────────────────────────────────────────────────────────────

interface ScimConnection {
  id: string;
  name: string;
  provider: 'google' | 'entra' | 'custom';
  endpoint: string | null;
  syncIntervalMinutes: number;
  lastSync: string | null;
  status: 'active' | 'error' | 'syncing';
  usersSynced: number;
  createdAt: string;
}

interface SyncLogEntry {
  id: string;
  connectionId: string;
  startedAt: string;
  completedAt: string | null;
  status: 'running' | 'completed' | 'error';
  usersCreated: number;
  usersUpdated: number;
  usersDeleted: number;
  errors: number;
  message: string | null;
}

interface ScimConflict {
  id: string;
  connectionId: string;
  userId: string;
  localData: Record<string, unknown>;
  remoteData: Record<string, unknown>;
  conflictType: string;
  resolved: boolean;
  createdAt: string;
}

type Tab = 'connections' | 'log' | 'conflicts';

const PROVIDER_LABELS: Record<string, string> = {
  google: 'Google Workspace',
  entra: 'Microsoft Entra ID',
  custom: 'Eigener IdP',
};

const SYNC_INTERVAL_OPTIONS = [
  { label: '15 Minuten', value: 15 },
  { label: '30 Minuten', value: 30 },
  { label: '1 Stunde', value: 60 },
  { label: '4 Stunden', value: 240 },
  { label: '24 Stunden', value: 1440 },
];

// ── Provider Icon ──────────────────────────────────────────────────────────────

function ProviderIcon({ provider, size = 24 }: { provider: string; size?: number }) {
  if (provider === 'google') {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
    );
  }
  if (provider === 'entra') {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <rect x="2" y="2" width="9" height="9" fill="#F25022"/>
        <rect x="13" y="2" width="9" height="9" fill="#7FBA00"/>
        <rect x="2" y="13" width="9" height="9" fill="#00A4EF"/>
        <rect x="13" y="13" width="9" height="9" fill="#FFB900"/>
      </svg>
    );
  }
  return <ServerStackIcon style={{ width: size, height: size, color: '#6B7280' }} />;
}

// ── Status Badge ───────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  if (status === 'active' || status === 'completed') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: '#DCFCE7', color: '#16A34A', fontSize: 12, fontWeight: 500 }}>
        <CheckCircleIcon style={{ width: 12, height: 12 }} />
        {status === 'completed' ? 'Abgeschlossen' : 'Aktiv'}
      </span>
    );
  }
  if (status === 'error') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: '#FEE2E2', color: '#DC2626', fontSize: 12, fontWeight: 500 }}>
        <ExclamationCircleIcon style={{ width: 12, height: 12 }} />
        Fehler
      </span>
    );
  }
  if (status === 'syncing' || status === 'running') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: '#DBEAFE', color: '#2563EB', fontSize: 12, fontWeight: 500 }}>
        <ArrowPathIcon style={{ width: 12, height: 12, animation: 'spin 1s linear infinite' }} />
        Synchronisiert
      </span>
    );
  }
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: '#F3F4F6', color: '#6B7280', fontSize: 12, fontWeight: 500 }}>
      {status}
    </span>
  );
}

// ── Add Connection Modal ───────────────────────────────────────────────────────

interface AddConnectionModalProps {
  onClose: () => void;
  onSaved: () => void;
}

function AddConnectionModal({ onClose, onSaved }: AddConnectionModalProps) {
  const [provider, setProvider] = useState<'google' | 'entra' | 'custom'>('google');
  const [name, setName] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [bearerToken, setBearerToken] = useState('');
  const [syncInterval, setSyncInterval] = useState(60);
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    setSaving(true);
    try {
      await api.post('/api/scim/connections', { name, provider, endpoint, bearerToken, syncInterval });
      toast.success('Verbindung hinzugefügt');
      onSaved();
    } catch {
      toast.error('Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#fff', borderRadius: 12, padding: 28, width: 480, maxWidth: '90vw', boxShadow: '0 20px 60px rgba(0,0,0,0.15)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: '#111' }}>Verbindung hinzufügen</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6B7280' }}>
            <XMarkIcon style={{ width: 20, height: 20 }} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: '#374151', marginBottom: 6 }}>Provider</label>
            <div style={{ display: 'flex', gap: 8 }}>
              {(['google', 'entra', 'custom'] as const).map(p => (
                <button
                  key={p}
                  onClick={() => setProvider(p)}
                  style={{
                    flex: 1, padding: '10px 8px', borderRadius: 8, border: provider === p ? '2px solid #2563EB' : '1px solid #D1D5DB',
                    background: provider === p ? '#EFF6FF' : '#fff', cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                  }}
                >
                  <ProviderIcon provider={p} size={20} />
                  <span style={{ fontSize: 11, color: provider === p ? '#2563EB' : '#374151', fontWeight: 500 }}>{PROVIDER_LABELS[p]}</span>
                </button>
              ))}
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: '#374151', marginBottom: 6 }}>Name</label>
            <input
              value={name} onChange={e => setName(e.target.value)} placeholder={PROVIDER_LABELS[provider]}
              style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid #D1D5DB', fontSize: 14, boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: '#374151', marginBottom: 6 }}>SCIM Endpoint URL</label>
            <input
              value={endpoint} onChange={e => setEndpoint(e.target.value)} placeholder="https://..."
              style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid #D1D5DB', fontSize: 14, boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: '#374151', marginBottom: 6 }}>Bearer Token</label>
            <input
              type="password" value={bearerToken} onChange={e => setBearerToken(e.target.value)} placeholder="Bearer Token"
              style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid #D1D5DB', fontSize: 14, boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: '#374151', marginBottom: 6 }}>Synchronisierungsintervall</label>
            <select
              value={syncInterval} onChange={e => setSyncInterval(Number(e.target.value))}
              style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid #D1D5DB', fontSize: 14, background: '#fff' }}
            >
              {SYNC_INTERVAL_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 24 }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid #D1D5DB', background: '#fff', fontSize: 14, cursor: 'pointer' }}>
            Abbrechen
          </button>
          <button
            onClick={handleSave} disabled={saving}
            style={{ padding: '8px 16px', borderRadius: 8, border: 'none', background: '#2563EB', color: '#fff', fontSize: 14, fontWeight: 500, cursor: saving ? 'not-allowed' : 'pointer', opacity: saving ? 0.7 : 1 }}
          >
            {saving ? 'Speichert...' : 'Speichern'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function SyncView() {
  const [activeTab, setActiveTab] = useState<Tab>('connections');
  const [connections, setConnections] = useState<ScimConnection[]>([]);
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);
  const [syncLog, setSyncLog] = useState<SyncLogEntry[]>([]);
  const [conflicts, setConflicts] = useState<ScimConflict[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [syncingIds, setSyncingIds] = useState<Set<string>>(new Set());

  const loadConnections = useCallback(async () => {
    try {
      const res = await api.get('/api/scim/connections');
      setConnections(Array.isArray(res.data) ? res.data : []);
    } catch {
      setConnections([]);
    }
  }, []);

  const loadConflicts = useCallback(async () => {
    try {
      const res = await api.get('/api/scim/conflicts');
      setConflicts(Array.isArray(res.data) ? res.data : []);
    } catch {
      setConflicts([]);
    }
  }, []);

  const loadSyncLog = useCallback(async (connectionId: string) => {
    try {
      const res = await api.get(`/api/scim/connections/${connectionId}/log`);
      setSyncLog(Array.isArray(res.data) ? res.data : []);
    } catch {
      setSyncLog([]);
    }
  }, []);

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await Promise.all([loadConnections(), loadConflicts()]);
      setLoading(false);
    };
    init();
  }, [loadConnections, loadConflicts]);

  useEffect(() => {
    if (activeTab === 'log' && connections.length > 0) {
      const id = selectedConnectionId || connections[0].id;
      if (!selectedConnectionId) setSelectedConnectionId(id);
      loadSyncLog(id);
    }
  }, [activeTab, connections, selectedConnectionId, loadSyncLog]);

  const handleSync = async (connectionId: string) => {
    setSyncingIds(prev => new Set(prev).add(connectionId));
    try {
      await api.post(`/api/scim/connections/${connectionId}/sync`);
      toast.success('Synchronisierung gestartet');
      setTimeout(() => {
        loadConnections();
        setSyncingIds(prev => { const n = new Set(prev); n.delete(connectionId); return n; });
      }, 3000);
    } catch {
      toast.error('Fehler beim Synchronisieren');
      setSyncingIds(prev => { const n = new Set(prev); n.delete(connectionId); return n; });
    }
  };

  const handleDelete = async (connectionId: string) => {
    if (!confirm('Verbindung wirklich löschen?')) return;
    try {
      await api.delete(`/api/scim/connections/${connectionId}`);
      toast.success('Verbindung gelöscht');
      loadConnections();
    } catch {
      toast.error('Fehler beim Löschen');
    }
  };

  const handleResolveConflict = async (conflictId: string, action: 'keep_local' | 'use_remote' | 'merge') => {
    try {
      await api.post(`/api/scim/conflicts/${conflictId}/resolve`, { action });
      toast.success('Konflikt gelöst');
      loadConflicts();
    } catch {
      toast.error('Fehler beim Lösen des Konflikts');
    }
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: 'connections', label: 'Verbindungen' },
    { id: 'log', label: 'Sync-Protokoll' },
    { id: 'conflicts', label: `Konflikte${conflicts.length > 0 ? ` (${conflicts.length})` : ''}` },
  ];

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111', margin: 0 }}>Verzeichnis-Synchronisierung</h1>
          <p style={{ fontSize: 14, color: '#6B7280', marginTop: 4 }}>SCIM-Verbindungen zu Google Workspace, Microsoft Entra ID und anderen Identitätsanbietern</p>
        </div>
        {activeTab === 'connections' && (
          <button
            onClick={() => setShowAddModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, border: 'none', background: '#2563EB', color: '#fff', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}
          >
            <PlusIcon style={{ width: 16, height: 16 }} />
            Verbindung hinzufügen
          </button>
        )}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid #E5E7EB', marginBottom: 24 }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '10px 16px', fontSize: 14, fontWeight: activeTab === tab.id ? 600 : 400,
              color: activeTab === tab.id ? '#2563EB' : '#6B7280',
              borderBottom: activeTab === tab.id ? '2px solid #2563EB' : '2px solid transparent',
              background: 'none', border: 'none', cursor: 'pointer', marginBottom: -1,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 48, color: '#6B7280' }}>Laden...</div>
      ) : (
        <>
          {/* Connections Tab */}
          {activeTab === 'connections' && (
            <div>
              {connections.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 48, color: '#6B7280' }}>
                  <ArrowPathIcon style={{ width: 40, height: 40, margin: '0 auto 12px', color: '#D1D5DB' }} />
                  <p style={{ margin: 0, fontWeight: 500 }}>Keine Verbindungen konfiguriert</p>
                  <p style={{ margin: '4px 0 0', fontSize: 13 }}>Fügen Sie eine SCIM-Verbindung hinzu, um zu beginnen.</p>
                </div>
              ) : (
                <div style={{ background: '#fff', borderRadius: 12, border: '1px solid #E5E7EB', overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ background: '#F9FAFB' }}>
                        {['Provider', 'Name', 'Status', 'Letzte Synchronisierung', 'Benutzer', 'Aktionen'].map(h => (
                          <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: '#6B7280', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {connections.map((conn, i) => (
                        <tr key={conn.id} style={{ borderTop: i > 0 ? '1px solid #F3F4F6' : 'none' }}>
                          <td style={{ padding: '12px 16px' }}>
                            <ProviderIcon provider={conn.provider} size={22} />
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <p style={{ margin: 0, fontSize: 14, fontWeight: 500, color: '#111' }}>{conn.name}</p>
                            {conn.endpoint && <p style={{ margin: '2px 0 0', fontSize: 12, color: '#9CA3AF' }}>{conn.endpoint}</p>}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <StatusBadge status={syncingIds.has(conn.id) ? 'syncing' : conn.status} />
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: '#6B7280' }}>
                            {conn.lastSync ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                <ClockIcon style={{ width: 14, height: 14 }} />
                                {new Date(conn.lastSync).toLocaleString('de-CH')}
                              </div>
                            ) : '—'}
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 14, color: '#374151', fontWeight: 500 }}>{conn.usersSynced}</td>
                          <td style={{ padding: '12px 16px' }}>
                            <div style={{ display: 'flex', gap: 6 }}>
                              <button
                                onClick={() => handleSync(conn.id)}
                                disabled={syncingIds.has(conn.id)}
                                title="Jetzt synchronisieren"
                                style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 10px', borderRadius: 6, border: '1px solid #D1D5DB', background: '#fff', fontSize: 12, cursor: syncingIds.has(conn.id) ? 'not-allowed' : 'pointer', opacity: syncingIds.has(conn.id) ? 0.6 : 1 }}
                              >
                                <ArrowPathIcon style={{ width: 14, height: 14, animation: syncingIds.has(conn.id) ? 'spin 1s linear infinite' : 'none' }} />
                                Jetzt synchronisieren
                              </button>
                              <button
                                onClick={() => handleDelete(conn.id)}
                                title="Verbindung löschen"
                                style={{ display: 'flex', alignItems: 'center', padding: '6px 8px', borderRadius: 6, border: '1px solid #FEE2E2', background: '#FFF5F5', cursor: 'pointer', color: '#DC2626' }}
                              >
                                <TrashIcon style={{ width: 14, height: 14 }} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Sync Log Tab */}
          {activeTab === 'log' && (
            <div>
              {connections.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <select
                    value={selectedConnectionId || connections[0].id}
                    onChange={e => { setSelectedConnectionId(e.target.value); loadSyncLog(e.target.value); }}
                    style={{ padding: '8px 12px', borderRadius: 8, border: '1px solid #D1D5DB', fontSize: 14, background: '#fff' }}
                  >
                    {connections.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </select>
                </div>
              )}

              {syncLog.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 48, color: '#6B7280' }}>
                  <p style={{ margin: 0 }}>Keine Sync-Protokolleinträge</p>
                </div>
              ) : (
                <div style={{ background: '#fff', borderRadius: 12, border: '1px solid #E5E7EB', overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ background: '#F9FAFB' }}>
                        {['Zeitpunkt', 'Status', 'Erstellt', 'Aktualisiert', 'Gelöscht', 'Fehler', 'Meldung'].map(h => (
                          <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: '#6B7280', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {syncLog.map((entry, i) => (
                        <tr key={entry.id} style={{ borderTop: i > 0 ? '1px solid #F3F4F6' : 'none' }}>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: '#374151' }}>{new Date(entry.startedAt).toLocaleString('de-CH')}</td>
                          <td style={{ padding: '12px 16px' }}><StatusBadge status={entry.status} /></td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: '#16A34A', fontWeight: 500 }}>+{entry.usersCreated}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: '#2563EB', fontWeight: 500 }}>~{entry.usersUpdated}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: '#DC2626', fontWeight: 500 }}>-{entry.usersDeleted}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: entry.errors > 0 ? '#DC2626' : '#9CA3AF' }}>{entry.errors}</td>
                          <td style={{ padding: '12px 16px', fontSize: 12, color: '#6B7280' }}>{entry.message || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Conflicts Tab */}
          {activeTab === 'conflicts' && (
            <div>
              {conflicts.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 64, color: '#6B7280' }}>
                  <CheckCircleIcon style={{ width: 48, height: 48, margin: '0 auto 16px', color: '#22C55E' }} />
                  <p style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#111' }}>Keine Konflikte</p>
                  <p style={{ margin: '4px 0 0', fontSize: 14 }}>Alle Synchronisierungen verliefen konfliktfrei.</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {conflicts.map(conflict => (
                    <div key={conflict.id} style={{ background: '#fff', borderRadius: 12, border: '1px solid #FEE2E2', padding: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
                        <div>
                          <p style={{ margin: 0, fontSize: 14, fontWeight: 600, color: '#111' }}>Benutzer: {conflict.userId}</p>
                          <p style={{ margin: '2px 0 0', fontSize: 12, color: '#9CA3AF' }}>Typ: {conflict.conflictType} · {new Date(conflict.createdAt).toLocaleString('de-CH')}</p>
                        </div>
                        <ExclamationCircleIcon style={{ width: 20, height: 20, color: '#DC2626', flexShrink: 0 }} />
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
                        <div style={{ background: '#F9FAFB', borderRadius: 8, padding: 12 }}>
                          <p style={{ margin: '0 0 8px', fontSize: 12, fontWeight: 600, color: '#374151' }}>Lokale Daten</p>
                          <pre style={{ margin: 0, fontSize: 11, color: '#6B7280', overflow: 'auto', maxHeight: 80 }}>{JSON.stringify(conflict.localData, null, 2)}</pre>
                        </div>
                        <div style={{ background: '#F9FAFB', borderRadius: 8, padding: 12 }}>
                          <p style={{ margin: '0 0 8px', fontSize: 12, fontWeight: 600, color: '#374151' }}>Remote-Daten</p>
                          <pre style={{ margin: 0, fontSize: 11, color: '#6B7280', overflow: 'auto', maxHeight: 80 }}>{JSON.stringify(conflict.remoteData, null, 2)}</pre>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => handleResolveConflict(conflict.id, 'keep_local')} style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid #D1D5DB', background: '#fff', fontSize: 12, cursor: 'pointer', fontWeight: 500 }}>Lokal behalten</button>
                        <button onClick={() => handleResolveConflict(conflict.id, 'use_remote')} style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid #D1D5DB', background: '#fff', fontSize: 12, cursor: 'pointer', fontWeight: 500 }}>Remote übernehmen</button>
                        <button onClick={() => handleResolveConflict(conflict.id, 'merge')} style={{ padding: '6px 12px', borderRadius: 6, border: 'none', background: '#2563EB', color: '#fff', fontSize: 12, cursor: 'pointer', fontWeight: 500 }}>Zusammenführen</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {showAddModal && (
        <AddConnectionModal
          onClose={() => setShowAddModal(false)}
          onSaved={() => { setShowAddModal(false); loadConnections(); }}
        />
      )}
    </div>
  );
}
