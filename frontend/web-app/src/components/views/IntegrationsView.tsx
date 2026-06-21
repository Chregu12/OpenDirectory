'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  PlusIcon,
  TrashIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  XMarkIcon,
  ClipboardDocumentIcon,
  BoltIcon,
  ClockIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { api } from '@/lib/api';

// ── Types ──────────────────────────────────────────────────────────────────────

interface ApiKey {
  id: string;
  name: string;
  permissions: string[];
  created: string;
  created_at?: string;
  lastUsed?: string;
  last_used?: string;
  active?: boolean;
}

interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  active: boolean;
  createdAt?: string;
  created_at?: string;
  lastTriggered?: string;
  last_triggered?: string;
  deliveryCount?: number;
  delivery_count?: number;
  failureCount?: number;
  failure_count?: number;
}

interface WebhookDelivery {
  id: string;
  webhookId?: string;
  webhook_id?: string;
  eventType?: string;
  event_type?: string;
  responseStatus?: number;
  response_status?: number;
  deliveredAt?: string;
  delivered_at?: string;
  success: boolean;
}

interface OAuthClient {
  id?: string;
  clientId?: string;
  name: string;
  redirectUris?: string[];
  scopes?: string[];
}

type Tab = 'apikeys' | 'webhooks' | 'oauth';

const ALL_EVENTS = [
  'user.created', 'user.updated', 'user.deleted',
  'device.enrolled', 'device.compliance_failed',
  'group.created', 'auth.login_failed', 'auth.mfa_disabled',
];

const PERMISSION_OPTIONS = [
  { value: 'read', label: 'Lesen' },
  { value: 'write', label: 'Schreiben' },
  { value: 'admin', label: 'Admin' },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDate(d: string | null | undefined): string {
  if (!d) return '—';
  return new Date(d).toLocaleString('de-CH');
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success('In Zwischenablage kopiert'),
    () => toast.error('Kopieren fehlgeschlagen'),
  );
}

// ── Event Badges ───────────────────────────────────────────────────────────────

function EventBadges({ events }: { events: string[] }) {
  const visible = events.slice(0, 3);
  const rest = events.length - visible.length;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
      {visible.map(e => (
        <span key={e} style={{ padding: '2px 6px', borderRadius: 4, background: 'var(--accent-light)', color: 'var(--accent)', fontSize: 11, fontWeight: 500 }}>{e}</span>
      ))}
      {rest > 0 && <span style={{ padding: '2px 6px', borderRadius: 4, background: 'var(--bg-overlay)', color: 'var(--text-muted)', fontSize: 11 }}>+{rest}</span>}
    </div>
  );
}

// ── Create API Key Modal ───────────────────────────────────────────────────────

interface CreateApiKeyModalProps {
  onClose: () => void;
  onCreated: (key: { name: string; key: string }) => void;
}

function CreateApiKeyModal({ onClose, onCreated }: CreateApiKeyModalProps) {
  const [name, setName] = useState('');
  const [permissions, setPermissions] = useState<string[]>(['read']);
  const [saving, setSaving] = useState(false);

  const toggle = (perm: string) => {
    setPermissions(prev => prev.includes(perm) ? prev.filter(p => p !== perm) : [...prev, perm]);
  };

  const handleCreate = async () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    if (permissions.length === 0) { toast.error('Mind. eine Berechtigung wählen'); return; }
    setSaving(true);
    try {
      const res = await api.post('/api/gateway/api-keys', { name, permissions });
      onCreated({ name, key: res.data.key });
    } catch {
      toast.error('Fehler beim Erstellen des API-Schlüssels');
      setSaving(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, padding: 28, width: 440, maxWidth: '90vw', boxShadow: '0 20px 60px rgba(0,0,0,0.4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>API-Schlüssel erstellen</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <XMarkIcon style={{ width: 20, height: 20 }} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6 }}>Name</label>
            <input
              value={name} onChange={e => setName(e.target.value)} placeholder="z.B. CI/CD Pipeline"
              style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border-strong)', fontSize: 14, boxSizing: 'border-box', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 8 }}>Berechtigungen</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {PERMISSION_OPTIONS.map(opt => (
                <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 14, color: 'var(--text-secondary)' }}>
                  <input
                    type="checkbox" checked={permissions.includes(opt.value)} onChange={() => toggle(opt.value)}
                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 24 }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)', fontSize: 14, cursor: 'pointer' }}>Abbrechen</button>
          <button
            onClick={handleCreate} disabled={saving}
            style={{ padding: '8px 16px', borderRadius: 8, border: 'none', background: '#006FFF', color: '#fff', fontSize: 14, fontWeight: 500, cursor: saving ? 'not-allowed' : 'pointer', opacity: saving ? 0.7 : 1 }}
          >
            {saving ? 'Erstellt...' : 'Erstellen'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Show API Key Modal ─────────────────────────────────────────────────────────

function ShowKeyModal({ keyName, rawKey, onClose }: { keyName: string; rawKey: string; onClose: () => void }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, padding: 28, width: 480, maxWidth: '90vw', boxShadow: '0 20px 60px rgba(0,0,0,0.4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>API-Schlüssel erstellt</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <XMarkIcon style={{ width: 20, height: 20 }} />
          </button>
        </div>

        <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 16 }}>
          Der Schlüssel <strong>{keyName}</strong> wurde erstellt.
        </p>

        <div style={{ background: 'var(--success-light)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <code style={{ fontSize: 13, color: 'var(--success)', wordBreak: 'break-all', flex: 1 }}>{rawKey}</code>
            <button
              onClick={() => copyToClipboard(rawKey)}
              style={{ flexShrink: 0, padding: 6, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-surface-raised)', cursor: 'pointer' }}
              title="Kopieren"
            >
              <ClipboardDocumentIcon style={{ width: 16, height: 16, color: 'var(--success)' }} />
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: 'var(--warning-light)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, marginBottom: 20 }}>
          <ExclamationCircleIcon style={{ width: 16, height: 16, color: 'var(--warning)', flexShrink: 0, marginTop: 1 }} />
          <p style={{ margin: 0, fontSize: 13, color: 'var(--warning)' }}>Speichere diesen Schlüssel — er wird nicht mehr angezeigt.</p>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 8, border: 'none', background: '#006FFF', color: '#fff', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>
            Fertig
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Add Webhook Modal ──────────────────────────────────────────────────────────

interface AddWebhookModalProps {
  onClose: () => void;
  onSaved: () => void;
}

function AddWebhookModal({ onClose, onSaved }: AddWebhookModalProps) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<string[]>([]);
  const [secret, setSecret] = useState('');
  const [saving, setSaving] = useState(false);

  const toggleEvent = (e: string) => setEvents(prev => prev.includes(e) ? prev.filter(x => x !== e) : [...prev, e]);

  const handleSave = async () => {
    if (!name.trim()) { toast.error('Name ist erforderlich'); return; }
    if (!url.trim()) { toast.error('URL ist erforderlich'); return; }
    setSaving(true);
    try {
      await api.post('/api/gateway/webhooks', { name, url, events, secret: secret || undefined });
      toast.success('Webhook hinzugefügt');
      onSaved();
    } catch {
      toast.error('Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, padding: 28, width: 520, maxWidth: '90vw', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Webhook hinzufügen</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <XMarkIcon style={{ width: 20, height: 20 }} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6 }}>Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="z.B. Slack-Benachrichtigungen" style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border-strong)', fontSize: 14, boxSizing: 'border-box', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }} />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6 }}>Payload-URL</label>
            <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://..." style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border-strong)', fontSize: 14, boxSizing: 'border-box', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }} />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 8 }}>Ereignisse</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
              {ALL_EVENTS.map(e => (
                <label key={e} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>
                  <input type="checkbox" checked={events.includes(e)} onChange={() => toggleEvent(e)} style={{ width: 14, height: 14, cursor: 'pointer' }} />
                  <code style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{e}</code>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6 }}>Secret (optional)</label>
            <input type="password" value={secret} onChange={e => setSecret(e.target.value)} placeholder="Webhook Secret" style={{ width: '100%', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border-strong)', fontSize: 14, boxSizing: 'border-box', background: 'var(--bg-surface-raised)', color: 'var(--text-primary)' }} />
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 24 }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 8, border: '1px solid var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)', fontSize: 14, cursor: 'pointer' }}>Abbrechen</button>
          <button
            onClick={handleSave} disabled={saving}
            style={{ padding: '8px 16px', borderRadius: 8, border: 'none', background: '#006FFF', color: '#fff', fontSize: 14, fontWeight: 500, cursor: saving ? 'not-allowed' : 'pointer', opacity: saving ? 0.7 : 1 }}
          >
            {saving ? 'Speichert...' : 'Speichern'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Delivery Log Panel ─────────────────────────────────────────────────────────

function DeliveryLogPanel({ webhookId, onClose }: { webhookId: string; onClose: () => void }) {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get(`/api/gateway/webhooks/${webhookId}/deliveries`)
      .then(res => setDeliveries(Array.isArray(res.data) ? res.data : []))
      .catch(() => setDeliveries([]))
      .finally(() => setLoading(false));
  }, [webhookId]);

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg-surface)', borderRadius: 12, padding: 24, width: 600, maxWidth: '90vw', maxHeight: '80vh', overflowY: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Zustellungsprotokoll</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <XMarkIcon style={{ width: 20, height: 20 }} />
          </button>
        </div>

        {loading ? (
          <p style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Laden...</p>
        ) : deliveries.length === 0 ? (
          <p style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>Keine Zustellungen</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--bg-surface-raised)' }}>
                {['Zeitpunkt', 'Ereignis', 'Status', 'HTTP'].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {deliveries.map((d, i) => (
                <tr key={d.id} style={{ borderTop: i > 0 ? '1px solid var(--border)' : 'none' }}>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-secondary)' }}>{fmtDate(d.deliveredAt || d.delivered_at)}</td>
                  <td style={{ padding: '10px 12px' }}><code style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{d.eventType || d.event_type}</code></td>
                  <td style={{ padding: '10px 12px' }}>
                    {d.success
                      ? <span style={{ color: '#16A34A', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}><CheckCircleIcon style={{ width: 14, height: 14 }} />Zugestellt</span>
                      : <span style={{ color: '#DC2626', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}><ExclamationCircleIcon style={{ width: 14, height: 14 }} />Fehler</span>}
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-muted)' }}>{d.responseStatus ?? d.response_status ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function IntegrationsView() {
  const [activeTab, setActiveTab] = useState<Tab>('apikeys');
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [oauthClients, setOauthClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateKeyModal, setShowCreateKeyModal] = useState(false);
  const [newKeyData, setNewKeyData] = useState<{ name: string; key: string } | null>(null);
  const [showAddWebhookModal, setShowAddWebhookModal] = useState(false);
  const [selectedWebhookId, setSelectedWebhookId] = useState<string | null>(null);
  const [testingIds, setTestingIds] = useState<Set<string>>(new Set());

  const loadData = useCallback(async () => {
    setLoading(true);
    const [keysRes, hooksRes, oauthRes] = await Promise.allSettled([
      api.get('/api/gateway/api-keys'),
      api.get('/api/gateway/webhooks'),
      api.get('/api/clients'),
    ]);

    if (keysRes.status === 'fulfilled') setApiKeys(Array.isArray(keysRes.value.data) ? keysRes.value.data : []);
    if (hooksRes.status === 'fulfilled') setWebhooks(Array.isArray(hooksRes.value.data) ? hooksRes.value.data : []);
    if (oauthRes.status === 'fulfilled') setOauthClients(Array.isArray(oauthRes.value.data) ? oauthRes.value.data : []);
    setLoading(false);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm('API-Schlüssel wirklich widerrufen?')) return;
    try {
      await api.delete(`/api/gateway/api-keys/${keyId}`);
      toast.success('Schlüssel widerrufen');
      loadData();
    } catch {
      toast.error('Fehler beim Widerrufen');
    }
  };

  const handleDeleteWebhook = async (webhookId: string) => {
    if (!confirm('Webhook wirklich löschen?')) return;
    try {
      await api.delete(`/api/gateway/webhooks/${webhookId}`);
      toast.success('Webhook gelöscht');
      loadData();
    } catch {
      toast.error('Fehler beim Löschen');
    }
  };

  const handleTestWebhook = async (webhookId: string) => {
    setTestingIds(prev => new Set(prev).add(webhookId));
    try {
      const res = await api.post(`/api/gateway/webhooks/${webhookId}/test`);
      const result = res.data as { success: boolean; responseStatus: number };
      if (result.success) {
        toast.success(`Test zugestellt (HTTP ${result.responseStatus})`);
      } else {
        toast.error(`Test fehlgeschlagen (HTTP ${result.responseStatus})`);
      }
    } catch {
      toast.error('Fehler beim Testen');
    } finally {
      setTestingIds(prev => { const n = new Set(prev); n.delete(webhookId); return n; });
    }
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: 'apikeys', label: 'API-Schlüssel' },
    { id: 'webhooks', label: 'Webhooks' },
    { id: 'oauth', label: 'OAuth-Apps' },
  ];

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>Integrationen</h1>
          <p style={{ fontSize: 14, color: 'var(--text-muted)', marginTop: 4 }}>API-Schlüssel, Webhooks und OAuth-Anwendungen verwalten</p>
        </div>
        {activeTab === 'apikeys' && (
          <button
            onClick={() => setShowCreateKeyModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, border: 'none', background: '#006FFF', color: '#fff', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}
          >
            <PlusIcon style={{ width: 16, height: 16 }} />
            API-Schlüssel erstellen
          </button>
        )}
        {activeTab === 'webhooks' && (
          <button
            onClick={() => setShowAddWebhookModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, border: 'none', background: '#006FFF', color: '#fff', fontSize: 14, fontWeight: 500, cursor: 'pointer' }}
          >
            <PlusIcon style={{ width: 16, height: 16 }} />
            Webhook hinzufügen
          </button>
        )}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 24 }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '10px 16px', fontSize: 14, fontWeight: activeTab === tab.id ? 600 : 400,
              color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
              background: 'none', border: 'none', cursor: 'pointer', marginBottom: -1,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>Laden...</div>
      ) : (
        <>
          {/* API Keys Tab */}
          {activeTab === 'apikeys' && (
            <div>
              {apiKeys.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>
                  <p style={{ margin: 0, fontWeight: 500 }}>Keine API-Schlüssel</p>
                  <p style={{ margin: '4px 0 0', fontSize: 13 }}>Erstellen Sie einen Schlüssel für externe Integrationen.</p>
                </div>
              ) : (
                <div style={{ background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ background: 'var(--bg-surface-raised)' }}>
                        {['Name', 'Berechtigungen', 'Erstellt', 'Zuletzt verwendet', 'Status', 'Aktionen'].map(h => (
                          <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {apiKeys.map((key, i) => (
                        <tr key={key.id} style={{ borderTop: i > 0 ? '1px solid var(--border)' : 'none' }}>
                          <td style={{ padding: '12px 16px', fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>{key.name}</td>
                          <td style={{ padding: '12px 16px' }}>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                              {(key.permissions || []).map(p => (
                                <span key={p} style={{ padding: '2px 6px', borderRadius: 4, background: 'var(--bg-overlay)', color: 'var(--text-secondary)', fontSize: 12, fontWeight: 500 }}>{p}</span>
                              ))}
                            </div>
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: 'var(--text-muted)' }}>{fmtDate(key.created || key.created_at)}</td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: 'var(--text-muted)' }}>
                            {key.lastUsed || key.last_used ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                <ClockIcon style={{ width: 14, height: 14 }} />
                                {fmtDate(key.lastUsed || key.last_used)}
                              </div>
                            ) : '—'}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: key.active !== false ? 'var(--success-light)' : 'var(--bg-overlay)', color: key.active !== false ? 'var(--success)' : 'var(--text-muted)', fontSize: 12, fontWeight: 500 }}>
                              <CheckCircleIcon style={{ width: 12, height: 12 }} />
                              {key.active !== false ? 'Aktiv' : 'Inaktiv'}
                            </span>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <button
                              onClick={() => handleRevokeKey(key.id)}
                              style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 10px', borderRadius: 6, border: '1px solid var(--danger-light)', background: 'var(--danger-light)', fontSize: 12, cursor: 'pointer', color: 'var(--danger)' }}
                            >
                              <TrashIcon style={{ width: 14, height: 14 }} />
                              Widerrufen
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Webhooks Tab */}
          {activeTab === 'webhooks' && (
            <div>
              {webhooks.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>
                  <GlobeAltIcon style={{ width: 40, height: 40, margin: '0 auto 12px', color: 'var(--text-muted)' }} />
                  <p style={{ margin: 0, fontWeight: 500 }}>Keine Webhooks konfiguriert</p>
                  <p style={{ margin: '4px 0 0', fontSize: 13 }}>Fügen Sie einen Webhook hinzu, um externe Dienste zu benachrichtigen.</p>
                </div>
              ) : (
                <div style={{ background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ background: 'var(--bg-surface-raised)' }}>
                        {['Name', 'URL', 'Ereignisse', 'Status', 'Letzter Aufruf', 'Aktionen'].map(h => (
                          <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {webhooks.map((wh, i) => (
                        <tr
                          key={wh.id}
                          style={{ borderTop: i > 0 ? '1px solid var(--border)' : 'none', cursor: 'pointer' }}
                          onClick={() => setSelectedWebhookId(wh.id)}
                        >
                          <td style={{ padding: '12px 16px', fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>{wh.name}</td>
                          <td style={{ padding: '12px 16px', fontSize: 12, color: 'var(--text-muted)', maxWidth: 200 }}>
                            <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{wh.url}</span>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <EventBadges events={wh.events || []} />
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: wh.active ? 'var(--success-light)' : 'var(--bg-overlay)', color: wh.active ? 'var(--success)' : 'var(--text-muted)', fontSize: 12, fontWeight: 500 }}>
                              <CheckCircleIcon style={{ width: 12, height: 12 }} />
                              {wh.active ? 'Aktiv' : 'Inaktiv'}
                            </span>
                          </td>
                          <td style={{ padding: '12px 16px', fontSize: 13, color: 'var(--text-muted)' }}>
                            {fmtDate(wh.lastTriggered || wh.last_triggered)}
                          </td>
                          <td style={{ padding: '12px 16px' }} onClick={e => e.stopPropagation()}>
                            <div style={{ display: 'flex', gap: 6 }}>
                              <button
                                onClick={() => handleTestWebhook(wh.id)}
                                disabled={testingIds.has(wh.id)}
                                style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border-strong)', background: 'var(--bg-surface-raised)', color: 'var(--text-secondary)', fontSize: 12, cursor: testingIds.has(wh.id) ? 'not-allowed' : 'pointer', opacity: testingIds.has(wh.id) ? 0.6 : 1 }}
                              >
                                <BoltIcon style={{ width: 14, height: 14 }} />
                                Test senden
                              </button>
                              <button
                                onClick={() => handleDeleteWebhook(wh.id)}
                                style={{ display: 'flex', alignItems: 'center', padding: '6px 8px', borderRadius: 6, border: '1px solid var(--danger-light)', background: 'var(--danger-light)', cursor: 'pointer', color: 'var(--danger)' }}
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

          {/* OAuth Apps Tab */}
          {activeTab === 'oauth' && (
            <div>
              {oauthClients.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>
                  <p style={{ margin: 0, fontWeight: 500 }}>Keine OAuth-Apps registriert</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {oauthClients.map(client => (
                    <div key={client.id || client.clientId} style={{ background: 'var(--bg-surface)', borderRadius: 12, border: '1px solid var(--border)', padding: 20 }}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
                        <div>
                          <p style={{ margin: 0, fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>{client.name}</p>
                          <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--text-muted)' }}>Client ID: <code style={{ background: 'var(--bg-overlay)', padding: '1px 4px', borderRadius: 3 }}>{client.id || client.clientId}</code></p>
                        </div>
                        <GlobeAltIcon style={{ width: 20, height: 20, color: 'var(--text-muted)' }} />
                      </div>
                      {(client.redirectUris || []).length > 0 && (
                        <div style={{ marginBottom: 8 }}>
                          <p style={{ margin: '0 0 4px', fontSize: 12, fontWeight: 500, color: 'var(--text-secondary)' }}>Redirect URIs</p>
                          {(client.redirectUris || []).map(uri => (
                            <p key={uri} style={{ margin: '2px 0', fontSize: 12, color: 'var(--text-muted)' }}>{uri}</p>
                          ))}
                        </div>
                      )}
                      {(client.scopes || []).length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {(client.scopes || []).map(s => (
                            <span key={s} style={{ padding: '2px 6px', borderRadius: 4, background: 'var(--bg-overlay)', color: 'var(--text-secondary)', fontSize: 12 }}>{s}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Modals */}
      {showCreateKeyModal && (
        <CreateApiKeyModal
          onClose={() => setShowCreateKeyModal(false)}
          onCreated={data => { setShowCreateKeyModal(false); setNewKeyData(data); loadData(); }}
        />
      )}

      {newKeyData && (
        <ShowKeyModal
          keyName={newKeyData.name}
          rawKey={newKeyData.key}
          onClose={() => setNewKeyData(null)}
        />
      )}

      {showAddWebhookModal && (
        <AddWebhookModal
          onClose={() => setShowAddWebhookModal(false)}
          onSaved={() => { setShowAddWebhookModal(false); loadData(); }}
        />
      )}

      {selectedWebhookId && (
        <DeliveryLogPanel
          webhookId={selectedWebhookId}
          onClose={() => setSelectedWebhookId(null)}
        />
      )}
    </div>
  );
}
