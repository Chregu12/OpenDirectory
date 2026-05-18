'use client';

import React, { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import {
  KeyIcon,
  GlobeAltIcon,
  ShieldCheckIcon,
  PlusIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ArrowTopRightOnSquareIcon,
  FingerPrintIcon,
  LockClosedIcon,
  UserGroupIcon,
  Cog6ToothIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

// ─── Types ──────────────────────────────────────────────────────────────────────

type IdpTab = 'overview' | 'apps' | 'oauth' | 'saml' | 'mfa' | 'settings' | 'certificates';

interface SaasApp {
  id: string;
  name: string;
  logo: string;
  protocol: 'oidc' | 'saml' | 'oauth2';
  status: 'active' | 'inactive' | 'pending';
  users: number;
  lastLogin?: string;
}

interface OAuthClient {
  id: string;
  name: string;
  clientId: string;
  scopes: string[];
  redirectUris: string[];
  grantTypes: string[];
  status: 'active' | 'inactive';
}

// ─── Mock Data ──────────────────────────────────────────────────────────────────

const SAAS_APPS: SaasApp[] = [
  { id: '1', name: 'GitHub Enterprise',    logo: '🐙', protocol: 'oidc',  status: 'active',   users: 12, lastLogin: '2 min ago' },
  { id: '2', name: 'Grafana',              logo: '📊', protocol: 'oidc',  status: 'active',   users: 8,  lastLogin: '15 min ago' },
  { id: '3', name: 'GitLab',              logo: '🦊', protocol: 'saml',  status: 'active',   users: 5,  lastLogin: '1 hr ago' },
  { id: '4', name: 'Nextcloud',           logo: '☁️', protocol: 'oidc',  status: 'active',   users: 13, lastLogin: '3 hr ago' },
  { id: '5', name: 'Proxmox VE',         logo: '🖥️', protocol: 'oidc',  status: 'inactive', users: 3,  lastLogin: '2 days ago' },
  { id: '6', name: 'Mattermost',         logo: '💬', protocol: 'oauth2', status: 'pending',  users: 0 },
];

const OAUTH_CLIENTS: OAuthClient[] = [
  {
    id: '1',
    name: 'Grafana Dashboard',
    clientId: 'grafana-od-client',
    scopes: ['openid', 'profile', 'email', 'groups'],
    redirectUris: ['https://grafana.example.com/login/generic_oauth'],
    grantTypes: ['authorization_code', 'refresh_token'],
    status: 'active',
  },
  {
    id: '2',
    name: 'Internal Dev Portal',
    clientId: 'devportal-od-client',
    scopes: ['openid', 'profile', 'email'],
    redirectUris: ['https://dev.example.com/auth/callback'],
    grantTypes: ['authorization_code'],
    status: 'active',
  },
];

// ─── Sub-Components ──────────────────────────────────────────────────────────────

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy} className="text-gray-400 hover:text-blue-600 transition-colors ml-2 shrink-0">
      {copied ? <CheckIcon className="w-4 h-4 text-green-500" /> : <ClipboardDocumentIcon className="w-4 h-4" />}
    </button>
  );
}

function EndpointRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-gray-100 last:border-0">
      <span className="text-sm text-gray-500 w-44 shrink-0">{label}</span>
      <div className="flex items-center flex-1 min-w-0">
        <code className="text-xs text-blue-700 bg-blue-50 px-2 py-1 rounded truncate flex-1">{value}</code>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: SaasApp['status'] }) {
  const styles = {
    active:   'bg-green-100 text-green-700',
    inactive: 'bg-gray-100 text-gray-500',
    pending:  'bg-yellow-100 text-yellow-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${styles[status]}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function ProtocolBadge({ protocol }: { protocol: SaasApp['protocol'] }) {
  const styles: Record<string, string> = {
    oidc:   'bg-blue-100 text-blue-700',
    saml:   'bg-purple-100 text-purple-700',
    oauth2: 'bg-orange-100 text-orange-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${styles[protocol]}`}>
      {protocol.toUpperCase()}
    </span>
  );
}

// ─── Overview Tab ────────────────────────────────────────────────────────────────

function OverviewTab({ domain }: { domain: string }) {
  const issuer = `https://${domain}`;
  return (
    <div className="space-y-6">
      {/* Status banner */}
      <div className="bg-green-50 border border-green-200 rounded-xl p-4 flex items-start gap-3">
        <CheckCircleIcon className="w-5 h-5 text-green-600 mt-0.5 shrink-0" />
        <div>
          <p className="text-sm font-semibold text-green-800">Identity Provider aktiv</p>
          <p className="text-xs text-green-700 mt-0.5">
            OpenDirectory läuft als vollständiger OAuth2/OIDC/SAML Identity Provider. Alle SaaS-Apps können sich gegen diesen Endpoint authentifizieren — kein Entra ID oder Okta nötig.
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Verbundene Apps',   value: '6',   icon: GlobeAltIcon,    color: 'text-blue-600',   bg: 'bg-blue-50' },
          { label: 'Aktive Clients',    value: '2',   icon: KeyIcon,         color: 'text-purple-600', bg: 'bg-purple-50' },
          { label: 'Authentifizierungen heute', value: '143', icon: FingerPrintIcon, color: 'text-green-600',  bg: 'bg-green-50' },
          { label: 'MFA-Nutzer',        value: '11',  icon: ShieldCheckIcon, color: 'text-orange-600', bg: 'bg-orange-50' },
        ].map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-gray-200 p-4 flex items-center gap-3">
            <div className={`${s.bg} rounded-lg p-2.5`}>
              <s.icon className={`w-5 h-5 ${s.color}`} />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{s.value}</p>
              <p className="text-xs text-gray-500 leading-tight">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* OIDC Endpoints */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center gap-2 mb-4">
          <GlobeAltIcon className="w-5 h-5 text-blue-600" />
          <h3 className="text-sm font-semibold text-gray-900">OIDC Discovery Endpoints</h3>
          <span className="ml-auto text-xs text-gray-400">Issuer: <code className="font-mono">{issuer}</code></span>
        </div>
        <div>
          <EndpointRow label="Discovery Document"   value={`${issuer}/.well-known/openid-configuration`} />
          <EndpointRow label="Authorization"        value={`${issuer}/oauth/authorize`} />
          <EndpointRow label="Token"                value={`${issuer}/oauth/token`} />
          <EndpointRow label="UserInfo"             value={`${issuer}/oauth/userinfo`} />
          <EndpointRow label="JWKS"                 value={`${issuer}/.well-known/jwks.json`} />
          <EndpointRow label="Introspection"        value={`${issuer}/oauth/introspect`} />
          <EndpointRow label="Revocation"           value={`${issuer}/oauth/revoke`} />
          <EndpointRow label="SAML Metadata"        value={`${issuer}/saml/metadata`} />
          <EndpointRow label="SAML SSO"             value={`${issuer}/saml/sso`} />
        </div>
      </div>

      {/* Supported Protocols */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <h3 className="text-sm font-semibold text-gray-900 mb-4">Unterstützte Standards</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              name: 'OAuth 2.0 / OIDC',
              color: 'border-blue-200 bg-blue-50',
              icon: '🔑',
              items: ['Authorization Code Flow', 'PKCE', 'Refresh Tokens', 'Client Credentials', 'Device Flow'],
            },
            {
              name: 'SAML 2.0',
              color: 'border-purple-200 bg-purple-50',
              icon: '🔐',
              items: ['SP-initiated SSO', 'IdP-initiated SSO', 'Signed Assertions', 'Encrypted Assertions', 'Single Logout'],
            },
            {
              name: 'Moderne Auth',
              color: 'border-green-200 bg-green-50',
              icon: '🛡️',
              items: ['TOTP/HOTP MFA', 'WebAuthn (FIDO2)', 'Passkeys', 'Conditional Access', 'Risk-Based Auth'],
            },
          ].map(p => (
            <div key={p.name} className={`rounded-lg border p-4 ${p.color}`}>
              <p className="text-sm font-semibold text-gray-800 mb-2">{p.icon} {p.name}</p>
              <ul className="space-y-1">
                {p.items.map(i => (
                  <li key={i} className="text-xs text-gray-600 flex items-center gap-1.5">
                    <CheckIcon className="w-3.5 h-3.5 text-green-600 shrink-0" />
                    {i}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Apps Tab ─────────────────────────────────────────────────────────────────────

function AppsTab() {
  const [showAdd, setShowAdd] = useState(false);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Verbundene Anwendungen</h3>
          <p className="text-xs text-gray-500 mt-0.5">SaaS-Apps und interne Dienste, die OpenDirectory als Identity Provider nutzen</p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-1.5 bg-blue-600 text-white text-sm px-3 py-2 rounded-lg hover:bg-blue-700 transition-colors"
        >
          <PlusIcon className="w-4 h-4" />
          App verbinden
        </button>
      </div>

      {showAdd && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-sm font-semibold text-gray-900">Neue App verbinden</h4>
            <button onClick={() => setShowAdd(false)} className="text-gray-400 hover:text-gray-600">
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { name: 'GitHub',      logo: '🐙' },
              { name: 'Slack',       logo: '💬' },
              { name: 'Salesforce',  logo: '☁️' },
              { name: 'AWS SSO',     logo: '🟠' },
              { name: 'Datadog',     logo: '🐕' },
              { name: 'Jira',        logo: '🔵' },
              { name: 'Confluence',  logo: '📖' },
              { name: 'Custom App',  logo: '⚙️' },
            ].map(a => (
              <button
                key={a.name}
                onClick={() => { setShowAdd(false); toast.success(`${a.name} Wizard gestartet`); }}
                className="flex items-center gap-2 bg-white border border-gray-200 rounded-lg p-3 text-left hover:border-blue-400 hover:bg-blue-50 transition-colors"
              >
                <span className="text-xl">{a.logo}</span>
                <span className="text-sm font-medium text-gray-700">{a.name}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50">
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wide px-4 py-3">Anwendung</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wide px-4 py-3">Protokoll</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wide px-4 py-3">Status</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wide px-4 py-3">Nutzer</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wide px-4 py-3">Letzter Login</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {SAAS_APPS.map(app => (
              <tr key={app.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xl">{app.logo}</span>
                    <span className="text-sm font-medium text-gray-900">{app.name}</span>
                  </div>
                </td>
                <td className="px-4 py-3"><ProtocolBadge protocol={app.protocol} /></td>
                <td className="px-4 py-3"><StatusBadge status={app.status} /></td>
                <td className="px-4 py-3 text-sm text-gray-600">{app.users}</td>
                <td className="px-4 py-3 text-sm text-gray-400">{app.lastLogin ?? '—'}</td>
                <td className="px-4 py-3">
                  <button className="text-gray-400 hover:text-blue-600 transition-colors">
                    <Cog6ToothIcon className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── OAuth2 Tab ──────────────────────────────────────────────────────────────────

function OAuthTab() {
  const [selected, setSelected] = useState<OAuthClient | null>(null);
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-gray-900">OAuth2 / OIDC Clients</h3>
        <p className="text-xs text-gray-500 mt-0.5">Anwendungen, die Authorization Code, Client Credentials oder Device Flow nutzen</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {OAUTH_CLIENTS.map(client => (
          <div
            key={client.id}
            onClick={() => setSelected(client)}
            className={`bg-white rounded-xl border p-4 cursor-pointer hover:border-blue-400 transition-colors ${selected?.id === client.id ? 'border-blue-500 ring-1 ring-blue-200' : 'border-gray-200'}`}
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className="text-sm font-semibold text-gray-900">{client.name}</p>
                <p className="text-xs font-mono text-gray-500 mt-0.5">{client.clientId}</p>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${client.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                {client.status}
              </span>
            </div>
            <div className="flex flex-wrap gap-1 mb-2">
              {client.scopes.map(s => (
                <span key={s} className="bg-blue-50 text-blue-700 text-xs px-1.5 py-0.5 rounded font-mono">{s}</span>
              ))}
            </div>
            <p className="text-xs text-gray-400">{client.grantTypes.join(' · ')}</p>
          </div>
        ))}

        <button
          onClick={() => toast.success('Client-Wizard geöffnet')}
          className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-xl p-4 flex items-center justify-center gap-2 text-gray-500 hover:border-blue-400 hover:text-blue-600 hover:bg-blue-50 transition-colors"
        >
          <PlusIcon className="w-5 h-5" />
          <span className="text-sm font-medium">Neuer OAuth2 Client</span>
        </button>
      </div>

      {selected && (
        <div className="bg-white rounded-xl border border-blue-200 p-5">
          <h4 className="text-sm font-semibold text-gray-900 mb-4">{selected.name} — Konfiguration</h4>
          <div className="space-y-2">
            <EndpointRow label="Client ID"     value={selected.clientId} />
            <EndpointRow label="Client Secret" value="••••••••••••••••••••••••" />
            {selected.redirectUris.map((uri, i) => (
              <EndpointRow key={i} label={i === 0 ? 'Redirect URI' : ''} value={uri} />
            ))}
          </div>

          <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <p className="text-xs font-semibold text-gray-700 mb-2">Grafana-Beispielkonfiguration</p>
            <pre className="text-xs font-mono text-gray-600 whitespace-pre-wrap">{`[auth.generic_oauth]
enabled = true
name = OpenDirectory
client_id = ${selected.clientId}
client_secret = <secret>
scopes = openid profile email groups
auth_url = https://od.example.com/oauth/authorize
token_url = https://od.example.com/oauth/token
api_url = https://od.example.com/oauth/userinfo
role_attribute_path = contains(groups[*], 'admins') && 'Admin' || 'Viewer'`}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── SAML Tab ────────────────────────────────────────────────────────────────────

function SamlTab({ domain }: { domain: string }) {
  const issuer = `https://${domain}`;
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-gray-900">SAML 2.0 Service Provider Verbindungen</h3>
        <p className="text-xs text-gray-500 mt-0.5">OpenDirectory fungiert als SAML Identity Provider (IdP) für alle verbundenen SPs</p>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
        <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wide">IdP Metadaten</h4>
        <EndpointRow label="Entity ID / Issuer" value={issuer} />
        <EndpointRow label="SSO URL (POST)"     value={`${issuer}/saml/sso`} />
        <EndpointRow label="SSO URL (Redirect)" value={`${issuer}/saml/sso?binding=redirect`} />
        <EndpointRow label="SLO URL"            value={`${issuer}/saml/slo`} />
        <EndpointRow label="Metadata XML"       value={`${issuer}/saml/metadata`} />
        <div className="pt-2">
          <button
            onClick={() => toast.success('Metadaten-XML wird heruntergeladen...')}
            className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            <ArrowTopRightOnSquareIcon className="w-4 h-4" />
            IdP Metadaten herunterladen
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          { name: 'GitLab', logo: '🦊', entityId: 'https://gitlab.example.com', users: 5, nameid: 'email' },
        ].map(sp => (
          <div key={sp.name} className="bg-white rounded-xl border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-xl">{sp.logo}</span>
              <span className="text-sm font-semibold text-gray-900">{sp.name}</span>
              <span className="ml-auto bg-green-100 text-green-700 text-xs px-2 py-0.5 rounded-full">Aktiv</span>
            </div>
            <div className="text-xs text-gray-500 space-y-1">
              <div><span className="text-gray-400">Entity ID:</span> <code className="font-mono">{sp.entityId}</code></div>
              <div><span className="text-gray-400">NameID Format:</span> <code className="font-mono">{sp.nameid}</code></div>
              <div><span className="text-gray-400">Aktive Nutzer:</span> {sp.users}</div>
            </div>
          </div>
        ))}

        <button
          onClick={() => toast.success('SAML SP Wizard geöffnet')}
          className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-xl p-4 flex items-center justify-center gap-2 text-gray-500 hover:border-purple-400 hover:text-purple-600 hover:bg-purple-50 transition-colors"
        >
          <PlusIcon className="w-5 h-5" />
          <span className="text-sm font-medium">Service Provider verbinden</span>
        </button>
      </div>
    </div>
  );
}

// ─── MFA Setup Modal ──────────────────────────────────────────────────────────────

function MfaSetupModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [step, setStep] = useState<'loading'|'show-qr'|'verify'|'done'>('loading');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.post('/api/auth/mfa/setup')
      .then(res => {
        setQrDataUrl(res.data.qrDataUrl);
        setSecret(res.data.secret);
        setStep('show-qr');
      })
      .catch(() => setError('MFA-Setup fehlgeschlagen'));
  }, []);

  const verify = async () => {
    if (code.length !== 6) return setError('6-stelligen Code eingeben');
    setLoading(true);
    try {
      await api.post('/api/auth/mfa/verify-setup', { token: code });
      setStep('done');
      setTimeout(() => { onSuccess(); onClose(); }, 1500);
    } catch (e: any) {
      setError(e?.response?.data?.error || 'Ungültiger Code');
    }
    setLoading(false);
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 w-full max-w-sm">
        <h3 className="text-white font-semibold text-lg mb-4">TOTP-MFA einrichten</h3>

        {step === 'loading' && <div className="h-32 bg-gray-700 rounded animate-pulse" />}

        {step === 'show-qr' && (
          <div className="text-center space-y-4">
            <p className="text-gray-400 text-sm">Scannen Sie den QR-Code mit Google Authenticator, Authy oder einer kompatiblen App:</p>
            <img src={qrDataUrl} alt="TOTP QR Code" className="mx-auto rounded-lg w-48 h-48" />
            <p className="text-gray-500 text-xs break-all">Manuell: {secret}</p>
            <button onClick={() => setStep('verify')} className="w-full bg-blue-600 text-white py-2 rounded-lg font-medium">Weiter →</button>
          </div>
        )}

        {step === 'verify' && (
          <div className="space-y-4">
            <p className="text-gray-400 text-sm">Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein:</p>
            <input
              type="text" inputMode="numeric" maxLength={6} value={code}
              onChange={e => setCode(e.target.value.replace(/\D/g,''))}
              placeholder="000000"
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-3 text-white text-center text-2xl tracking-widest"
              autoFocus
            />
            {error && <p className="text-red-400 text-sm">{error}</p>}
            <button onClick={verify} disabled={loading || code.length !== 6} className="w-full bg-blue-600 disabled:opacity-50 text-white py-2 rounded-lg font-medium">
              {loading ? 'Überprüfe...' : 'Bestätigen'}
            </button>
          </div>
        )}

        {step === 'done' && (
          <div className="text-center py-8">
            <div className="text-green-400 text-4xl mb-3">✓</div>
            <p className="text-white font-medium">MFA erfolgreich aktiviert</p>
          </div>
        )}

        <button onClick={onClose} className="mt-3 w-full text-gray-500 text-sm hover:text-gray-300">Abbrechen</button>
      </div>
    </div>
  );
}

// ─── MFA Tab ─────────────────────────────────────────────────────────────────────

function MfaTab() {
  const [fido2, setFido2] = useState(true);
  const [totp, setTotp] = useState(true);
  const [conditional, setConditional] = useState(true);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [showMfaSetup, setShowMfaSetup] = useState(false);

  useEffect(() => {
    api.get('/api/auth/mfa/status')
      .then(res => setMfaEnabled(res.data.enabled))
      .catch(() => {});
  }, []);

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-gray-900">Multi-Faktor Authentifizierung</h3>
        <p className="text-xs text-gray-500 mt-0.5">Konfiguriere MFA-Methoden und Zero-Trust Richtlinien</p>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
        {/* FIDO2 row */}
        <div className="flex items-center justify-between p-4">
          <div className="flex items-start gap-3">
            <span className="text-2xl mt-0.5">🔑</span>
            <div>
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium text-gray-900">FIDO2 / Passkeys / WebAuthn</p>
                <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-green-100 text-green-700">Empfohlen</span>
              </div>
              <p className="text-xs text-gray-500 mt-0.5">Hardware-Keys (YubiKey), Windows Hello, Touch ID, Face ID — Phishing-resistent</p>
            </div>
          </div>
          <button
            onClick={() => { setFido2(!fido2); toast.success(`FIDO2 / Passkeys / WebAuthn ${!fido2 ? 'aktiviert' : 'deaktiviert'}`); }}
            className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${fido2 ? 'bg-blue-600' : 'bg-gray-300'}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${fido2 ? 'translate-x-5' : 'translate-x-0'}`} />
          </button>
        </div>

        {/* TOTP row — real setup controls */}
        <div className="p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-start gap-3">
              <span className="text-2xl mt-0.5">📱</span>
              <div>
                <p className="text-sm font-medium text-gray-900">TOTP / HOTP (Authenticator-App)</p>
                <p className="text-xs text-gray-500 mt-0.5">Google Authenticator, Aegis, Bitwarden Authenticator — zeitbasierte OTPs</p>
              </div>
            </div>
            <button
              onClick={() => { setTotp(!totp); toast.success(`TOTP / HOTP ${!totp ? 'aktiviert' : 'deaktiviert'}`); }}
              className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${totp ? 'bg-blue-600' : 'bg-gray-300'}`}
            >
              <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${totp ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
          </div>
          <div className="flex items-center justify-between p-4 bg-gray-800/5 rounded-lg border border-gray-200">
            <div>
              <p className="text-white font-medium text-sm" style={{ color: '#111827' }}>TOTP Authenticator</p>
              <p className="text-gray-400 text-xs mt-0.5">Google Authenticator, Authy, etc.</p>
            </div>
            {mfaEnabled ? (
              <button
                onClick={() => api.delete('/api/auth/mfa/disable').then(() => setMfaEnabled(false)).catch(() => {})}
                className="px-3 py-1.5 bg-red-600/20 border border-red-600 text-red-400 rounded-lg text-xs font-medium"
              >
                Deaktivieren
              </button>
            ) : (
              <button
                onClick={() => setShowMfaSetup(true)}
                className="px-3 py-1.5 bg-blue-600 text-white rounded-lg text-xs font-medium"
              >
                Einrichten
              </button>
            )}
          </div>
          {showMfaSetup && <MfaSetupModal onClose={() => setShowMfaSetup(false)} onSuccess={() => setMfaEnabled(true)} />}
        </div>

        {/* Conditional Access row */}
        <div className="flex items-center justify-between p-4">
          <div className="flex items-start gap-3">
            <span className="text-2xl mt-0.5">🛡️</span>
            <div>
              <p className="text-sm font-medium text-gray-900">Conditional Access</p>
              <p className="text-xs text-gray-500 mt-0.5">MFA-Anforderung basierend auf Gerät, Standort, Risikowert und Gruppe</p>
            </div>
          </div>
          <button
            onClick={() => { setConditional(!conditional); toast.success(`Conditional Access ${!conditional ? 'aktiviert' : 'deaktiviert'}`); }}
            className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${conditional ? 'bg-blue-600' : 'bg-gray-300'}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${conditional ? 'translate-x-5' : 'translate-x-0'}`} />
          </button>
        </div>
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3">
        <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-semibold text-amber-800">Zero Trust Empfehlung</p>
          <p className="text-amber-700 mt-0.5 text-xs">
            Aktiviere FIDO2 für alle Admin-Accounts. TOTP als Fallback. Conditional Access blockiert unbekannte Geräte aus Hochrisiko-Standorten automatisch.
          </p>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <h4 className="text-sm font-semibold text-gray-900 mb-3">Conditional Access Regeln</h4>
        <div className="space-y-2">
          {[
            { name: 'Admin-Accounts', condition: 'FIDO2 oder TOTP immer', action: 'Erlaubt', color: 'text-green-600' },
            { name: 'Unbekanntes Gerät + Risikoland', condition: 'IP-Geolocation in Sperrliste', action: 'Blockiert', color: 'text-red-600' },
            { name: 'Firmenlaptop + CH/DE/AT', condition: 'Compliance-Score > 80%', action: 'Ohne MFA', color: 'text-blue-600' },
            { name: 'BYOD-Geräte', condition: 'Alle Standorte', action: 'MFA erforderlich', color: 'text-orange-600' },
          ].map(r => (
            <div key={r.name} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
              <span className="text-sm font-medium text-gray-800">{r.name}</span>
              <span className="text-xs text-gray-500 mx-4 flex-1">{r.condition}</span>
              <span className={`text-xs font-semibold ${r.color}`}>{r.action}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Certificates Tab ────────────────────────────────────────────────────────────

function CertificatesTab() {
  const [certs, setCerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showIssue, setShowIssue] = useState(false);
  const [form, setForm] = useState({ commonName: '', sans: '', durationDays: 365, type: 'server' });
  const [issuing, setIssuing] = useState(false);
  const [newCert, setNewCert] = useState<any>(null);

  useEffect(() => {
    api.get('/api/ca/certificates')
      .then(r => setCerts(Array.isArray(r.data) ? r.data : []))
      .catch(() => setCerts([]))
      .finally(() => setLoading(false));
  }, []);

  const issueCert = async () => {
    setIssuing(true);
    try {
      const res = await api.post('/api/ca/issue', {
        commonName: form.commonName,
        sans: form.sans.split(',').map(s => s.trim()).filter(Boolean),
        durationDays: form.durationDays,
        type: form.type,
      });
      setNewCert(res.data);
      setCerts(prev => [res.data, ...prev]);
    } catch (e: any) {
      alert(e?.response?.data?.error || 'Fehler beim Ausstellen');
    }
    setIssuing(false);
  };

  const revokeCert = async (id: string) => {
    await api.post(`/api/ca/revoke/${id}`).catch(() => {});
    setCerts(prev => prev.map(c => c.id === id ? { ...c, revoked: true } : c));
  };

  const downloadPem = (pem: string, filename: string) => {
    const blob = new Blob([pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-white font-semibold">Interne Zertifikatsstelle</h3>
          <p className="text-gray-400 text-sm mt-0.5">Ausstellen und Verwalten von TLS-Zertifikaten</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => api.get('/api/ca/root').then(r => downloadPem(r.data, 'opendirectory-ca.pem'))} className="px-3 py-1.5 bg-gray-700 text-gray-300 rounded-lg text-sm">Root-CA herunterladen</button>
          <button onClick={() => setShowIssue(!showIssue)} className="px-3 py-1.5 bg-blue-600 text-white rounded-lg text-sm font-medium">+ Zertifikat ausstellen</button>
        </div>
      </div>

      {showIssue && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 space-y-4">
          <h4 className="text-white font-medium text-sm">Neues Zertifikat</h4>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-gray-400 text-xs">Common Name *</label>
              <input value={form.commonName} onChange={e => setForm(f => ({...f, commonName: e.target.value}))} placeholder="app.example.local" className="w-full mt-1 bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
            </div>
            <div>
              <label className="text-gray-400 text-xs">SANs (kommagetrennt)</label>
              <input value={form.sans} onChange={e => setForm(f => ({...f, sans: e.target.value}))} placeholder="app.local,192.168.1.10" className="w-full mt-1 bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
            </div>
            <div>
              <label className="text-gray-400 text-xs">Typ</label>
              <select value={form.type} onChange={e => setForm(f => ({...f, type: e.target.value}))} className="w-full mt-1 bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm">
                <option value="server">Server</option>
                <option value="client">Client</option>
                <option value="both">Server + Client</option>
              </select>
            </div>
            <div>
              <label className="text-gray-400 text-xs">Gültigkeit (Tage)</label>
              <input type="number" value={form.durationDays} onChange={e => setForm(f => ({...f, durationDays: parseInt(e.target.value)}))} className="w-full mt-1 bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
            </div>
          </div>
          <button onClick={issueCert} disabled={issuing || !form.commonName} className="px-4 py-2 bg-blue-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium">{issuing ? 'Ausstellen...' : 'Zertifikat ausstellen'}</button>

          {newCert && (
            <div className="mt-4 p-4 bg-green-900/30 border border-green-700 rounded-lg">
              <p className="text-green-400 text-sm font-medium mb-2">&#10003; Zertifikat ausgestellt</p>
              <div className="flex gap-2">
                <button onClick={() => downloadPem(newCert.certificate, `${form.commonName}.crt`)} className="px-3 py-1.5 bg-gray-700 text-gray-300 rounded text-xs">Zertifikat (.crt)</button>
                <button onClick={() => downloadPem(newCert.privateKey, `${form.commonName}.key`)} className="px-3 py-1.5 bg-gray-700 text-gray-300 rounded text-xs">Privater Schlüssel (.key)</button>
              </div>
            </div>
          )}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">{[...Array(3)].map((_, i) => <div key={i} className="h-12 bg-gray-700 rounded animate-pulse" />)}</div>
      ) : certs.length === 0 ? (
        <div className="text-center py-8 text-gray-400 text-sm">Keine Zertifikate ausgestellt</div>
      ) : (
        <div className="overflow-hidden border border-gray-700 rounded-xl">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50"><tr className="text-gray-400 text-xs">
              <th className="px-4 py-3 text-left">Common Name</th>
              <th className="px-4 py-3 text-left">Typ</th>
              <th className="px-4 py-3 text-left">Ablauf</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left"></th>
            </tr></thead>
            <tbody className="divide-y divide-gray-700/50">
              {certs.map(c => (
                <tr key={c.id} className="hover:bg-gray-700/30">
                  <td className="px-4 py-3 text-white font-mono text-xs">{c.common_name}</td>
                  <td className="px-4 py-3 text-gray-300">{c.type}</td>
                  <td className="px-4 py-3 text-gray-300">{c.expires_at ? new Date(c.expires_at).toLocaleDateString('de-CH') : '—'}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${c.revoked ? 'bg-red-900/50 text-red-400' : 'bg-green-900/50 text-green-400'}`}>{c.revoked ? 'Widerrufen' : 'Aktiv'}</span></td>
                  <td className="px-4 py-3">{!c.revoked && <button onClick={() => revokeCert(c.id)} className="text-red-400 hover:text-red-300 text-xs">Widerrufen</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────────

export default function IdentityProviderView() {
  const [activeTab, setActiveTab] = useState<IdpTab>('overview');
  const domain = process.env.NEXT_PUBLIC_AD_DOMAIN ?? 'opendirectory.local';

  const TABS: { id: IdpTab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'overview',      label: 'Übersicht',    icon: ShieldCheckIcon },
    { id: 'apps',          label: 'Apps',          icon: GlobeAltIcon },
    { id: 'oauth',         label: 'OAuth2/OIDC',   icon: KeyIcon },
    { id: 'saml',          label: 'SAML 2.0',      icon: LockClosedIcon },
    { id: 'mfa',           label: 'MFA & Access',  icon: FingerPrintIcon },
    { id: 'certificates',  label: 'Zertifikate',   icon: ShieldCheckIcon },
    { id: 'settings',      label: 'Einstellungen', icon: Cog6ToothIcon },
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 bg-blue-600 rounded-xl flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">Identity Provider</h1>
            <span className="bg-blue-100 text-blue-700 text-xs px-2.5 py-1 rounded-full font-medium">Entra ID Ersatz</span>
          </div>
          <p className="text-sm text-gray-500 ml-12">
            OpenDirectory als vollständiger Identity Provider — OAuth2, OIDC, SAML, MFA, Conditional Access
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-gray-200">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === t.id
                ? 'border-blue-600 text-blue-700'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview'     && <OverviewTab domain={domain} />}
      {activeTab === 'apps'         && <AppsTab />}
      {activeTab === 'oauth'        && <OAuthTab />}
      {activeTab === 'saml'         && <SamlTab domain={domain} />}
      {activeTab === 'mfa'          && <MfaTab />}
      {activeTab === 'certificates' && <CertificatesTab />}
      {activeTab === 'settings'  && (
        <div className="bg-white rounded-xl border border-gray-200 p-8 text-center text-gray-400">
          <Cog6ToothIcon className="w-10 h-10 mx-auto mb-2 opacity-30" />
          <p className="text-sm">IdP-Einstellungen (Token-Laufzeiten, Signing-Keys, Session-Policies)</p>
        </div>
      )}
    </div>
  );
}
