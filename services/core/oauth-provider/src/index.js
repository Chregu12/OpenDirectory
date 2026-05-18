'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { APP_CATALOG } = require('./appCatalog');
const db = require('./db');

const promClient = require('prom-client');
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// HTTP request counter
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
});

// HTTP request duration
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [register],
});

const activeTokensGauge = new promClient.Gauge({ name: 'oauth_active_tokens', help: 'Active OAuth tokens in memory', registers: [register] });
const scimPushErrorsCounter = new promClient.Counter({ name: 'scim_push_errors_total', help: 'SCIM push failures', labelNames: ['app'], registers: [register] });
const enrolledDevicesGauge = new promClient.Gauge({ name: 'enrolled_devices_total', help: 'Total enrolled devices', labelNames: ['platform', 'status'], registers: [register] });

// Update gauges periodically
setInterval(() => {
  activeTokensGauge.set(tokens.size);
}, 30000);

// ─── Redis-backed token blacklist with in-memory fallback ────────────────────

let redisClient = null;
const revokedTokens = new Set(); // in-memory fallback

async function initRedis() {
  try {
    const redis = require('redis');
    redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379', password: process.env.REDIS_PASSWORD || undefined });
    redisClient.on('error', err => { console.warn('[redis]', err.message); redisClient = null; });
    await redisClient.connect();
    console.log('[redis] connected for token blacklist');
  } catch (err) {
    console.warn('[redis] not available, using in-memory blacklist:', err.message);
    redisClient = null;
  }
}

async function blacklistToken(tokenHash, ttlSeconds = 3600) {
  revokedTokens.add(tokenHash);
  if (revokedTokens.size > 10000) revokedTokens.clear(); // prevent unbounded growth
  if (redisClient) {
    try { await redisClient.setEx(`revoked:${tokenHash}`, ttlSeconds, '1'); } catch {}
  }
}

async function isTokenRevoked(tokenHash) {
  if (revokedTokens.has(tokenHash)) return true;
  if (redisClient) {
    try {
      const val = await redisClient.get(`revoked:${tokenHash}`);
      return val === '1';
    } catch {}
  }
  return false;
}

// ─── Config ──────────────────────────────────────────────────────────────────────

const PORT    = process.env.OAUTH_PROVIDER_PORT ?? 3010;
const ISSUER  = process.env.OAUTH_ISSUER ?? 'https://opendirectory.local';
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL_SECONDS ?? '3600', 10);

// ─── RSA Key Pair (RS256) ─────────────────────────────────────────────────────

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// ─── SAML Signing Key Pair ────────────────────────────────────────────────────

const { privateKey: samlPrivKey, publicKey: samlPubKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Strip PEM headers for embedding in XML / metadata
const samlCertBody = samlPubKey
  .replace('-----BEGIN PUBLIC KEY-----', '')
  .replace('-----END PUBLIC KEY-----', '')
  .replace(/\n/g, '');

// Build JWK representation of the public key
function buildJwk() {
  const keyObj = crypto.createPublicKey(publicKey);
  const jwk = keyObj.export({ format: 'jwk' });
  return {
    kty: 'RSA',
    use: 'sig',
    alg: 'RS256',
    kid: 'od-rsa-key-1',
    n: jwk.n,
    e: jwk.e,
  };
}

// ─── In-memory stores ─────────────────────────────────────────────────────────

const clients         = new Map(); // clientId → ClientRecord
const authCodes       = new Map(); // code → CodeRecord
const tokens          = new Map(); // tokenHash → TokenRecord
const deviceCodes     = new Map(); // device_code → DeviceCodeRecord
const enrollmentTokens = new Map();
const scimUsers       = new Map();
const scimGroups      = new Map();

// ─── Connected Apps (SCIM push targets) ──────────────────────────────────────

const connectedApps = new Map([
  ['grafana', { id: 'grafana', name: 'Grafana', scimEndpoint: 'https://grafana.example.com/api/scim', token: 'grafana-scim-token', groups: ['Engineering', 'IT'], status: 'active' }],
  ['nextcloud', { id: 'nextcloud', name: 'Nextcloud', scimEndpoint: 'https://nextcloud.example.com/apps/user_saml/scim', token: 'nextcloud-scim-token', groups: ['Engineering'], status: 'active' }],
]);

// ─── SCIM Push Log ────────────────────────────────────────────────────────────

const scimPushLog = [];

async function triggerScimPush(action, userId, groupName) {
  const user = scimUsers.get(userId);
  if (!user) return;

  const appsToNotify = APP_CATALOG.filter(app => app.scimEnabled && app.scimEndpoint && app.scimToken);

  for (const app of appsToNotify) {
    const logEntry = { appId: app.id, action, userId, groupName, timestamp: new Date().toISOString(), success: false, error: null };
    try {
      let endpoint, method, body;

      if (action === 'add_to_group' || action === 'remove_from_group') {
        // SCIM patch group membership
        endpoint = `${app.scimEndpoint}/Groups/${encodeURIComponent(groupName)}`;
        method = 'PATCH';
        body = JSON.stringify({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{
            op: action === 'add_to_group' ? 'add' : 'remove',
            path: 'members',
            value: [{ value: user.id, display: user.userName }]
          }]
        });
      } else if (action === 'create') {
        endpoint = `${app.scimEndpoint}/Users`;
        method = 'POST';
        body = JSON.stringify({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          id: user.id,
          userName: user.userName,
          name: user.name || { formatted: user.userName },
          emails: user.emails || [],
          active: user.active !== false
        });
      } else if (action === 'delete') {
        endpoint = `${app.scimEndpoint}/Users/${user.id}`;
        method = 'DELETE';
        body = null;
      } else {
        endpoint = `${app.scimEndpoint}/Users/${user.id}`;
        method = 'PUT';
        body = JSON.stringify({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          id: user.id,
          userName: user.userName,
          name: user.name || { formatted: user.userName },
          emails: user.emails || [],
          active: user.active !== false
        });
      }

      const fetchOptions = {
        method,
        headers: {
          'Authorization': `Bearer ${app.scimToken}`,
          'Content-Type': 'application/scim+json',
          'Accept': 'application/scim+json'
        }
      };
      if (body) fetchOptions.body = body;

      const response = await fetch(endpoint, fetchOptions);
      logEntry.success = response.ok;
      if (!response.ok) {
        logEntry.error = `HTTP ${response.status}`;
      }
    } catch (err) {
      logEntry.error = err.message;
    }
    scimPushLog.push(logEntry);
    // Keep only last 500 log entries
    if (scimPushLog.length > 500) scimPushLog.shift();
  }
}

// ─── Update Rings ─────────────────────────────────────────────────────────────

const updateRings = new Map([
  ['stable', { id: 'stable', name: 'Stable', deferralDays: { windows: 14, macos: 7, linux: 0 }, description: 'Production devices — 2-week deferral', deviceCount: 8, assignedDevices: [] }],
  ['beta',   { id: 'beta',   name: 'Beta',   deferralDays: { windows: 3,  macos: 3, linux: 0 }, description: 'Early adopters — 3-day deferral', deviceCount: 3, assignedDevices: [] }],
  ['dev',    { id: 'dev',    name: 'Dev',     deferralDays: { windows: 0,  macos: 0, linux: 0 }, description: 'Developers — no deferral', deviceCount: 2, assignedDevices: [] }],
]);

// ─── Seed demo clients ───────────────────────────────────────────────────────────

[
  {
    clientId:     'grafana-od-client',
    clientSecret: 'grafana-secret-changeme',
    name:         'Grafana Dashboard',
    redirectUris: ['https://grafana.example.com/login/generic_oauth'],
    scopes:       ['openid', 'profile', 'email', 'groups'],
    grantTypes:   ['authorization_code', 'refresh_token'],
  },
  {
    clientId:     'devportal-od-client',
    clientSecret: 'devportal-secret-changeme',
    name:         'Internal Dev Portal',
    redirectUris: ['https://dev.example.com/auth/callback', 'http://localhost:4000/callback'],
    scopes:       ['openid', 'profile', 'email'],
    grantTypes:   ['authorization_code'],
  },
].forEach(c => {
  clients.set(c.clientId, c);
  if (db.isAvailable()) {
    db.upsertClient({ id: c.clientId, name: c.name, clientSecret: c.clientSecret, redirectUris: c.redirectUris, grants: c.grantTypes, scopes: c.scopes }).catch(err => console.error('[clients-db]', err.message));
  }
});

// ─── Seed SCIM Users ──────────────────────────────────────────────────────────

[
  { id: uuidv4(), userName: 'alice', displayName: 'Alice Admin', emails: [{ value: 'alice@opendirectory.local', primary: true }], active: true, groups: [] },
  { id: uuidv4(), userName: 'bob',   displayName: 'Bob Developer', emails: [{ value: 'bob@opendirectory.local', primary: true }], active: true, groups: [] },
].forEach(u => scimUsers.set(u.id, u));

// ─── Seed SCIM Groups ─────────────────────────────────────────────────────────

[
  { id: uuidv4(), displayName: 'Engineering', members: [] },
  { id: uuidv4(), displayName: 'IT',          members: [] },
].forEach(g => scimGroups.set(g.id, g));

// ─── App ──────────────────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 60_000, max: 500 }));

// ─── Prometheus metrics middleware ────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const route = req.route?.path ?? req.path ?? 'unknown';
    const duration = (Date.now() - start) / 1000;
    httpRequestsTotal.inc({ method: req.method, route, status: res.statusCode });
    httpRequestDuration.observe({ method: req.method, route }, duration);
  });
  next();
});

app.get('/metrics', async (req, res) => {
  res.setHeader('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// ─── OIDC Discovery ───────────────────────────────────────────────────────────────

app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer:                                ISSUER,
    authorization_endpoint:                `${ISSUER}/oauth/authorize`,
    token_endpoint:                        `${ISSUER}/oauth/token`,
    userinfo_endpoint:                     `${ISSUER}/oauth/userinfo`,
    jwks_uri:                              `${ISSUER}/.well-known/jwks.json`,
    introspection_endpoint:                `${ISSUER}/oauth/introspect`,
    revocation_endpoint:                   `${ISSUER}/oauth/revoke`,
    end_session_endpoint:                  `${ISSUER}/oauth/logout`,
    device_authorization_endpoint:         `${ISSUER}/oauth/device/code`,
    scopes_supported:                      ['openid', 'profile', 'email', 'groups', 'offline_access'],
    response_types_supported:              ['code', 'token', 'id_token'],
    grant_types_supported:                 ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    claims_supported:                      ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email', 'groups', 'preferred_username'],
    code_challenge_methods_supported:      ['S256', 'plain'],
  });
});

// ─── JWKS Endpoint (RS256) ────────────────────────────────────────────────────

app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [buildJwk()] });
});

// ─── Helper: sign token with RS256 ───────────────────────────────────────────

function signToken(payload, expiresIn) {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: 'od-rsa-key-1', expiresIn: expiresIn ?? TOKEN_TTL });
}

function verifyToken(token) {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

// ─── Authorization Endpoint ──────────────────────────────────────────────────────

app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, device_id } = req.query;

  const client = clients.get(client_id);
  if (!client) return res.status(400).send('<h2>Error: invalid_client</h2>');
  if (redirect_uri && !client.redirectUris.includes(redirect_uri)) return res.status(400).send('<h2>Error: invalid_redirect_uri</h2>');

  // Show login form
  const params = new URLSearchParams({ client_id, redirect_uri: redirect_uri || '', scope: scope || 'openid profile email', state: state || '', code_challenge: code_challenge || '', code_challenge_method: code_challenge_method || '', device_id: device_id || '' });
  res.send(`<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenDirectory Login</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;width:380px}
  .logo{text-align:center;margin-bottom:32px}
  .logo h1{color:#fff;font-size:22px;font-weight:700;letter-spacing:-0.5px}
  .logo p{color:#94a3b8;font-size:13px;margin-top:4px}
  .app-badge{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;margin-bottom:24px;display:flex;align-items:center;gap:10px}
  .app-badge span{color:#94a3b8;font-size:12px}
  .app-badge strong{color:#e2e8f0;font-size:13px}
  label{display:block;color:#94a3b8;font-size:12px;font-weight:500;margin-bottom:6px;margin-top:16px}
  input{width:100%;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;color:#fff;font-size:14px;outline:none}
  input:focus{border-color:#3b82f6}
  .error{background:#7f1d1d;border:1px solid #dc2626;border-radius:8px;padding:10px 14px;color:#fca5a5;font-size:13px;margin-top:16px;display:none}
  .error.visible{display:block}
  button{width:100%;margin-top:24px;background:#3b82f6;border:none;border-radius:8px;padding:12px;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
  button:hover{background:#2563eb}
  button:disabled{opacity:0.5;cursor:not-allowed}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>OpenDirectory</h1>
    <p>Sichere Anmeldung</p>
  </div>
  <div class="app-badge">
    <span>App:</span>
    <strong>${client.name || client_id}</strong>
  </div>
  <form id="loginForm" method="POST" action="/oauth/authorize/login">
    <input type="hidden" name="client_id" value="${client_id}">
    <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}">
    <input type="hidden" name="scope" value="${scope || 'openid profile email'}">
    <input type="hidden" name="state" value="${state || ''}">
    <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
    <input type="hidden" name="device_id" value="${device_id || ''}">
    <label>Benutzername</label>
    <input type="text" name="username" autocomplete="username" required autofocus>
    <label>Passwort</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <div class="error" id="errBox"></div>
    <button type="submit" id="submitBtn">Anmelden</button>
  </form>
</div>
<script>
  const f=document.getElementById('loginForm');
  const err=document.getElementById('errBox');
  const btn=document.getElementById('submitBtn');
  // Check for error param in URL
  const urlErr=new URLSearchParams(location.search).get('error');
  if(urlErr){err.textContent=decodeURIComponent(urlErr);err.classList.add('visible');}
</script>
</body>
</html>`);
});

app.post('/oauth/authorize/login', async (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, device_id, username, password } = req.body;

  if (!username || !password) {
    const params = new URLSearchParams({ client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, device_id, error: 'Benutzername und Passwort erforderlich' });
    return res.redirect(`/oauth/authorize?${params}`);
  }

  // Validate credentials against auth service
  const AUTH_SERVICE = process.env.AUTH_SERVICE_URL || 'http://localhost:3002';
  let userId = null;
  let userInfo = null;
  try {
    const loginRes = await fetch(`${AUTH_SERVICE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!loginRes.ok) {
      const params = new URLSearchParams({ client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, device_id, error: 'Ungültige Anmeldedaten' });
      return res.redirect(`/oauth/authorize?${params}`);
    }
    const data = await loginRes.json();
    userId = data.user?.id ?? data.userId ?? data.id ?? username;
    userInfo = data.user ?? data;
  } catch (err) {
    // Auth service unreachable — fall back to username as ID (dev mode)
    console.warn('[oauth/authorize] auth service unreachable, using username as userId:', err.message);
    userId = username;
    userInfo = { id: username, username, name: username };
  }

  const client = clients.get(client_id);
  if (!client) return res.status(400).send('<h2>Error: invalid_client</h2>');

  const code = uuidv4();
  authCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope: scope ?? 'openid profile email',
    userId,
    userInfo,
    deviceId: device_id || undefined,
    codeChallenge: code_challenge || undefined,
    codeChallengeMethod: code_challenge_method || undefined,
    expiresAt: Date.now() + 60_000,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

// ─── Token Endpoint ───────────────────────────────────────────────────────────────

app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token, device_code } = req.body;

  // Device code grant does not require client secret for public clients
  const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

  if (grant_type !== DEVICE_GRANT) {
    const client = clients.get(client_id);
    if (!client || (client.clientSecret && client.clientSecret !== client_secret)) {
      return res.status(401).json({ error: 'invalid_client' });
    }
  }

  if (grant_type === 'authorization_code') {
    const record = authCodes.get(code);
    if (!record || record.expiresAt < Date.now() || record.clientId !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    authCodes.delete(code);

    // Device compliance check — try DB first, then in-memory registry, then external device service
    const deviceId = record.deviceId; // may be undefined for browser flows
    if (deviceId) {
      let deviceStatus = null;

      // 1. Check DB (enrolled_devices table)
      if (db.isAvailable()) {
        try {
          const dbDevice = await db.getDevice(deviceId);
          if (dbDevice) deviceStatus = dbDevice.status;
        } catch {}
      }

      // 2. Fall back to in-memory registry
      if (!deviceStatus) {
        const memDevice = deviceRegistry.get(deviceId);
        if (memDevice) deviceStatus = memDevice.status;
      }

      // 3. If still not found, try external device service
      if (!deviceStatus) {
        const DEVICE_SERVICE = process.env.DEVICE_SERVICE_URL || 'http://localhost:3003';
        try {
          const devRes = await fetch(`${DEVICE_SERVICE}/api/devices/${deviceId}`, {
            headers: { 'Authorization': `Bearer ${process.env.SERVICE_TOKEN || ''}` }
          });
          if (devRes.ok) {
            const devData = await devRes.json();
            deviceStatus = devData.status ?? devData.complianceStatus ?? devData.compliance_status;
          }
        } catch {}
      }

      if (deviceStatus === 'quarantined' || deviceStatus === 'blocked') {
        return res.status(403).json({
          error: 'device_compliance_failure',
          error_description: 'Device is quarantined and cannot obtain tokens.',
        });
      }
    }

    const scimUser = scimUsers.get(record.userId);
    const ui = record.userInfo || {};
    const payload = {
      sub:   record.userId,
      iss:   ISSUER,
      aud:   client_id,
      iat:   Math.floor(Date.now() / 1000),
      name:  scimUser?.name?.formatted ?? scimUser?.displayName ?? ui.name ?? ui.displayName ?? record.userId,
      email: scimUser?.emails?.[0]?.value ?? ui.email ?? `${record.userId}@opendirectory.local`,
      preferred_username: scimUser?.userName ?? ui.username ?? record.userId,
      groups: (scimUser?.groups ?? ui.groups ?? []).map((g) => g.value ?? g.display ?? g).filter(Boolean),
      scope: record.scope,
    };

    const access_token = signToken(payload);
    const id_token     = signToken({ ...payload, nonce: uuidv4() });
    const rt           = uuidv4();

    const atHash = crypto.createHash('sha256').update(access_token).digest('hex');
    const rtHash = crypto.createHash('sha256').update(rt).digest('hex');
    tokens.set(atHash, { ...payload, type: 'access' });
    tokens.set(rtHash, { ...payload, type: 'refresh' });
    if (db.isAvailable()) {
      db.saveToken(atHash, payload).catch(err => console.error('[token-db]', err.message));
    }

    return res.json({ access_token, id_token, refresh_token: rt, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: record.scope });
  }

  if (grant_type === 'refresh_token') {
    const hash = crypto.createHash('sha256').update(refresh_token ?? '').digest('hex');
    const record = tokens.get(hash);
    if (!record || record.type !== 'refresh') return res.status(400).json({ error: 'invalid_grant' });

    const payload = { sub: record.sub, iss: ISSUER, aud: client_id, iat: Math.floor(Date.now() / 1000), name: record.name, email: record.email, preferred_username: record.preferred_username, groups: record.groups, scope: record.scope };
    const access_token = signToken(payload);
    const new_rt = uuidv4();
    tokens.delete(hash);
    const newAtHash = crypto.createHash('sha256').update(access_token).digest('hex');
    tokens.set(newAtHash, { ...payload, type: 'access' });
    tokens.set(crypto.createHash('sha256').update(new_rt).digest('hex'), { ...payload, type: 'refresh' });
    if (db.isAvailable()) {
      db.saveToken(newAtHash, payload).catch(err => console.error('[token-db]', err.message));
    }
    return res.json({ access_token, refresh_token: new_rt, token_type: 'Bearer', expires_in: TOKEN_TTL });
  }

  if (grant_type === 'client_credentials') {
    const payload = { sub: client_id, iss: ISSUER, aud: client_id, iat: Math.floor(Date.now() / 1000), scope: req.body.scope ?? '' };
    const access_token = signToken(payload);
    return res.json({ access_token, token_type: 'Bearer', expires_in: TOKEN_TTL });
  }

  if (grant_type === DEVICE_GRANT) {
    const record = deviceCodes.get(device_code);
    if (!record) return res.status(400).json({ error: 'expired_token' });
    if (record.expiresAt < Date.now()) { deviceCodes.delete(device_code); return res.status(400).json({ error: 'expired_token' }); }
    if (!record.approved) return res.status(400).json({ error: 'authorization_pending' });

    deviceCodes.delete(device_code);
    const payload = { sub: record.userId ?? 'device-user', iss: ISSUER, aud: client_id ?? 'device-client', iat: Math.floor(Date.now() / 1000), scope: record.scope ?? 'openid profile' };
    const access_token = signToken(payload);
    return res.json({ access_token, token_type: 'Bearer', expires_in: TOKEN_TTL });
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// ─── UserInfo Endpoint ────────────────────────────────────────────────────────────

app.get('/oauth/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'invalid_token' });
  const bearerToken = req.headers.authorization?.replace('Bearer ', '');
  if (bearerToken) {
    const hash = crypto.createHash('sha256').update(bearerToken).digest('hex');
    if (await isTokenRevoked(hash)) return res.status(401).json({ error: 'token_revoked' });
  }
  try {
    const payload = verifyToken(token);
    return res.json({ sub: payload.sub, name: payload.name, email: payload.email, preferred_username: payload.preferred_username, groups: payload.groups ?? [] });
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// ─── Token Introspection ─────────────────────────────────────────────────────────

app.post('/oauth/introspect', async (req, res) => {
  const { token, client_id, client_secret } = req.body;
  const client = clients.get(client_id);
  if (!client || client.clientSecret !== client_secret) return res.status(401).json({ error: 'invalid_client' });
  const hash = crypto.createHash('sha256').update(token ?? '').digest('hex');
  if (await isTokenRevoked(hash)) {
    return res.json({ active: false });
  }
  try {
    const payload = verifyToken(token);
    return res.json({ active: true, ...payload });
  } catch {
    return res.json({ active: false });
  }
});

// ─── Token Revocation ────────────────────────────────────────────────────────────

app.post('/oauth/revoke', async (req, res) => {
  const { token } = req.body;
  const hash = crypto.createHash('sha256').update(token ?? '').digest('hex');
  tokens.delete(hash);
  await blacklistToken(hash, TOKEN_TTL);
  if (db.isAvailable()) { db.revokeToken(hash).catch(() => {}); }
  res.status(200).json({ ok: true });
});

// ─── Logout ───────────────────────────────────────────────────────────────────────

app.get('/oauth/logout', (req, res) => {
  const { post_logout_redirect_uri } = req.query;
  if (post_logout_redirect_uri) return res.redirect(post_logout_redirect_uri);
  res.json({ ok: true });
});

// ─── Device Authorization Flow (RFC 8628) ────────────────────────────────────────

app.post('/oauth/device/code', (req, res) => {
  const { client_id, scope } = req.body;
  const device_code = uuidv4();
  const user_code = crypto.randomBytes(3).toString('hex').toUpperCase().replace(/(.{4})/, '$1-');
  const expiresAt = Date.now() + 15 * 60_000; // 15 min

  deviceCodes.set(device_code, {
    user_code,
    client_id,
    scope: scope ?? 'openid profile',
    approved: false,
    userId: null,
    expiresAt,
  });

  res.json({
    device_code,
    user_code,
    verification_uri: `${ISSUER}/oauth/device/verify`,
    verification_uri_complete: `${ISSUER}/oauth/device/verify?user_code=${user_code}`,
    expires_in: 900,
    interval: 5,
  });
});

app.get('/oauth/device/verify', (req, res) => {
  const { user_code, error } = req.query;
  res.set('Content-Type', 'text/html');
  const errorHtml = error ? `<p style="color:#dc2626;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:10px;margin-top:12px;">${error}</p>` : '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Device Authorization — OpenDirectory</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:24px;background:#f9fafb;}
h1{font-size:1.5rem;font-weight:700;color:#1e293b;}
input{width:100%;padding:10px;border:1px solid #d1d5db;border-radius:8px;font-size:1rem;margin:8px 0;}
input[name="user_code"]{font-size:1.1rem;letter-spacing:4px;text-align:center;}
label{display:block;font-size:0.85rem;color:#475569;margin-top:12px;}
button{width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer;margin-top:16px;}
button:hover{background:#1d4ed8;}.msg{margin-top:16px;padding:12px;border-radius:8px;}
</style></head>
<body>
<h1>Device Authorization</h1>
<p>Enter the code displayed on your device and your credentials to authorize access.</p>
${errorHtml}
<form method="POST" action="/oauth/device/approve">
  <label>Device Code</label>
  <input name="user_code" type="text" placeholder="XXXX-XXXX" value="${user_code ?? ''}" maxlength="9"/>
  <label>Username</label>
  <input name="username" type="text" autocomplete="username" required/>
  <label>Password</label>
  <input name="password" type="password" autocomplete="current-password" required/>
  <button type="submit">Authorize Device</button>
</form>
</body></html>`);
});

app.post('/oauth/device/approve', express.urlencoded({ extended: true }), async (req, res) => {
  const { user_code, username, password } = req.body;
  let found = null;
  for (const [dc, rec] of deviceCodes.entries()) {
    if (rec.user_code === user_code && rec.expiresAt > Date.now()) { found = [dc, rec]; break; }
  }
  if (!found) return res.send('<html><body><p>Invalid or expired code.</p></body></html>');

  // Validate credentials against auth service
  const AUTH_SERVICE = process.env.AUTH_SERVICE_URL || 'http://localhost:3002';
  let userId = username; // fallback: use submitted username
  try {
    const loginRes = await fetch(`${AUTH_SERVICE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!loginRes.ok) {
      return res.redirect(`/oauth/device/verify?user_code=${encodeURIComponent(user_code)}&error=${encodeURIComponent('Invalid credentials')}`);
    }
    const data = await loginRes.json();
    userId = data.user?.id ?? data.userId ?? data.id ?? username;
  } catch (err) {
    // Auth service unreachable — fall back to username (dev mode)
    console.warn('[device/approve] auth service unreachable, using username as userId:', err.message);
    userId = username;
  }

  found[1].approved = true;
  found[1].userId = userId;
  res.send('<html><body><h2 style="font-family:system-ui;color:#16a34a;">Device authorized! You may close this window.</h2></body></html>');
});

// ─── SAML Helper: build signed assertion XML ─────────────────────────────────

function buildSamlResponse(spEntityId, relayState, userId) {
  const now = new Date();
  const notBefore = now.toISOString();
  const notOnOrAfter = new Date(now.getTime() + 3600_000).toISOString();
  const responseId = `_${crypto.randomBytes(16).toString('hex')}`;
  const assertionId = `_${crypto.randomBytes(16).toString('hex')}`;
  const scimUser = userId ? scimUsers.get(userId) : null;
  const nameId = scimUser?.emails?.[0]?.value ?? `${userId ?? 'user'}@opendirectory.local`;
  const displayName = scimUser?.name?.formatted ?? scimUser?.displayName ?? userId ?? 'User';

  // Build the Assertion XML (unsigned first, then compute signature)
  const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${notBefore}" Version="2.0">` +
    `<saml:Issuer>${ISSUER}</saml:Issuer>` +
    `<saml:Subject>` +
      `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
        `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${ISSUER}/saml/acs-demo"/>` +
      `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
      `<saml:AudienceRestriction><saml:Audience>${spEntityId || ISSUER}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${notBefore}">` +
      `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `<saml:AttributeStatement>` +
      `<saml:Attribute Name="email"><saml:AttributeValue>${nameId}</saml:AttributeValue></saml:Attribute>` +
      `<saml:Attribute Name="name"><saml:AttributeValue>${displayName}</saml:AttributeValue></saml:Attribute>` +
      `<saml:Attribute Name="groups"><saml:AttributeValue>users</saml:AttributeValue></saml:Attribute>` +
    `</saml:AttributeStatement>` +
  `</saml:Assertion>`;

  // Sign the assertion with RS256
  const sign = crypto.createSign('SHA256');
  sign.update(assertionXml);
  const signatureBase64 = sign.sign(samlPrivKey, 'base64');

  const signedAssertionXml = assertionXml.replace(
    `<saml:Issuer>${ISSUER}</saml:Issuer>`,
    `<saml:Issuer>${ISSUER}</saml:Issuer>` +
    `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
      `<ds:SignedInfo>` +
        `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
        `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
        `<ds:Reference URI="#${assertionId}">` +
          `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
          `<ds:DigestValue>${crypto.createHash('sha256').update(assertionXml).digest('base64')}</ds:DigestValue>` +
        `</ds:Reference>` +
      `</ds:SignedInfo>` +
      `<ds:SignatureValue>${signatureBase64}</ds:SignatureValue>` +
      `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${samlCertBody}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>`
  );

  const responseXml = `<?xml version="1.0" encoding="UTF-8"?>` +
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${responseId}" InResponseTo="" IssueInstant="${notBefore}" Version="2.0">` +
      `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${ISSUER}</saml:Issuer>` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      signedAssertionXml +
    `</samlp:Response>`;

  return Buffer.from(responseXml).toString('base64');
}

// ─── SAML SSO Endpoint (GET + POST) ──────────────────────────────────────────

function handleSamlSso(req, res) {
  const rawRequest = req.query.SAMLRequest ?? req.body?.SAMLRequest;
  const relayState = req.query.RelayState ?? req.body?.RelayState ?? '';

  let spEntityId = ISSUER;
  if (rawRequest) {
    try {
      const decoded = Buffer.from(rawRequest, 'base64').toString('utf-8');
      const match = decoded.match(/<(?:[a-zA-Z]+:)?Issuer[^>]*>([^<]+)<\/(?:[a-zA-Z]+:)?Issuer>/);
      if (match) spEntityId = match[1].trim();
    } catch (_) { /* ignore parse errors */ }
  }

  const acsUrl = req.query.redirect_uri ?? req.body?.redirect_uri ?? `${ISSUER}/saml/acs-demo`;
  const samlResponseBase64 = buildSamlResponse(spEntityId, relayState);

  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><head><title>SAML SSO — OpenDirectory</title></head><body>` +
    `<form method="POST" action="${acsUrl}">` +
      `<input type="hidden" name="SAMLResponse" value="${samlResponseBase64}" />` +
      `<input type="hidden" name="RelayState" value="${relayState}" />` +
      `<script>document.forms[0].submit();</script>` +
    `</form>` +
    `<p>Redirecting to service provider&hellip;</p>` +
    `</body></html>`);
}

app.get('/saml/sso', handleSamlSso);
app.post('/saml/sso', handleSamlSso);

// ─── SAML Certificate Endpoint ────────────────────────────────────────────────

app.get('/saml/certificate', (req, res) => {
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.send(samlPubKey);
});

// ─── SAML Metadata ────────────────────────────────────────────────────────────────

app.get('/saml/metadata', (req, res) => {
  res.set('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${ISSUER}">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
                    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${samlCertBody}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="${ISSUER}/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="${ISSUER}/saml/sso"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="${ISSUER}/saml/slo"/>
  </IDPSSODescriptor>
</EntityDescriptor>`);
});

// ─── OAuth2 Client Management API (full CRUD) ─────────────────────────────────────

app.get('/api/clients', async (req, res) => {
  if (db.isAvailable()) {
    try {
      const dbClients = await db.getAllClients();
      // Merge with in-memory (in-memory may have more recent data)
      return res.json(dbClients);
    } catch (err) { console.error('[clients-db]', err.message); }
  }
  res.json([...clients.values()]);
});

app.post('/api/clients', (req, res) => {
  const { name, redirectUris, scopes, grantTypes } = req.body;
  if (!name || !redirectUris?.length) return res.status(400).json({ error: 'name and redirectUris required' });
  const clientId     = `${name.toLowerCase().replace(/\s+/g, '-')}-${uuidv4().slice(0, 8)}`;
  const clientSecret = crypto.randomBytes(32).toString('hex');
  const record = { clientId, clientSecret, name, redirectUris, scopes: scopes ?? ['openid', 'profile', 'email'], grantTypes: grantTypes ?? ['authorization_code'] };
  clients.set(clientId, record);
  db.upsertClient({ id: clientId, name, clientSecret, redirectUris, grants: record.grantTypes, scopes: record.scopes }).catch(err => console.error('[clients-db]', err.message));
  res.status(201).json({ clientId, clientSecret, name });
});

app.put('/api/clients/:id', (req, res) => {
  const client = clients.get(req.params.id);
  if (!client) return res.status(404).json({ error: 'Client not found' });
  const { name, redirectUris, scopes, grantTypes } = req.body;
  const updated = { ...client, ...(name && { name }), ...(redirectUris && { redirectUris }), ...(scopes && { scopes }), ...(grantTypes && { grantTypes }) };
  clients.set(req.params.id, updated);
  const { clientSecret: _, ...safe } = updated;
  res.json(safe);
});

app.delete('/api/clients/:id', (req, res) => {
  if (!clients.has(req.params.id)) return res.status(404).json({ error: 'Client not found' });
  clients.delete(req.params.id);
  db.deleteClient(req.params.id).catch(err => console.error('[clients-db]', err.message));
  res.status(204).send();
});

// ─── SCIM 2.0 ─────────────────────────────────────────────────────────────────────

function scimUserResource(u) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: u.id,
    userName: u.userName,
    displayName: u.displayName,
    emails: u.emails,
    active: u.active,
    groups: u.groups,
    meta: { resourceType: 'User', location: `/scim/v2/Users/${u.id}` },
  };
}

function scimGroupResource(g) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    id: g.id,
    displayName: g.displayName,
    members: g.members,
    meta: { resourceType: 'Group', location: `/scim/v2/Groups/${g.id}` },
  };
}

// SCIM Users
app.get('/scim/v2/Users', (req, res) => {
  const list = [...scimUsers.values()].map(scimUserResource);
  res.json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: list.length, Resources: list });
});

app.post('/scim/v2/Users', (req, res) => {
  const id = uuidv4();
  const user = { id, userName: req.body.userName, displayName: req.body.displayName ?? req.body.userName, emails: req.body.emails ?? [], active: req.body.active !== false, groups: [] };
  scimUsers.set(id, user);
  res.status(201).json(scimUserResource(user));
});

app.get('/scim/v2/Users/:id', (req, res) => {
  const u = scimUsers.get(req.params.id);
  if (!u) return res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: 404, detail: 'User not found' });
  res.json(scimUserResource(u));
});

app.put('/scim/v2/Users/:id', (req, res) => {
  const existing = scimUsers.get(req.params.id);
  if (!existing) return res.status(404).json({ status: 404, detail: 'User not found' });
  const user = { id: req.params.id, userName: req.body.userName, displayName: req.body.displayName, emails: req.body.emails ?? [], active: req.body.active !== false, groups: req.body.groups ?? [] };
  scimUsers.set(req.params.id, user);
  // Trigger SCIM push deactivation if user was just deactivated
  if (existing.active === true && user.active === false) {
    triggerScimPush('deactivate', req.params.id, '').catch(err => console.error('[SCIM push error]', err.message));
  }
  res.json(scimUserResource(user));
});

app.delete('/scim/v2/Users/:id', (req, res) => {
  if (!scimUsers.has(req.params.id)) return res.status(404).json({ status: 404, detail: 'User not found' });
  scimUsers.delete(req.params.id);
  res.status(204).send();
});

// SCIM Groups
app.get('/scim/v2/Groups', (req, res) => {
  const list = [...scimGroups.values()].map(scimGroupResource);
  res.json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: list.length, Resources: list });
});

app.post('/scim/v2/Groups', (req, res) => {
  const id = uuidv4();
  const group = { id, displayName: req.body.displayName, members: req.body.members ?? [] };
  scimGroups.set(id, group);
  res.status(201).json(scimGroupResource(group));
});

app.get('/scim/v2/Groups/:id', (req, res) => {
  const g = scimGroups.get(req.params.id);
  if (!g) return res.status(404).json({ status: 404, detail: 'Group not found' });
  res.json(scimGroupResource(g));
});

app.put('/scim/v2/Groups/:id', (req, res) => {
  const existing = scimGroups.get(req.params.id);
  if (!existing) return res.status(404).json({ status: 404, detail: 'Group not found' });
  const group = { id: req.params.id, displayName: req.body.displayName, members: req.body.members ?? [] };
  scimGroups.set(req.params.id, group);
  // Trigger SCIM push for newly added members
  const existingMemberIds = new Set((existing.members ?? []).map(m => m.value ?? m.id ?? m));
  for (const member of (group.members ?? [])) {
    const memberId = member.value ?? member.id ?? member;
    if (!existingMemberIds.has(memberId)) {
      triggerScimPush('add', memberId, group.displayName).catch(err => console.error('[SCIM push error]', err.message));
    }
  }
  res.json(scimGroupResource(group));
});

app.delete('/scim/v2/Groups/:id', (req, res) => {
  if (!scimGroups.has(req.params.id)) return res.status(404).json({ status: 404, detail: 'Group not found' });
  scimGroups.delete(req.params.id);
  res.status(204).send();
});

// ─── Device Registry ─────────────────────────────────────────────────────────────

const deviceRegistry = new Map();

// Seed 3 demo devices (lastSeen values: recent, 35 days ago, 65 days ago)
[
  { id: 'dev-001', hostname: 'ws-alice-mbp',   platform: 'macos',   enrolledAt: new Date(Date.now() - 10 * 86400_000).toISOString(), lastSeen: new Date(Date.now() - 2 * 86400_000).toISOString(),  status: 'active' },
  { id: 'dev-002', hostname: 'ws-bob-win11',   platform: 'windows', enrolledAt: new Date(Date.now() - 40 * 86400_000).toISOString(), lastSeen: new Date(Date.now() - 35 * 86400_000).toISOString(), status: 'active' },
  { id: 'dev-003', hostname: 'srv-ci-ubuntu',  platform: 'linux',   enrolledAt: new Date(Date.now() - 70 * 86400_000).toISOString(), lastSeen: new Date(Date.now() - 65 * 86400_000).toISOString(), status: 'active' },
].forEach(d => deviceRegistry.set(d.id, d));

// Auto-quarantine cron: runs every 30s (represents a daily check)
setInterval(() => {
  const now = Date.now();
  const DAY_MS = 86400_000;
  let flagged = 0;
  let quarantined = 0;
  for (const device of deviceRegistry.values()) {
    const lastSeenMs = new Date(device.lastSeen).getTime();
    const daysSinceLastSeen = (now - lastSeenMs) / DAY_MS;
    if (daysSinceLastSeen > 60) {
      device.status = 'quarantined';
      quarantined++;
      // Queue update_policy command for quarantined device
      if (!mdmCommands.has(device.id)) mdmCommands.set(device.id, []);
      const queue = mdmCommands.get(device.id);
      // Only queue if not already pending
      if (!queue.find(c => c.command === 'update_policy' && c.status === 'pending')) {
        queue.push({
          id: uuidv4(),
          command: 'update_policy',
          payload: { reason: 'auto_quarantine', policy: 'compliance_remediation' },
          issuedAt: new Date().toISOString(),
          status: 'pending'
        });
        // Persist to DB
        if (db.isAvailable()) {
          db.query(
            `INSERT INTO mdm_commands(id, device_id, command, payload, status) VALUES($1,$2,'update_policy',$3,'pending') ON CONFLICT(id) DO NOTHING`,
            [queue[queue.length-1].id, device.id, JSON.stringify({ reason: 'auto_quarantine' })]
          ).catch(() => {});
        }
      }
    } else if (daysSinceLastSeen > 30) {
      device.status = 'flagged';
      flagged++;
      // Queue collect_logs command for flagged device
      if (!mdmCommands.has(device.id)) mdmCommands.set(device.id, []);
      const queue = mdmCommands.get(device.id);
      if (!queue.find(c => c.command === 'collect_logs' && c.status === 'pending')) {
        queue.push({ id: uuidv4(), command: 'collect_logs', payload: { reason: 'compliance_check' }, issuedAt: new Date().toISOString(), status: 'pending' });
      }
    }
  }
  console.log(`[device-quarantine] flagged=${flagged} quarantined=${quarantined}`);
}, 30_000);

app.get('/api/devices/registry', async (req, res) => {
  if (db.isAvailable()) {
    try {
      const rows = await db.getAllDevices();
      if (rows.length > 0) return res.json(rows.map(r => ({ ...r, ...r.data })));
    } catch (err) { console.error('[registry-db]', err.message); }
  }
  res.json([...deviceRegistry.values()]);
});

app.put('/api/devices/:id/status', (req, res) => {
  const device = deviceRegistry.get(req.params.id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  const { status } = req.body;
  if (!['active', 'flagged', 'quarantined'].includes(status)) {
    return res.status(400).json({ error: 'status must be active, flagged, or quarantined' });
  }
  device.status = status;
  res.json(device);
});

// ─── MDM Command Queue ────────────────────────────────────────────────────────

const mdmCommands = new Map(); // deviceId → [command]

app.post('/api/devices/:deviceId/commands', (req, res) => {
  const { command, payload } = req.body;
  const VALID_COMMANDS = ['wipe', 'lock', 'unlock', 'update_policy', 'restart', 'collect_logs', 'install_app', 'uninstall_app'];
  if (!VALID_COMMANDS.includes(command)) return res.status(400).json({ error: `Unknown command. Valid: ${VALID_COMMANDS.join(', ')}` });

  const deviceId = req.params.deviceId;
  const queue = mdmCommands.get(deviceId) || [];
  const cmdRecord = { id: uuidv4(), command, payload: payload || {}, issuedAt: new Date().toISOString(), status: 'pending' };
  queue.push(cmdRecord);
  mdmCommands.set(deviceId, queue);

  // Persist to DB if available
  if (db.isAvailable()) {
    db.query(
      `INSERT INTO mdm_commands(id, device_id, command, payload, status) VALUES($1,$2,$3,$4,'pending')`,
      [cmdRecord.id, deviceId, command, JSON.stringify(payload || {})]
    ).catch(() => {});
  }

  console.log(`[MDM] Command ${command} queued for device ${deviceId}`);
  res.status(201).json(cmdRecord);
});

// Agent polls this endpoint to get pending commands
app.get('/api/devices/:deviceId/commands/pending', (req, res) => {
  const deviceId = req.params.deviceId;
  const queue = (mdmCommands.get(deviceId) || []).filter(c => c.status === 'pending');
  res.json(queue);
});

// Agent reports command result
app.patch('/api/devices/:deviceId/commands/:cmdId', (req, res) => {
  const { deviceId, cmdId } = req.params;
  const { status, result } = req.body;
  const queue = mdmCommands.get(deviceId) || [];
  const cmd = queue.find(c => c.id === cmdId);
  if (!cmd) return res.status(404).json({ error: 'Command not found' });
  cmd.status = status || 'completed';
  cmd.result = result;
  cmd.completedAt = new Date().toISOString();
  res.json(cmd);
});

// List all commands for a device
app.get('/api/devices/:deviceId/commands', (req, res) => {
  const queue = mdmCommands.get(req.params.deviceId) || [];
  res.json(queue);
});

// ─── Compliance Check Endpoint ────────────────────────────────────────────────────

app.post('/api/devices/:deviceId/compliance-check', async (req, res) => {
  const { deviceId } = req.params;
  const { settings } = req.body; // device reports its current settings

  if (!settings) return res.status(400).json({ error: 'settings object required' });

  // Get device platform
  let platform = 'unknown';
  const dbDevice = db.isAvailable() ? await db.getDevice(deviceId).catch(() => null) : null;
  const memDevice = deviceRegistry.get(deviceId);
  platform = dbDevice?.platform ?? memDevice?.platform ?? req.body.platform ?? 'unknown';

  // Basic compliance rules per platform
  const RULES = {
    windows: [
      { key: 'firewall_enabled', expected: 'true', severity: 'high', description: 'Windows Firewall muss aktiviert sein' },
      { key: 'bitlocker_enabled', expected: 'true', severity: 'high', description: 'BitLocker-Verschlüsselung erforderlich' },
      { key: 'auto_update_enabled', expected: 'true', severity: 'medium', description: 'Automatische Updates müssen aktiviert sein' },
      { key: 'antivirus_enabled', expected: 'true', severity: 'high', description: 'Antivirenschutz erforderlich' },
    ],
    macos: [
      { key: 'filevault_enabled', expected: 'true', severity: 'high', description: 'FileVault-Verschlüsselung erforderlich' },
      { key: 'firewall_enabled', expected: 'true', severity: 'high', description: 'macOS Firewall muss aktiviert sein' },
      { key: 'screen_lock_enabled', expected: 'true', severity: 'medium', description: 'Bildschirmsperre erforderlich' },
      { key: 'gatekeeper_enabled', expected: 'true', severity: 'high', description: 'Gatekeeper muss aktiviert sein' },
    ],
    linux: [
      { key: 'firewall_enabled', expected: 'true', severity: 'high', description: 'UFW/iptables Firewall erforderlich' },
      { key: 'full_disk_encryption', expected: 'true', severity: 'high', description: 'LUKS-Verschlüsselung empfohlen' },
      { key: 'auto_update_enabled', expected: 'true', severity: 'medium', description: 'Automatische Sicherheitsupdates erforderlich' },
    ],
  };

  const rules = RULES[platform.toLowerCase()] || [];
  const passing = [];
  const failing = [];

  for (const rule of rules) {
    if (settings[rule.key] === rule.expected) {
      passing.push(rule);
    } else {
      failing.push({ ...rule, actual: settings[rule.key] ?? 'not_reported' });
    }
  }

  const score = rules.length > 0 ? Math.round((passing.length / rules.length) * 100) : 100;
  const compliant = failing.filter(f => f.severity === 'high').length === 0;

  // Update device compliance status in DB
  if (db.isAvailable()) {
    await db.query(
      'UPDATE enrolled_devices SET compliance_status=$2, data=data||$3 WHERE id=$1',
      [deviceId, compliant ? 'compliant' : 'non_compliant', JSON.stringify({ complianceScore: score, lastCheck: new Date().toISOString() })]
    ).catch(() => {});
  }

  // Auto-queue remediation if non-compliant
  if (!compliant) {
    if (!mdmCommands.has(deviceId)) mdmCommands.set(deviceId, []);
    const queue = mdmCommands.get(deviceId);
    if (!queue.find(c => c.command === 'update_policy' && c.status === 'pending')) {
      queue.push({ id: uuidv4(), command: 'update_policy', payload: { failingRules: failing, score }, issuedAt: new Date().toISOString(), status: 'pending' });
    }
  }

  res.json({ deviceId, platform, score, compliant, passing: passing.length, failing, total: rules.length });
});

// ─── Enrollment Token API ─────────────────────────────────────────────────────────

const PLATFORMS = ['windows', 'macos', 'linux', 'ios', 'android'];

PLATFORMS.forEach(p => {
  const token = `${p[0].toUpperCase()}E-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  enrollmentTokens.set(p, { platform: p, token, created: new Date().toISOString().split('T')[0], expires: new Date(Date.now() + 30 * 86400_000).toISOString().split('T')[0], uses: 0, maxUses: p === 'linux' ? 100 : p === 'windows' || p === 'macos' ? 50 : 25, devices: new Map() });
});

app.get('/api/enrollment/tokens', (req, res) => {
  res.json([...enrollmentTokens.values()].map(({ devices: _, ...t }) => t));
});

app.post('/api/enrollment/tokens/:platform/rotate', (req, res) => {
  const { platform } = req.params;
  if (!PLATFORMS.includes(platform)) return res.status(400).json({ error: 'unknown platform' });
  const existing = enrollmentTokens.get(platform);
  const newToken = `${platform[0].toUpperCase()}E-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  enrollmentTokens.set(platform, { ...existing, token: newToken, uses: 0, created: new Date().toISOString().split('T')[0] });
  const { devices: _, ...t } = enrollmentTokens.get(platform);
  res.json(t);
});

app.post('/api/enrollment/register', (req, res) => {
  const { token, platform, hostname, os, serial } = req.body;
  const record = [...enrollmentTokens.values()].find(t => t.token === token && t.platform === platform);
  if (!record) return res.status(401).json({ error: 'invalid token' });
  if (record.uses >= record.maxUses) return res.status(429).json({ error: 'token exhausted' });
  record.uses += 1;
  const deviceId = uuidv4();
  const deviceToken = signToken({ sub: deviceId, platform, hostname, serial, iss: ISSUER }, '365d');
  if (db.isAvailable()) {
    db.upsertDevice({ id: deviceId, enrollmentToken: token, hostname, platform, os: req.body.os, ip: req.ip, status: 'active' }).catch(err => console.error('[device-db]', err.message));
  }
  res.status(201).json({ deviceId, deviceToken, serverUrl: ISSUER, message: `Device enrolled successfully as ${hostname} (${platform})` });
});

// ─── Phase 2: Enrollment Script Generation ────────────────────────────────────────

app.get('/api/enroll/macos/profile.mobileconfig', (req, res) => {
  const token = req.query.token ?? 'REPLACE_WITH_TOKEN';
  const profileUUID = uuidv4().toUpperCase();
  const mdmUUID     = uuidv4().toUpperCase();
  const caUUID      = uuidv4().toUpperCase();
  res.set('Content-Type', 'application/x-apple-aspen-config');
  res.set('Content-Disposition', 'attachment; filename="opendirectory-enroll.mobileconfig"');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.mdm</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>local.opendirectory.mdm</string>
      <key>PayloadUUID</key>
      <string>${mdmUUID}</string>
      <key>PayloadDisplayName</key>
      <string>OpenDirectory MDM</string>
      <key>ServerURL</key>
      <string>${ISSUER}/mdm</string>
      <key>CheckInURL</key>
      <string>${ISSUER}/mdm/checkin</string>
      <key>CheckOutWhenRemoved</key>
      <true/>
      <key>Topic</key>
      <string>com.apple.mgmt.External.opendirectory</string>
      <key>EnrollmentToken</key>
      <string>${token}</string>
      <key>AccessRights</key>
      <integer>8191</integer>
      <key>SignMessage</key>
      <true/>
    </dict>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>local.opendirectory.ca</string>
      <key>PayloadUUID</key>
      <string>${caUUID}</string>
      <key>PayloadDisplayName</key>
      <string>OpenDirectory Root CA</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>OpenDirectory Enrollment</string>
  <key>PayloadIdentifier</key>
  <string>local.opendirectory.enrollment</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${profileUUID}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`);
});

app.get('/api/enroll/windows/agent.ps1', (req, res) => {
  const token = req.query.token ?? 'REPLACE_WITH_TOKEN';
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="opendirectory-enroll.ps1"');
  res.send(`#Requires -RunAsAdministrator
<#
.SYNOPSIS
  OpenDirectory Windows Enrollment Script
.DESCRIPTION
  Downloads and installs the OpenDirectory agent, registers with server.
#>

$ErrorActionPreference = "Stop"
$AgentUrl    = "${ISSUER}/downloads/od-agent-windows-amd64.msi"
$ServerUrl   = "${ISSUER}"
$EnrollToken = "${token}"

Write-Host "[OpenDirectory] Starting enrollment..." -ForegroundColor Cyan

# Set enrollment token as machine environment variable
[System.Environment]::SetEnvironmentVariable("OD_ENROLLMENT_TOKEN", $EnrollToken, [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable("OD_SERVER_URL", $ServerUrl, [System.EnvironmentVariableTarget]::Machine)

# Download agent installer
$TempMsi = "$env:TEMP\\od-agent.msi"
Write-Host "[OpenDirectory] Downloading agent from $AgentUrl..."
Invoke-WebRequest -Uri $AgentUrl -OutFile $TempMsi -UseBasicParsing

# Install agent silently
Write-Host "[OpenDirectory] Installing agent..."
Start-Process msiexec.exe -ArgumentList "/i $TempMsi /quiet /norestart SERVERURL=$ServerUrl TOKEN=$EnrollToken" -Wait -NoNewWindow

# Enable and start service
Write-Host "[OpenDirectory] Enabling service..."
Set-Service -Name "OpenDirectoryAgent" -StartupType Automatic
Start-Service -Name "OpenDirectoryAgent"

# Trigger enrollment
Write-Host "[OpenDirectory] Registering device..."
$Body = @{ token=$EnrollToken; platform="windows"; hostname=$env:COMPUTERNAME; os=[System.Environment]::OSVersion.VersionString; serial=(Get-WmiObject Win32_BIOS).SerialNumber } | ConvertTo-Json
Invoke-RestMethod -Uri "$ServerUrl/api/enrollment/register" -Method POST -Body $Body -ContentType "application/json"

Write-Host "[OpenDirectory] Enrollment complete!" -ForegroundColor Green
`);
});

app.get('/api/enroll/linux/install.sh', (req, res) => {
  const token = req.query.token ?? 'REPLACE_WITH_TOKEN';
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="od-install.sh"');
  res.send(`#!/usr/bin/env bash
# OpenDirectory Linux Enrollment Script
set -euo pipefail

SERVER_URL="${ISSUER}"
ENROLL_TOKEN="${token}"
AGENT_VERSION="1.0.0"

log() { echo "[OpenDirectory] \$*"; }
die() { echo "[ERROR] \$*" >&2; exit 1; }

log "Detecting distribution..."
if command -v apt-get &>/dev/null; then
  PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
  PKG_MGR="pacman"
else
  die "Unsupported package manager"
fi

log "Package manager: \$PKG_MGR"

# Download agent binary
log "Downloading OpenDirectory agent..."
curl -fsSL "\$SERVER_URL/downloads/od-agent-linux-amd64" -o /tmp/od-agent
chmod +x /tmp/od-agent
mv /tmp/od-agent /usr/local/bin/od-agent

# Write config
mkdir -p /etc/opendirectory
cat > /etc/opendirectory/agent.conf <<EOF
server_url=\$SERVER_URL
enrollment_token=\$ENROLL_TOKEN
EOF
chmod 600 /etc/opendirectory/agent.conf

# Create systemd service
cat > /etc/systemd/system/od-agent.service <<'SVCEOF'
[Unit]
Description=OpenDirectory Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/opendirectory/agent.conf
ExecStart=/usr/local/bin/od-agent --config /etc/opendirectory/agent.conf
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable od-agent
systemctl start od-agent

# Trigger enrollment
log "Registering device with server..."
curl -fsSL -X POST "\$SERVER_URL/api/enrollment/register" \\
  -H "Content-Type: application/json" \\
  -d "{\"token\":\"\$ENROLL_TOKEN\",\"platform\":\"linux\",\"hostname\":\"\$(hostname)\",\"os\":\"\$(uname -r)\"}"

log "Enrollment complete!"
`);
});

app.get('/api/enroll/ios/profile.mobileconfig', (req, res) => {
  const token = req.query.token ?? 'REPLACE_WITH_TOKEN';
  const profileUUID = uuidv4().toUpperCase();
  const mdmUUID     = uuidv4().toUpperCase();
  res.set('Content-Type', 'application/x-apple-aspen-config');
  res.set('Content-Disposition', 'attachment; filename="opendirectory-ios-enroll.mobileconfig"');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.mdm</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>local.opendirectory.ios.mdm</string>
      <key>PayloadUUID</key>
      <string>${mdmUUID}</string>
      <key>PayloadDisplayName</key>
      <string>OpenDirectory iOS MDM</string>
      <key>ServerURL</key>
      <string>${ISSUER}/mdm</string>
      <key>CheckInURL</key>
      <string>${ISSUER}/mdm/checkin</string>
      <key>Topic</key>
      <string>com.apple.mgmt.External.opendirectory.ios</string>
      <key>EnrollmentToken</key>
      <string>${token}</string>
      <key>APNSCertificate</key>
      <string>BASE64_ENCODED_APNS_CERT_HERE</string>
      <key>AccessRights</key>
      <integer>8191</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>OpenDirectory iOS Enrollment</string>
  <key>PayloadIdentifier</key>
  <string>local.opendirectory.ios.enrollment</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${profileUUID}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`);
});

// ─── Device Heartbeat ─────────────────────────────────────────────────────────────

app.post('/api/devices/:id/heartbeat', (req, res) => {
  const { id } = req.params;
  // Update last_seen across enrollment token records
  for (const rec of enrollmentTokens.values()) {
    if (rec.devices && rec.devices.has(id)) {
      rec.devices.get(id).last_seen = new Date().toISOString();
    }
  }
  res.json({ ok: true, deviceId: id, last_seen: new Date().toISOString(), policySync: { required: false, version: '1.0.0' } });
});

// ─── SCIM Push Log ────────────────────────────────────────────────────────────────

app.get('/api/scim-push/log', (req, res) => {
  res.json(scimPushLog.slice(-50));
});

// ─── Update Rings ─────────────────────────────────────────────────────────────────

app.get('/api/update-rings', (req, res) => {
  res.json([...updateRings.values()]);
});

app.put('/api/update-rings/:id', (req, res) => {
  const ring = updateRings.get(req.params.id);
  if (!ring) return res.status(404).json({ error: 'Ring not found' });
  const { deferralDays, description } = req.body;
  if (deferralDays) {
    if (typeof deferralDays.windows === 'number') ring.deferralDays.windows = deferralDays.windows;
    if (typeof deferralDays.macos === 'number') ring.deferralDays.macos = deferralDays.macos;
    if (typeof deferralDays.linux === 'number') ring.deferralDays.linux = deferralDays.linux;
  }
  if (description) ring.description = description;
  updateRings.set(req.params.id, ring);
  res.json(ring);
});

app.post('/api/update-rings/:id/assign', (req, res) => {
  const ring = updateRings.get(req.params.id);
  if (!ring) return res.status(404).json({ error: 'Ring not found' });
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });
  if (!ring.assignedDevices.includes(deviceId)) {
    ring.assignedDevices.push(deviceId);
    ring.deviceCount = ring.assignedDevices.length;
  }
  updateRings.set(req.params.id, ring);
  res.json({ ringId: req.params.id, deviceId, assignedDevices: ring.assignedDevices });
});

// ─── Phase 5: App Catalog ─────────────────────────────────────────────────────────

app.get('/api/app-catalog', (req, res) => {
  res.json(APP_CATALOG);
});

app.post('/api/scim-push/:appId/provision', (req, res) => {
  const { appId } = req.params;
  const { userId, action } = req.body;
  if (!['create', 'update', 'deactivate'].includes(action)) return res.status(400).json({ error: 'invalid action' });
  res.json({ success: true, appId, userId, action, timestamp: new Date().toISOString() });
});

// ─── App Deployment Repository ───────────────────────────────────────────────

const appPackages = new Map([
  ['chrome-latest', { id: 'chrome-latest', name: 'Google Chrome', version: 'latest', platform: 'windows', type: 'msi', downloadUrl: 'https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi', silent: '/quiet /norestart', checkCommand: 'reg query "HKLM\\SOFTWARE\\Google\\Chrome"', checkValue: 'version' }],
  ['firefox-esr', { id: 'firefox-esr', name: 'Mozilla Firefox ESR', version: '115', platform: 'windows', type: 'msi', downloadUrl: 'https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=win64&lang=de', silent: '/S', checkCommand: 'reg query "HKLM\\SOFTWARE\\Mozilla\\Mozilla Firefox ESR"' }],
  ['vscode', { id: 'vscode', name: 'Visual Studio Code', version: 'latest', platform: 'windows', type: 'exe', downloadUrl: 'https://update.code.visualstudio.com/latest/win32-x64-user/stable', silent: '/VERYSILENT /MERGETASKS=!runcode' }],
  ['chrome-mac', { id: 'chrome-mac', name: 'Google Chrome', version: 'latest', platform: 'macos', type: 'dmg', downloadUrl: 'https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg' }],
  ['homebrew', { id: 'homebrew', name: 'Homebrew Package Manager', version: 'latest', platform: 'macos', type: 'script', installScript: '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' }],
]);

app.get('/api/packages', (req, res) => {
  const platform = req.query.platform;
  const packages = [...appPackages.values()];
  res.json(platform ? packages.filter(p => p.platform === platform || p.platform === 'all') : packages);
});

app.get('/api/packages/:id', (req, res) => {
  const pkg = appPackages.get(req.params.id);
  if (!pkg) return res.status(404).json({ error: 'Package not found' });
  res.json(pkg);
});

app.post('/api/packages', (req, res) => {
  const { name, version, platform, type, downloadUrl, silent, installScript } = req.body;
  if (!name || !platform) return res.status(400).json({ error: 'name and platform required' });
  const id = `pkg-${uuidv4().slice(0, 8)}`;
  const pkg = { id, name, version: version || 'latest', platform, type: type || 'script', downloadUrl, silent, installScript, addedAt: new Date().toISOString() };
  appPackages.set(id, pkg);
  res.status(201).json(pkg);
});

// Deploy package to a device
app.post('/api/packages/:pkgId/deploy/:deviceId', (req, res) => {
  const pkg = appPackages.get(req.params.pkgId);
  if (!pkg) return res.status(404).json({ error: 'Package not found' });

  const queue = mdmCommands.get(req.params.deviceId) || [];
  const cmd = { id: uuidv4(), command: 'install_app', payload: { packageId: pkg.id, name: pkg.name, version: pkg.version, downloadUrl: pkg.downloadUrl, silent: pkg.silent, installScript: pkg.installScript, type: pkg.type }, issuedAt: new Date().toISOString(), status: 'pending' };
  queue.push(cmd);
  mdmCommands.set(req.params.deviceId, queue);

  // Persist to DB
  if (db.isAvailable()) {
    db.query('INSERT INTO mdm_commands(id,device_id,command,payload,status) VALUES($1,$2,$3,$4,$5)', [cmd.id, req.params.deviceId, 'install_app', JSON.stringify(cmd.payload), 'pending']).catch(() => {});
  }

  res.status(201).json({ commandId: cmd.id, deviceId: req.params.deviceId, package: pkg.name });
});

// Bulk deploy to all devices by platform
app.post('/api/packages/:pkgId/deploy-all', (req, res) => {
  const pkg = appPackages.get(req.params.pkgId);
  if (!pkg) return res.status(404).json({ error: 'Package not found' });

  const targetDevices = [...deviceRegistry.values()].filter(d => d.platform === pkg.platform || pkg.platform === 'all');
  const commands = [];

  for (const device of targetDevices) {
    const cmd = { id: uuidv4(), command: 'install_app', payload: { packageId: pkg.id, name: pkg.name, downloadUrl: pkg.downloadUrl, silent: pkg.silent }, issuedAt: new Date().toISOString(), status: 'pending' };
    const queue = mdmCommands.get(device.id) || [];
    queue.push(cmd);
    mdmCommands.set(device.id, queue);
    commands.push({ deviceId: device.id, hostname: device.hostname, commandId: cmd.id });
  }

  res.json({ package: pkg.name, devicesTargeted: targetDevices.length, commands });
});

// ─── Health ───────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'oauth-provider', issuer: ISSUER, clients: clients.size, algorithm: 'RS256' });
});

// ─── Seed Default Update Rings (DB) ──────────────────────────────────────────────

async function seedDefaultUpdateRings() {
  try {
    const existing = await db.query('SELECT COUNT(*) FROM update_rings');
    if (existing.rows[0].count === '0') {
      const rings = [
        { id: 'ring-canary', name: 'Canary', description: 'Early adopters', delay_days: 0, rollout_percent: 5 },
        { id: 'ring-preview', name: 'Preview', description: 'IT team', delay_days: 3, rollout_percent: 20 },
        { id: 'ring-broad', name: 'Broad', description: 'General rollout', delay_days: 7, rollout_percent: 100 },
      ];
      for (const r of rings) {
        await db.query(
          'INSERT INTO update_rings(id,name,description,delay_days,rollout_percent) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING',
          [r.id, r.name, r.description, r.delay_days, r.rollout_percent]
        );
      }
    }
  } catch (err) {
    console.warn('[DB] Could not seed update rings:', err.message);
  }
}

// ─── Agent binary downloads ───────────────────────────────────────────────────────

const fs   = require('fs');
const path = require('path');

const AGENT_DIST = process.env.AGENT_DIST_PATH ||
  path.join(__dirname, '..', '..', '..', '..', 'agent', 'dist');

app.get('/downloads', (req, res) => {
  if (!fs.existsSync(AGENT_DIST)) {
    return res.json({ binaries: [], note: 'Agent not built yet. Run: cd agent && make all' });
  }
  const files = fs.readdirSync(AGENT_DIST)
    .filter(f => !f.startsWith('.'))
    .map(f => ({
      filename: f,
      url: `${ISSUER}/downloads/${f}`,
      size: fs.statSync(path.join(AGENT_DIST, f)).size,
    }));
  res.json({ binaries: files });
});

app.get('/downloads/:filename', (req, res) => {
  const safeName = path.basename(req.params.filename);
  const filePath = path.join(AGENT_DIST, safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      error: 'Binary not available.',
      hint: 'Build the agent first: cd agent && make all',
    });
  }
  res.download(filePath, safeName);
});

// ─── Start ────────────────────────────────────────────────────────────────────────

db.initDb().then(async () => {
  initRedis().catch(err => console.warn('[redis] init error:', err.message));
  if (db.isAvailable()) {
    try {
      const existing = await db.query('SELECT COUNT(*) FROM oauth_clients');
      if (existing.rows[0].count === '0') {
        for (const [, client] of clients.entries()) {
          await db.upsertClient({ id: client.clientId, name: client.name, clientSecret: client.clientSecret, redirectUris: client.redirectUris, grants: client.grantTypes, scopes: client.scopes });
        }
        console.log('[db] Seeded initial OAuth clients');
      }
    } catch (err) {
      console.warn('[db] Could not seed clients:', err.message);
    }

    try {
      const devCount = await db.query('SELECT COUNT(*) FROM enrolled_devices');
      if (devCount.rows[0].count === '0') {
        for (const [, device] of deviceRegistry.entries()) {
          await db.upsertDevice(device).catch(() => {});
        }
        console.log('[db] Seeded demo devices to enrolled_devices');
      }
    } catch (err) {
      console.warn('[db] Could not seed devices:', err.message);
    }
  }
  app.listen(PORT, () => {
    console.log(`[oauth-provider] listening on :${PORT}`);
    // Seed default update rings if DB available
    if (db.isAvailable()) {
      seedDefaultUpdateRings();
    }
  });
}).catch(err => {
  console.error('[oauth-provider] startup error:', err.message);
  process.exit(1);
});

module.exports = app;
