'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

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
].forEach(c => clients.set(c.clientId, c));

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
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

  const client = clients.get(client_id);
  if (!client) return res.status(400).json({ error: 'invalid_client' });
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).json({ error: 'invalid_redirect_uri' });

  const code = uuidv4();
  authCodes.set(code, {
    clientId:   client_id,
    redirectUri: redirect_uri,
    scope:       scope ?? 'openid profile email',
    userId:     'demo-user',
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    expiresAt:  Date.now() + 60_000,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

// ─── Token Endpoint ───────────────────────────────────────────────────────────────

app.post('/oauth/token', (req, res) => {
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

    const payload = {
      sub:   record.userId,
      iss:   ISSUER,
      aud:   client_id,
      iat:   Math.floor(Date.now() / 1000),
      name:  'Demo User',
      email: 'demo@opendirectory.local',
      preferred_username: 'demo',
      groups: ['users', 'developers'],
      scope: record.scope,
    };

    const access_token = signToken(payload);
    const id_token     = signToken({ ...payload, nonce: uuidv4() });
    const rt           = uuidv4();

    tokens.set(crypto.createHash('sha256').update(access_token).digest('hex'), { ...payload, type: 'access' });
    tokens.set(crypto.createHash('sha256').update(rt).digest('hex'), { ...payload, type: 'refresh' });

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
    tokens.set(crypto.createHash('sha256').update(access_token).digest('hex'), { ...payload, type: 'access' });
    tokens.set(crypto.createHash('sha256').update(new_rt).digest('hex'), { ...payload, type: 'refresh' });
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

app.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'invalid_token' });
  try {
    const payload = verifyToken(token);
    return res.json({ sub: payload.sub, name: payload.name, email: payload.email, preferred_username: payload.preferred_username, groups: payload.groups ?? [] });
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// ─── Token Introspection ─────────────────────────────────────────────────────────

app.post('/oauth/introspect', (req, res) => {
  const { token, client_id, client_secret } = req.body;
  const client = clients.get(client_id);
  if (!client || client.clientSecret !== client_secret) return res.status(401).json({ error: 'invalid_client' });
  try {
    const payload = verifyToken(token);
    return res.json({ active: true, ...payload });
  } catch {
    return res.json({ active: false });
  }
});

// ─── Token Revocation ────────────────────────────────────────────────────────────

app.post('/oauth/revoke', (req, res) => {
  const { token } = req.body;
  const hash = crypto.createHash('sha256').update(token ?? '').digest('hex');
  tokens.delete(hash);
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
  const { user_code } = req.query;
  res.set('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Device Authorization — OpenDirectory</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:24px;background:#f9fafb;}
h1{font-size:1.5rem;font-weight:700;color:#1e293b;}
input{width:100%;padding:10px;border:1px solid #d1d5db;border-radius:8px;font-size:1.1rem;letter-spacing:4px;text-align:center;margin:12px 0;}
button{width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer;}
button:hover{background:#1d4ed8;}.msg{margin-top:16px;padding:12px;border-radius:8px;}
</style></head>
<body>
<h1>Device Authorization</h1>
<p>Enter the code displayed on your device to authorize access.</p>
<form method="POST" action="/oauth/device/approve">
  <input name="user_code" type="text" placeholder="XXXX-XXXX" value="${user_code ?? ''}" maxlength="9"/>
  <button type="submit">Authorize Device</button>
</form>
</body></html>`);
});

app.post('/oauth/device/approve', express.urlencoded({ extended: true }), (req, res) => {
  const { user_code } = req.body;
  let found = null;
  for (const [dc, rec] of deviceCodes.entries()) {
    if (rec.user_code === user_code && rec.expiresAt > Date.now()) { found = [dc, rec]; break; }
  }
  if (!found) return res.send('<html><body><p>Invalid or expired code.</p></body></html>');
  found[1].approved = true;
  found[1].userId = 'demo-user';
  res.send('<html><body><h2 style="font-family:system-ui;color:#16a34a;">Device authorized! You may close this window.</h2></body></html>');
});

// ─── SAML Metadata ────────────────────────────────────────────────────────────────

app.get('/saml/metadata', (req, res) => {
  res.set('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${ISSUER}">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
                    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
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

app.get('/api/clients', (req, res) => {
  const list = [...clients.values()].map(({ clientSecret: _, ...c }) => c);
  res.json(list);
});

app.post('/api/clients', (req, res) => {
  const { name, redirectUris, scopes, grantTypes } = req.body;
  if (!name || !redirectUris?.length) return res.status(400).json({ error: 'name and redirectUris required' });
  const clientId     = `${name.toLowerCase().replace(/\s+/g, '-')}-${uuidv4().slice(0, 8)}`;
  const clientSecret = crypto.randomBytes(32).toString('hex');
  const record = { clientId, clientSecret, name, redirectUris, scopes: scopes ?? ['openid', 'profile', 'email'], grantTypes: grantTypes ?? ['authorization_code'] };
  clients.set(clientId, record);
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
  if (!scimUsers.has(req.params.id)) return res.status(404).json({ status: 404, detail: 'User not found' });
  const user = { id: req.params.id, userName: req.body.userName, displayName: req.body.displayName, emails: req.body.emails ?? [], active: req.body.active !== false, groups: req.body.groups ?? [] };
  scimUsers.set(req.params.id, user);
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
  if (!scimGroups.has(req.params.id)) return res.status(404).json({ status: 404, detail: 'Group not found' });
  const group = { id: req.params.id, displayName: req.body.displayName, members: req.body.members ?? [] };
  scimGroups.set(req.params.id, group);
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
    } else if (daysSinceLastSeen > 30) {
      device.status = 'flagged';
      flagged++;
    }
  }
  console.log(`[device-quarantine] flagged=${flagged} quarantined=${quarantined}`);
}, 30_000);

app.get('/api/devices/registry', (req, res) => {
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

// ─── Phase 5: App Catalog ─────────────────────────────────────────────────────────

const { APP_CATALOG } = require('./appCatalog');

app.get('/api/app-catalog', (req, res) => {
  res.json(APP_CATALOG);
});

app.post('/api/scim-push/:appId/provision', (req, res) => {
  const { appId } = req.params;
  const { userId, action } = req.body;
  if (!['create', 'update', 'deactivate'].includes(action)) return res.status(400).json({ error: 'invalid action' });
  res.json({ success: true, appId, userId, action, timestamp: new Date().toISOString() });
});

// ─── Health ───────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'oauth-provider', issuer: ISSUER, clients: clients.size, algorithm: 'RS256' });
});

// ─── Start ────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[OpenDirectory OAuth2/OIDC Provider] Listening on port ${PORT}`);
  console.log(`  Issuer:    ${ISSUER}`);
  console.log(`  Discovery: ${ISSUER}/.well-known/openid-configuration`);
  console.log(`  JWKS:      ${ISSUER}/.well-known/jwks.json`);
  console.log(`  Algorithm: RS256 (RSA-2048)`);
  console.log(`  Clients:   ${clients.size} pre-configured`);
});

module.exports = app;
