'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// ─── Config ──────────────────────────────────────────────────────────────────────

const PORT      = process.env.OAUTH_PROVIDER_PORT ?? 3010;
const ISSUER    = process.env.OAUTH_ISSUER ?? 'https://opendirectory.local';
const JWT_SECRET = process.env.JWT_SECRET ?? crypto.randomBytes(64).toString('hex');
const TOKEN_TTL  = parseInt(process.env.TOKEN_TTL_SECONDS ?? '3600', 10);

// In-memory stores (replace with PostgreSQL/Redis in production)
const clients    = new Map(); // clientId → ClientRecord
const authCodes  = new Map(); // code → CodeRecord
const tokens     = new Map(); // tokenHash → TokenRecord

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

// ─── App ──────────────────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 60_000, max: 200 }));

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
    scopes_supported:                      ['openid', 'profile', 'email', 'groups', 'offline_access'],
    response_types_supported:              ['code', 'token', 'id_token'],
    grant_types_supported:                 ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'HS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    claims_supported:                      ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email', 'groups', 'preferred_username'],
    code_challenge_methods_supported:      ['S256', 'plain'],
  });
});

// Minimal JWKS (public key set — in prod, use RSA key pair from Vault/secrets)
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [] }); // In prod: expose public RSA JWK
});

// ─── Authorization Endpoint ──────────────────────────────────────────────────────

app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

  const client = clients.get(client_id);
  if (!client) return res.status(400).json({ error: 'invalid_client' });
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).json({ error: 'invalid_redirect_uri' });

  // In production: show login page → user authenticates → issue code
  // For now: issue code immediately (demo mode — requires auth middleware in prod)
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
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token } = req.body;

  // Client authentication
  const client = clients.get(client_id);
  if (!client || client.clientSecret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
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
      exp:   Math.floor(Date.now() / 1000) + TOKEN_TTL,
      name:  'Demo User',
      email: 'demo@opendirectory.local',
      preferred_username: 'demo',
      groups: ['users', 'developers'],
      scope: record.scope,
    };

    const access_token = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
    const id_token     = jwt.sign({ ...payload, nonce: uuidv4() }, JWT_SECRET, { algorithm: 'HS256' });
    const rt           = uuidv4();

    tokens.set(crypto.createHash('sha256').update(access_token).digest('hex'), { ...payload, type: 'access' });
    tokens.set(crypto.createHash('sha256').update(rt).digest('hex'), { ...payload, type: 'refresh' });

    return res.json({
      access_token,
      id_token,
      refresh_token: rt,
      token_type:    'Bearer',
      expires_in:    TOKEN_TTL,
      scope:         record.scope,
    });
  }

  if (grant_type === 'client_credentials') {
    const payload = {
      sub:  client_id,
      iss:  ISSUER,
      aud:  client_id,
      iat:  Math.floor(Date.now() / 1000),
      exp:  Math.floor(Date.now() / 1000) + TOKEN_TTL,
      scope: req.body.scope ?? '',
    };
    const access_token = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
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
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({
      sub:                payload.sub,
      name:               payload.name,
      email:              payload.email,
      preferred_username: payload.preferred_username,
      groups:             payload.groups ?? [],
    });
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// ─── Token Introspection ─────────────────────────────────────────────────────────

app.post('/oauth/introspect', (req, res) => {
  const { token, client_id, client_secret } = req.body;
  const client = clients.get(client_id);
  if (!client || client.clientSecret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
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

// ─── SAML Metadata ────────────────────────────────────────────────────────────────

app.get('/saml/metadata', (req, res) => {
  res.set('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="${ISSUER}">
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

// ─── OAuth2 Client Management API ────────────────────────────────────────────────

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

// ─── Enrollment Token API ─────────────────────────────────────────────────────────

const enrollmentTokens = new Map();

const PLATFORMS = ['windows', 'macos', 'linux', 'ios', 'android'];

// Pre-seed tokens
PLATFORMS.forEach(p => {
  const token = `${p[0].toUpperCase()}E-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  enrollmentTokens.set(p, {
    platform: p,
    token,
    created:  new Date().toISOString().split('T')[0],
    expires:  new Date(Date.now() + 30 * 86400_000).toISOString().split('T')[0],
    uses:     0,
    maxUses:  p === 'linux' ? 100 : p === 'windows' || p === 'macos' ? 50 : 25,
  });
});

app.get('/api/enrollment/tokens', (req, res) => {
  res.json([...enrollmentTokens.values()]);
});

app.post('/api/enrollment/tokens/:platform/rotate', (req, res) => {
  const { platform } = req.params;
  if (!PLATFORMS.includes(platform)) return res.status(400).json({ error: 'unknown platform' });
  const existing = enrollmentTokens.get(platform);
  const newToken = `${platform[0].toUpperCase()}E-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  enrollmentTokens.set(platform, { ...existing, token: newToken, uses: 0, created: new Date().toISOString().split('T')[0] });
  res.json(enrollmentTokens.get(platform));
});

// Enrollment registration endpoint (called by agents on new devices)
app.post('/api/enrollment/register', (req, res) => {
  const { token, platform, hostname, os, serial } = req.body;
  const record = [...enrollmentTokens.values()].find(t => t.token === token && t.platform === platform);
  if (!record) return res.status(401).json({ error: 'invalid token' });
  if (record.uses >= record.maxUses) return res.status(429).json({ error: 'token exhausted' });

  record.uses += 1;

  // In production: create device record in DB, issue device certificate
  const deviceId = uuidv4();
  const deviceToken = jwt.sign(
    { sub: deviceId, platform, hostname, serial, iss: ISSUER },
    JWT_SECRET,
    { expiresIn: '365d' },
  );

  res.status(201).json({
    deviceId,
    deviceToken,
    serverUrl: ISSUER,
    message: `Device enrolled successfully as ${hostname} (${platform})`,
  });
});

// ─── Health ───────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'oauth-provider', issuer: ISSUER, clients: clients.size });
});

// ─── Start ────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[OpenDirectory OAuth2/OIDC Provider] Listening on port ${PORT}`);
  console.log(`  Issuer:    ${ISSUER}`);
  console.log(`  Discovery: ${ISSUER}/.well-known/openid-configuration`);
  console.log(`  Clients:   ${clients.size} pre-configured`);
  console.log(`  Mode:      ${process.env.NODE_ENV ?? 'development'}`);
});

module.exports = app;
