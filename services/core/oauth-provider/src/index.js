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
const { resolveScopes, userCanDelegateScopes, userAuthorizationClaims, workloadAuthorizationClaims, escapeHtml, validPkceRequest } = require('./oauthScopes');
const { authenticateUser } = require('./authenticateUser');
const { TokenRevocationStore } = require('./TokenRevocationStore');
const { SessionStore, viewer } = require('./SessionStore');
const { SigningKeys } = require('./SigningKeys');
const { IdentityAuthority, IdentityAuthorityError } = require('./IdentityAuthority');
const { CredentialAuthority } = require('./CredentialAuthority');
const { ClientRegistry, permissionsOf, publicClient, etag } = require('./ClientRegistry');
const { hashSecret } = require('./clientSecrets');
const { ApplicationAccess } = require('./ApplicationAccess');
const { MfaAuthority, MfaError } = require('./MfaAuthority');
const { MfaRecovery } = require('./MfaRecovery');
const { MfaEnrollment } = require('./MfaEnrollment');
const { acceptsAuthentication } = require('./applicationAuthentication');
const { sameContext } = require('../../../../packages/identity-authorization-contract');
const credentialContract = require('../../../../packages/credential-authorization-contract');
const { oidcAuth, configureJwks, requireAdmin } = require('./middleware/oidcAuth');
const { requirePolicyDeviceAccess, policyDeviceView } = require('./middleware/policyDeviceAccess');

// ─── Event Bus ───────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'oauth-provider' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }

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

const signedTokensCounter = new promClient.Counter({ name: 'oauth_tokens_signed_total', help: 'OAuth tokens signed, including attempts not committed to a session', registers: [register] });
const scimPushErrorsCounter = new promClient.Counter({ name: 'scim_push_errors_total', help: 'SCIM push failures', labelNames: ['app'], registers: [register] });
const enrolledDevicesGauge = new promClient.Gauge({ name: 'enrolled_devices_total', help: 'Total enrolled devices', labelNames: ['platform', 'status'], registers: [register] });

const revocations = new TokenRevocationStore(db, { demo: process.env.OAUTH_REVOCATION_DEMO_MODE === 'true' });
const sessions = new SessionStore(db, { demo: process.env.OAUTH_REVOCATION_DEMO_MODE === 'true' });

async function isTokenRevoked(tokenHash, payload) {
  return !await verifiedAccessState(tokenHash, payload);
}

async function verifiedAccessState(tokenHash, payload) {
  if (await revocations.revoked(tokenHash)) return false;
  const audience = process.env.OAUTH_API_AUDIENCE || 'opendirectory-api';
  const apiToken = payload?.aud === audience || (Array.isArray(payload?.aud) && payload.aud.includes(audience));
  if (!apiToken || !await clientRegistry.active(payload) || !await sessions.active(payload)) return false;
  const state = await identityAuthority.verifiedState(payload);
  if (!state || (payload.actor_type === 'user' && (!await mfaAuthority.matches(payload)
    || !await applicationAccess.matches(payload.client_id,state,payload.application_authorization)))) return false;
  return state;
}

// ─── Config ──────────────────────────────────────────────────────────────────────

const PORT    = process.env.OAUTH_PROVIDER_PORT ?? 3010;
const ISSUER  = process.env.OAUTH_ISSUER ?? 'https://opendirectory.local';
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL_SECONDS ?? '3600', 10);

// ─── RSA Key Pair (RS256) ─────────────────────────────────────────────────────

const signingKeys = new SigningKeys();
const privateKey = signingKeys.privateKey;
const signingKeyId = signingKeys.kid;
const credentialAuthority = new CredentialAuthority({ signingKeys, issuer: ISSUER });
const identityAuthority = new IdentityAuthority({ signingKeys, issuer: ISSUER, credentialAuthority, demo: process.env.OAUTH_REVOCATION_DEMO_MODE === 'true' });
const companyRegistration = new (require('./CompanyRegistrationGateway').CompanyRegistrationGateway)({ signingKeys, issuer: ISSUER, client: id => clientRegistry.get(id) });

// Build JWK representation of the public key
configureJwks(signingKeys.jwks());

// adminAuth            - requires a valid, non-revoked bearer JWT.
// adminAuthOrInternal  - same, but a request with NO Authorization header
//                        may instead present OAUTH_PROVIDER_INTERNAL_TOKEN
//                        via x-oauth-internal-token. Mounted ONLY on the
//                        two routes server-to-server callers
//                        (antivirus-protection, policy-service) hit without
//                        an admin JWT today: GET /api/devices/registry and
//                        POST /api/devices/:deviceId/commands.
const adminAuth = oidcAuth({ isTokenRevoked });
const adminAuthOrInternal = oidcAuth({ isTokenRevoked, allowInternalToken: true });
const deviceSelfAuth = oidcAuth({ isTokenRevoked, deviceSelf: true, isDeviceTokenRevoked: hash => revocations.revoked(hash) });

// ─── In-memory stores ─────────────────────────────────────────────────────────

const clientSeeds     = [];
const authCodes       = new Map(); // code → CodeRecord
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
    clientSecretHash: process.env.GRAFANA_CLIENT_SECRET ? hashSecret(process.env.GRAFANA_CLIENT_SECRET) : null,
    name:         'Grafana Dashboard',
    redirectUris: ['https://grafana.example.com/login/generic_oauth'],
    scopes:       ['openid', 'profile', 'email', 'groups'],
    grantTypes:   ['authorization_code', 'refresh_token', 'client_credentials'],
  },
  {
    clientId:     'devportal-od-client',
    clientSecretHash: process.env.DEVPORTAL_CLIENT_SECRET ? hashSecret(process.env.DEVPORTAL_CLIENT_SECRET) : null,
    name:         'Internal Dev Portal',
    redirectUris: ['https://dev.example.com/auth/callback', 'http://localhost:4000/callback'],
    scopes:       ['openid', 'profile', 'email', 'roles', 'sessions.self.read', 'sessions.self.revoke'],
    // Deliberately NOT client_credentials — this client is used to
    // regression-test grantTypes enforcement (an authorization_code/
    // refresh_token/device-flow client must not also be able to mint
    // tokens via client_credentials just by asserting a different
    // grant_type). See "grantTypes enforcement" describe block in
    // src/__tests__/api.e2e.test.js.
    grantTypes:   ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
  },
].forEach(c => {
  if (c.clientSecretHash) clientSeeds.push({ ...c, publicClient: false });
});

const { configuredWebClient, assertWebClient } = require('./webClient');
const webClient = configuredWebClient();
if (webClient) clientSeeds.push(webClient);
const clientRegistry = new ClientRegistry(db, { demo: process.env.OAUTH_REVOCATION_DEMO_MODE === 'true', seeds: clientSeeds,companyTenantActive:(id,tenant)=>identityAuthority.companyAppTenant(id,tenant) });
const applicationAccess = new ApplicationAccess(db, { identity: identityAuthority, demo: process.env.OAUTH_REVOCATION_DEMO_MODE === 'true' });
const mfaAuthority = new MfaAuthority(db, { demo: process.env.OAUTH_REVOCATION_DEMO_MODE === 'true' });
const mfaRecovery = new MfaRecovery({ mfa: mfaAuthority, identity: identityAuthority, issuer: ISSUER });
const mfaEnrollment = new MfaEnrollment({ mfa: mfaAuthority, clients: clientRegistry, identity: identityAuthority, applications: applicationAccess, issuer: ISSUER });

function protocol(handler, load = true) {
  return async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      if (load) req.oauthClient = await clientRegistry.get(req.method === 'GET' ? req.query.client_id : req.body.client_id);
      return await handler(req, res);
    } catch (error) { return res.status(error.status || 503).json({ error: error.code || 'client_authority_unavailable' }); }
  };
}

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
app.use('/oauth/access-state', rateLimit({ windowMs: 60_000, max: 5000 }));
app.use('/oauth/tenant-state', rateLimit({ windowMs: 60_000, max: 5000 }));
app.use(rateLimit({ windowMs: 60_000, max: 500, skip: req => req.method === 'GET' && ['/oauth/access-state','/oauth/tenant-state'].includes(req.path) }));
app.use('/oauth/company-registration', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.get('/oauth/company-registration', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_company_registration' });
  const activation = process.env.COMPANY_ACTIVATION_ENABLED === 'true' && !!process.env.COMPANY_CONSOLE_CLIENT_ID && process.env.OAUTH_REVOCATION_DEMO_MODE !== 'true';
  res.json({ schemaVersion: activation ? 2 : 1, enabled: process.env.COMPANY_REGISTRATION_ENABLED === 'true' && process.env.OAUTH_REVOCATION_DEMO_MODE !== 'true', requiresExistingAccount: true, activationSupported: activation, status: 'pending-verification' });
});
app.post('/oauth/company-registration/:operation', rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'company_registration_rate_limited' } }), async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (process.env.COMPANY_REGISTRATION_ENABLED !== 'true' || process.env.OAUTH_REVOCATION_DEMO_MODE === 'true') return res.status(503).json({ error: 'company_registration_disabled' });
  if (!['submit', 'status', 'activate'].includes(req.params.operation) || Object.keys(req.query).length) return res.status(400).json({ error: 'invalid_company_registration' });
  if (req.params.operation === 'activate' && process.env.COMPANY_ACTIVATION_ENABLED !== 'true') return res.status(503).json({ error: 'company_activation_disabled' });
  try { const receipt = await companyRegistration.execute(req.params.operation, req.body); res.status(req.params.operation === 'submit' && !receipt.replayed ? 201 : 200).json(receipt); }
  catch (error) { res.status(error.status || 503).json({ error: error.code || (error.status === 400 ? 'invalid_company_registration' : 'company_registration_unavailable') }); }
});

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
    device_authorization_endpoint:         `${ISSUER}/oauth/device/code`,
    scopes_supported:                      ['openid', 'profile', 'email', 'groups', 'roles', 'offline_access'],
    response_types_supported:              ['code'],
    grant_types_supported:                 ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    claims_supported:                      ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'amr', 'name', 'email', 'groups', 'roles', 'permissions', 'preferred_username'],
    code_challenge_methods_supported:      ['S256', 'plain'],
  });
});

// ─── JWKS Endpoint (RS256) ────────────────────────────────────────────────────

app.get('/.well-known/jwks.json', (req, res) => {
  res.json(signingKeys.jwks());
});

// ─── Helper: sign token with RS256 ───────────────────────────────────────────

function signToken(payload, expiresIn) {
  const tokenUse = payload.token_use || 'access';
  const audience = tokenUse === 'access' && typeof payload.aud === 'string' ? process.env.OAUTH_API_AUDIENCE || 'opendirectory-api' : payload.aud;
  const token = jwt.sign({ ...payload, token_use: tokenUse, aud: audience, ...(tokenUse === 'access' ? { client_id: payload.aud } : {}), jti: uuidv4() }, privateKey, { algorithm: 'RS256', keyid: signingKeyId, expiresIn: expiresIn ?? TOKEN_TTL });
  signedTokensCounter.inc();
  return token;
}

async function issueSession(payload, principalType, withRefresh = false, client) {
  const bound = { ...payload, client_revision: client.version, sid: uuidv4(), actor_type: principalType, ...(client.companyTenant?{company_tenant:client.companyTenant}:{}),auth_time: Number.isInteger(payload.auth_time) ? payload.auth_time : Math.floor(Date.now() / 1000) };
  const state = await identityAuthority.verifiedState(bound);
  if (!state) throw new IdentityAuthorityError(403, 'identity_not_eligible');
  if (principalType === 'user' && !await mfaAuthority.matches(bound)) throw new MfaError(400, 'invalid_grant');
  if (!acceptsAuthentication(client, bound)) throw new MfaError(400, 'invalid_grant');
  if (principalType === 'user' && !await applicationAccess.matches(client.clientId,state,bound.application_authorization)) throw new IdentityAuthorityError(400,'invalid_grant');
  if (!await clientRegistry.current(client)) throw new IdentityAuthorityError(400, 'invalid_grant');
  const accessToken = signToken(bound);
  const decoded = jwt.decode(accessToken);
  const expiry = withRefresh ? bound.auth_time * 1000 + 30 * 86400_000 : decoded.exp * 1000;
  const refreshToken = withRefresh ? crypto.randomBytes(32).toString('base64url') : undefined;
  await sessions.create({ id: bound.sid, issuer: ISSUER, subject: bound.sub, principalType, clientId: bound.aud, authTime: bound.auth_time, expiresAt: expiry },
    refreshToken ? { hash: crypto.createHash('sha256').update(refreshToken).digest('hex'), scope: bound.scope, authorization: bound, expiresAt: expiry } : undefined);
  if (db.isAvailable()) db.saveToken(crypto.createHash('sha256').update(accessToken).digest('hex'), decoded).catch(() => {});
  return { accessToken, refreshToken, payload: bound };
}

function verifyToken(token) {
  const payload = signingKeys.verify(token, { issuer: ISSUER, audience: process.env.OAUTH_API_AUDIENCE || 'opendirectory-api' });
  if (payload.token_use !== 'access') throw new Error('Only access tokens can authorize API calls');
  return payload;
}

// ─── Authorization Endpoint ──────────────────────────────────────────────────────

app.get('/oauth/authorize', protocol((req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, device_id, nonce } = req.query;

  const client = req.oauthClient;
  if (!client?.enabled) return res.status(400).send('<h2>Error: invalid_client</h2>');
  if (!client.grantTypes?.includes('authorization_code')) return res.status(400).json({ error: 'unauthorized_client' });
  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  if (typeof redirect_uri !== 'string' || !client.redirectUris.includes(redirect_uri)) return res.status(400).send('<h2>Error: invalid_redirect_uri</h2>');
  const approvedScope = resolveScopes(client, scope, ['openid', 'profile', 'email']);
  if (approvedScope === null) return res.status(400).json({ error: 'invalid_scope' });
  if (!validPkceRequest(client, code_challenge, code_challenge_method) || (nonce !== undefined && (typeof nonce !== 'string' || nonce.length > 255))) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  // Show login form
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
    <strong>${escapeHtml(client.name || client_id)}</strong>
  </div>
  ${federationLinks({ client_id, redirect_uri, response_type: 'code', scope: approvedScope, ...Object.fromEntries(Object.entries({ state, nonce, code_challenge, code_challenge_method, device_id }).filter(([, value]) => typeof value === 'string')) })}
  <form id="loginForm" method="POST" action="/oauth/authorize/login">
    <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
    <input type="hidden" name="scope" value="${escapeHtml(approvedScope)}">
    <input type="hidden" name="state" value="${escapeHtml(state)}">
    <input type="hidden" name="nonce" value="${escapeHtml(nonce)}">
    <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}">
    <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method)}">
    <input type="hidden" name="device_id" value="${escapeHtml(device_id)}">
    <label>Benutzername</label>
    <input type="text" name="username" autocomplete="username" required autofocus>
    <label>Passwort</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <label>Einmalcode des Passwortanbieters (falls dort aktiviert)</label>
    <input type="text" name="mfaCode" autocomplete="one-time-code" inputmode="numeric">
    <label>OpenDirectory-Einmalcode (falls eingerichtet)</label>
    <input type="text" name="otpCode" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6">
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
}));

function validateAuthorization(req, res, params) {
  const { redirect_uri, scope, code_challenge, code_challenge_method, nonce, state, device_id } = params;
  const client = req.oauthClient;
  const fail = (status, error) => { res.status(status).json({ error }); return null; };
  if (!client?.enabled) return fail(400, 'invalid_client');
  if (!client.grantTypes?.includes('authorization_code')) return fail(400, 'unauthorized_client');
  if (req.method === 'GET' && params.response_type !== 'code') return fail(400, 'unsupported_response_type');
  if (typeof redirect_uri !== 'string' || !client.redirectUris.includes(redirect_uri)) return fail(400, 'invalid_redirect_uri');
  const approvedScope = resolveScopes(client, scope, ['openid', 'profile', 'email']);
  if (approvedScope === null) return fail(400, 'invalid_scope');
  if (!validPkceRequest(client, code_challenge, code_challenge_method)
    || [nonce, state, device_id].some(value => value !== undefined && (typeof value !== 'string' || value.length > 255))) return fail(400, 'invalid_request');
  return approvedScope;
}

app.post('/oauth/authorize/login', protocol(async (req, res) => {
  if (validateAuthorization(req, res, req.body) === null) return;
  const { username, password, mfaCode } = req.body;
  const authentication = await authenticateUser({ username, password, mfaCode });
  if (authentication.error) return res.status(authentication.status).json({ error: authentication.error });
  return authorizeUser(req, res, req.oauthClient, authentication.user, 'pwd', authentication.credentialAuthentication);
}));

async function authorizeUser(req, res, client, authenticatedUser, primaryMethod = 'pwd', credentialAuthentication) {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, device_id, otpCode, nonce } = req.body;
  const approvedScope = resolveScopes(client, req.body.scope, ['openid', 'profile', 'email']);
  let userInfo = authenticatedUser;
  const userId = userInfo.id;
  if (!await clientRegistry.current(client)) return res.status(400).json({ error: 'unauthorized_client' });

  let identityContext; let credentialAuthorization; let applicationContext; let mfaContext;
  try {
    const state = await identityAuthority.state(userId);
    if (primaryMethod === 'pwd' && !credentialContract.matchesPasswordAuthentication(state, credentialAuthentication, userId)) {
      throw new MfaError(401, 'credential_authorization_changed');
    }
    identityContext = state.context;
    credentialAuthorization = state.credentialAuthorization;
    applicationContext = await applicationAccess.context(client_id,state);
    mfaContext = await mfaAuthority.login(state.context?.userId, otpCode, primaryMethod);
    if ((client.mfaRequired || state.authentication?.required) && mfaContext.methods.length !== 2) throw new MfaError(401, 'mfa_enrollment_required');
    if (state.authorization) userInfo = { ...userInfo, ...state.authorization };
  }
  catch (error) { return res.status(error.status || 503).json({ error: error.code || 'identity_authority_unavailable' }); }
  if (!userCanDelegateScopes(userInfo, approvedScope)) return res.status(403).json({ error: 'invalid_scope' });
  if (!await clientRegistry.current(client)) return res.status(400).json({ error: 'unauthorized_client' });
  const code = uuidv4();
  authCodes.set(code, {
    clientId: client_id,
    clientRevision: client.version,
    redirectUri: redirect_uri,
    scope: approvedScope,
    userId,
    userInfo,
    identityContext,
    credentialAuthorization,
    applicationContext,
    mfaContext,
    authTime: mfaContext.authTime,
    nonce: nonce || undefined,
    deviceId: device_id || undefined,
    codeChallenge: code_challenge || undefined,
    codeChallengeMethod: code_challenge_method || undefined,
    expiresAt: Date.now() + 60_000,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
}

const federationLinks = require('./federationRoutes').mountFederation(app, { issuer: ISSUER, protocol, validate: validateAuthorization, authorize: authorizeUser });

// ─── Token Endpoint ───────────────────────────────────────────────────────────────

// RFC 7636 §4.6 — verify code_verifier against the code_challenge stored at
// /oauth/authorize time. 'plain' is RFC 7636's default when
// code_challenge_method is omitted but a code_challenge was supplied.
// Constant-time comparison (both branches) since this is effectively a
// credential check — a timing side-channel on the challenge comparison
// would erode the whole point of PKCE.
function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a ?? ''));
  const bBuf = Buffer.from(String(b ?? ''));
  if (aBuf.length !== bBuf.length) return false;
  try { return crypto.timingSafeEqual(aBuf, bBuf); } catch { return false; }
}

function verifyPkce(codeChallenge, codeChallengeMethod, verifier) {
  if (typeof codeChallenge !== 'string' || typeof verifier !== 'string' || !verifier
    || (codeChallengeMethod !== undefined && typeof codeChallengeMethod !== 'string')) return false;
  const method = (codeChallengeMethod || 'plain').toLowerCase();
  if (method === 's256') {
    const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
    return safeEqual(computed, codeChallenge);
  }
  if (method === 'plain') {
    return safeEqual(verifier, codeChallenge);
  }
  return false; // unrecognized method -> fail closed
}

// Grant types this token endpoint actually implements. The client.grantTypes
// allowlist (set via POST /api/clients, or the seed data below) is only
// enforced for these — an entirely-unimplemented grant_type (e.g. the
// never-supported 'password'/ROPC) must keep falling through to the generic
// unsupported_grant_type response at the bottom of this handler rather than
// being reported as unauthorized_client.
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const IMPLEMENTED_GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials', DEVICE_GRANT];

app.post('/oauth/token', protocol(async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token, device_code } = req.body;

  const client = req.oauthClient;
  if (!clientRegistry.authenticated(client, client_secret, grant_type === 'client_credentials')) {
    return res.status(401).json({ error: 'invalid_client' });
  }
    // Per-client grant-type allowlist (RFC 6749 §3.2.1 / §5.2 unauthorized_client):
    // a client registered only for e.g. authorization_code must not be able
    // to mint tokens via client_credentials (or any other implemented grant
    // it wasn't configured for) just by asserting a different grant_type.
  if (IMPLEMENTED_GRANT_TYPES.includes(grant_type) &&
      !(Array.isArray(client.grantTypes) && client.grantTypes.includes(grant_type))) {
    return res.status(400).json({ error: 'unauthorized_client' });
  }
  try { await revocations.ready(); await sessions.ready(); await mfaAuthority.ready(); }
  catch { return res.status(503).json({ error: 'token_state_unavailable' }); }
  if (!await clientRegistry.current(client)) return res.status(401).json({ error: 'invalid_client' });

  if (grant_type === 'authorization_code') {
    const record = authCodes.get(code);
    if (!record || record.expiresAt < Date.now() || record.clientId !== client_id || record.clientRevision !== client.version) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    authCodes.delete(code);

    // RFC 6749 §4.1.3 — redirect_uri, if present at /oauth/authorize time,
    // must match byte-for-byte at redemption time. Without this a code
    // obtained via one registered redirect_uri (e.g. leaked through a
    // referrer header or an open redirect on that endpoint) could be
    // redeemed by an attacker in control of a *different* registered
    // redirect_uri for the same client.
    if (record.redirectUri && record.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // RFC 7636 — if the authorize request included a code_challenge, the
    // token request MUST supply a matching code_verifier. Previously
    // code_verifier was read off req.body but never compared against
    // anything, making PKCE a complete no-op despite discovery advertising
    // S256/plain support.
    if (record.codeChallenge && !verifyPkce(record.codeChallenge, record.codeChallengeMethod, code_verifier)) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    if (client.publicClient && (!record.codeChallenge || record.codeChallengeMethod !== 'S256')) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    const approvedScope = resolveScopes(client, record.scope);
    if (approvedScope === null) return res.status(400).json({ error: 'invalid_scope' });

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
        const DEVICE_SERVICE = process.env.DEVICE_SERVICE_URL || 'http://device-service';
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
      ...(record.identityContext ? { identity_authorization: record.identityContext } : {}),
      ...(record.credentialAuthorization ? { credential_authorization: record.credentialAuthorization } : {}),
      ...(record.applicationContext ? { application_authorization: record.applicationContext } : {}),
      auth_time: record.authTime,
      amr: record.mfaContext?.methods || ['pwd'],
      ...(record.mfaContext?.schemaVersion ? { mfa_authorization: record.mfaContext } : {}),
      iss:   ISSUER,
      aud:   client_id,
      iat:   Math.floor(Date.now() / 1000),
      name:  scimUser?.name?.formatted ?? scimUser?.displayName ?? ui.name ?? ui.displayName ?? record.userId,
      email: scimUser?.emails?.[0]?.value ?? ui.email ?? `${record.userId}@opendirectory.local`,
      preferred_username: scimUser?.userName ?? ui.username ?? record.userId,
      groups: (Array.isArray(scimUser?.groups) ? scimUser.groups : Array.isArray(ui.groups) ? ui.groups : []).map((group) => group?.value ?? group?.display ?? group).filter(group => typeof group === 'string'),
      scope: approvedScope,
      ...userAuthorizationClaims(ui, approvedScope),
    };

    if (!await clientRegistry.current(client) || record.expiresAt <= Date.now()) return res.status(400).json({ error: 'invalid_grant' });
    let issued;
    try { issued = await issueSession(payload, 'user', client.grantTypes.includes('refresh_token'), client); }
    catch (error) { return res.status(error.status || 503).json({ error: error.code || 'session_authority_unavailable' }); }
    const access_token = issued.accessToken;
    const identityPayload = Object.fromEntries(Object.entries(issued.payload).filter(([claim]) => !['roles', 'permissions', 'scope', 'credential_authorization'].includes(claim)));
    const id_token = approvedScope.split(' ').includes('openid')
      ? signToken({ ...identityPayload, token_use: 'id', ...(record.nonce ? { nonce: record.nonce } : {}) }) : undefined;

    publish('identity.token.issued', { clientId: client_id, userId: record.userId, scope: record.scope, issuedAt: new Date().toISOString() });
    return res.json({ access_token, id_token, refresh_token: issued.refreshToken, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: record.scope });
  }

  if (grant_type === 'refresh_token') {
    if (typeof refresh_token !== 'string' || !refresh_token) return res.status(400).json({ error: 'invalid_grant' });
    const hash = crypto.createHash('sha256').update(refresh_token).digest('hex');
    try {
      const result = await sessions.rotate(hash, client_id, async (record, session) => {
        if (record.authorization.client_revision !== client.version || !await clientRegistry.current(client)) return { error: 'invalid_grant' };
        const state = await identityAuthority.verifiedState(record.authorization);
        if (!state || !acceptsAuthentication(client, record.authorization) || !await mfaAuthority.matches(record.authorization)
          || !await applicationAccess.matches(client_id,state,record.authorization.application_authorization)) return { error: 'invalid_grant' };
        const approvedScope = resolveScopes(client, req.body.scope === undefined ? record.scope : req.body.scope, [], record.scope);
        if (approvedScope === null) return { error: 'invalid_scope' };
        const { roles, permissions, iat, ...original } = record.authorization;
        const payload = { ...original, iss: ISSUER, aud: client_id, scope: approvedScope, iat: Math.floor(Date.now() / 1000), ...userAuthorizationClaims(record.authorization, approvedScope) };
        const accessToken = signToken(payload, Math.max(1, Math.min(TOKEN_TTL, Math.floor((session.expiresAt - Date.now()) / 1000))));
        const refreshToken = crypto.randomBytes(32).toString('base64url');
        return { refresh: { hash: crypto.createHash('sha256').update(refreshToken).digest('hex'), scope: approvedScope, authorization: payload, expiresAt: record.expiresAt },
          response: { access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: jwt.decode(accessToken).exp - payload.iat, scope: approvedScope } };
      });
      if (result.error) return res.status(400).json(result);
      return res.json(result);
    } catch (error) { return res.status(error.status || 503).json({ error: error.code || 'session_authority_unavailable' }); }
  }

  if (grant_type === 'client_credentials') {
    const approvedScope = resolveScopes(client, req.body.scope);
    if (approvedScope === null) return res.status(400).json({ error: 'invalid_scope' });
    const payload = { sub: client_id, iss: ISSUER, aud: client_id, iat: Math.floor(Date.now() / 1000), scope: approvedScope, ...workloadAuthorizationClaims(approvedScope) };
    let access_token;
    try { access_token = (await issueSession(payload, 'application', false, client)).accessToken; }
    catch (error) { return res.status(error.status || 503).json({ error: error.code || 'session_authority_unavailable' }); }
    publish('identity.token.issued', { clientId: client_id, userId: client_id, scope: payload.scope, issuedAt: new Date().toISOString() });
    return res.json({ access_token, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: approvedScope });
  }

  if (grant_type === DEVICE_GRANT) {
    const record = deviceCodes.get(device_code);
    if (!record) return res.status(400).json({ error: 'expired_token' });
    if (record.client_id !== client_id || record.clientRevision !== client.version) return res.status(400).json({ error: 'invalid_grant' });
    if (record.expiresAt < Date.now()) { deviceCodes.delete(device_code); return res.status(400).json({ error: 'expired_token' }); }
    if (!record.approved) return res.status(400).json({ error: 'authorization_pending' });
    const approvedScope = resolveScopes(client, record.scope);
    if (approvedScope === null) return res.status(400).json({ error: 'invalid_scope' });

    deviceCodes.delete(device_code);
    const payload = { sub: record.userId, iss: ISSUER, aud: client_id, auth_time: record.authTime, iat: Math.floor(Date.now() / 1000), scope: approvedScope,
      amr: record.mfaContext?.methods || ['pwd'],
      ...(record.mfaContext?.schemaVersion ? { mfa_authorization: record.mfaContext } : {}),
      ...(record.identityContext ? { identity_authorization: record.identityContext } : {}),
      ...(record.credentialAuthorization ? { credential_authorization: record.credentialAuthorization } : {}),
      ...(record.applicationContext ? { application_authorization: record.applicationContext } : {}), ...userAuthorizationClaims(record.userInfo, approvedScope) };
    let access_token;
    try { access_token = (await issueSession(payload, 'user', false, client)).accessToken; }
    catch (error) { return res.status(error.status || 503).json({ error: error.code || 'session_authority_unavailable' }); }
    publish('identity.token.issued', { clientId: client_id ?? 'device-client', userId: payload.sub, scope: payload.scope, issuedAt: new Date().toISOString() });
    return res.json({ access_token, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: approvedScope });
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
}));

// ─── UserInfo Endpoint ────────────────────────────────────────────────────────────

app.get('/oauth/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'invalid_token' });
  try {
    const payload = verifyToken(token);
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    if (await isTokenRevoked(hash, payload)) return res.status(401).json({ error: 'token_revoked' });
    return res.json({ sub: payload.sub, name: payload.name, email: payload.email, preferred_username: payload.preferred_username, groups: payload.groups ?? [] });
  } catch (error) {
    if (error.status === 503) return res.status(503).json({ error: 'token_state_unavailable' });
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// ─── Token Introspection ─────────────────────────────────────────────────────────

app.post('/oauth/introspect', protocol(async (req, res) => {
  const { token, client_id, client_secret } = req.body;
  const client = req.oauthClient;
  if (!clientRegistry.authenticated(client, client_secret, true)) return res.status(401).json({ error: 'invalid_client' });
  if (typeof token !== 'string' || !token) return res.json({ active: false });
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  try {
    const payload = verifyToken(token);
    if (payload.client_id !== client_id) return res.json({ active: false });
    if (await isTokenRevoked(hash, payload)) return res.json({ active: false });
    return res.json({ active: true, ...payload });
  } catch (error) {
    if (error.status === 503) return res.status(503).json({ error: 'token_state_unavailable' });
    return res.json({ active: false });
  }
}));

app.get('/oauth/access-state', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const authorization = req.headers.authorization;
  if (Object.keys(req.query).length || req.headers['x-api-key'] || typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) return res.status(401).json({ error: 'invalid_token' });
  try {
    const token = authorization.slice(7);
    const payload = signingKeys.verify(token, { issuer: ISSUER, audience: process.env.OAUTH_API_AUDIENCE || 'opendirectory-api' });
    if (payload.token_use !== 'access' || typeof payload.sub !== 'string' || !payload.sub.trim() || typeof payload.jti !== 'string' || !payload.jti
      || payload.sub.length > 255 || payload.jti.length > 255 || !Number.isFinite(payload.exp) || !Number.isFinite(payload.iat)
      || payload.exp <= payload.iat || payload.iat > Date.now() / 1000 + 30) return res.status(401).json({ error: 'invalid_token' });
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const active = !await isTokenRevoked(hash, payload);
    return res.json(active ? { schemaVersion: 1, active, issuer: payload.iss, subject: payload.sub, tokenId: payload.jti, expiresAt: payload.exp } : { schemaVersion: 1, active: false });
  } catch (error) {
    return res.status(error.status === 503 ? 503 : 401).json({ error: error.status === 503 ? 'token_state_unavailable' : 'invalid_token' });
  }
});

// ─── Token Revocation ────────────────────────────────────────────────────────────

app.get('/oauth/tenant-state', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const authorization = req.headers.authorization;
  if (req.originalUrl !== '/oauth/tenant-state' || req.headers['x-api-key'] || Object.keys(req.body || {}).length
    || typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) return res.status(401).json({ error: 'invalid_token' });
  try {
    const token = authorization.slice(7);
    const payload = signingKeys.verify(token, { issuer: ISSUER, audience: process.env.OAUTH_API_AUDIENCE || 'opendirectory-api' });
    if (payload.actor_type !== 'user' || payload.token_use !== 'access' || typeof payload.sub !== 'string' || !payload.sub.trim() || payload.sub.length > 255
      || typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > 255 || !Number.isFinite(payload.exp) || !Number.isFinite(payload.iat)
      || payload.exp <= payload.iat || payload.iat > Date.now() / 1000 + 30) return res.status(401).json({ error: 'invalid_token' });
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    if (identityAuthority.demo) return res.json({ schemaVersion: 1, active: false });
    const state = await verifiedAccessState(hash, payload);
    if (!state || !require('../../../../packages/tenant-authorization-contract').validTenantContext(state.tenant)) return res.json({ schemaVersion: 1, active: false });
    return res.json({ schemaVersion: 1, active: true, issuer: payload.iss, subject: payload.sub, tokenId: payload.jti,
      expiresAt: payload.exp, context: state.context, tenant: state.tenant });
  } catch (error) {
    return res.status(error.status === 503 ? 503 : 401).json({ error: error.status === 503 ? 'tenant_state_unavailable' : 'invalid_token' });
  }
});

// RFC 7009 §2.1 requires the revocation endpoint to authenticate the client
// the same way /oauth/token does; previously this endpoint had NO client
// auth at all, so any caller who merely obtained (or guessed the hash of) a
// token could revoke it for someone else — a trivial DoS/sabotage primitive
// against any client's users. Client auth here mirrors /oauth/introspect
// immediately above (client_id + client_secret in the body, not a Basic-Auth
// header — this service has never used Basic Auth for client auth anywhere,
// including /oauth/token, so body-based auth is the established convention
// to stay consistent with, not a gap of its own).
app.post('/oauth/revoke', protocol(async (req, res) => {
  const { token, client_id, client_secret } = req.body;
  const client = req.oauthClient;
  if (!clientRegistry.authenticated(client, client_secret)) return res.status(401).json({ error: 'invalid_client' });
  if (typeof token !== 'string' || !token) return res.status(400).json({ error: 'invalid_request' });

  const hash = crypto.createHash('sha256').update(token ?? '').digest('hex');

  let decoded;
  try { decoded = signingKeys.verify(token, { issuer: ISSUER, ignoreExpiration: true }); } catch {}
  let changed = false;
  try {
    if (decoded) {
      if (decoded.token_use !== 'access' || decoded.client_id !== client_id || !Number.isFinite(decoded.exp)) return res.json({ ok: true });
      await revocations.revoke(hash, client_id, decoded.exp * 1000);
      changed = true;
    } else {
      changed = await sessions.revokeRefresh(hash, client_id);
    }
  } catch { return res.status(503).json({ error: 'token_state_unavailable' }); }
  if (changed) publish('identity.token.revoked', { tokenId: hash, revokedAt: new Date().toISOString() });
  res.status(200).json({ ok: true });
}));

// ─── Logout ───────────────────────────────────────────────────────────────────────

app.get('/oauth/logout', (req, res) => {
  res.status(410).set('Cache-Control', 'no-store').json({ error: 'oidc_logout_not_implemented',
    message: 'Browser OIDC end-session redirects are not implemented. Use scoped header-authenticated session revocation to terminate a session family.' });
});

function canAdministerSessions(payload) {
  return payload.actor_type === 'user' && ((Array.isArray(payload.roles) && payload.roles.some(role => ['admin', 'session-administrator'].includes(role)))
    || (Array.isArray(payload.permissions) && payload.permissions.includes('sessions.revoke')));
}

function sessionRoute(scope, operation, administrative = false) {
  return async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const authorization = req.headers.authorization;
    if (Object.keys(req.query).length || req.headers['x-api-key'] || typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) return res.status(401).json({ error: 'invalid_token' });
    try {
      const token = authorization.slice(7);
      const payload = signingKeys.verify(token, { issuer: ISSUER, audience: process.env.OAUTH_API_AUDIENCE || 'opendirectory-api' });
      if (payload.token_use !== 'access' || await isTokenRevoked(crypto.createHash('sha256').update(token).digest('hex'), payload)) return res.status(401).json({ error: 'invalid_token' });
      const administrator = canAdministerSessions(payload);
      if ((administrative || !payload.scope?.split(' ').includes(scope)) && !administrator) return res.status(403).json({ error: 'forbidden' });
      return res.json(await operation(req, payload, administrator));
    } catch (error) {
      return res.status(error.status || 401).json({ error: error.code && error.status ? error.code : 'invalid_token' });
    }
  };
}

app.get('/oauth/sessions', sessionRoute('sessions.self.read', async (_req, payload) => ({ sessions: (await sessions.list(viewer(payload))).map(session => ({ ...session, current: session.id === payload.sid })) })));
app.delete('/oauth/sessions/:id', sessionRoute('sessions.self.revoke', (req, payload, administrator) => sessions.revokeSession(req.params.id, viewer(payload), administrator)));
app.post('/oauth/sessions/current/revoke', sessionRoute('sessions.self.revoke', (_req, payload) => sessions.revokeSession(payload.sid, viewer(payload))));
app.post('/oauth/sessions/revoke-all', sessionRoute('sessions.self.revoke', (_req, payload) => sessions.revokeAll(viewer(payload), viewer(payload))));
app.post('/oauth/users/:subject/sessions/revoke', sessionRoute(null, (req, payload) => {
  if (!req.params.subject.trim() || req.params.subject.length > 255) throw Object.assign(new Error('Invalid subject'), { status: 400, code: 'invalid_subject' });
  return sessions.revokeAll({ issuer: ISSUER, subject: req.params.subject, principalType: 'user' }, viewer(payload));
}, true));

// ─── Device Authorization Flow (RFC 8628) ────────────────────────────────────────

app.post('/oauth/device/code', protocol((req, res) => {
  const { client_id, client_secret, scope } = req.body;
  const client = req.oauthClient;
  if (!clientRegistry.authenticated(client, client_secret)) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  if (!Array.isArray(client.grantTypes) || !client.grantTypes.includes(DEVICE_GRANT)) return res.status(400).json({ error: 'unauthorized_client' });
  const approvedScope = resolveScopes(client, scope, ['openid', 'profile']);
  if (approvedScope === null) return res.status(400).json({ error: 'invalid_scope' });
  const device_code = uuidv4();
  const user_code = crypto.randomBytes(3).toString('hex').toUpperCase().replace(/(.{4})/, '$1-');
  const expiresAt = Date.now() + 15 * 60_000; // 15 min

  deviceCodes.set(device_code, {
    user_code,
    client_id,
    clientRevision: client.version,
    scope: approvedScope,
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
}));

app.get('/oauth/device/verify', (req, res) => {
  const { user_code, error } = req.query;
  res.set('Content-Type', 'text/html');
  const errorHtml = error ? `<p style="color:#dc2626;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:10px;margin-top:12px;">${escapeHtml(error)}</p>` : '';
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
  <input name="user_code" type="text" placeholder="XXXX-XXXX" value="${escapeHtml(user_code)}" maxlength="9"/>
  <label>Username</label>
  <input name="username" type="text" autocomplete="username" required/>
  <label>Password</label>
  <input name="password" type="password" autocomplete="current-password" required/>
  <label>Code of the password provider (if required there)</label>
  <input name="mfaCode" type="text" autocomplete="one-time-code" inputmode="numeric"/>
  <label>OpenDirectory-Einmalcode (falls eingerichtet)</label>
  <input name="otpCode" type="text" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"/>
  <button type="submit">Authorize Device</button>
</form>
</body></html>`);
});

app.post('/oauth/device/approve', express.urlencoded({ extended: true }), protocol(async (req, res) => {
  const { user_code, username, password, mfaCode, otpCode } = req.body;
  let found = null;
  for (const [dc, rec] of deviceCodes.entries()) {
    if (rec.user_code === user_code && rec.expiresAt > Date.now()) { found = [dc, rec]; break; }
  }
  if (!found) return res.send('<html><body><p>Invalid or expired code.</p></body></html>');

  const authentication = await authenticateUser({ username, password, mfaCode });
  if (authentication.error) return res.status(authentication.status).json({ error: authentication.error });
  const client = await clientRegistry.get(found[1].client_id);
  if (!client?.enabled || found[1].clientRevision !== client.version || !Array.isArray(client.grantTypes) || !client.grantTypes.includes(DEVICE_GRANT)) return res.status(400).json({ error: 'unauthorized_client' });
  if (resolveScopes(client, found[1].scope) === null) return res.status(403).json({ error: 'invalid_scope' });
  if (found[1].expiresAt <= Date.now() || found[1].approved) return res.status(400).json({ error: 'invalid_grant' });
  let identityContext; let credentialAuthorization; let applicationContext; let mfaContext;
  let userInfo = authentication.user;
  try {
    const state = await identityAuthority.state(userInfo.id);
    if (!credentialContract.matchesPasswordAuthentication(state, authentication.credentialAuthentication, userInfo.id)) {
      throw new MfaError(401, 'credential_authorization_changed');
    }
    identityContext = state.context;
    credentialAuthorization = state.credentialAuthorization;
    applicationContext = await applicationAccess.context(found[1].client_id,state);
    mfaContext = await mfaAuthority.login(state.context?.userId, otpCode);
    if ((client.mfaRequired || state.authentication?.required) && mfaContext.methods.length !== 2) throw new MfaError(401, 'mfa_enrollment_required');
    if (state.authorization) userInfo = { ...userInfo, ...state.authorization };
  }
  catch (error) { return res.status(error.status || 503).json({ error: error.code || 'identity_authority_unavailable' }); }
  if (!userCanDelegateScopes(userInfo, found[1].scope)) return res.status(403).json({ error: 'invalid_scope' });
  if (deviceCodes.get(found[0]) !== found[1] || !await clientRegistry.current(client) || found[1].expiresAt <= Date.now() || found[1].approved) return res.status(400).json({ error: 'invalid_grant' });
  found[1].approved = true;
  found[1].userId = authentication.user.id;
  found[1].userInfo = userInfo;
  found[1].identityContext = identityContext;
  found[1].credentialAuthorization = credentialAuthorization;
  found[1].applicationContext = applicationContext;
  found[1].mfaContext = mfaContext;
  found[1].authTime = mfaContext.authTime;
  res.send('<html><body><h2 style="font-family:system-ui;color:#16a34a;">Device authorized! You may close this window.</h2></body></html>');
}, false));

// SAML launches use verified user tokens and a registered ACS; no anonymous assertions.
require('./samlRoutes').mountSaml(app, { issuer: ISSUER, adminAuth, protocol, clientRegistry, identityAuthority, applicationAccess });

// ─── OAuth2 Client Management API (full CRUD) ─────────────────────────────────────

app.use('/api/clients', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
const companyApps=new(require('./CompanyApps').CompanyApps)(clientRegistry);
app.use('/api/clients/company',require('./companyAppRoutes').companyAppRoutes({store:companyApps,authenticate:adminAuth}));
app.get('/api/license-source-clients/:id',adminAuth,protocol(async(req,res)=>{
 if(Object.keys(req.query).length)return res.status(400).json({error:'exact_source_client_required'});return res.json(await clientRegistry.licenseSource(req.params.id,req.user));
},false));
function clientRoute(permission, handler) {
  return [adminAuth, protocol(async (req, res) => {
    if (!permissionsOf(req.user).includes(permission)) return res.status(403).json({ error: 'forbidden' });
    const result = await handler(req, res);
    if (result === undefined) return;
    if (result.clientSecret) {
      const hash = crypto.createHash('sha256').update(req.headers.authorization.slice(7)).digest('hex');
      if (await isTokenRevoked(hash, req.user)) return res.status(401).json({ error: 'authorization_changed_outcome_unknown' });
    }
    if (result.clientId && result.version) res.set('ETag', etag(result));
    return res.json(result);
  }, false)];
}
app.use('/api/mfa', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
function mfaRoute(fields, handler) {
  return [adminAuth, protocol(async (req, res) => {
    mfaAuthority.actor(req.user);
    if (Object.keys(req.query).length || !req.body || Object.keys(req.body).some(field => !fields.includes(field))) throw new MfaError(400, 'invalid_request');
    return res.json(await handler(req));
  }, false)];
}
async function reauthenticateMfa(req) {
  const { username, password, mfaCode } = req.body;
  const result = await authenticateUser({ username, password, mfaCode });
  if (result.error) throw new MfaError(result.status, result.error);
  if (result.user.id !== req.user.sub) throw new MfaError(403, 'same_user_required');
  const state = await identityAuthority.state(result.user.id);
  if (!credentialContract.matchesPasswordAuthentication(state, result.credentialAuthentication, result.user.id)
    || !sameContext(state.context, req.user.identity_authorization)
    || !credentialContract.sameBinding(state.credentialAuthorization, req.user.credential_authorization)) throw new MfaError(401, 'authorization_changed');
}
app.get('/api/mfa', ...mfaRoute([], req => mfaAuthority.status(req.user)));
app.post('/api/mfa/enroll', ...mfaRoute(['username', 'password', 'mfaCode'], async req => {
  await reauthenticateMfa(req);
  const setup = await mfaAuthority.enroll(req.user);
  if (await isTokenRevoked(crypto.createHash('sha256').update(req.headers.authorization.slice(7)).digest('hex'), req.user)) throw new MfaError(401, 'authorization_changed_outcome_unknown');
  return setup;
}));
app.post('/api/mfa/confirm', ...mfaRoute(['code'], req => mfaAuthority.confirm(req.user, req.body.code)));
app.post('/api/mfa/disable', ...mfaRoute(['username', 'password', 'mfaCode', 'code'], async req => {
  await reauthenticateMfa(req); return mfaAuthority.disable(req.user, req.body.code);
}));
app.get('/api/mfa/recovery-codes', ...mfaRoute([], req => mfaRecovery.status(req.user)));
app.post('/api/mfa/recovery-codes', ...mfaRoute(['username', 'password', 'mfaCode', 'code'], async req => {
  await reauthenticateMfa(req); const result = await mfaRecovery.rotate(req.user, req.body.code);
  if (await isTokenRevoked(crypto.createHash('sha256').update(req.headers.authorization.slice(7)).digest('hex'), req.user)) throw new MfaError(401, 'authorization_changed_outcome_unknown');
  return result;
}));
function recoveryRequest(req, fields) {
  if (Object.keys(req.query).length || !req.body || Array.isArray(req.body) || Object.keys(req.body).some(field => !fields.includes(field))) throw new MfaError(400, 'invalid_request');
}
app.post('/oauth/mfa/recovery/start', protocol(async (req, res) => {
  recoveryRequest(req, ['username', 'password', 'mfaCode', 'recoveryCode']);
  const authentication = await authenticateUser(req.body);
  if (authentication.error) return res.status(authentication.status).json({ error: authentication.error });
  const state = await identityAuthority.state(authentication.user.id);
  return res.json(await mfaRecovery.start(authentication.user.id, state.context, req.body.recoveryCode, authentication.credentialAuthentication));
}, false));
app.post('/oauth/mfa/recovery/confirm', protocol(async (req, res) => {
  recoveryRequest(req, ['challenge', 'code']); return res.json(await mfaRecovery.confirm(req.body.challenge, req.body.code));
}, false));
app.post('/oauth/mfa/enrollment/start', protocol(async (req, res) => {
  recoveryRequest(req, ['clientId', 'username', 'password', 'mfaCode']);
  const authentication = await authenticateUser(req.body);
  if (authentication.error) return res.status(authentication.status).json({ error: authentication.error });
  return res.json(await mfaEnrollment.start(req.body.clientId, authentication.user.id, authentication.credentialAuthentication));
}, false));
app.post('/oauth/mfa/enrollment/confirm', protocol(async (req, res) => {
  recoveryRequest(req, ['challenge', 'code']); return res.json(await mfaEnrollment.confirm(req.body.challenge, req.body.code));
}, false));
app.get('/api/clients/:id/authentication', ...clientRoute('applications.authentication.read', async (req, res) => {
  recoveryRequest(req, []); const result = await clientRegistry.authentication(req.params.id, req.user);
  res.set('ETag', `"od-client:${result.clientId}:${result.version}"`); return result;
}));
app.put('/api/clients/:id/authentication', ...clientRoute('applications.authentication.manage', req => {
  recoveryRequest(req, ['required', 'maxAgeSeconds', 'reason']); return clientRegistry.setAuthentication(req.params.id, req.headers['if-match'], req.body, req.user);
}));
app.get('/api/clients/access', adminAuth, (req, res) => res.set('Cache-Control', 'no-store').json({ permissions: permissionsOf(req.user), subject: req.user.sub, userId: req.user.identity_authorization?.userId || null, clientId: req.user.client_id, demoMode: clientRegistry.demo }));
app.get('/api/clients', ...clientRoute('applications.read', req => clientRegistry.list(req.user)));
app.get('/api/clients/:id', ...clientRoute('applications.read', async req => {
  clientRegistry.actor(req.user, 'applications.read'); const client = await clientRegistry.get(req.params.id);
  if (!client || client.companyTenant) throw Object.assign(new Error('client_not_found'), { status: 404, code: 'client_not_found' });
  return publicClient(client);
}));
app.post('/api/clients', ...clientRoute('applications.create', async (req, res) => { const result = await clientRegistry.create(req.body, req.user); res.status(201); return result; }));
app.put('/api/clients/:id', ...clientRoute('applications.update', req => clientRegistry.mutate(req.params.id, req.headers['if-match'], req.body, req.user)));
app.post('/api/clients/:id/rotate-secret', ...clientRoute('applications.credentials.rotate', req => clientRegistry.mutate(req.params.id, req.headers['if-match'], null, req.user, 'rotated')));
app.delete('/api/clients/:id', ...clientRoute('applications.delete', async (req, res) => { await clientRegistry.mutate(req.params.id, req.headers['if-match'], null, req.user, 'deleted'); res.status(204).send(); }));
function assignmentRequest(req) {
  if (Object.keys(req.query).length || (req.method === 'DELETE' && Object.keys(req.body || {}).length)) throw Object.assign(new Error('invalid_assignment_request'), { status: 400, code: 'invalid_assignment_request' });
}
app.get('/api/clients/:id/assignments', ...clientRoute('applications.assignments.read', req => { assignmentRequest(req); return applicationAccess.list(req.params.id,req.user); }));
app.post('/api/clients/:id/assignments', ...clientRoute('applications.assignments.manage', async (req,res) => {
  assignmentRequest(req); const result = await applicationAccess.grant(req.params.id,req.body,req.user); res.status(result.reused ? 200 : 201); return result;
}));
app.delete('/api/clients/:id/assignments/:assignmentId', ...clientRoute('applications.assignments.manage', req => {
  assignmentRequest(req); return applicationAccess.revoke(req.params.id,req.params.assignmentId,req.user);
}));

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
app.get('/scim/v2/Users', adminAuth, requireAdmin, (req, res) => {
  const list = [...scimUsers.values()].map(scimUserResource);
  res.json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: list.length, Resources: list });
});

app.post('/scim/v2/Users', adminAuth, requireAdmin, (req, res) => {
  const id = uuidv4();
  const user = { id, userName: req.body.userName, displayName: req.body.displayName ?? req.body.userName, emails: req.body.emails ?? [], active: req.body.active !== false, groups: [] };
  scimUsers.set(id, user);
  if (db.isAvailable()) {
    db.saveScimUser('__catalog__', id, user).catch(err => console.error('[scim-db]', err.message));
  }
  res.status(201).json(scimUserResource(user));
});

app.get('/scim/v2/Users/:id', adminAuth, requireAdmin, (req, res) => {
  const u = scimUsers.get(req.params.id);
  if (!u) return res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: 404, detail: 'User not found' });
  res.json(scimUserResource(u));
});

app.put('/scim/v2/Users/:id', adminAuth, requireAdmin, (req, res) => {
  const existing = scimUsers.get(req.params.id);
  if (!existing) return res.status(404).json({ status: 404, detail: 'User not found' });
  const user = { id: req.params.id, userName: req.body.userName, displayName: req.body.displayName, emails: req.body.emails ?? [], active: req.body.active !== false, groups: req.body.groups ?? [] };
  scimUsers.set(req.params.id, user);
  if (db.isAvailable()) {
    db.saveScimUser('__catalog__', req.params.id, user).catch(err => console.error('[scim-db]', err.message));
  }
  // Trigger SCIM push deactivation if user was just deactivated
  if (existing.active === true && user.active === false) {
    triggerScimPush('deactivate', req.params.id, '').catch(err => console.error('[SCIM push error]', err.message));
  }
  res.json(scimUserResource(user));
});

app.delete('/scim/v2/Users/:id', adminAuth, requireAdmin, (req, res) => {
  if (!scimUsers.has(req.params.id)) return res.status(404).json({ status: 404, detail: 'User not found' });
  scimUsers.delete(req.params.id);
  if (db.isAvailable()) {
    db.deleteScimUser('__catalog__', req.params.id).catch(err => console.error('[scim-db]', err.message));
  }
  res.status(204).send();
});

// SCIM Groups
app.get('/scim/v2/Groups', adminAuth, requireAdmin, (req, res) => {
  const list = [...scimGroups.values()].map(scimGroupResource);
  res.json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: list.length, Resources: list });
});

app.post('/scim/v2/Groups', adminAuth, requireAdmin, (req, res) => {
  const id = uuidv4();
  const group = { id, displayName: req.body.displayName, members: req.body.members ?? [] };
  scimGroups.set(id, group);
  res.status(201).json(scimGroupResource(group));
});

app.get('/scim/v2/Groups/:id', adminAuth, requireAdmin, (req, res) => {
  const g = scimGroups.get(req.params.id);
  if (!g) return res.status(404).json({ status: 404, detail: 'Group not found' });
  res.json(scimGroupResource(g));
});

app.put('/scim/v2/Groups/:id', adminAuth, requireAdmin, (req, res) => {
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

app.delete('/scim/v2/Groups/:id', adminAuth, requireAdmin, (req, res) => {
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
const quarantineTimer = setInterval(() => {
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
quarantineTimer.unref();

app.get('/api/devices/registry', adminAuthOrInternal, requirePolicyDeviceAccess('inventory'), async (req, res) => {
  if (req.policyDeviceOperator && !db.isAvailable()) return res.status(503).json({ error: 'device_authority_unavailable' });
  if (db.isAvailable()) {
    try {
      const rows = await db.getAllDevices();
      if (rows.length > 0 || req.policyDeviceOperator) return res.json(rows.map(row => policyDeviceView(req, req.policyDeviceOperator ? row : { ...row, ...row.data })));
    } catch (err) {
      if (req.policyDeviceOperator) return res.status(503).json({ error: 'device_authority_unavailable' });
      console.error('[registry-db]', err.message);
    }
  }
  res.json([...deviceRegistry.values()].map(device => policyDeviceView(req, device)));
});

app.put('/api/devices/:id/status', adminAuth, requireAdmin, (req, res) => {
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
const policyDeviceQueue = new (require('./PolicyDeviceQueue').PolicyDeviceQueue)(db, {
  isUserRevoked: isTokenRevoked, isDeviceRevoked: hash => revocations.revoked(hash),
});
const policyDeviceRoute = operation => async (req, res) => {
  const controller = new AbortController(); const close = () => controller.abort(); req.once('aborted', close); res.once('close', close); res.set('Cache-Control', 'no-store');
  try { await operation(req, res, controller.signal); }
  catch (error) { if (!res.headersSent && !res.destroyed) res.status(error.status || 503).json({ error: error.code || 'policy_command_unavailable', enforcementConfirmed: false }); }
  finally { req.removeListener('aborted', close); res.removeListener('close', close); }
};

app.get('/api/devices/policy-command-access', adminAuth, requirePolicyDeviceAccess('protocol'), policyDeviceRoute(async (req, res, signal) => {
  res.json(await policyDeviceQueue.access(req.user, req.headers.authorization, signal));
}));
app.get('/api/devices/policy-registry', adminAuth, requirePolicyDeviceAccess('protocol'), policyDeviceRoute(async (req, res, signal) => {
  res.json(await policyDeviceQueue.inventory(req.user, req.headers.authorization, signal));
}));
app.get('/api/devices/policy-commands', adminAuth, requirePolicyDeviceAccess('protocol'), policyDeviceRoute(async (req, res, signal) => {
  if (Object.keys(req.query).some(key => !['resourceKind','resourceId','limit','offset'].includes(key))) return res.status(400).json({ error: 'bounded_owned_policy_commands_required' });
  res.json(await policyDeviceQueue.ownedHistory({ resourceKind: req.query.resourceKind, resourceId: req.query.resourceId, limit: Number(req.query.limit ?? 200), offset: Number(req.query.offset ?? 0) }, req.user, req.headers.authorization, signal));
}));
app.post('/api/devices/:deviceId/commands/:cmdId/cancel', adminAuth, requirePolicyDeviceAccess('protocol'), policyDeviceRoute(async (req, res, signal) => {
  res.json(await policyDeviceQueue.cancel(req.params.deviceId, req.params.cmdId, req.body, req.headers['x-od-operation-id'], req.user, req.headers.authorization, signal));
}));

app.post('/api/devices/:deviceId/commands', adminAuthOrInternal, requirePolicyDeviceAccess('command'), policyDeviceRoute(async (req, res, signal) => {
  const { command, payload } = req.body;
  if (command === 'update_policy') return res.status(201).json(await policyDeviceQueue.queue(req.params.deviceId, req.body, req.headers['x-od-operation-id'], req.user, req.headers.authorization, signal));
  // 'run_av_scan' is antivirus-protection's real MDM command name (see
  // POST /api/antivirus/scan in services/enterprise/antivirus-protection/
  // src/index.js, which dispatches exactly this command via the
  // internal-service-token bypass below) — it was missing from this
  // allowlist, so every AV-scan dispatch 400'd here and the fleet-wide scan
  // feature was silently broken end-to-end.
  const VALID_COMMANDS = ['wipe', 'lock', 'unlock', 'update_policy', 'restart', 'collect_logs', 'install_app', 'uninstall_app', 'run_av_scan'];
  if (!VALID_COMMANDS.includes(command)) return res.status(400).json({ error: `Unknown command. Valid: ${VALID_COMMANDS.join(', ')}` });

  const deviceId = req.params.deviceId;
  if (req.policyDeviceOperator && !deviceRegistry.has(deviceId)) {
    try { if (!db.isAvailable() || !await db.getDevice(deviceId)) return res.status(404).json({ error: 'Device not found' }); }
    catch { return res.status(503).json({ error: 'device_authority_unavailable' }); }
  }
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
}));

app.get('/api/devices/:deviceId/commands/pending', deviceSelfAuth, policyDeviceRoute(async (req, res, signal) => {
  const deviceId = req.params.deviceId;
  const verified = await policyDeviceQueue.pending(deviceId, req.user, req.headers.authorization, signal);
  const queue = (mdmCommands.get(deviceId) || []).filter(c => c.status === 'pending' && c.command !== 'update_policy');
  res.json([...queue, ...verified]);
}));

// Agent reports command result — device-authenticated (see comment above).
app.patch('/api/devices/:deviceId/commands/:cmdId', deviceSelfAuth, policyDeviceRoute(async (req, res, signal) => {
  const { deviceId, cmdId } = req.params;
  await policyDeviceQueue.check(req.user, req.headers.authorization, signal, true);
  if (!db.isAvailable()) return res.status(503).json({ error: 'policy_command_storage_unavailable' });
  const persisted = (await db.query('SELECT command FROM mdm_commands WHERE device_id=$1 AND id=$2', [deviceId, cmdId])).rows[0];
  if (persisted?.command === 'update_policy') return res.json(await policyDeviceQueue.report(deviceId, cmdId, req.body, req.user, req.headers.authorization, signal));
  const { status, result } = req.body;
  const queue = mdmCommands.get(deviceId) || [];
  const cmd = queue.find(c => c.id === cmdId && c.command !== 'update_policy');
  if (!cmd) return res.status(404).json({ error: 'Command not found' });
  cmd.status = status || 'completed';
  cmd.result = result;
  cmd.completedAt = new Date().toISOString();
  res.json(cmd);
}));

// List all commands for a device (admin UI use — distinct from the agent's
// own /commands/pending poll above).
app.get('/api/devices/:deviceId/commands', adminAuth, requireAdmin, policyDeviceRoute(async (req, res) => {
  if (Object.keys(req.query).some(key => !['limit','offset'].includes(key))) return res.status(400).json({ error: 'bounded_policy_command_history_required' });
  const verified = await policyDeviceQueue.list(req.params.deviceId, Number(req.query.limit ?? 200), Number(req.query.offset ?? 0));
  const queue = (mdmCommands.get(req.params.deviceId) || []).filter(command => command.command !== 'update_policy');
  res.set('X-Policy-Command-Truncated', String(verified.truncated)).json([...queue, ...verified.commands]);
}));

// ─── Compliance Check Endpoint ────────────────────────────────────────────────────

// Device-authenticated (see comment on /commands/pending above) — the agent
// reports its own compliance settings using its deviceToken.
app.post('/api/devices/:deviceId/compliance-check', deviceSelfAuth, async (req, res) => {
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

  res.json({ deviceId, platform, score, compliant, passing: passing.length, failing, total: rules.length, remediationQueued: false, approvedPublicationRequired: !compliant });
});

// ─── Enrollment Token API ─────────────────────────────────────────────────────────

const PLATFORMS = ['windows', 'macos', 'linux', 'ios', 'android'];

PLATFORMS.forEach(p => {
  const token = `${p[0].toUpperCase()}E-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  enrollmentTokens.set(p, { platform: p, token, created: new Date().toISOString().split('T')[0], expires: new Date(Date.now() + 30 * 86400_000).toISOString().split('T')[0], uses: 0, maxUses: p === 'linux' ? 100 : p === 'windows' || p === 'macos' ? 50 : 25, devices: new Map() });
});

app.get('/api/enrollment/tokens', adminAuth, requireAdmin, (req, res) => {
  res.json([...enrollmentTokens.values()].map(({ devices: _, ...t }) => t));
});

app.post('/api/enrollment/tokens/:platform/rotate', adminAuth, requireAdmin, (req, res) => {
  const { platform } = req.params;
  if (!PLATFORMS.includes(platform)) return res.status(400).json({ error: 'unknown platform' });
  const existing = enrollmentTokens.get(platform);
  const newToken = `${platform[0].toUpperCase()}E-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  enrollmentTokens.set(platform, { ...existing, token: newToken, uses: 0, created: new Date().toISOString().split('T')[0] });
  const { devices: _, ...t } = enrollmentTokens.get(platform);
  res.json(t);
});

app.post('/api/enrollment/register', async (req, res) => {
  const { token, platform, hostname, os, serial } = req.body;
  const record = [...enrollmentTokens.values()].find(t => t.token === token && t.platform === platform);
  if (!record || Date.parse(record.expires) <= Date.now()) return res.status(401).json({ error: 'invalid token' });
  if (record.uses >= record.maxUses) return res.status(429).json({ error: 'token exhausted' });
  if (Object.keys(req.body).some(key => !['token','platform','hostname','os','serial'].includes(key)) || typeof hostname !== 'string' || !hostname.trim() || hostname.length > 255
    || [os,serial].some(value => value !== undefined && (typeof value !== 'string' || value.length > 255))) return res.status(400).json({ error: 'bounded_device_enrollment_required' });
  if (!db.isAvailable()) return res.status(503).json({ error: 'persistent_device_enrollment_required' });
  record.uses += 1;
  const deviceId = uuidv4();
  let persisted = false;
  try {
    const stored = await db.upsertDevice({ id: deviceId, enrollmentToken: token, hostname, platform, os, ip: req.ip, status: 'active' }); persisted = true;
    if (stored?.id !== deviceId || stored.platform !== platform || !require('../../../../packages/identity-authorization-contract').validRevision(String(stored.policy_generation))) throw new Error('Device persistence receipt unavailable');
    if (enrollmentTokens.get(platform) !== record || Date.parse(record.expires) <= Date.now() || req.aborted || res.destroyed) throw new Error('Original enrollment authority no longer current');
    const deviceToken = signToken({ sub: deviceId, platform, hostname, serial, device_generation: String(stored.policy_generation), iss: ISSUER, token_use: 'device', aud: 'opendirectory-device-agent' }, '365d');
    res.status(201).json({ deviceId, deviceToken, serverUrl: ISSUER, message: `Device enrolled successfully as ${hostname} (${platform})` });
  } catch {
    if (!persisted) record.uses -= 1;
    res.status(503).json({ error: 'persistent_device_enrollment_required' });
  }
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
$AgentUrl    = "${ISSUER}/downloads/od-agent-windows-amd64.exe"
$ServerUrl   = "${ISSUER}"
$EnrollToken = "${token}"
$AgentDest   = "C:\\Program Files\\OpenDirectory\\od-agent.exe"

Write-Host "[OpenDirectory] Starting enrollment..." -ForegroundColor Cyan

# Create install directory
New-Item -ItemType Directory -Force -Path "C:\\Program Files\\OpenDirectory" | Out-Null

# Set enrollment token as machine environment variable
[System.Environment]::SetEnvironmentVariable("OD_ENROLLMENT_TOKEN", $EnrollToken, [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable("OD_SERVER_URL", $ServerUrl, [System.EnvironmentVariableTarget]::Machine)

# Download agent binary
Write-Host "[OpenDirectory] Downloading agent from $AgentUrl..."
Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentDest -UseBasicParsing

# Enroll this device
Write-Host "[OpenDirectory] Enrolling device..."
& $AgentDest enroll

# Create Windows scheduled task to run agent at startup
$Action  = New-ScheduledTaskAction -Execute $AgentDest -Argument "run"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 10 -StartWhenAvailable
Register-ScheduledTask -TaskName "OpenDirectoryAgent" -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "OpenDirectoryAgent"

Write-Host "[OpenDirectory] Enrollment complete! Agent is running." -ForegroundColor Green
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

// Device-authenticated (see comment on /commands/pending above).
app.post('/api/devices/:id/heartbeat', deviceSelfAuth, (req, res) => {
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

app.get('/api/scim-push/log', adminAuth, requireAdmin, (req, res) => {
  res.json(scimPushLog.slice(-50));
});

// ─── SCIM Connections Management ──────────────────────────────────────────────────

// In-memory stores for SCIM connections, sync log, and conflicts
const scimConnections = new Map();
const scimSyncLog = new Map(); // connectionId → [log entries]
const scimConflicts = new Map();

// Seed demo connections
[
  { id: uuidv4(), name: 'Google Workspace', provider: 'google', endpoint: 'https://scim.googleapis.com/v2', syncIntervalMinutes: 60, lastSync: new Date(Date.now() - 2 * 3600_000).toISOString(), status: 'active', usersSynced: 42, createdAt: new Date(Date.now() - 30 * 86400_000).toISOString() },
  { id: uuidv4(), name: 'Microsoft Entra ID', provider: 'entra', endpoint: 'https://scim.microsoftonline.com/v2', syncIntervalMinutes: 30, lastSync: new Date(Date.now() - 1 * 3600_000).toISOString(), status: 'active', usersSynced: 128, createdAt: new Date(Date.now() - 15 * 86400_000).toISOString() },
].forEach(c => {
  scimConnections.set(c.id, c);
  scimSyncLog.set(c.id, [
    { id: uuidv4(), connectionId: c.id, startedAt: new Date(Date.now() - 2 * 3600_000).toISOString(), completedAt: new Date(Date.now() - 2 * 3600_000 + 45000).toISOString(), status: 'completed', usersCreated: 2, usersUpdated: 5, usersDeleted: 0, errors: 0, message: 'Sync completed successfully' },
    { id: uuidv4(), connectionId: c.id, startedAt: new Date(Date.now() - 26 * 3600_000).toISOString(), completedAt: new Date(Date.now() - 26 * 3600_000 + 60000).toISOString(), status: 'completed', usersCreated: 0, usersUpdated: 3, usersDeleted: 1, errors: 0, message: 'Sync completed successfully' },
  ]);
});

app.get('/api/scim/connections', adminAuth, requireAdmin, (req, res) => {
  res.json([...scimConnections.values()]);
});

app.post('/api/scim/connections', adminAuth, requireAdmin, (req, res) => {
  const { name, provider, endpoint, bearerToken, syncInterval } = req.body;
  if (!name || !provider) return res.status(400).json({ error: 'name and provider are required' });
  if (!['google', 'entra', 'custom'].includes(provider)) return res.status(400).json({ error: 'provider must be google, entra, or custom' });
  const id = uuidv4();
  const tokenHash = bearerToken ? crypto.createHash('sha256').update(bearerToken).digest('hex') : null;
  const connection = {
    id,
    name,
    provider,
    endpoint: endpoint || null,
    bearerTokenHash: tokenHash,
    syncIntervalMinutes: syncInterval || 60,
    lastSync: null,
    status: 'active',
    usersSynced: 0,
    createdAt: new Date().toISOString(),
  };
  scimConnections.set(id, connection);
  scimSyncLog.set(id, []);
  const { bearerTokenHash: _, ...safe } = connection;
  res.status(201).json(safe);
});

app.put('/api/scim/connections/:id', adminAuth, requireAdmin, (req, res) => {
  const connection = scimConnections.get(req.params.id);
  if (!connection) return res.status(404).json({ error: 'Connection not found' });
  const { name, provider, endpoint, bearerToken, syncInterval } = req.body;
  const tokenHash = bearerToken ? crypto.createHash('sha256').update(bearerToken).digest('hex') : connection.bearerTokenHash;
  const updated = {
    ...connection,
    ...(name && { name }),
    ...(provider && { provider }),
    ...(endpoint !== undefined && { endpoint }),
    bearerTokenHash: tokenHash,
    ...(syncInterval && { syncIntervalMinutes: syncInterval }),
  };
  scimConnections.set(req.params.id, updated);
  const { bearerTokenHash: _, ...safe } = updated;
  res.json(safe);
});

app.delete('/api/scim/connections/:id', adminAuth, requireAdmin, (req, res) => {
  if (!scimConnections.has(req.params.id)) return res.status(404).json({ error: 'Connection not found' });
  scimConnections.delete(req.params.id);
  scimSyncLog.delete(req.params.id);
  res.status(204).send();
});

app.post('/api/scim/connections/:id/sync', adminAuth, requireAdmin, (req, res) => {
  const connection = scimConnections.get(req.params.id);
  if (!connection) return res.status(404).json({ error: 'Connection not found' });
  // Simulate a sync
  const logId = uuidv4();
  const startedAt = new Date().toISOString();
  connection.status = 'syncing';
  const logEntry = { id: logId, connectionId: req.params.id, startedAt, completedAt: null, status: 'running', usersCreated: 0, usersUpdated: 0, usersDeleted: 0, errors: 0, message: 'Sync in progress' };
  const log = scimSyncLog.get(req.params.id) || [];
  log.unshift(logEntry);
  scimSyncLog.set(req.params.id, log);

  // Simulate async completion
  setTimeout(() => {
    const usersCreated = Math.floor(Math.random() * 5);
    const usersUpdated = Math.floor(Math.random() * 10);
    logEntry.completedAt = new Date().toISOString();
    logEntry.status = 'completed';
    logEntry.usersCreated = usersCreated;
    logEntry.usersUpdated = usersUpdated;
    logEntry.message = 'Sync completed successfully';
    connection.status = 'active';
    connection.lastSync = logEntry.completedAt;
    connection.usersSynced = (connection.usersSynced || 0) + usersCreated + usersUpdated;
  }, 2000);

  res.json({ message: 'Sync started', logId, startedAt });
});

app.get('/api/scim/connections/:id/log', adminAuth, requireAdmin, (req, res) => {
  if (!scimConnections.has(req.params.id)) return res.status(404).json({ error: 'Connection not found' });
  const log = scimSyncLog.get(req.params.id) || [];
  res.json(log.slice(0, 50));
});

app.get('/api/scim/conflicts', adminAuth, requireAdmin, (req, res) => {
  const all = [...scimConflicts.values()].filter(c => !c.resolved);
  res.json(all);
});

app.post('/api/scim/conflicts/:id/resolve', adminAuth, requireAdmin, (req, res) => {
  const conflict = scimConflicts.get(req.params.id);
  if (!conflict) return res.status(404).json({ error: 'Conflict not found' });
  const { action } = req.body;
  if (!['keep_local', 'use_remote', 'merge'].includes(action)) return res.status(400).json({ error: 'action must be keep_local, use_remote, or merge' });
  conflict.resolved = true;
  conflict.resolution = action;
  conflict.resolvedAt = new Date().toISOString();
  scimConflicts.set(req.params.id, conflict);
  res.json(conflict);
});

// ─── Update Rings ─────────────────────────────────────────────────────────────────

app.get('/api/update-rings', adminAuth, requireAdmin, (req, res) => {
  res.json([...updateRings.values()]);
});

app.put('/api/update-rings/:id', adminAuth, requireAdmin, (req, res) => {
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

app.post('/api/update-rings/:id/assign', adminAuth, requireAdmin, (req, res) => {
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

app.post('/api/scim-push/:appId/provision', adminAuth, requireAdmin, (req, res) => {
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

app.post('/api/packages', adminAuth, requireAdmin, (req, res) => {
  const { name, version, platform, type, downloadUrl, silent, installScript } = req.body;
  if (!name || !platform) return res.status(400).json({ error: 'name and platform required' });
  const id = `pkg-${uuidv4().slice(0, 8)}`;
  const pkg = { id, name, version: version || 'latest', platform, type: type || 'script', downloadUrl, silent, installScript, addedAt: new Date().toISOString() };
  appPackages.set(id, pkg);
  res.status(201).json(pkg);
});

// Deploy package to a device
app.post('/api/packages/:pkgId/deploy/:deviceId', adminAuth, requireAdmin, (req, res) => {
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
app.post('/api/packages/:pkgId/deploy-all', adminAuth, requireAdmin, (req, res) => {
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
  res.json({ status: 'ok', service: 'oauth-provider', issuer: ISSUER, algorithm: 'RS256' });
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

async function start() {
  await db.initDb();
  if (process.env.NODE_ENV === 'production' && !db.isAvailable()) throw new Error('Client storage unavailable');
  await initializeClients();
  await mfaAuthority.ready();
  if (!mfaAuthority.demo) await mfaRecovery.ready();
  if (!mfaAuthority.demo) await mfaEnrollment.ready();
  connectBus();
  if (db.isAvailable()) {
    // Load existing SCIM catalog from DB into the in-memory Map (write-through cache)
    try {
      const scimRows = await db.getScimUsers('__catalog__');
      for (const row of scimRows) {
        if (!scimUsers.has(row.user_id)) {
          scimUsers.set(row.user_id, {
            id: row.user_id,
            userName: row.username,
            displayName: row.display_name,
            emails: row.email ? [{ value: row.email, primary: true }] : [],
            active: row.active !== false,
            groups: [],
          });
        }
      }
      if (scimRows.length > 0) {
        console.log(`[db] Loaded ${scimRows.length} SCIM user(s) from catalog`);
      }
    } catch (err) {
      console.warn('[db] Could not load SCIM catalog:', err.message);
    }
  }
  return app.listen(PORT, () => {
    console.log(`[oauth-provider] listening on :${PORT}`);
    // Seed default update rings if DB available
    if (db.isAvailable()) {
      seedDefaultUpdateRings();
    }
  });
}

if (require.main === module) {
  start().catch(err => {
    console.error('[oauth-provider] startup error:', err.message);
    process.exit(1);
  });
}

module.exports = app;
module.exports.start = start;
async function initializeClients() { return clientRegistry.initialize(clientSeeds, webClient, assertWebClient); }
module.exports.initializeClients = initializeClients;
