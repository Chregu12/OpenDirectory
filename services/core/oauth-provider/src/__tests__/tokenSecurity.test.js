'use strict';

process.env.OAUTH_ISSUER = 'https://opendirectory.security.test';
process.env.OAUTH_EPHEMERAL_SIGNING_KEYS = 'true';
process.env.OAUTH_SIGNING_KEY_FILE = '';
process.env.OAUTH_VERIFICATION_JWKS_FILE = '';
process.env.OAUTH_REVOCATION_DEMO_MODE = 'true';
process.env.OAUTH_PROVIDER_PORT = '0';
process.env.DEVPORTAL_CLIENT_SECRET = 'security-devportal-secret';
process.env.GRAFANA_CLIENT_SECRET = 'security-grafana-secret';

jest.mock('../db', () => ({
  isAvailable: jest.fn(() => false),
  saveToken: jest.fn().mockResolvedValue(undefined),
  getScimUsers: jest.fn().mockResolvedValue([]),
  query: jest.fn().mockResolvedValue({ rows: [{ count: '1' }] }),
  initDb: jest.fn().mockResolvedValue(undefined),
  upsertDevice: jest.fn(),
}));
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({ on: jest.fn(), connect: jest.fn().mockResolvedValue(undefined) })),
}));
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({ connect: jest.fn().mockResolvedValue(undefined), publish: jest.fn().mockResolvedValue(undefined) })),
}), { virtual: true });

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const supertest = require('supertest');
const app = require('../index');
const request = target => supertest(target === app ? testServer : target);
const db = require('../db');
const { getLicensePermissions } = require('../../../policy-service/src/middleware/licenseAccess');
const originalFetch = global.fetch;
const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
const clientId = 'devportal-od-client';
const clientSecret = 'security-devportal-secret';
const redirectUri = 'http://localhost:4000/callback';
let verificationKey;
let testServer;

beforeAll(async () => {
  testServer = app.listen(0);
  await new Promise(resolve => testServer.listening ? resolve() : testServer.once('listening', resolve));
  const jwks = await request(app).get('/.well-known/jwks.json');
  verificationKey = crypto.createPublicKey({ key: jwks.body.keys[0], format: 'jwk' });
});

beforeEach(() => {
  db.isAvailable.mockReturnValue(false);
  db.saveToken.mockReset().mockResolvedValue(undefined);
  global.fetch = jest.fn(async (url, options) => {
    if (!url.endsWith('/api/auth/login')) throw new Error('Unexpected authentication target');
    const credentials = JSON.parse(options.body);
    if (credentials.username === 'mfa-user' && credentials.mfaCode !== '123456') {
      return { ok: true, status: 202, json: async () => ({ mfaRequired: true, userId: 'mfa-user' }) };
    }
    return { ok: true, status: 200, json: async () => ({ success: true, user: {
      id: `verified-${credentials.username}`, username: credentials.username,
      roles: credentials.username === 'root' ? ['admin'] : credentials.username === 'session-admin' ? ['session-administrator'] : credentials.username === 'licensing' ? ['license-manager'] : ['user'],
      permissions: [],
    } }) };
  });
});

afterAll(async () => {
  global.fetch = originalFetch;
  await new Promise(resolve => testServer.close(resolve));
});

function verifiedPayload(token) {
  return jwt.verify(token, verificationKey, { algorithms: ['RS256'], issuer: process.env.OAUTH_ISSUER });
}

function login(username = 'alice', scope = 'openid', overrides = {}) {
  return request(app).post('/oauth/authorize/login').send({
    client_id: clientId, redirect_uri: redirectUri, username, password: 'valid-password', scope, ...overrides,
  });
}

async function tokenPair(username = 'alice', scope = 'openid', overrides = {}) {
  const response = await login(username, scope, overrides);
  expect(response.status).toBe(302);
  const code = new URL(response.headers.location).searchParams.get('code');
  const pair = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', code,
    client_id: overrides.client_id || clientId, client_secret: overrides.client_secret || clientSecret,
    redirect_uri: overrides.redirect_uri || redirectUri, code_verifier: overrides.code_verifier });
  expect(pair.status).toBe(200);
  return pair.body;
}

async function administrator() {
  return (await tokenPair('root', 'openid roles')).access_token;
}

async function createClient(metadata) {
  const token = await administrator();
  const response = await request(app).post('/api/clients').set('Authorization', `Bearer ${token}`).send({
    name: 'Security Test Application', scopes: ['openid'], grantTypes: ['authorization_code', 'refresh_token'],
    redirectUris: [redirectUri], enabled: true, ...metadata,
  });
  expect(response.status).toBe(201);
  return { ...response.body, adminToken: token };
}

async function deviceCode(scope = 'openid') {
  const response = await request(app).post('/oauth/device/code').send({ client_id: clientId, client_secret: clientSecret, scope });
  expect(response.status).toBe(200);
  return response.body;
}

function pollDevice(code, overrides = {}) {
  return request(app).post('/oauth/token').send({ grant_type: deviceGrant, client_id: clientId,
    client_secret: clientSecret, device_code: code, ...overrides });
}

describe('Application scope grants', () => {
  test.each(['oauth.admin', 'least-privilege.admin', 'openid oauth.admin', ['openid'], null, 'openid\nprofile', 'openid\tprofile'])('rejects ungranted or malformed scope %j before issuing a token', async scope => {
    const response = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials',
      client_id: 'grafana-od-client', client_secret: 'security-grafana-secret', scope });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_scope');
    expect(response.body.access_token).toBeUndefined();
  });

  test('requires explicit scopes even for an application with an approved administrative grant', async () => {
    const client = await createClient({ redirectUris: [], grantTypes: ['client_credentials'], scopes: ['oauth.admin'] });
    const omitted = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret });
    expect(verifiedPayload(omitted.body.access_token).scope).toBe('');
    expect((await request(app).get('/api/clients').set('Authorization', `Bearer ${omitted.body.access_token}`)).status).toBe(403);
    const granted = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret, scope: 'oauth.admin' });
    expect(granted.status).toBe(200);
    expect((await request(app).get('/api/clients').set('Authorization', `Bearer ${granted.body.access_token}`)).status).toBe(403);
  });

  test.each(['get', 'post'])('checks scope grants on %s authorization requests, including direct form posts', async method => {
    const operation = method === 'get' ? request(app).get('/oauth/authorize').query({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'oauth.admin' })
      : login('alice', 'oauth.admin');
    const response = await operation;
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_scope');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('a delegated application scope does not elevate an ordinary signed-in user', async () => {
    const client = await createClient({ scopes: ['openid', 'oauth.admin'] });
    const response = await login('alice', 'openid oauth.admin', { client_id: client.clientId, roles: ['admin'], permissions: ['oauth.admin'] });
    expect(response.status).toBe(403);
    expect(response.body.error).toBe('invalid_scope');
  });

  test('rechecks client scope grants at code redemption', async () => {
    const client = await createClient({ scopes: ['openid', 'profile'] });
    const authorization = await login('alice', 'openid profile', { client_id: client.clientId });
    expect(authorization.status).toBe(302);
    expect((await request(app).put(`/api/clients/${client.clientId}`).set('Authorization', `Bearer ${client.adminToken}`).set('If-Match', `"od-client:${client.clientId}:${client.version}"`).send({ scopes: ['openid'] })).status).toBe(200);
    const response = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', client_id: client.clientId,
      client_secret: client.clientSecret, redirect_uri: redirectUri, code: new URL(authorization.headers.location).searchParams.get('code') });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_grant');
  });

  test('identical token requests produce distinct revocable credentials', async () => {
    const body = { grant_type: 'client_credentials', client_id: 'grafana-od-client', client_secret: 'security-grafana-secret', scope: 'openid' };
    const first = await request(app).post('/oauth/token').send(body);
    const second = await request(app).post('/oauth/token').send(body);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(verifiedPayload(first.body.access_token).jti).not.toBe(verifiedPayload(second.body.access_token).jti);
  });
});

describe('Verified identities and MFA', () => {
  test('authentication outage fails closed instead of accepting the submitted username', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Authentication service offline'));
    const response = await login('root', 'openid roles');
    expect(response.status).toBe(503);
    expect(response.body.error).toBe('authentication_unavailable');
    expect(response.headers.location).toBeUndefined();
  });

  test.each([
    { mfaRequired: true, userId: 'root' },
    { requiresMFA: true, tempToken: 'challenge' },
    { success: true, user: { roles: ['admin'] } },
    { success: false, user: { id: 'root', roles: ['admin'] } },
    { success: true, user: { id: 'root', active: false, roles: ['admin'] } },
  ])('does not issue a code for incomplete or failed authentication: %j', async data => {
    global.fetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => data });
    const response = await login('root', 'openid roles');
    expect(response.status).toBe(401);
    expect(response.headers.location).toBeUndefined();
  });

  test('requires a completed MFA challenge and forwards the one-time code', async () => {
    expect((await login('mfa-user')).status).toBe(401);
    const pair = await tokenPair('mfa-user', 'openid', { mfaCode: '123456' });
    expect(verifiedPayload(pair.access_token).sub).toBe('verified-mfa-user');
    const upstream = global.fetch.mock.calls.find(([, options]) => JSON.parse(options.body).mfaCode === '123456');
    expect(upstream).toBeDefined();
  });

  test('issues license roles only from the completed authentication result', async () => {
    const pair = await tokenPair('licensing', 'openid roles', { roles: ['admin'], permissions: ['*'] });
    const payload = verifiedPayload(pair.access_token);
    expect(payload.sub).toBe('verified-licensing');
    expect(payload.roles).toEqual(['license-manager']);
    expect(getLicensePermissions(payload)).toContain('licenses.catalog.manage');
    expect(getLicensePermissions(payload)).not.toContain('licenses.requests.review');
  });

  test('stores the actual signed expiry and token identifier instead of missing expiry metadata', async () => {
    db.isAvailable.mockReturnValue(true);
    const pair = await tokenPair('alice', 'openid');
    const payload = verifiedPayload(pair.access_token);
    expect(db.saveToken).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ exp: payload.exp, iat: payload.iat, jti: payload.jti }));
    expect(payload.exp).toBeGreaterThan(payload.iat);
  });

  test('does not send administrative claims to an application without the roles scope', async () => {
    const pair = await tokenPair('root', 'openid profile');
    const payload = verifiedPayload(pair.access_token);
    expect(payload.roles).toBeUndefined();
    expect(payload.permissions).toBeUndefined();
    expect((await request(app).get('/api/clients').set('Authorization', `Bearer ${pair.access_token}`)).status).toBe(403);
  });

  test('ID tokens cannot substitute for access tokens', async () => {
    const pair = await tokenPair('root', 'openid roles');
    const identity = verifiedPayload(pair.id_token);
    expect(identity.token_use).toBe('id');
    expect(identity.roles).toBeUndefined();
    expect(identity.permissions).toBeUndefined();
    expect(identity.scope).toBeUndefined();
    expect((await request(app).get('/api/clients').set('Authorization', `Bearer ${pair.id_token}`)).status).toBe(403);
    expect((await request(app).get('/oauth/userinfo').set('Authorization', `Bearer ${pair.id_token}`)).status).toBe(401);
  });

  test('binds the OIDC nonce to the signed identity token rather than inventing one', async () => {
    const pair = await tokenPair('alice', 'openid', { nonce: 'browser-session-nonce' });
    expect(verifiedPayload(pair.id_token).nonce).toBe('browser-session-nonce');
    expect(verifiedPayload(pair.access_token).nonce).toBeUndefined();
  });

  test('validates the posted redirect URI before contacting the authentication service', async () => {
    const response = await login('root', 'openid', { redirect_uri: 'https://unregistered.example/callback' });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_redirect_uri');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('escapes attacker-controlled HTML values in authentication forms', async () => {
    const injected = '"><script>window.injected=true</script>';
    const response = await request(app).get('/oauth/authorize').query({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', state: injected });
    expect(response.status).toBe(200);
    expect(response.text).not.toContain(injected);
    expect(response.text).toContain('&lt;script&gt;');
    const device = await request(app).get('/oauth/device/verify').query({ user_code: injected, error: injected });
    expect(device.text).not.toContain(injected);
  });
});

describe('Shared API audience and issuing application ownership', () => {
  test('does not advertise or fake whole-session logout using an arbitrary redirect', async () => {
    const discovery = await request(app).get('/.well-known/openid-configuration');
    expect(discovery.body.end_session_endpoint).toBeUndefined();
    const result = await request(app).get('/oauth/logout').query({ post_logout_redirect_uri: 'https://untrusted.example' });
    expect(result.status).toBe(410);
    expect(result.headers.location).toBeUndefined();
    expect(result.body.error).toBe('oidc_logout_not_implemented');
  });

  test('does not turn a long-lived legacy enrollment credential into a first-party API access token', async () => {
    const administratorToken = await administrator();
    const enrollment = await request(app).get('/api/enrollment/tokens').set('Authorization', `Bearer ${administratorToken}`);
    db.isAvailable.mockReturnValueOnce(true);db.upsertDevice.mockImplementationOnce(async device=>({id:device.id,platform:device.platform,policy_generation:'1'}));
    const issued = await request(app).post('/api/enrollment/register').send({ token: enrollment.body.find(record => record.platform === 'linux').token,
      platform: 'linux', hostname: 'audience-boundary-test', serial: 'test' });
    expect(issued.status).toBe(201);
    const payload = verifiedPayload(issued.body.deviceToken);
    expect(payload.aud).toBe('opendirectory-device-agent');
    expect(payload.token_use).toBe('device');
    expect(payload.device_generation).toBe('1');
    expect(payload.client_id).toBeUndefined();
    expect(() => jwt.verify(issued.body.deviceToken, verificationKey, { algorithms: ['RS256'], issuer: process.env.OAUTH_ISSUER, audience: 'opendirectory-api' })).toThrow();
    expect((await request(app).get(`/api/devices/${issued.body.deviceId}/commands/pending`).set('Authorization', `Bearer ${issued.body.deviceToken}`)).status).toBe(503);
    expect((await request(app).get('/api/devices/another-device/commands/pending').set('Authorization', `Bearer ${issued.body.deviceToken}`)).status).toBe(403);
    expect((await request(app).get('/api/clients').set('Authorization', `Bearer ${issued.body.deviceToken}`)).status).toBe(403);
    expect((await request(app).get(`/api/devices/${issued.body.deviceId}/commands/pending`).set('Authorization', `Bearer ${(await tokenPair('alice', 'openid roles')).access_token}`)).status).toBe(403);
  });

  test('keeps the identity audience client-specific and ignores requested API audience overrides', async () => {
    const pair = await tokenPair('alice', 'openid', { aud: 'attacker-api', audience: 'attacker-api', resource: 'https://attacker.example' });
    expect(verifiedPayload(pair.access_token)).toMatchObject({ aud: 'opendirectory-api', client_id: clientId, token_use: 'access' });
    expect(verifiedPayload(pair.id_token)).toMatchObject({ aud: clientId, token_use: 'id' });
    expect(verifiedPayload(pair.id_token).client_id).toBeUndefined();
  });

  test('preserves the API audience and original application after refresh rotation', async () => {
    const pair = await tokenPair();
    const refreshed = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: clientId, client_secret: clientSecret, audience: 'other-api' });
    expect(refreshed.status).toBe(200);
    expect(verifiedPayload(refreshed.body.access_token)).toMatchObject({ aud: 'opendirectory-api', client_id: clientId });
  });

  test('does not reveal another application token through shared-audience introspection', async () => {
    const pair = await tokenPair();
    const own = await request(app).post('/oauth/introspect').send({ token: pair.access_token, client_id: clientId, client_secret: clientSecret });
    expect(own.body).toMatchObject({ active: true, aud: 'opendirectory-api', client_id: clientId });
    const other = await request(app).post('/oauth/introspect').send({ token: pair.access_token,
      client_id: 'grafana-od-client', client_secret: 'security-grafana-secret' });
    expect(other.body).toEqual({ active: false });
  });

  test('binds signed client-credentials ownership to client_id for revocation without an access-token map record', async () => {
    const client = await createClient({ grantTypes: ['client_credentials'], redirectUris: [], scopes: ['openid'] });
    const issued = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials', client_id: client.clientId,
      client_secret: client.clientSecret, scope: 'openid' });
    expect(issued.status).toBe(200);
    expect(verifiedPayload(issued.body.access_token)).toMatchObject({ aud: 'opendirectory-api', client_id: client.clientId });
    await request(app).post('/oauth/revoke').send({ token: issued.body.access_token, client_id: clientId, client_secret: clientSecret }).expect(200);
    const inspect = () => request(app).post('/oauth/introspect').send({ token: issued.body.access_token,
      client_id: client.clientId, client_secret: client.clientSecret });
    expect((await inspect()).body.active).toBe(true);
    await request(app).post('/oauth/revoke').send({ token: issued.body.access_token,
      client_id: client.clientId, client_secret: client.clientSecret }).expect(200);
    expect((await inspect()).body).toEqual({ active: false });
  });
});

describe('Client-bound refresh grants', () => {
  test('parallel refresh requests cannot redeem the same credential twice across the live-state await', async () => {
    const pair = await tokenPair();
    const renew = () => request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token, client_id: clientId, client_secret: clientSecret });
    const results = await Promise.all([renew(), renew()]);
    expect(results.map(result => result.status).sort()).toEqual([200, 400]);
    expect(results.filter(result => result.body.access_token)).toHaveLength(1);
    const winner = results.find(result => result.status === 200).body.access_token;
    expect((await request(app).get('/oauth/access-state').set('Authorization', `Bearer ${winner}`)).body.active).toBe(false);
  });

  test.each([{}, [], null, ''])('rejects malformed refresh credentials without a server error: %j', async credential => {
    const response = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: credential, client_id: clientId, client_secret: clientSecret });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_grant');
  });
  test('cannot redeem a stolen refresh token as another authenticated application', async () => {
    const pair = await tokenPair();
    const response = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: 'grafana-od-client', client_secret: 'security-grafana-secret' });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_grant');
    const valid = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token, client_id: clientId, client_secret: clientSecret });
    expect(valid.status).toBe(200);
    expect(verifiedPayload(valid.body.access_token).aud).toBe('opendirectory-api');
    expect(verifiedPayload(valid.body.access_token).client_id).toBe(clientId);
  });

  test.each(['openid roles', 'oauth.admin', null, ['openid']])('cannot expand or corrupt the original scope grant: %j', async scope => {
    const pair = await tokenPair('alice', 'openid');
    const response = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: clientId, client_secret: clientSecret, scope });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_scope');
  });

  test('downscopes permanently and removes authorization claims when roles is dropped', async () => {
    const pair = await tokenPair('root', 'openid roles');
    const narrowed = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: clientId, client_secret: clientSecret, scope: 'openid' });
    expect(narrowed.status).toBe(200);
    expect(narrowed.body.scope).toBe('openid');
    expect(verifiedPayload(narrowed.body.access_token).roles).toBeUndefined();
    const widened = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: narrowed.body.refresh_token,
      client_id: clientId, client_secret: clientSecret, scope: 'openid roles' });
    expect(widened.status).toBe(400);
    expect(widened.body.error).toBe('invalid_scope');
  });

  test('refresh credentials have an absolute lifetime', async () => {
    const pair = await tokenPair();
    const now = Date.now();
    const time = jest.spyOn(Date, 'now').mockReturnValue(now + 31 * 86400_000);
    try {
      const response = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token, client_id: clientId, client_secret: clientSecret });
      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_grant');
    } finally { time.mockRestore(); }
  });
});

describe('Least-privilege session control', () => {
  const selfScopes = 'openid sessions.self.read sessions.self.revoke';

  test('requires an approved self-service scope and never substitutes URL credentials or body roles', async () => {
    const pair = await tokenPair('session-user', 'openid');
    expect((await request(app).get('/oauth/sessions').set('Authorization', `Bearer ${pair.access_token}`)).status).toBe(403);
    expect((await request(app).get('/oauth/sessions').query({ token: pair.access_token })).status).toBe(401);
    expect((await request(app).post('/oauth/sessions/revoke-all').set('Authorization', `Bearer ${pair.access_token}`).send({ roles: ['admin'] })).status).toBe(403);
  });

  test('lists only minimal owner metadata and hides another subject session from revoke attempts', async () => {
    const own = await tokenPair('own-sessions', selfScopes); const other = await tokenPair('other-sessions', selfScopes);
    const listed = await request(app).get('/oauth/sessions').set('Authorization', `Bearer ${own.access_token}`);
    expect(listed.status).toBe(200); expect(listed.body.sessions).toHaveLength(1);
    expect(listed.body.sessions[0]).toMatchObject({ id: verifiedPayload(own.access_token).sid, current: true, principalType: 'user' });
    expect(JSON.stringify(listed.body)).not.toMatch(/refresh_token|claims_snapshot|permissions|email|token_hash/);
    const attempt = await request(app).delete(`/oauth/sessions/${verifiedPayload(other.access_token).sid}`).set('Authorization', `Bearer ${own.access_token}`).send({ permissions: ['sessions.revoke'] });
    expect(attempt.status).toBe(404);
    expect((await request(app).get('/oauth/access-state').set('Authorization', `Bearer ${other.access_token}`)).body.active).toBe(true);
  });

  test('terminates the complete current family while keeping an independent login active', async () => {
    const pair = await tokenPair('family-owner', selfScopes); const independent = await tokenPair('family-owner', selfScopes);
    const renewed = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: pair.refresh_token, client_id: clientId, client_secret: clientSecret });
    expect(renewed.status).toBe(200);
    expect(verifiedPayload(renewed.body.access_token)).toMatchObject({ sid: verifiedPayload(pair.access_token).sid, auth_time: verifiedPayload(pair.access_token).auth_time });
    expect((await request(app).post('/oauth/sessions/current/revoke').set('Authorization', `Bearer ${renewed.body.access_token}`)).status).toBe(200);
    for (const token of [pair.access_token, renewed.body.access_token]) expect((await request(app).get('/oauth/access-state').set('Authorization', `Bearer ${token}`)).body.active).toBe(false);
    expect((await request(app).get('/oauth/access-state').set('Authorization', `Bearer ${independent.access_token}`)).body.active).toBe(true);
    expect((await request(app).post('/oauth/token').send({ grant_type: 'refresh_token', refresh_token: renewed.body.refresh_token, client_id: clientId, client_secret: clientSecret })).status).toBe(400);
  });

  test('a narrow session administrator can revoke a target family without gaining client administration', async () => {
    const target = await tokenPair('session-target', selfScopes); const administratorPair = await tokenPair('session-admin', 'openid roles');
    const authorization = `Bearer ${administratorPair.access_token}`;
    expect((await request(app).get('/api/clients').set('Authorization', authorization)).status).toBe(403);
    expect((await request(app).delete(`/oauth/sessions/${verifiedPayload(target.access_token).sid}`).set('Authorization', authorization)).status).toBe(200);
    expect((await request(app).get('/oauth/access-state').set('Authorization', `Bearer ${target.access_token}`)).body.active).toBe(false);
  });
});

describe('Device authorization trust', () => {
  test.each([{}, { client_id: 'unknown' }, { client_id: clientId }, { client_id: clientId, client_secret: 'wrong' }])('requires a registered authenticated device application: %j', async body => {
    const response = await request(app).post('/oauth/device/code').send(body);
    expect(response.status).toBe(401);
  });

  test('scope checks also protect device code issuance', async () => {
    const response = await request(app).post('/oauth/device/code').send({ client_id: clientId, client_secret: clientSecret, scope: 'oauth.admin' });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_scope');
  });

  test('does not approve devices while the authentication service is down', async () => {
    const code = await deviceCode();
    global.fetch.mockRejectedValueOnce(new Error('Offline'));
    const approval = await request(app).post('/oauth/device/approve').send({ user_code: code.user_code, username: 'root', password: 'test-password' });
    expect(approval.status).toBe(503);
    expect((await pollDevice(code.device_code)).body.error).toBe('authorization_pending');
  });

  test('MFA-required approval stays pending until a verified result arrives', async () => {
    const code = await deviceCode('openid roles');
    expect((await request(app).post('/oauth/device/approve').send({ user_code: code.user_code, username: 'mfa-user', password: 'test-password' })).status).toBe(401);
    expect((await pollDevice(code.device_code)).body.error).toBe('authorization_pending');
    expect((await request(app).post('/oauth/device/approve').send({ user_code: code.user_code, username: 'mfa-user', password: 'test-password', mfaCode: '123456' })).status).toBe(200);
    const token = await pollDevice(code.device_code);
    expect(token.status).toBe(200);
    expect(verifiedPayload(token.body.access_token).sub).toBe('verified-mfa-user');
  });

  test('binds an approved device code to its original client and consumes it only once', async () => {
    const other = await createClient({ publicClient: true, redirectUris: [], grantTypes: [deviceGrant] });
    const code = await deviceCode();
    expect((await request(app).post('/oauth/device/approve').send({ user_code: code.user_code, username: 'alice', password: 'test-password' })).status).toBe(200);
    const wrongClient = await pollDevice(code.device_code, { client_id: other.clientId, client_secret: undefined });
    expect(wrongClient.status).toBe(400);
    expect(wrongClient.body.error).toBe('invalid_grant');
    expect((await pollDevice(code.device_code)).status).toBe(200);
    expect((await pollDevice(code.device_code)).body.error).toBe('expired_token');
  });
});

describe('Client administration and persistent grants', () => {
  test.each([
    { publicClient: true, grantTypes: ['client_credentials'], redirectUris: [] },
    { scopes: 'oauth.admin' },
    { scopes: ['openid', {}] },
    { grantTypes: ['password'] },
    { redirectUris: ['javascript:alert(1)'] },
    { publicClient: 'false' },
  ])('rejects invalid client metadata: %j', async metadata => {
    const token = await administrator();
    const response = await request(app).post('/api/clients').set('Authorization', `Bearer ${token}`).send({
      name: 'Invalid Application', redirectUris: [redirectUri], ...metadata,
    });
    expect(response.status).toBe(400);
  });

  test('requires exact versions for changed scope grants and rejects a stale replacement', async () => {
    const client = await createClient({ grantTypes: ['client_credentials'], redirectUris: [], scopes: ['openid'] });
    const version = `"od-client:${client.clientId}:${client.version}"`;
    const updated = await request(app).put(`/api/clients/${client.clientId}`).set('Authorization', `Bearer ${client.adminToken}`).set('If-Match', version).send({ scopes: ['openid', 'oauth.admin'] });
    expect(updated.status).toBe(200);
    expect(updated.body.scopes).toEqual(['openid', 'oauth.admin']);
    const failed = await request(app).put(`/api/clients/${client.clientId}`).set('Authorization', `Bearer ${client.adminToken}`).set('If-Match', version).send({ scopes: ['openid', 'oauth.admin', 'least-privilege.admin'] });
    expect(failed.status).toBe(412);
    const uncommitted = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret, scope: 'least-privilege.admin' });
    expect(uncommitted.status).toBe(400);
    expect(uncommitted.body.error).toBe('invalid_scope');
  });

  test('supports public browser applications with S256 PKCE and no client credentials', async () => {
    const client = await createClient({ publicClient: true });
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const authorization = await login('alice', 'openid', { client_id: client.clientId, code_challenge: challenge, code_challenge_method: 'S256' });
    const code = new URL(authorization.headers.location).searchParams.get('code');
    const response = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', client_id: client.clientId,
      redirect_uri: redirectUri, code, code_verifier: verifier });
    expect(response.status).toBe(200);
    expect(verifiedPayload(response.body.access_token).sub).toBe('verified-alice');
    const service = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials', client_id: client.clientId });
    expect(service.status).toBe(401);
    const revoked = await request(app).post('/oauth/revoke').send({ client_id: client.clientId, token: response.body.access_token });
    expect(revoked.status).toBe(200);
    expect((await request(app).get('/oauth/userinfo').set('Authorization', `Bearer ${response.body.access_token}`)).status).toBe(401);
  });

  test.each([{}, { code_challenge: 'plain-verifier', code_challenge_method: 'plain' }, { code_challenge: 'invalid', code_challenge_method: 'S256' }])('public browser applications cannot initiate a flow without valid S256 PKCE: %j', async challenge => {
    const client = await createClient({ publicClient: true });
    const response = await login('alice', 'openid', { client_id: client.clientId, ...challenge });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_request');
  });
});

describe('Registry startup authority', () => {
  test('does not start a production issuer with a missing client database', async () => {
    const environment = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try { await expect(app.start()).rejects.toThrow('Client storage unavailable'); }
    finally {
      if (environment === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = environment;
    }
  });

});
