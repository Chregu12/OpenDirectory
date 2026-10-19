'use strict';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { once } = require('node:events');
const { BrowserAuth, BrowserAuthError } = require('../src/server/browserAuth.cjs');
const { generate } = require('../scripts/browser-secret.cjs');

let directory; let config; let signer; let server; let auth; let flow; let tokenCalls; let stateActive; let stateUnavailable; let invalidId;
const subject = 'verified-user'; const sid = crypto.randomUUID(); const issuer = 'https://issuer.test';
const now = Math.floor(Date.now() / 1000); const originalRefresh = 'disposable-opaque-refresh-token-123456789';
function recoveryRequest(body = {}, headers = {}, action = 'start') {
  return new Request(config.origin + '/api/auth/oidc/recovery/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: config.origin, 'X-OD-Recovery': '1', 'Sec-Fetch-Site': 'same-origin', ...headers }, body: JSON.stringify(body) });
}
function companyRequest(body, headers = {}, query = '') {
  return new Request(config.origin + '/api/company-registration/submit' + query, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: config.origin, 'X-OD-Company-Registration': '1', 'Sec-Fetch-Site': 'same-origin', ...headers }, body: JSON.stringify(body) });
}
function companyFixture() {
  const registrationId = crypto.randomUUID();
  const body = { registrationId, username: 'verified-provider-user', password: 'disposable-provider-password', mfaCode: '', confirm: true,
    profile: { name: 'Company AG', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' } };
  const receipt = { schemaVersion: 1, registrationId, tenantId: crypto.randomUUID(), administratorId: crypto.randomUUID(), createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed: false };
  return { body, receipt };
}
test('company activation requires explicit same-origin intent and a real active receipt without returning a session', async () => {
  const { body, receipt } = companyFixture(); const input = { registrationId: body.registrationId, username: body.username, password: body.password, mfaCode: '', confirm: true };
  const active = { ...receipt, schemaVersion: 3, status: 'active', tenantEnabled: true, administratorEnabled: true, profileSaved: true, activationSupported: true, reviewedAt: '2026-10-19T01:00:00Z', activatedAt: '2026-10-19T02:00:00Z', consoleClientId: 'web-app', mfaRequired: true };
  const local = new BrowserAuth({ ...config, fetchImpl: async () => json(active) }); const result = await local.companyRegistration(companyRequest(input), 'activate'); assert.equal(result.status, 200); assert.deepEqual(await result.json(), active); assert.equal(result.headers.get('set-cookie'), null);
  assert.equal((await local.companyRegistration(companyRequest({ ...input, confirm: false }), 'activate')).status, 400);
  const pending = new BrowserAuth({ ...config, fetchImpl: async () => json(receipt) }); assert.equal((await pending.companyRegistration(companyRequest(input), 'activate')).status, 503);
});
test('reviewed company status passes the BFF only as a versioned disabled receipt, without a session or private review disclosure', async () => {
  const { body, receipt } = companyFixture(); const credentials = { registrationId: body.registrationId, username: body.username, password: body.password, mfaCode: '' };
  for (const status of ['pending-activation', 'rejected']) {
    const observed = { ...receipt, schemaVersion: 2, status, reviewedAt: '2026-10-19T01:00:00Z', replayed: true };
    const local = new BrowserAuth({ ...config, fetchImpl: async () => json(observed) }); const result = await local.companyRegistration(companyRequest(credentials), 'status');
    assert.equal(result.status, 200); assert.deepEqual(await result.json(), observed); assert.equal(result.headers.get('set-cookie'), null); assert.equal(result.headers.get('cache-control'), 'no-store');
    const leaking = new BrowserAuth({ ...config, fetchImpl: async () => json({ ...observed, reason: 'Private platform review evidence' }) });
    assert.equal((await leaking.companyRegistration(companyRequest(credentials), 'status')).status, 503);
  }
});
test('anonymous company registration forwards only the explicit same-origin credential request to the configured issuer, not existing cookies or bearers', async () => {
  const { body, receipt } = companyFixture(); let observed;
  const local = new BrowserAuth({ ...config, fetchImpl: async (url, options) => { observed = { url, options }; return json(receipt, 201); } });
  const response = await local.companyRegistration(companyRequest(body, { Cookie: 'old-session', Authorization: 'Bearer old-token' }), 'submit'); assert.equal(response.status, 201); assert.deepEqual(await response.json(), receipt);
  assert.equal(observed.url.origin, new URL(config.internalUrl).origin); assert.equal(observed.url.pathname, '/oauth/company-registration/submit'); assert.deepEqual(Object.keys(observed.options.headers), ['Content-Type']); assert.equal(response.headers.getSetCookie().length, 0);
});
test('anonymous company registration rejects cross-origin, missing intent, selector queries, privilege fields and oversized input before reaching the issuer', async () => {
  const { body } = companyFixture(); let calls = 0; const local = new BrowserAuth({ ...config, fetchImpl: async () => { calls++; throw new Error('must not reach issuer'); } });
  for (const request of [companyRequest(body, { Origin: 'https://attacker.test' }), companyRequest(body, { 'X-OD-Company-Registration': '' }), companyRequest(body, { 'Sec-Fetch-Site': 'cross-site' }), companyRequest(body, {}, '?tenantId=foreign'), companyRequest({ ...body, roles: ['admin'] }), companyRequest({ ...body, password: 'x'.repeat(40000) })]) assert.ok([400, 403].includes((await local.companyRegistration(request, 'submit')).status));
  assert.equal(calls, 0);
});
test('anonymous company registration never accepts an activated, foreign or token-bearing plausible receipt', async () => {
  const { body, receipt } = companyFixture();
  for (const value of [{ ...receipt, tenantEnabled: true }, { ...receipt, registrationId: crypto.randomUUID() }, { ...receipt, access_token: 'invalid-purpose' }]) {
    const local = new BrowserAuth({ ...config, fetchImpl: async () => json(value, 201) }); assert.equal((await local.companyRegistration(companyRequest(body), 'submit')).status, 503);
  }
});
test('anonymous company capabilities are actual pending-only issuer metadata and carry no browser credentials', async () => {
  const capabilities = { schemaVersion: 1, enabled: false, requiresExistingAccount: true, activationSupported: false, status: 'pending-verification' }; let observed;
  const local = new BrowserAuth({ ...config, fetchImpl: async (url, options) => { observed = { url, options }; return json(capabilities); } });
  const response = await local.companyRegistration(new Request(config.origin + '/api/company-registration'), 'capabilities'); assert.equal(response.status, 200); assert.deepEqual(await response.json(), capabilities); assert.equal(observed.url.pathname, '/oauth/company-registration'); assert.equal(observed.options.headers, undefined);
});
test('anonymous company registration treats a lost issuer acknowledgement as unconfirmed without an automatic second write', async () => {
  const { body } = companyFixture(); let calls = 0; const local = new BrowserAuth({ ...config, fetchImpl: async () => { calls++; throw new Error('response lost'); } });
  const response = await local.companyRegistration(companyRequest(body), 'submit'); assert.equal(response.status, 503); assert.equal(calls, 1); assert.equal(JSON.stringify(await response.json()).includes(body.password), false);
});

async function signed(overrides = {}, purpose = 'access') {
  const { SignJWT } = await import('jose');
  return new SignJWT({ iss: issuer, sub: subject, aud: purpose === 'id' ? 'web-app' : 'opendirectory-api', iat: now, exp: now + 1800,
    jti: crypto.randomUUID(), sid, auth_time: now, actor_type: 'user', token_use: purpose, client_id: 'web-app', roles: ['user'],
    ...(purpose === 'id' ? { nonce: flow?.nonce } : {}), ...overrides }).setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'JWT' }).sign(signer);
}

function json(value, status = 200) { return Response.json(value, { status }); }
function cookies(response) { return response.headers.getSetCookie().map(value => value.split(';')[0]).join('; '); }
function sessionCookie(overrides = {}) {
  return auth.sessionCookie + '=' + auth.seal({ subject, sid, authTime: now, csrf: 'disposable-csrf', refreshToken: originalRefresh,
    expiresAt: (now + 86400) * 1000, ...overrides }, 'session');
}
function sessionRequest(overrides = {}) {
  return new Request(config.origin + '/api/auth/oidc/session', { method: 'POST', headers: {
    Origin: config.origin, Cookie: sessionCookie(), 'X-OD-CSRF': 'disposable-csrf', 'Sec-Fetch-Site': 'same-origin', ...overrides } });
}

before(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-browser-auth-'));
  const keyFile = path.join(directory, 'cookie.key'); const clientSecretFile = path.join(directory, 'client.secret');
  fs.writeFileSync(keyFile, crypto.randomBytes(32), { mode: 0o600 });
  fs.writeFileSync(clientSecretFile, 'disposable-confidential-secret-123456789', { mode: 0o600 });
  const material = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }); signer = material.privateKey;
  const jwk = { ...material.publicKey.export({ format: 'jwk' }), alg: 'RS256', use: 'sig', kid: 'test-key' };
  server = http.createServer((request, response) => {
    assert.equal(request.url, '/.well-known/jwks.json'); response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ keys: [jwk] }));
  }).listen(0, '127.0.0.1'); await once(server, 'listening');
  config = { origin: 'https://web.test', issuer, publicUrl: 'https://login.test', internalUrl: 'http://127.0.0.1:' + server.address().port,
    keyFile, clientSecretFile, fetchImpl: async (url, options) => {
      if (url.pathname === '/oauth/token') {
        tokenCalls++; const body = JSON.parse(options.body);
        assert.equal(body.client_id, 'web-app'); assert.equal(body.client_secret, 'disposable-confidential-secret-123456789');
        if (body.grant_type === 'authorization_code') assert.equal(body.code_verifier, flow.verifier);
        return json({ token_type: 'Bearer', access_token: await signed(), id_token: await signed(invalidId ? { nonce: 'wrong' } : {}, 'id'),
          refresh_token: tokenCalls === 1 ? originalRefresh : 'rotated-opaque-refresh-token-123456789' });
      }
      if (url.pathname === '/oauth/access-state') {
        if (stateUnavailable) return json({}, 503);
        const token = options.headers.Authorization.slice(7); const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));
        return json(stateActive ? { schemaVersion: 1, active: true, issuer: claims.iss, subject: claims.sub, tokenId: claims.jti, expiresAt: claims.exp } : { schemaVersion: 1, active: false });
      }
      if (url.pathname === '/oauth/revoke') return json(stateUnavailable ? {} : { revoked: true }, stateUnavailable ? 503 : 200);
      throw new Error('Unexpected authority endpoint');
    } };
});
beforeEach(() => { auth = new BrowserAuth(config); flow = null; tokenCalls = 0; stateActive = true; stateUnavailable = false; invalidId = false; });
after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); fs.rmSync(directory, { recursive: true, force: true }); });

async function callback(queryOverride) {
  const login = await auth.login(); const location = new URL(login.headers.get('location'));
  const cookie = cookies(login); flow = auth.unseal(cookie.slice(cookie.indexOf('=') + 1), 'flow');
  const query = queryOverride === undefined ? '?state=' + location.searchParams.get('state') + '&code=one-use-code' : queryOverride;
  return auth.callback(new Request(config.origin + '/auth/callback' + query, { headers: { Cookie: cookie } }));
}

test('login uses canonical authorize, exact callback, fresh state/nonce and S256; flow cookie is sealed, HttpOnly and Lax', async () => {
  const response = await auth.login(); const location = new URL(response.headers.get('location'));
  assert.equal(location.origin, 'https://login.test'); assert.equal(location.pathname, '/oauth/authorize');
  assert.equal(location.searchParams.get('redirect_uri'), 'https://web.test/auth/callback');
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
  const cookie = response.headers.getSetCookie()[0]; assert.match(cookie, /; HttpOnly; Secure/); assert.match(cookie, /SameSite=Lax/);
  const decoded = auth.unseal(cookies(response).split('=')[1], 'flow');
  assert.equal(location.searchParams.get('code_challenge'), crypto.createHash('sha256').update(decoded.verifier).digest('base64url'));
  assert.notEqual(new URL((await auth.login()).headers.get('location')).searchParams.get('state'), decoded.state);
});

test('callback verifies identity/access/live state and exposes neither token nor secret in the redirect', async () => {
  const response = await callback(); assert.equal(response.status, 303); assert.equal(response.headers.get('location'), config.origin + '/dashboard');
  const headers = response.headers.getSetCookie(); const session = headers.find(value => value.startsWith(auth.sessionCookie + '='));
  assert.equal(auth.csrfCookie, '__Host-od_csrf');
  assert.match(session, /Path=\/api\/auth\/oidc/); assert.match(session, /SameSite=Strict; HttpOnly; Secure/);
  assert.equal(session.includes(originalRefresh), false); assert.equal(session.includes(subject), false); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(headers.find(value => value.startsWith(auth.csrfCookie + '=')), /Path=\/;.*SameSite=Strict; Secure$/);
});

for (const query of ['?code=x', '?code=x&state=wrong', '?code=x&state=ä'.repeat(2), '?code=x&state=x&state=x', '?state=x&code=x&code=y']) {
  test('callback rejects missing, duplicate or mismatched state before code exchange: ' + query, async () => {
    const response = await callback(query); assert.equal(response.status, 401); assert.equal(tokenCalls, 0);
  });
}
test('ID-token nonce failure does not create an authenticated cookie', async () => {
  invalidId = true; const response = await callback(); assert.equal(response.status, 401);
  assert.equal(response.headers.getSetCookie().some(value => value.startsWith(auth.sessionCookie + '=')), false);
});
test('tampered, expired and purpose-confused cookies fail authentication', () => {
  const value = auth.seal({ expiresAt: Date.now() + 10000 }, 'flow');
  assert.throws(() => auth.unseal(value, 'session'), BrowserAuthError);
  assert.throws(() => auth.unseal(value + 'x', 'flow'), BrowserAuthError);
  assert.throws(() => auth.unseal(auth.seal({ expiresAt: 1 }, 'flow'), 'flow'), BrowserAuthError);
  const other = new BrowserAuth({ ...config, origin: 'https://other.test' }); assert.throws(() => other.unseal(value, 'flow'), BrowserAuthError);
});

for (const overrides of [{ Origin: 'https://evil.test' }, { Origin: '' }, { 'X-OD-CSRF': 'wrong' }, { 'Sec-Fetch-Site': 'cross-site' }]) {
  test('session and logout deny foreign origin or missing CSRF without rotating: ' + JSON.stringify(overrides), async () => {
    assert.equal((await auth.session(sessionRequest(overrides))).status, 403);
    assert.equal((await auth.logout(sessionRequest(overrides))).status, 403); assert.equal(tokenCalls, 0);
  });
}
test('only a short-lived access token and verified user are returned; refresh stays encrypted HttpOnly', async () => {
  const response = await auth.session(sessionRequest()); assert.equal(response.status, 200);
  const body = await response.json(); assert.deepEqual(Object.keys(body).sort(), ['access_token', 'expires_at', 'user']);
  assert.deepEqual(body.user.roles, ['user']); assert.equal(body.user.role, 'user'); assert.equal(JSON.stringify(body).includes(originalRefresh), false);
});
test('a bound live access token avoids unnecessary refresh rotation', async () => {
  const response = await auth.session(sessionRequest({ Authorization: 'Bearer ' + await signed() }));
  assert.equal(response.status, 200); assert.equal(tokenCalls, 0); assert.equal(response.headers.getSetCookie().length, 0);
});
test('API audience is explicit configuration, not a browser-selected token audience', async () => {
  const configured = new BrowserAuth({ ...config, apiAudience: 'dedicated-api' });
  await assert.rejects(configured.verify(await signed(), 'access'), error => error.status === 401);
  assert.equal((await configured.verify(await signed({ aud: 'dedicated-api' }), 'access')).aud, 'dedicated-api');
});
test('a changed signature cannot authenticate even with trusted claims and key ID', async () => {
  const token = await signed(); const parts = token.split('.');
  const signature = Buffer.from(parts[2], 'base64url'); signature[0] ^= 1; parts[2] = signature.toString('base64url');
  await assert.rejects(auth.verify(parts.join('.'), 'access'), error => error.status === 401);
});
test('an access token from another session cannot replace the cookie-bound user', async () => {
  const response = await auth.session(sessionRequest({ Authorization: 'Bearer ' + await signed({ sub: 'attacker', roles: ['admin'] }) }));
  const body = await response.json(); assert.equal(body.user.id, subject); assert.deepEqual(body.user.roles, ['user']); assert.equal(tokenCalls, 1);
});
for (const overrides of [{ iss: 'https://evil.test' }, { aud: 'another-api' }, { token_use: 'id' }, { actor_type: 'application' }, { client_id: 'other' },
  { iat: now + 999 }, { sid: '------------------------------------' }, { auth_time: now + 99 }, { sub: '' }]) {
  test('signed but incorrectly bound tokens are refused: ' + JSON.stringify(overrides), async () => {
    await assert.rejects(auth.verify(await signed(overrides), 'access'), error => error.status === 401);
  });
}
test('live revocation clears the local session instead of authenticating from the JWT alone', async () => {
  stateActive = false; const response = await auth.session(sessionRequest({ Authorization: 'Bearer ' + await signed() }));
  assert.equal(response.status, 401); assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
});
test('live authority outage returns 503 without exposing access and preserves a newly rotated refresh cookie', async () => {
  stateUnavailable = true; const response = await auth.session(sessionRequest());
  assert.equal(response.status, 503); assert.equal((await response.json()).access_token, undefined);
  const cookie = response.headers.getSetCookie().find(value => value.startsWith(auth.sessionCookie + '=')); assert.ok(cookie); assert.doesNotMatch(cookie, /Max-Age=0/);
});
test('JWKS outage after rotation retains the new refresh credential rather than replaying the spent one', async () => {
  auth.jwks = async () => { throw new TypeError('fetch failed'); };
  const response = await auth.session(sessionRequest()); assert.equal(response.status, 503); assert.equal(tokenCalls, 1);
  assert.ok(response.headers.getSetCookie().find(value => value.startsWith(auth.sessionCookie + '=')));
});
test('JWKS outage with an existing token does not consume a refresh credential', async () => {
  auth.jwks = async () => { throw new TypeError('fetch failed'); };
  const response = await auth.session(sessionRequest({ Authorization: 'Bearer ' + await signed() }));
  assert.equal(response.status, 503); assert.equal(tokenCalls, 0);
});
test('logout only clears cookies after authority confirmation; outages never fake success', async () => {
  stateUnavailable = true; const failed = await auth.logout(sessionRequest()); assert.equal(failed.status, 503); assert.equal(failed.headers.getSetCookie().length, 0);
  stateUnavailable = false; const success = await auth.logout(sessionRequest()); assert.equal(success.status, 200);
  assert.deepEqual(await success.json(), { revoked: true }); assert.match(success.headers.get('set-cookie'), /Max-Age=0/);
});
test('unsafe URLs, non-loopback HTTP and exposed cookie keys fail closed', () => {
  for (const origin of ['http://web.test', 'https://user:password@web.test', 'https://web.test/path', 'https://web.test/?query=1']) {
    assert.throws(() => new BrowserAuth({ ...config, origin }), BrowserAuthError);
  }
  assert.throws(() => new BrowserAuth({ ...config, origin: 'http://localhost:3000' }), BrowserAuthError);
  assert.throws(() => new BrowserAuth({ ...config, issuer: 'http://untrusted.test' }), BrowserAuthError);
  const local = new BrowserAuth({ ...config, origin: 'http://localhost:3000', publicUrl: 'http://localhost:3015', allowHttpLoopback: true });
  assert.equal(local.secure, false);
  fs.chmodSync(config.keyFile, 0o644); assert.throws(() => new BrowserAuth(config), BrowserAuthError); fs.chmodSync(config.keyFile, 0o600);
});

test('secret utility creates distinct protected material and never overwrites existing files', () => {
  const cookie = path.join(directory, 'generated-cookie.key'); const client = path.join(directory, 'generated-client.secret');
  generate('cookie', cookie); generate('client', client);
  assert.equal(fs.statSync(cookie).mode & 0o777, 0o600); assert.equal(fs.statSync(client).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(cookie).length, 32); assert.match(fs.readFileSync(client, 'utf8'), /^[A-Za-z0-9_-]{43}$/);
  const before = fs.readFileSync(cookie); assert.throws(() => generate('cookie', cookie)); assert.deepEqual(fs.readFileSync(cookie), before);
  assert.throws(() => generate('cookie', 'relative-path')); assert.throws(() => generate('signing', cookie));
});

test('anonymous recovery forwards only the bounded explicit factor request, not cookies, bearers or OAuth client credentials', async () => {
  let observed; const local = new BrowserAuth({ ...config, fetchImpl: async (url, options) => { observed = { url, options }; return json({ challenge: 'opaque-setup-only' }); } });
  const body = { username: 'owner', password: 'verified-password', recoveryCode: '11223344-55667788-99aabbcc-ddeeff00' };
  const result = await local.recovery(recoveryRequest(body, { Cookie: 'old-session', Authorization: 'Bearer old-token' }), 'start');
  assert.equal(result.status, 200); assert.equal(result.headers.get('cache-control'), 'no-store'); assert.equal(result.headers.get('referrer-policy'), 'no-referrer'); assert.equal(result.headers.get('set-cookie'), null);
  assert.equal(observed.url.origin, new URL(config.internalUrl).origin); assert.equal(observed.url.pathname, '/oauth/mfa/recovery/start');
  assert.deepEqual(JSON.parse(observed.options.body), body); assert.deepEqual(observed.options.headers, { 'Content-Type': 'application/json' }); assert.equal(observed.options.redirect, 'error');
});
test('recovery rejects cross-origin, missing intent, query selectors, extra identities, unknown actions and oversized bodies without reaching the issuer', async () => {
  let calls = 0; const local = new BrowserAuth({ ...config, fetchImpl: async () => { calls++; return json({}); } });
  for (const [request, action] of [
    [recoveryRequest({}, { Origin: 'https://attacker.test' }), 'start'], [recoveryRequest({}, { 'X-OD-Recovery': '' }), 'start'],
    [recoveryRequest({}, { 'Sec-Fetch-Site': 'cross-site' }), 'start'], [recoveryRequest({ userId: crypto.randomUUID() }), 'start'],
    [recoveryRequest({ password: 'a'.repeat(9000) }), 'start'], [recoveryRequest({}), 'admin-reset'],
    [new Request(config.origin + '/api/auth/oidc/recovery/confirm?userId=target', { method: 'POST', headers: { Origin: config.origin, 'Content-Type': 'application/json', 'X-OD-Recovery': '1' }, body: '{}' }), 'confirm'],
  ]) assert.ok([400, 403].includes((await local.recovery(request, action)).status));
  assert.equal(calls, 0);
});
test('recovery preserves safe denial and throttling, but never returns an arbitrary upstream error or pretends a redirect is successful', async () => {
  const denied = new BrowserAuth({ ...config, fetchImpl: async () => json({ error: 'mfa_temporarily_locked' }, 429) });
  const result = await denied.recovery(recoveryRequest({ challenge: 'opaque', code: '123456' }, {}, 'confirm'), 'confirm');
  assert.equal(result.status, 429); assert.deepEqual(await result.json(), { error: 'mfa_temporarily_locked' });
  const secretError = new BrowserAuth({ ...config, fetchImpl: async () => json({ error: 'upstream secret response' }, 401) });
  const failed = await secretError.recovery(recoveryRequest({}), 'start'); assert.equal(failed.status, 503); assert.equal((await failed.text()).includes('upstream secret'), false);
  const redirect = new BrowserAuth({ ...config, fetchImpl: async () => { throw new TypeError('redirect forbidden'); } }); assert.equal((await redirect.recovery(recoveryRequest({}), 'start')).status, 503);
});
test('first enrollment has its own fixed purpose and intent and never forwards cookies, bearer or client secrets', async () => {
  let observed; const local = new BrowserAuth({ ...config, fetchImpl: async (url, options) => { observed = { url, options }; return json({ challenge: 'registration-only' }); } });
  const body = { clientId: 'assigned-app', username: 'owner', password: 'password' };
  const req = new Request(config.origin + '/api/auth/oidc/enrollment/start', { method: 'POST', headers: { Origin: config.origin, 'Content-Type': 'application/json', 'X-OD-Enrollment': '1', Cookie: 'old-session', Authorization: 'Bearer old' }, body: JSON.stringify(body) });
  const result = await local.enrollment(req, 'start'); assert.equal(result.status, 200); assert.equal(result.headers.get('set-cookie'), null); assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(observed.url.pathname, '/oauth/mfa/enrollment/start'); assert.deepEqual(observed.options.headers, { 'Content-Type': 'application/json' }); assert.deepEqual(JSON.parse(observed.options.body), body);
});
test('enrollment cannot borrow the recovery intent or accept an arbitrary second-factor/identity field', async () => {
  let calls = 0; const local = new BrowserAuth({ ...config, fetchImpl: async () => { calls++; return json({}); } });
  assert.equal((await local.enrollment(recoveryRequest({ clientId: 'assigned-app' }), 'start')).status, 403);
  const request = new Request(config.origin + '/api/auth/oidc/enrollment/start', { method: 'POST', headers: { Origin: config.origin, 'Content-Type': 'application/json', 'X-OD-Enrollment': '1' }, body: JSON.stringify({ clientId: 'assigned-app', recoveryCode: 'not-allowed', userId: crypto.randomUUID() }) });
  assert.equal((await local.enrollment(request, 'start')).status, 400); assert.equal(calls, 0);
});
