'use strict';

const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const request = require('supertest');
const { OidcAdapter } = require('../OidcAdapter');
const { mountFederation } = require('../federationRoutes');

let server; let issuer; let mode; let nonce; let verifier; let tokenCalls; let temp; let expectedChallenge;
const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256', use: 'sig' };
let settings;
beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/.well-known/openid-configuration') return res.end(JSON.stringify({ issuer, response_types_supported: ['code'], id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'], authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks' }));
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    if (req.url !== '/token') { res.statusCode = 404; return res.end('{}'); }
    tokenCalls++;
    let body = ''; for await (const chunk of req) body += chunk;
    const params = new URLSearchParams(body);
    const validVerifier = expectedChallenge ? crypto.createHash('sha256').update(params.get('code_verifier') || '').digest('base64url') === expectedChallenge : params.get('code_verifier') === verifier;
    if (!validVerifier || params.get('redirect_uri') !== issuer + '/oauth/federation/test/callback'
      || req.headers.authorization !== 'Basic ' + Buffer.from('client:secret').toString('base64')) { res.statusCode = 400; return res.end('{}'); }
    const payload = { iss: issuer, sub: 'external-alice', aud: 'client', nonce, exp: Math.floor(Date.now() / 1000) + 60 };
    if (mode === 'nonce') payload.nonce = 'attacker';
    if (mode === 'audience') payload.aud = 'other-client';
    if (mode === 'issuer') payload.iss = 'https://attacker.test';
    if (mode === 'expired') payload.exp -= 120;
    if (mode === 'expiry') delete payload.exp;
    if (mode === 'unbound') payload.sub = 'admin';
    if (mode === 'multiple-audiences') payload.aud = ['client', 'attacker'];
    const key = mode === 'signature' ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey : keys.privateKey;
    return res.end(JSON.stringify({ id_token: jwt.sign(payload, key, { algorithm: 'RS256', keyid: 'test' }) }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  issuer = 'http://127.0.0.1:' + server.address().port;
  settings = { issuer, clientId: 'client', clientSecret: 'secret', subjects: { 'external-alice': 'local-alice' } };
  temp = fs.mkdtempSync(path.join(os.tmpdir(), 'od-oidc-'));
});
afterAll(async () => { await new Promise(resolve => server.close(resolve)); fs.rmSync(temp, { recursive: true, force: true }); });
beforeEach(() => { mode = ''; tokenCalls = 0; expectedChallenge = undefined; });
async function begin() {
  const adapter = new OidcAdapter(settings, issuer + '/oauth/federation/test/callback');
  const started = await adapter.begin(); nonce = started.transaction.nonce; verifier = started.transaction.verifier;
  return { adapter, ...started };
}
test('real discovery, S256 and JWKS validation bind only the configured subject', async () => {
  const { adapter, url, transaction } = await begin();
  const params = new URL(url).searchParams;
  expect(params.get('code_challenge')).toBe(crypto.createHash('sha256').update(verifier).digest('base64url'));
  expect(params.get('code_challenge_method')).toBe('S256');
  expect(await adapter.complete({ code: 'valid-code', state: transaction.state }, transaction)).toEqual({ id: 'local-alice', username: 'local-alice', roles: [], permissions: [] });
});
test.each(['nonce', 'audience', 'issuer', 'expired', 'expiry', 'unbound', 'multiple-audiences', 'signature'])('rejects invalid %s', async failure => {
  const { adapter, transaction } = await begin(); mode = failure;
  await expect(adapter.complete({ code: 'valid-code', state: transaction.state }, transaction)).rejects.toThrow();
});
test('wrong state and provider errors never exchange a code', async () => {
  const { adapter, transaction } = await begin();
  await expect(adapter.complete({ code: 'code', state: 'wrong' }, transaction)).rejects.toThrow();
  await expect(adapter.complete({ error: 'access_denied', state: transaction.state }, transaction)).rejects.toThrow();
  expect(tokenCalls).toBe(0);
});
test('provider secrets and transport configuration fail closed', () => {
  expect(() => new OidcAdapter({ ...settings, issuer: 'http://idp.example.com' }, issuer)).toThrow();
  expect(() => new OidcAdapter({ ...settings, clientSecret: '' }, issuer)).toThrow();
});

async function federation() {
  const filename = path.join(temp, 'providers.json');
  fs.writeFileSync(filename, JSON.stringify({ test: settings }), { mode: 0o600 });
  process.env.OAUTH_OIDC_CONFIG_FILE = filename;
  const app = express(); app.use(express.urlencoded({ extended: false }));
  const authorize = jest.fn(async (_req, res) => res.redirect('/authorized'));
  const protocol = handler => async (req, res) => { req.oauthClient = { clientId: 'local-client' }; await handler(req, res); };
  mountFederation(app, { issuer, protocol, validate: () => 'openid', authorize });
  delete process.env.OAUTH_OIDC_CONFIG_FILE;
  return { app, authorize };
}
test('browser binding and one-time completion preserve the local MFA step', async () => {
  const { app, authorize } = await federation();
  const response = await request(app).get('/oauth/federation/test?client_id=local-client&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback&state=downstream');
  expect(response.status).toBe(302);
  const params = new URL(response.headers.location).searchParams;
  nonce = params.get('nonce');
  const cookie = response.headers['set-cookie'][0].split(';')[0];
  const state = params.get('state');
  const stolen = await request(app).get('/oauth/federation/test/callback').query({ code: 'code', state });
  expect(stolen.status).toBe(400); expect(tokenCalls).toBe(0);
  // A failed token exchange consumes the legitimate transaction rather than permitting replay.
  verifier = 'wrong';
  const callback = await request(app).get('/oauth/federation/test/callback').set('Cookie', cookie).query({ code: 'code', state });
  expect(callback.status).toBe(400);
  expect((await request(app).get('/oauth/federation/test/callback').set('Cookie', cookie).query({ code: 'code', state })).status).toBe(400);
  expect(tokenCalls).toBe(1); expect(authorize).not.toHaveBeenCalled();
});

test('expired callbacks fail before code exchange', async () => {
  const { app, authorize } = await federation();
  const started = await request(app).get('/oauth/federation/test?client_id=local-client');
  const state = new URL(started.headers.location).searchParams.get('state');
  const cookie = started.headers['set-cookie'][0].split(';')[0];
  const clock = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 300001);
  try {
    const callback = await request(app).get('/oauth/federation/test/callback').set('Cookie', cookie).query({ code: 'code', state });
    expect(callback.status).toBe(400); expect(tokenCalls).toBe(0); expect(authorize).not.toHaveBeenCalled();
  } finally { clock.mockRestore(); }
});

test('complete browser flow issues a local authorization code and honestly labelled tokens', async () => {
  const filename = path.join(temp, 'real-providers.json');
  fs.writeFileSync(filename, JSON.stringify({ test: settings }), { mode: 0o600 });
  Object.assign(process.env, { OAUTH_OIDC_CONFIG_FILE: filename, OAUTH_ISSUER: issuer, OAUTH_EPHEMERAL_SIGNING_KEYS: 'true', OAUTH_SIGNING_KEY_FILE: '',
    OAUTH_VERIFICATION_JWKS_FILE: '', OAUTH_MFA_KEY_FILE: '', OAUTH_REVOCATION_DEMO_MODE: 'true', DEVPORTAL_CLIENT_SECRET: 'test-local-secret' });
  const app = require('../index');
  const params = { client_id: 'devportal-od-client', redirect_uri: 'http://localhost:4000/callback', response_type: 'code', scope: 'openid', state: 'downstream-state', nonce: 'downstream-nonce' };
  const login = await request(app).get('/oauth/authorize').query(params);
  expect(login.status).toBe(200); expect(login.text).toContain('Mit test anmelden');
  const start = await request(app).get('/oauth/federation/test').query(params);
  expect(start.status).toBe(302);
  const external = new URL(start.headers.location).searchParams;
  nonce = external.get('nonce'); expectedChallenge = external.get('code_challenge');
  const cookie = start.headers['set-cookie'][0].split(';')[0];
  const callback = await request(app).get('/oauth/federation/test/callback').set('Cookie', cookie).query({ code: 'external-code', state: external.get('state') });
  expect(callback.status).toBe(200);
  const ticket = callback.text.match(/name="ticket" value="([^"]+)"/)[1];
  expect(callback.text).not.toContain('access_token');
  expect((await request(app).post('/oauth/federation/test/complete').type('form').send({ ticket })).status).toBe(400);
  const complete = await request(app).post('/oauth/federation/test/complete').set('Cookie', cookie).type('form').send({ ticket });
  expect(complete.status).toBe(302);
  const local = new URL(complete.headers.location);
  expect(local.origin).toBe('http://localhost:4000'); expect(local.searchParams.get('state')).toBe('downstream-state');
  expect((await request(app).post('/oauth/federation/test/complete').set('Cookie', cookie).type('form').send({ ticket })).status).toBe(400);
  const tokens = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', client_id: params.client_id, client_secret: 'test-local-secret', code: local.searchParams.get('code'), redirect_uri: params.redirect_uri });
  expect(tokens.status).toBe(200);
  const jwks = (await request(app).get('/.well-known/jwks.json')).body;
  const identity = jwt.verify(tokens.body.id_token, crypto.createPublicKey({ key: jwks.keys[0], format: 'jwk' }), { issuer, audience: params.client_id, algorithms: ['RS256'] });
  expect(identity.sub).toBe('local-alice'); expect(identity.amr).toEqual(['federated']); expect(identity.nonce).toBe('downstream-nonce');
  const invalid = await request(app).get('/oauth/federation/test').query({ ...params, redirect_uri: 'https://attacker.test' });
  expect(invalid.status).toBe(400);
  delete process.env.OAUTH_OIDC_CONFIG_FILE;
});
