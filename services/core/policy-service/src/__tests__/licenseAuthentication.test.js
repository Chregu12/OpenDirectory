'use strict';

jest.mock('../db/postgres', () => ({ query: jest.fn() }));
jest.mock('../licenses/GroupSnapshotClient', () => ({
  ...jest.requireActual('../licenses/GroupSnapshotClient'),
  GroupSnapshotClient: class {
    async subject(_authorization, expected) { return require('./fixtures/licenseIdentities.cjs').principal(expected.subject, expected.issuer); }
    async user(userId) { return { schemaVersion: 1, userId, revision: '1', enabled: true, deleted: false }; }
  },
}));
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({})),
}), { virtual: true });

const http = require('http');
const request = require('supertest');
const { generateKeyPair, exportJWK, SignJWT } = require('jose');
const db = require('../db/postgres');
const issuer = 'https://identity.test.opendirectory';
let privateKey;
let jwksServer;
let app;

beforeAll(async () => {
  const keyPair = await generateKeyPair('RS256');
  privateKey = keyPair.privateKey;
  const publicKey = { ...await exportJWK(keyPair.publicKey), kid: 'license-auth-test', alg: 'RS256', use: 'sig' };
  jwksServer = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/oauth/access-state') {
      try {
        const { payload } = await require('jose').jwtVerify(req.headers.authorization.slice(7), keyPair.publicKey, { issuer, audience: 'opendirectory-api' });
        return res.end(JSON.stringify({ schemaVersion: 1, active: true, issuer: payload.iss, subject: payload.sub, tokenId: payload.jti, expiresAt: payload.exp }));
      } catch { res.statusCode = 401; return res.end('{}'); }
    }
    res.end(JSON.stringify({ keys: [publicKey] }));
  });
  await new Promise(resolve => jwksServer.listen(0, '127.0.0.1', resolve));
  const previousIssuer = process.env.OIDC_ISSUER;
  const previousJwksUri = process.env.JWKS_URI;
  process.env.OIDC_ISSUER = issuer;
  process.env.JWKS_URI = `http://127.0.0.1:${jwksServer.address().port}/jwks`;
  process.env.OIDC_ACCESS_STATE_URL = `http://127.0.0.1:${jwksServer.address().port}/oauth/access-state`;
  app = require('../index');
  if (previousIssuer === undefined) delete process.env.OIDC_ISSUER;
  else process.env.OIDC_ISSUER = previousIssuer;
  if (previousJwksUri === undefined) delete process.env.JWKS_URI;
  else process.env.JWKS_URI = previousJwksUri;
});

afterAll(async () => {
  await new Promise(resolve => jwksServer.close(resolve));
});

async function issueToken(payload, tokenIssuer = issuer, expiration = '2m') {
  return new SignJWT({ token_use: 'access', jti: require('crypto').randomUUID(), ...payload }).setProtectedHeader({ alg: 'RS256', kid: 'license-auth-test' })
    .setIssuer(tokenIssuer).setAudience('opendirectory-api').setIssuedAt().setExpirationTime(expiration).sign(privateKey);
}

test('requires a bearer token before exposing license capabilities', async () => {
  expect((await request(app).get('/api/licenses/access')).status).toBe(401);
});

test('uses roles from a genuinely signed token verified through JWKS', async () => {
  const token = await issueToken({ sub: 'manager', roles: ['license-manager'] });
  const response = await request(app).get('/api/licenses/access').set('Authorization', `Bearer ${token}`);
  expect(response.status).toBe(200);
  expect(response.body.permissions).toContain('licenses.catalog.manage');
  expect(response.body.permissions).not.toContain('licenses.requests.review');
});

test.each([
  ['get', '/api/policies'],
  ['post', '/api/policies'],
  ['get', '/api/licenses/access'],
  ['get', '/api/licenses/kiosk'],
])('rejects a signed source application before policy storage or human binding: %s %s', async (method, route) => {
  db.query.mockClear();
  const token = await issueToken({ sub: 'group-source', actor_type: 'application', client_id: 'group-source', client_revision: 1,
    scope: 'licenses.groups.derive', permissions: ['licenses.groups.derive'], roles: ['admin', 'license-manager'] });
  const response = await request(app)[method](route).set('Authorization', `Bearer ${token}`);
  expect(response.status).toBe(403);
  expect(response.body).toEqual({ error: 'workload_policy_administration_forbidden' });
  expect(db.query).not.toHaveBeenCalled();
});

test('ignores administrative claims supplied in headers, the body, or requested scopes', async () => {
  const token = await issueToken({ sub: 'alice', scope: 'licenses.catalog.manage', roles: ['user'] });
  const response = await request(app).post('/api/licenses').set('Authorization', `Bearer ${token}`)
    .set('X-User-Roles', 'admin').send({ name: 'Office', roles: ['admin'], permissions: ['licenses.catalog.manage'] });
  expect(response.status).toBe(403);
  expect(db.query).not.toHaveBeenCalled();
});

test('rejects a signed administrative token without a subject', async () => {
  const token = await issueToken({ roles: ['admin'] });
  expect((await request(app).get('/api/licenses/access').set('Authorization', `Bearer ${token}`)).status).toBe(401);
});

test('rejects a token from another issuer', async () => {
  const token = await issueToken({ sub: 'manager', roles: ['admin'] }, 'https://other-issuer.test');
  expect((await request(app).get('/api/licenses/access').set('Authorization', `Bearer ${token}`)).status).toBe(403);
});

test('rejects expired tokens', async () => {
  const expiredToken = await new SignJWT({ sub: 'manager', jti: require('crypto').randomUUID(), roles: ['admin'], token_use: 'access' }).setProtectedHeader({ alg: 'RS256', kid: 'license-auth-test' })
    .setIssuer(issuer).setAudience('opendirectory-api').setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1000) - 60).sign(privateKey);
  expect((await request(app).get('/api/licenses/access').set('Authorization', `Bearer ${expiredToken}`)).status).toBe(401);
});

test.each(['id', 'refresh', 'device'])('rejects a signed %s token used as an access token', async token_use => {
  const token = await issueToken({ sub: 'manager', roles: ['admin'], token_use });
  expect((await request(app).get('/api/licenses/access').set('Authorization', `Bearer ${token}`)).status).toBe(403);
});

test('rejects modified role claims without a matching signature', async () => {
  const token = await issueToken({ sub: 'alice', roles: ['user'] });
  const parts = token.split('.');
  parts[1] = Buffer.from(JSON.stringify({ sub: 'alice', iss: issuer, roles: ['admin'], exp: Math.floor(Date.now() / 1000) + 120 })).toString('base64url');
  expect((await request(app).get('/api/licenses/access').set('Authorization', `Bearer ${parts.join('.')}`)).status).toBe(403);
});
