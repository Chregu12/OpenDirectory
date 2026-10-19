'use strict';

/**
 * Companion to api.e2e.test.js: proves the other half of "DB-first mit
 * in-memory-Fallback" — that identity-service does NOT crash when
 * PostgreSQL is unavailable, and that reads/writes still work correctly
 * against the in-memory Maps (db.isAvailable() stays false throughout,
 * since every pg query here rejects, exactly like a real down/unreachable
 * database would during db.initDb()'s initial `SELECT 1`).
 *
 * Deliberately a separate file: jest.mock('pg', ...) applies per test file
 * (isolated module registry), so this file can mock a permanently-failing
 * pool without affecting api.e2e.test.js's stateful DB-path fake.
 */

process.env.PORT = '0';
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));
process.env.IDENTITY_DEMO_MODE = 'true';
process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';

jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    connect: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn(() => ({})),
  jwtVerify: jest.fn(async (token) => {
    try {
      const payload = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
      return { payload: { token_use: 'access', ...payload } };
    } catch {
      throw new Error('malformed token');
    }
  }),
}));

function makeToken(claims) {
  return Buffer.from(JSON.stringify(claims)).toString('base64url');
}
const adminToken = makeToken({ sub: 'admin-1', roles: ['admin'] });

const request = require('supertest');
let app;
let db;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  app = require('../index');
  db = require('../db');
  await db.initDb();
});

afterAll(() => {
  jest.restoreAllMocks();
});

const admin = (req) => req.set('Authorization', `Bearer ${adminToken}`);

it('does not crash on boot without a database: db.isAvailable() is false', () => {
  expect(db.isAvailable()).toBe(false);
});

it('GET /health reports degraded storage even when development demo CRUD is enabled', async () => {
  const res = await request(app).get('/health');
  expect(res.status).toBe(503);
  expect(res.body.status).toBe('degraded');
});

it('explicit demo mode cannot fabricate owned user creation without durable storage', async () => {
  const created = await admin(request(app).post('/api/users')).send({ username: 'nodb-user', email: 'nodb@example.com' });
  expect(created.status).toBe(503);expect(created.body.id).toBeUndefined();
  const listed=await admin(request(app).get('/api/users'));expect(listed.status).toBe(503);expect(listed.body.users).toBeUndefined();
});

it('explicit demo mode cannot fabricate owned group creation or a confirmed group identifier', async () => {
  const created = await admin(request(app).post('/api/groups')).send({ name: 'nodb-group' });
  expect(created.status).toBe(503);expect(created.body.id).toBeUndefined();
});

it('explicit demo mode cannot fabricate owned OU creation or a tree from unpartitioned memory', async () => {
  const created = await admin(request(app).post('/api/ous')).send({ name: 'nodb-ou' });
  expect(created.status).toBe(503);expect(created.body.id).toBeUndefined();
  const list = await admin(request(app).get('/api/ous'));
  expect(list.status).toBe(503);
  expect(list.body.tree).toBeUndefined();
});

it('auth is still enforced with no DB present (401 without a token)', async () => {
  const res = await request(app).get('/api/users');
  expect(res.status).toBe(401);
});
