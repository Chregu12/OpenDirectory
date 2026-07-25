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
      return { payload };
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
  await new Promise(resolve => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
});

const admin = (req) => req.set('Authorization', `Bearer ${adminToken}`);

it('does not crash on boot without a database: db.isAvailable() is false', () => {
  expect(db.isAvailable()).toBe(false);
});

it('GET /health still reports healthy with no DB', async () => {
  const res = await request(app).get('/health');
  expect(res.status).toBe(200);
  expect(res.body.status).toBe('healthy');
});

it('runs a full user CRUD roundtrip purely on the in-memory fallback', async () => {
  const created = await admin(request(app).post('/api/users')).send({ username: 'nodb-user', email: 'nodb@example.com' });
  expect(created.status).toBe(201);
  const id = created.body.id;

  const got = await admin(request(app).get(`/api/users/${id}`));
  expect(got.status).toBe(200);
  expect(got.body.username).toBe('nodb-user');

  const updated = await admin(request(app).put(`/api/users/${id}`)).send({ department: 'Ops' });
  expect(updated.status).toBe(200);
  expect(updated.body.department).toBe('Ops');

  const deleted = await admin(request(app).delete(`/api/users/${id}`));
  expect(deleted.status).toBe(204);

  const goneRes = await admin(request(app).get(`/api/users/${id}`));
  expect(goneRes.status).toBe(404);
});

it('runs a full group CRUD roundtrip (incl. membership) purely on the in-memory fallback', async () => {
  const created = await admin(request(app).post('/api/groups')).send({ name: 'nodb-group' });
  expect(created.status).toBe(201);
  const id = created.body.id;

  const withMember = await admin(request(app).post(`/api/groups/${id}/members`)).send({ userId: 'some-user-id' });
  expect(withMember.status).toBe(200);
  expect(withMember.body.members).toEqual(['some-user-id']);

  const deleted = await admin(request(app).delete(`/api/groups/${id}`));
  expect(deleted.status).toBe(204);
});

it('runs a full OU CRUD roundtrip purely on the in-memory fallback', async () => {
  const created = await admin(request(app).post('/api/ous')).send({ name: 'nodb-ou' });
  expect(created.status).toBe(201);
  const id = created.body.id;

  const updated = await admin(request(app).put(`/api/ous/${id}`)).send({ description: 'updated' });
  expect(updated.status).toBe(200);
  expect(updated.body.description).toBe('updated');

  const deleted = await admin(request(app).delete(`/api/ous/${id}`));
  expect(deleted.status).toBe(204);
});

it('auth is still enforced with no DB present (401 without a token)', async () => {
  const res = await request(app).get('/api/users');
  expect(res.status).toBe(401);
});
