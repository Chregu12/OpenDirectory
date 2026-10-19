'use strict';

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => ({ query: jest.fn().mockResolvedValue({ rows: [] }) })),
}));

const { Pool } = require('pg');
let db;

beforeAll(async () => {
  const originalUrl = process.env.DATABASE_URL;
  process.env.DATABASE_URL = 'postgres://test-user:disposable-test-password@registry-db:5432/oauth';
  db = require('../db');
  if (originalUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalUrl;
  await db.initDb();
});

beforeEach(() => { db.pool.query.mockClear(); });

test('uses the Compose-provided database URL', () => {
  expect(Pool).toHaveBeenCalledWith(expect.objectContaining({ connectionString: 'postgres://test-user:disposable-test-password@registry-db:5432/oauth' }));
});

test('unversioned plaintext client upsert/delete helpers are retired rather than an alternate authority', () => {
  for (const method of ['getClient','upsertClient','getAllClients','deleteClient']) expect(db[method]).toBeUndefined();
});

test('persists the issuing client rather than confusing it with the shared API audience', async () => {
  await db.saveToken('token-hash', { aud: 'opendirectory-api', client_id: 'application', sub: 'user', scope: 'openid', iat: 100, exp: 200 });
  expect(db.pool.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO oauth_tokens'),
    ['token-hash', 'application', 'user', 'openid', new Date(200000)]);
});

test('a failed migration cannot leave the issuer claiming persistent authority is ready', async () => {
  db.pool.query.mockResolvedValueOnce({ rows: [] }).mockRejectedValueOnce(new Error('migration unavailable'));
  await db.initDb();
  expect(db.isAvailable()).toBe(false);
  db.pool.query.mockResolvedValue({ rows: [] });
  await db.initDb();
  expect(db.isAvailable()).toBe(true);
});
