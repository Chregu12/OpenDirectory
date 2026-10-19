'use strict';

// Runs with Node's built-in test runner:
//   node --test src/db/__tests__/
//
// Separate file so DATABASE_URL is genuinely unset when src/db/index.js
// first runs (module-level pool construction happens once, at require
// time) — see migrate.test.js / migrateFailure.test.js for why this needs
// to be its own file under node --test's per-file worker isolation.
//
// This is the "service degrades gracefully without a DB" contract that the
// rest of samba-ad-dc (TrustManager/ComputerManager/ReplicationManager)
// depends on: no DATABASE_URL configured must never throw at require time,
// and must leave isAvailable() permanently false without ever attempting a
// network connection.

const { test } = require('node:test');
const assert = require('node:assert/strict');

delete process.env.DATABASE_URL;

const db = require('../index');

test('no DATABASE_URL: module loads without throwing and pool is null', () => {
  assert.equal(db.pool, null);
});

test('no DATABASE_URL: isAvailable() is false before initDb() ever runs', () => {
  assert.equal(db.isAvailable(), false);
});

test('no DATABASE_URL: initDb() resolves false without throwing (never attempts a connection)', async () => {
  const result = await db.initDb();
  assert.equal(result, false);
  assert.equal(db.isAvailable(), false);
});

test('no DATABASE_URL: runMigrations() no-ops cleanly (nothing to apply migrations against)', async () => {
  const result = await db.runMigrations();
  assert.deepEqual(result, { applied: [], failed: [] });
});

test('no DATABASE_URL: query() throws a clear "DB not available" error rather than crashing', async () => {
  await assert.rejects(() => db.query('SELECT 1'), /DB not available/);
});
