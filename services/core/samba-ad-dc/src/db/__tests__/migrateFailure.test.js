'use strict';

// Runs with Node's built-in test runner:
//   node --test src/db/__tests__/
//
// Separate file from migrate.test.js/noDatabaseUrl.test.js on purpose:
// node --test isolates each matched file in its own worker, so this file's
// "one migration file fails" fake pool can't collide with the always-
// succeeds fake pool in migrate.test.js or the "no pool at all" case in
// noDatabaseUrl.test.js — each needs src/db/index.js's module-level
// pool/dbAvailable state seeded differently before first require.
//
// Covers the Abbruch-Mandat this task was built under: if a migration
// really fails (schema conflict, broken SQL, whatever), initDb() must NOT
// report the DB as available just because the initial `SELECT 1` worked.
// Reporting available=true here would let computerManager.escrowBitLockerKey
// (see src/computer/computerManager.js) go on to INSERT into a table that
// was never actually created — a fake-green schema state that would look
// exactly like the original silent-data-loss bug from the caller's side.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const pgPath = require.resolve('pg');

class FlakyMigrationPool {
  constructor(opts) {
    this.opts = opts;
  }
  query(sql) {
    if (sql === 'SELECT 1') return Promise.resolve({ rows: [] });
    // Simulate 002_computer_laps.sql hitting a real schema conflict
    // (e.g. bitlocker_keys already exists with an incompatible column set)
    // while 001 and 003 still apply fine.
    if (sql.includes('bitlocker_keys')) {
      return Promise.reject(new Error('relation "bitlocker_keys" already exists with a conflicting schema'));
    }
    return Promise.resolve({ rows: [] });
  }
  on() {}
}

require.cache[pgPath] = {
  id: pgPath,
  filename: pgPath,
  loaded: true,
  exports: { Pool: FlakyMigrationPool }
};

process.env.DATABASE_URL = 'postgres://fake-user:fake-pass@fake-host:5432/fake_db';

const db = require('../index');

test('runMigrations() keeps trying remaining files after one fails, and reports the failure', async () => {
  const result = await db.runMigrations();

  assert.ok(result.applied.includes('001_trusts.sql'));
  assert.ok(result.applied.includes('003_replication.sql'));
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0].file, '002_computer_laps.sql');
  assert.match(result.failed[0].error, /conflicting schema/);
});

test('initDb() does NOT mark the DB available when a migration failed — no fake-green', async () => {
  const result = await db.initDb();

  assert.equal(result, false);
  assert.equal(db.isAvailable(), false);
});

test('query() refuses to run once isAvailable() is false, instead of hitting a half-migrated schema', async () => {
  await db.initDb();
  await assert.rejects(() => db.query('SELECT * FROM bitlocker_keys'), /DB not available/);
});
