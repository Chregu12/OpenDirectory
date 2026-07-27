'use strict';

// Runs with Node's built-in test runner:
//   node --test src/db/__tests__/
//
// Regression coverage for the persistence-audit finding: samba-ad-dc had a
// pg Pool (src/index.js) but no migration runner, so migrations/*.sql
// (domain_trusts, laps_passwords, bitlocker_keys, replication_log, ...)
// were never applied and every query against them threw at runtime. This
// file proves src/db/index.js's runMigrations()/initDb() actually apply
// every migrations/*.sql file, in filename order, against the pool.
//
// 'pg' is mocked by pre-seeding require.cache for its resolved path before
// requiring src/db/index.js, so no real network/DB connection is ever
// attempted. node --test isolates each matched test file in its own worker
// by default, so this mock can't leak into sibling test files that need a
// different fake pool (see migrateFailure.test.js / noDatabaseUrl.test.js).

const { test } = require('node:test');
const assert = require('node:assert/strict');

const pgPath = require.resolve('pg');

const executedQueries = [];

class FakePool {
  constructor(opts) {
    this.opts = opts;
  }
  query(sql) {
    executedQueries.push(sql);
    return Promise.resolve({ rows: [] });
  }
  on() {}
}

require.cache[pgPath] = {
  id: pgPath,
  filename: pgPath,
  loaded: true,
  exports: { Pool: FakePool }
};

process.env.DATABASE_URL = 'postgres://fake-user:fake-pass@fake-host:5432/fake_db';

const db = require('../index');

test('runMigrations() applies every migrations/*.sql file, in filename order', async () => {
  executedQueries.length = 0;
  const result = await db.runMigrations();

  assert.deepEqual(result.applied, ['001_trusts.sql', '002_computer_laps.sql', '003_replication.sql']);
  assert.deepEqual(result.failed, []);
});

test('runMigrations() actually issues the CREATE TABLE statements for every table the managers rely on', async () => {
  executedQueries.length = 0;
  await db.runMigrations();

  const allSql = executedQueries.join('\n');
  const expectedTables = [
    'domain_trusts',
    'laps_passwords',
    'laps_access_log',
    'bitlocker_keys',
    'bitlocker_key_access_log',
    'replication_log',
    'replication_state'
  ];
  for (const table of expectedTables) {
    assert.match(
      allSql,
      new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`),
      `expected a CREATE TABLE IF NOT EXISTS ${table} statement to have been executed`
    );
  }
});

test('initDb() probes connectivity (SELECT 1), migrates, and marks isAvailable() true on success', async () => {
  executedQueries.length = 0;
  const result = await db.initDb();

  assert.equal(result, true);
  assert.equal(db.isAvailable(), true);
  assert.equal(executedQueries[0], 'SELECT 1');
});

test('query() forwards to the pool once the DB is available', async () => {
  executedQueries.length = 0;
  await db.initDb();
  await db.query('SELECT * FROM domain_trusts', []);
  assert.ok(executedQueries.includes('SELECT * FROM domain_trusts'));
});
