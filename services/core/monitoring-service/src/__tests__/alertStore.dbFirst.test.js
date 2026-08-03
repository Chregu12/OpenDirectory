'use strict';

/**
 * DB-first persistence tests for AlertStore (src/database/alertStore.js),
 * against a STATEFUL fake `pg` Pool (see src/testSupport/fakePgPool.js) —
 * not the common "always resolve empty rows" mock, which would make
 * db.isAvailable() true while every SELECT still comes back empty, letting
 * a create -> findById roundtrip pass even if it's silently falling
 * through to the in-memory Map instead of actually going through the DB
 * path. This fake proves the SQL AlertStore issues (and the row <-> object
 * mapping in AlertStore._rowToAlert) round-trips real data.
 *
 * Companion file alertStore.inMemoryFallback.test.js covers the other half
 * ("DB-first mit in-memory-Fallback"): the same public API working with no
 * database at all.
 */

const { makeFakeAlertsPool } = require('../testSupport/fakePgPool');

const mockPool = makeFakeAlertsPool();

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => mockPool),
}));

const fs = require('fs');
const path = require('path');

let AlertStore;
let db;
let store;

beforeAll(async () => {
  AlertStore = require('../database/alertStore');
  db = require('../db/client');
  store = new AlertStore();
  // Let db.initDb() (fire-and-forget in the AlertStore constructor) settle.
  await new Promise((resolve) => setTimeout(resolve, 50));
});

it('connects successfully against the fake DB: db.isAvailable() is true', () => {
  expect(db.isAvailable()).toBe(true);
});

describe('001_alerts_schema.sql — DOUBLE PRECISION regression guard', () => {
  it('declares the timestamp columns as DOUBLE PRECISION, not BIGINT', () => {
    // Regression guard for the type bug fixed this session: node-postgres
    // returns BIGINT/int8 columns as strings (to avoid silent precision
    // loss), which would silently turn alert.createdAt/updatedAt/etc. into
    // strings on every DB-backed read. DOUBLE PRECISION (float8) is parsed
    // back into a JS number instead. If this migration ever regresses back
    // to BIGINT, this test catches it even before a roundtrip test would.
    const sql = fs.readFileSync(
      path.join(__dirname, '../db/migrations/001_alerts_schema.sql'),
      'utf8'
    );
    for (const col of ['created_at', 'updated_at', 'acknowledged_at', 'resolved_at']) {
      const line = sql.split('\n').find((l) => l.trim().startsWith(col));
      expect(line).toBeDefined();
      expect(line).toMatch(/DOUBLE PRECISION/);
      expect(line).not.toMatch(/BIGINT/);
    }
  });
});

describe('create -> findById -> acknowledge -> resolve -> delete roundtrip (DB path)', () => {
  let alertId;

  it('create() persists via the DB path (INSERT INTO alerts)', async () => {
    const alert = await store.create({
      name: 'High CPU',
      service: 'metrics-collector',
      severity: 'critical',
      message: 'CPU above threshold',
      metric: 'system.cpu_percent',
      threshold: 90,
      currentValue: 97.5,
    });
    alertId = alert.id;

    expect(alert).toMatchObject({
      name: 'High CPU',
      service: 'metrics-collector',
      severity: 'critical',
      status: 'active',
    });
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringMatching(/INSERT INTO alerts/i),
      expect.arrayContaining([alertId])
    );
    // Prove it actually landed in the fake table, not just the in-memory mirror.
    expect(mockPool._table.has(alertId)).toBe(true);
  });

  it('findById() reads the created alert back from the DB path', async () => {
    const found = await store.findById(alertId);
    expect(found).not.toBeNull();
    expect(found).toMatchObject({ id: alertId, name: 'High CPU', status: 'active' });
  });

  it('createdAt/updatedAt stay JS numbers after a DB roundtrip (type regression test)', async () => {
    // This is the actual regression test for the createdAt/updatedAt type
    // bug fixed this session: assert the DB-path read gives back numbers,
    // not strings, for every timestamp field the fake DB round-tripped.
    const found = await store.findById(alertId);
    expect(typeof found.createdAt).toBe('number');
    expect(typeof found.updatedAt).toBe('number');
    expect(Number.isFinite(found.createdAt)).toBe(true);
    expect(Number.isFinite(found.updatedAt)).toBe(true);
  });

  it('acknowledge() updates status/acknowledgedAt/acknowledgedBy and persists via UPDATE alerts', async () => {
    const acked = await store.acknowledge(alertId, 'alice@example.com');
    expect(acked).toMatchObject({
      id: alertId,
      status: 'acknowledged',
      acknowledgedBy: 'alice@example.com',
    });
    expect(typeof acked.acknowledgedAt).toBe('number');
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringMatching(/UPDATE alerts/i),
      expect.arrayContaining([alertId])
    );

    const reread = await store.findById(alertId);
    expect(reread.status).toBe('acknowledged');
    expect(reread.acknowledgedBy).toBe('alice@example.com');
    expect(typeof reread.acknowledgedAt).toBe('number');
  });

  it('resolve() updates status/resolvedAt and persists via UPDATE alerts', async () => {
    const resolved = await store.resolve(alertId);
    expect(resolved).toMatchObject({ id: alertId, status: 'resolved' });
    expect(typeof resolved.resolvedAt).toBe('number');

    const reread = await store.findById(alertId);
    expect(reread.status).toBe('resolved');
    expect(typeof reread.resolvedAt).toBe('number');
  });

  it('delete() removes it via the DB path and findById returns null afterward', async () => {
    const deleted = await store.delete(alertId);
    expect(deleted).toBe(true);
    expect(mockPool._table.has(alertId)).toBe(false);

    const reread = await store.findById(alertId);
    expect(reread).toBeNull();
  });

  it('delete() returns false for an unknown id', async () => {
    const deleted = await store.delete('does-not-exist');
    expect(deleted).toBe(false);
  });
});

describe('countByStatus / getActiveCount (DB path)', () => {
  beforeAll(async () => {
    mockPool._table.clear();
    await store.create({ name: 'a1', service: 'svc', severity: 'critical' }); // active
    const a2 = await store.create({ name: 'a2', service: 'svc', severity: 'warning' });
    await store.acknowledge(a2.id, 'bob');
    const a3 = await store.create({ name: 'a3', service: 'svc', severity: 'info' });
    await store.resolve(a3.id);
    await store.create({ name: 'a4', service: 'svc', severity: 'critical' }); // active
  });

  it('countByStatus reflects every persisted alert, grouped by status', async () => {
    const counts = await store.countByStatus();
    expect(counts).toEqual({ active: 2, acknowledged: 1, resolved: 1 });
  });

  it('getActiveCount returns only the active alerts', async () => {
    const count = await store.getActiveCount();
    expect(count).toBe(2);
  });
});
