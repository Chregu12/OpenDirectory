'use strict';

/**
 * Companion to alertStore.dbFirst.test.js: proves the other half of
 * "DB-first mit in-memory-Fallback" — that AlertStore does NOT crash and
 * still serves the exact same public API when PostgreSQL is unavailable
 * (db.isAvailable() stays false throughout, since every pg query here
 * rejects, exactly like a real down/unreachable database would during
 * db.initDb()'s initial `SELECT 1`).
 *
 * Deliberately a separate file: jest.mock('pg', ...) applies per test file
 * (isolated module registry), so this file can mock a permanently-failing
 * pool without affecting alertStore.dbFirst.test.js's stateful DB-path fake.
 */

jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    connect: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

let AlertStore;
let db;
let store;

beforeAll(async () => {
  AlertStore = require('../database/alertStore');
  db = require('../db/client');
  store = new AlertStore();
  await new Promise((resolve) => setTimeout(resolve, 50));
});

it('does not crash on construction without a database: db.isAvailable() is false', () => {
  expect(db.isAvailable()).toBe(false);
});

describe('create -> findById -> acknowledge -> resolve -> delete roundtrip (in-memory fallback)', () => {
  let alertId;

  it('create() still works purely on the in-memory Map', async () => {
    const alert = await store.create({ name: 'No DB Alert', service: 'svc', severity: 'warning' });
    alertId = alert.id;
    expect(alert).toMatchObject({ name: 'No DB Alert', status: 'active' });
    expect(typeof alert.createdAt).toBe('number');
  });

  it('findById() reads it back from the in-memory Map', async () => {
    const found = await store.findById(alertId);
    expect(found).toMatchObject({ id: alertId, name: 'No DB Alert' });
  });

  it('acknowledge() works with no DB present', async () => {
    const acked = await store.acknowledge(alertId, 'carol');
    expect(acked).toMatchObject({ id: alertId, status: 'acknowledged', acknowledgedBy: 'carol' });
  });

  it('resolve() works with no DB present', async () => {
    const resolved = await store.resolve(alertId);
    expect(resolved).toMatchObject({ id: alertId, status: 'resolved' });
  });

  it('delete() works with no DB present and findById returns null afterward', async () => {
    const deleted = await store.delete(alertId);
    expect(deleted).toBe(true);
    const reread = await store.findById(alertId);
    expect(reread).toBeNull();
  });
});

describe('countByStatus / getActiveCount (in-memory fallback)', () => {
  beforeAll(async () => {
    await store.create({ name: 'b1', service: 'svc', severity: 'critical' }); // active
    const b2 = await store.create({ name: 'b2', service: 'svc', severity: 'warning' });
    await store.acknowledge(b2.id, 'dave');
  });

  it('countByStatus reflects the in-memory alerts, grouped by status', async () => {
    const counts = await store.countByStatus();
    expect(counts.active).toBeGreaterThanOrEqual(1);
    expect(counts.acknowledged).toBeGreaterThanOrEqual(1);
  });

  it('getActiveCount returns only the active alerts', async () => {
    const activeAlerts = await store.findAll({ status: 'active', limit: Number.MAX_SAFE_INTEGER });
    const count = await store.getActiveCount();
    expect(count).toBe(activeAlerts.length);
  });
});
