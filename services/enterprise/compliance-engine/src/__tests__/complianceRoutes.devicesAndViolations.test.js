'use strict';

/**
 * Lean E2E test for the two new compliance-engine endpoints:
 *   GET /api/compliance/devices     - fleet-wide per-device roster
 *   GET /api/compliance/violations  - violations-by-severity summary
 *
 * compliance-engine has no pre-existing test suite (it isn't wired into
 * scripts/test-all.sh), so this follows the same "mount the real router,
 * mock `pg` at the db.query boundary, drive it with supertest" pattern used
 * by the gating core services (e.g. services/core/device-service).
 *
 * This file intentionally does not touch package.json - it assumes `express`
 * and `supertest` are resolvable (installed locally for verification; not a
 * committed dependency change).
 */

const express = require('express');
const request = require('supertest');
const createComplianceRoutes = require('../routes/complianceRoutes');

function buildApp(db) {
  const app = express();
  app.use(express.json());
  app.use('/api/compliance', createComplianceRoutes({ db }));
  return app;
}

describe('GET /api/compliance/devices', () => {
  test('aggregates the latest per-device results into a fleet roster', async () => {
    const rows = [
      {
        device_id: 'dev-1',
        last_evaluated_at: '2026-07-20T00:00:00.000Z',
        baselines_evaluated: '2',
        overall_score: '95.00',
        critical_failures: '0',
        high_failures: '0',
        medium_failures: '1',
        low_failures: '2',
        total_failures: '3',
        platforms: ['windows'],
      },
      {
        device_id: 'dev-2',
        last_evaluated_at: '2026-07-19T00:00:00.000Z',
        baselines_evaluated: '1',
        overall_score: '42.50',
        critical_failures: '3',
        high_failures: '4',
        medium_failures: '0',
        low_failures: '0',
        total_failures: '7',
        platforms: ['linux'],
      },
    ];
    const db = { query: jest.fn().mockResolvedValue({ rows }) };
    const app = buildApp(db);

    const res = await request(app).get('/api/compliance/devices');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.count).toBe(2);
    expect(res.body.data).toHaveLength(2);

    const [d1, d2] = res.body.data;
    expect(d1).toMatchObject({
      deviceId: 'dev-1',
      hostname: null,
      platform: 'windows',
      overallScore: 95,
      status: 'compliant',
      baselinesEvaluated: 2,
      violations: { critical: 0, high: 0, medium: 1, low: 2, total: 3 },
    });
    expect(d2).toMatchObject({
      deviceId: 'dev-2',
      overallScore: 42.5,
      status: 'non_compliant',
      violations: { critical: 3, high: 4, medium: 0, low: 0, total: 7 },
    });

    // Honesty check: hostname is documented as unavailable, not guessed.
    expect(res.body.meta.hostnameAvailable).toBe(false);
  });

  test('applies framework/platform query filters as SQL parameters', async () => {
    const db = { query: jest.fn().mockResolvedValue({ rows: [] }) };
    const app = buildApp(db);

    await request(app).get('/api/compliance/devices?framework=cis&platform=windows&limit=10&offset=5');

    expect(db.query).toHaveBeenCalledTimes(1);
    const [sql, params] = db.query.mock.calls[0];
    expect(sql).toContain('cb.framework = $1');
    expect(sql).toContain('cb.platform = $2');
    expect(sql).toContain('LIMIT $3');
    expect(sql).toContain('OFFSET $4');
    expect(params).toEqual(['cis', 'windows', 10, 5]);
  });

  test('filters the aggregated roster by status after bucketing', async () => {
    const rows = [
      { device_id: 'dev-1', last_evaluated_at: null, baselines_evaluated: '1', overall_score: '95', critical_failures: '0', high_failures: '0', medium_failures: '0', low_failures: '0', total_failures: '0', platforms: [] },
      { device_id: 'dev-2', last_evaluated_at: null, baselines_evaluated: '1', overall_score: '40', critical_failures: '1', high_failures: '0', medium_failures: '0', low_failures: '0', total_failures: '1', platforms: [] },
    ];
    const db = { query: jest.fn().mockResolvedValue({ rows }) };
    const app = buildApp(db);

    const res = await request(app).get('/api/compliance/devices?status=non_compliant');

    expect(res.body.count).toBe(1);
    expect(res.body.data[0].deviceId).toBe('dev-2');
  });

  test('returns 500 with an error envelope when the query fails', async () => {
    const db = { query: jest.fn().mockRejectedValue(new Error('db down')) };
    const app = buildApp(db);

    const res = await request(app).get('/api/compliance/devices');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to get device compliance roster' });
  });
});

describe('GET /api/compliance/violations', () => {
  test('returns counts and top offending checks grouped by severity', async () => {
    const countRows = [{ critical: '2', high: '5', medium: '10', low: '3', total: '20' }];
    const detailRows = [
      { check_id: 'c1', title: 'BitLocker not enabled', severity: 'critical', category: 'encryption', failure_count: '2', affected_devices: '2' },
      { check_id: 'h1', title: 'Screen lock timeout too long', severity: 'high', category: 'access', failure_count: '5', affected_devices: '4' },
    ];
    const db = {
      query: jest.fn((sql) => {
        if (sql.includes('jsonb_array_elements')) {
          return Promise.resolve({ rows: detailRows });
        }
        return Promise.resolve({ rows: countRows });
      }),
    };
    const app = buildApp(db);

    const res = await request(app).get('/api/compliance/violations');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.count).toBe(4);

    const bySeverity = Object.fromEntries(res.body.data.map((g) => [g.severity, g]));
    expect(bySeverity.critical.count).toBe(2);
    expect(bySeverity.critical.items).toEqual([
      { checkId: 'c1', title: 'BitLocker not enabled', severity: 'critical', category: 'encryption', affectedDevices: 2, failureCount: 2 },
    ]);
    expect(bySeverity.high.count).toBe(5);
    expect(bySeverity.high.items[0].checkId).toBe('h1');
    // Severities with no offending checks in the sample still appear with
    // their (possibly zero) count and an empty items list - the UI always
    // has all four severity buckets to render.
    expect(bySeverity.medium).toEqual({ severity: 'medium', count: 10, items: [] });
    expect(bySeverity.low).toEqual({ severity: 'low', count: 3, items: [] });
  });

  test('applies framework/platform filters to both the count and detail queries', async () => {
    const db = { query: jest.fn().mockResolvedValue({ rows: [] }) };
    const app = buildApp(db);

    await request(app).get('/api/compliance/violations?framework=nist&platform=macos');

    expect(db.query).toHaveBeenCalledTimes(2);
    for (const [sql, params] of db.query.mock.calls) {
      expect(sql).toContain('cb.framework = $1');
      expect(sql).toContain('cb.platform = $2');
      expect(params).toEqual(['nist', 'macos']);
    }
  });

  test('returns 500 with an error envelope when either query fails', async () => {
    const db = { query: jest.fn().mockRejectedValue(new Error('db down')) };
    const app = buildApp(db);

    const res = await request(app).get('/api/compliance/violations');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to get violations summary' });
  });
});
