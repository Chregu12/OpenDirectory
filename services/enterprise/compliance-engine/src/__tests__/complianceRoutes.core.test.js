'use strict';

/**
 * Lean E2E coverage for the pre-existing compliance-engine endpoints that
 * shipped without any test suite: baselines, results, evaluate, scores,
 * trend, waivers, dashboard, reports, and frameworks.
 *
 * These routes take their engines (evaluator, baselineManager, waiverManager,
 * scoreCalculator, trendAnalyzer, reportGenerator) as injected dependencies
 * and only reach into `db.query` directly for a few read paths (results,
 * frameworks) - the same pattern as devices/violations in
 * complianceRoutes.devicesAndViolations.test.js. Mocking those deps directly
 * with jest.fn() keeps this suite fast and free of any real Postgres/engine
 * wiring, matching the pattern already used for the sibling gating suites
 * (e.g. services/core/device-service).
 */

const express = require('express');
const request = require('supertest');
const createComplianceRoutes = require('../routes/complianceRoutes');

function buildApp(deps) {
  const app = express();
  app.use(express.json());
  app.use('/api/compliance', createComplianceRoutes(deps));
  return app;
}

function mockDeps(overrides = {}) {
  return {
    evaluator: { evaluateDevice: jest.fn(), getDeviceScore: jest.fn(), getFleetScore: jest.fn() },
    baselineManager: { listBaselines: jest.fn(), getBaseline: jest.fn(), createBaseline: jest.fn(), updateBaseline: jest.fn() },
    waiverManager: { listWaivers: jest.fn(), createWaiver: jest.fn(), revokeWaiver: jest.fn(), getStats: jest.fn() },
    scoreCalculator: { getOUScore: jest.fn(), getTrend: jest.fn(), getDomainScore: jest.fn() },
    trendAnalyzer: { analyzeTrends: jest.fn() },
    reportGenerator: { generateReport: jest.fn() },
    db: { query: jest.fn() },
    ...overrides,
  };
}

// ─── Baselines ──────────────────────────────────────────────────────────

describe('GET /api/compliance/baselines', () => {
  test('lists baselines and forwards query filters', async () => {
    const deps = mockDeps();
    deps.baselineManager.listBaselines.mockResolvedValue([{ id: 'b1' }, { id: 'b2' }]);
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/baselines?framework=cis&platform=windows&enabled=true');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, data: [{ id: 'b1' }, { id: 'b2' }], count: 2 });
    expect(deps.baselineManager.listBaselines).toHaveBeenCalledWith(
      expect.objectContaining({ framework: 'cis', platform: 'windows', enabled: true })
    );
  });

  test('returns 500 when listBaselines throws', async () => {
    const deps = mockDeps();
    deps.baselineManager.listBaselines.mockRejectedValue(new Error('boom'));
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/baselines');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to list baselines' });
  });
});

describe('GET /api/compliance/baselines/:id', () => {
  test('returns the baseline when found', async () => {
    const deps = mockDeps();
    deps.baselineManager.getBaseline.mockResolvedValue({ id: 'b1', name: 'CIS Windows 11' });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/baselines/b1');

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ id: 'b1', name: 'CIS Windows 11' });
  });

  test('returns 404 when the baseline does not exist', async () => {
    const deps = mockDeps();
    deps.baselineManager.getBaseline.mockResolvedValue(null);
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/baselines/missing');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ success: false, error: 'Baseline not found' });
  });
});

describe('POST /api/compliance/baselines', () => {
  test('rejects a request missing required fields without calling the manager', async () => {
    const deps = mockDeps();
    const app = buildApp(deps);

    const res = await request(app).post('/api/compliance/baselines').send({ name: 'Only Name' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Missing required fields/);
    expect(deps.baselineManager.createBaseline).not.toHaveBeenCalled();
  });

  test('creates a baseline and returns 201', async () => {
    const deps = mockDeps();
    const created = { id: 'b3', name: 'Custom', framework: 'custom', version: '1.0' };
    deps.baselineManager.createBaseline.mockResolvedValue(created);
    const app = buildApp(deps);

    const res = await request(app)
      .post('/api/compliance/baselines')
      .send({ name: 'Custom', framework: 'custom', version: '1.0' });

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ success: true, data: created });
  });

  test('maps validation errors from the manager to 400', async () => {
    const deps = mockDeps();
    deps.baselineManager.createBaseline.mockRejectedValue(new Error('Invalid platform'));
    const app = buildApp(deps);

    const res = await request(app)
      .post('/api/compliance/baselines')
      .send({ name: 'X', framework: 'cis', version: '1.0' });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ success: false, error: 'Invalid platform' });
  });

  test('maps unexpected errors from the manager to 500', async () => {
    const deps = mockDeps();
    deps.baselineManager.createBaseline.mockRejectedValue(new Error('db exploded'));
    const app = buildApp(deps);

    const res = await request(app)
      .post('/api/compliance/baselines')
      .send({ name: 'X', framework: 'cis', version: '1.0' });

    expect(res.status).toBe(500);
  });
});

describe('PUT /api/compliance/baselines/:id', () => {
  test('updates a baseline and returns 200', async () => {
    const deps = mockDeps();
    deps.baselineManager.updateBaseline.mockResolvedValue({ id: 'b1', name: 'Updated' });
    const app = buildApp(deps);

    const res = await request(app).put('/api/compliance/baselines/b1').send({ name: 'Updated' });

    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe('Updated');
  });

  test('returns 404 when the manager reports the baseline was not found', async () => {
    const deps = mockDeps();
    deps.baselineManager.updateBaseline.mockRejectedValue(new Error('Baseline not found'));
    const app = buildApp(deps);

    const res = await request(app).put('/api/compliance/baselines/missing').send({ name: 'X' });

    expect(res.status).toBe(404);
  });

  test('returns 400 when there are no valid fields to update', async () => {
    const deps = mockDeps();
    deps.baselineManager.updateBaseline.mockRejectedValue(new Error('No valid fields to update'));
    const app = buildApp(deps);

    const res = await request(app).put('/api/compliance/baselines/b1').send({});

    expect(res.status).toBe(400);
  });
});

// ─── Results & Evaluation ───────────────────────────────────────────────

describe('GET /api/compliance/results/:deviceId', () => {
  test('queries results filtered by baselineId/framework/limit', async () => {
    const deps = mockDeps();
    deps.db.query.mockResolvedValue({ rows: [{ id: 'r1' }] });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/results/dev-1?framework=cis&limit=5');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, data: [{ id: 'r1' }], count: 1 });
    const [sql, params] = deps.db.query.mock.calls[0];
    expect(sql).toContain('cb.framework = $2');
    expect(sql).toContain('LIMIT $3');
    expect(params).toEqual(['dev-1', 'cis', 5]);
  });

  test('returns 500 when the query fails', async () => {
    const deps = mockDeps();
    deps.db.query.mockRejectedValue(new Error('db down'));
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/results/dev-1');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to get compliance results' });
  });
});

describe('POST /api/compliance/evaluate/:deviceId', () => {
  test('rejects an empty body without invoking the evaluator', async () => {
    const deps = mockDeps();
    const app = buildApp(deps);

    const res = await request(app).post('/api/compliance/evaluate/dev-1').send({});

    expect(res.status).toBe(400);
    expect(deps.evaluator.evaluateDevice).not.toHaveBeenCalled();
  });

  test('evaluates the device and broadcasts the result when a broadcaster is wired', async () => {
    const deps = mockDeps();
    const result = { overallScore: 88, evaluatedAt: '2026-08-01T00:00:00.000Z' };
    deps.evaluator.evaluateDevice.mockResolvedValue(result);
    deps.broadcast = jest.fn();
    const app = buildApp(deps);

    const res = await request(app).post('/api/compliance/evaluate/dev-1').send({ os: 'windows' });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, data: result });
    expect(deps.evaluator.evaluateDevice).toHaveBeenCalledWith('dev-1', { os: 'windows' });
    expect(deps.broadcast).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'compliance.evaluation.completed', deviceId: 'dev-1', overallScore: 88 })
    );
  });

  test('returns 500 when evaluation fails', async () => {
    const deps = mockDeps();
    deps.evaluator.evaluateDevice.mockRejectedValue(new Error('boom'));
    const app = buildApp(deps);

    const res = await request(app).post('/api/compliance/evaluate/dev-1').send({ os: 'linux' });

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Compliance evaluation failed' });
  });
});

// ─── Scores & Trend ─────────────────────────────────────────────────────

describe('Score and trend endpoints', () => {
  test('GET /score/:deviceId returns the device score', async () => {
    const deps = mockDeps();
    deps.evaluator.getDeviceScore.mockResolvedValue({ deviceId: 'dev-1', score: 91 });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/score/dev-1');

    expect(res.status).toBe(200);
    expect(res.body.data.score).toBe(91);
  });

  test('GET /score/fleet forwards filters and returns the fleet score', async () => {
    const deps = mockDeps();
    deps.evaluator.getFleetScore.mockResolvedValue({ averageScore: 77 });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/score/fleet?framework=nist&platform=macos');

    expect(res.status).toBe(200);
    expect(deps.evaluator.getFleetScore).toHaveBeenCalledWith(
      expect.objectContaining({ framework: 'nist', platform: 'macos' })
    );
    expect(res.body.data.averageScore).toBe(77);
  });

  test('GET /score/ou/:ouId delegates to scoreCalculator', async () => {
    const deps = mockDeps();
    deps.scoreCalculator.getOUScore.mockResolvedValue({ ouId: 'ou-1', score: 60 });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/score/ou/ou-1');

    expect(res.status).toBe(200);
    expect(deps.scoreCalculator.getOUScore).toHaveBeenCalledWith('ou-1');
    expect(res.body.data.score).toBe(60);
  });

  test('GET /trend/:deviceId defaults to 30 days and forwards a custom window', async () => {
    const deps = mockDeps();
    deps.scoreCalculator.getTrend.mockResolvedValue([{ day: 1, score: 80 }]);
    const app = buildApp(deps);

    await request(app).get('/api/compliance/trend/dev-1');
    expect(deps.scoreCalculator.getTrend).toHaveBeenCalledWith('dev-1', 30);

    await request(app).get('/api/compliance/trend/dev-1?days=7');
    expect(deps.scoreCalculator.getTrend).toHaveBeenCalledWith('dev-1', 7);
  });
});

// ─── Waivers ────────────────────────────────────────────────────────────

describe('Waivers endpoints', () => {
  test('GET /waivers lists waivers with filters', async () => {
    const deps = mockDeps();
    deps.waiverManager.listWaivers.mockResolvedValue([{ id: 'w1' }]);
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/waivers?status=active&deviceId=dev-1');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, data: [{ id: 'w1' }], count: 1 });
    expect(deps.waiverManager.listWaivers).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'active', deviceId: 'dev-1' })
    );
  });

  test('POST /waivers rejects a request missing required fields', async () => {
    const deps = mockDeps();
    const app = buildApp(deps);

    const res = await request(app).post('/api/compliance/waivers').send({ checkId: 'c1' });

    expect(res.status).toBe(400);
    expect(deps.waiverManager.createWaiver).not.toHaveBeenCalled();
  });

  test('POST /waivers creates a waiver and returns 201', async () => {
    const deps = mockDeps();
    const waiver = { id: 'w1', checkId: 'c1' };
    deps.waiverManager.createWaiver.mockResolvedValue(waiver);
    const app = buildApp(deps);

    const res = await request(app)
      .post('/api/compliance/waivers')
      .send({ checkId: 'c1', reason: 'Approved risk', approvedBy: 'alice', expiresAt: '2026-12-31' });

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ success: true, data: waiver });
  });

  test('POST /waivers maps "already exists" errors to 400', async () => {
    const deps = mockDeps();
    deps.waiverManager.createWaiver.mockRejectedValue(new Error('Waiver already exists for this check'));
    const app = buildApp(deps);

    const res = await request(app)
      .post('/api/compliance/waivers')
      .send({ checkId: 'c1', reason: 'x', approvedBy: 'alice', expiresAt: '2026-12-31' });

    expect(res.status).toBe(400);
  });

  test('DELETE /waivers/:id revokes a waiver and returns 200', async () => {
    const deps = mockDeps();
    deps.waiverManager.revokeWaiver.mockResolvedValue({ id: 'w1', status: 'revoked' });
    const app = buildApp(deps);

    const res = await request(app).delete('/api/compliance/waivers/w1');

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('revoked');
  });

  test('DELETE /waivers/:id returns 404 when the waiver is not found', async () => {
    const deps = mockDeps();
    deps.waiverManager.revokeWaiver.mockRejectedValue(new Error('Waiver not found'));
    const app = buildApp(deps);

    const res = await request(app).delete('/api/compliance/waivers/missing');

    expect(res.status).toBe(404);
  });
});

// ─── Dashboard ──────────────────────────────────────────────────────────

describe('GET /api/compliance/dashboard', () => {
  test('aggregates fleet score, domain score, waiver stats and trends', async () => {
    const deps = mockDeps();
    deps.evaluator.getFleetScore.mockResolvedValue({ averageScore: 85 });
    deps.scoreCalculator.getDomainScore.mockResolvedValue({ domain: 'corp.local', score: 85 });
    deps.waiverManager.getStats.mockResolvedValue({ active: 3 });
    deps.trendAnalyzer.analyzeTrends.mockResolvedValue({ direction: 'improving' });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/dashboard');

    expect(res.status).toBe(200);
    expect(res.body.data.fleet).toEqual({ averageScore: 85 });
    expect(res.body.data.domain).toEqual({ domain: 'corp.local', score: 85 });
    expect(res.body.data.waivers).toEqual({ active: 3 });
    expect(res.body.data.trends).toEqual({ direction: 'improving' });
    expect(res.body.data.generatedAt).toEqual(expect.any(String));
  });

  test('returns 500 when any of the parallel aggregations fail', async () => {
    const deps = mockDeps();
    deps.evaluator.getFleetScore.mockResolvedValue({});
    deps.scoreCalculator.getDomainScore.mockResolvedValue({});
    deps.waiverManager.getStats.mockRejectedValue(new Error('boom'));
    deps.trendAnalyzer.analyzeTrends.mockResolvedValue({});
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/dashboard');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to build dashboard data' });
  });
});

// ─── Reports ────────────────────────────────────────────────────────────

describe('POST /api/compliance/reports/generate', () => {
  test('streams back a PDF buffer with a device-scoped filename', async () => {
    const deps = mockDeps();
    deps.reportGenerator.generateReport.mockResolvedValue(Buffer.from('%PDF-1.4 fake'));
    const app = buildApp(deps);

    const res = await request(app)
      .post('/api/compliance/reports/generate')
      .send({ deviceId: 'dev-1', framework: 'cis' });

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['content-disposition']).toContain('compliance-report-dev-1-');
  });

  test('returns 500 when report generation fails', async () => {
    const deps = mockDeps();
    deps.reportGenerator.generateReport.mockRejectedValue(new Error('render failed'));
    const app = buildApp(deps);

    const res = await request(app).post('/api/compliance/reports/generate').send({});

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to generate compliance report' });
  });
});

// ─── Frameworks ─────────────────────────────────────────────────────────

describe('GET /api/compliance/frameworks', () => {
  test('merges the static framework catalog with baseline counts from the DB', async () => {
    const deps = mockDeps();
    deps.db.query.mockResolvedValue({
      rows: [{ framework: 'cis', baseline_count: '4', platforms: ['windows', 'linux'] }],
    });
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/frameworks');

    expect(res.status).toBe(200);
    const cis = res.body.data.find((f) => f.id === 'cis');
    expect(cis.baselineCount).toBe(4);
    expect(cis.platforms).toEqual(['windows', 'linux']);
    const nist = res.body.data.find((f) => f.id === 'nist');
    expect(nist.baselineCount).toBe(0);
    expect(nist.platforms).toEqual([]);
  });

  test('returns 500 when the query fails', async () => {
    const deps = mockDeps();
    deps.db.query.mockRejectedValue(new Error('db down'));
    const app = buildApp(deps);

    const res = await request(app).get('/api/compliance/frameworks');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to list frameworks' });
  });
});
