'use strict';

/**
 * E2E API tests for monitoring-service.
 *
 * monitoring-service was previously untested and, before this session,
 * unrequireable in a test process at all (a bare `require('./index')`
 * opened a real listening HTTP server as a side effect of module load and
 * never returned — see the require.main guard added in src/index.js). This
 * suite exercises the real Express app (../index, now exported as
 * `{ app, start }`) via supertest, with:
 *
 *   - `pg` replaced by the STATEFUL fake pool from
 *     src/testSupport/fakePgPool.js (see that file's comment for why a
 *     "always resolve empty rows" mock would be too weak a proof of DB
 *     persistence).
 *   - `@opendirectory/grpc-event-bus` mocked (virtual — the package isn't
 *     installed under that name in this repo; see
 *     eventBusNoopFallback.test.js for what happens when neither
 *     require in src/index.js's resolution IIFE succeeds).
 *
 * Deliberately does NOT call start(): supertest drives the exported Express
 * `app` object directly without opening a real listening socket, and
 * start() is never invoked, so none of the six background-job timers in
 * startBackgroundJobs() ever run during this suite.
 */

process.env.PORT = '0';

const { makeFakeAlertsPool } = require('../testSupport/fakePgPool');

const mockPool = makeFakeAlertsPool();

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => mockPool),
}));

jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
    subscribe: jest.fn().mockResolvedValue(undefined),
    close: jest.fn().mockResolvedValue(undefined),
    isConnected: jest.fn().mockReturnValue(true),
  })),
}), { virtual: true });

const request = require('supertest');
let app;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  ({ app } = require('../index'));
  // Let db.initDb() (fire-and-forget from the AlertStore constructor) settle.
  await new Promise((resolve) => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
});

// ─── Health ─────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('is reachable and reports service identity + metrics summary', async () => {
    const res = await request(app).get('/health');
    // 503 is expected here, not a failure: HealthChecker (constructed as
    // part of the app) really pings the configured internal service URLs
    // (config.services.*, e.g. http://authentication-service/health) via
    // axios, and none of those hosts resolve in a test environment, so the
    // aggregate status legitimately comes back 'degraded' -> 503. This
    // mirrors what a real freshly-booted instance would report before its
    // sibling services are reachable; the endpoint being reachable at all
    // (not erroring/timing out) and returning the right shape is what
    // matters here.
    expect([200, 503]).toContain(res.status);
    expect(res.body).toMatchObject({ service: 'monitoring-service' });
    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('uptime');
    expect(res.body.metrics).toHaveProperty('alertsActive');
    expect(res.body.metrics).toHaveProperty('metricsCollected');
    expect(res.body.metrics).toHaveProperty('anomaliesDetected');
  });
});

// ─── Alerts CRUD roundtrip (DB path), via real HTTP routes ─────────────────

describe('Alert endpoints (DB path)', () => {
  let alertId;

  it('POST /api/alerts creates an alert (201) and persists via the DB path', async () => {
    const res = await request(app).post('/api/alerts').send({
      name: 'Disk Full',
      service: 'file-share',
      severity: 'critical',
      message: 'Disk usage above 95%',
      metric: 'disk.usage_percent',
      threshold: 95,
      currentValue: 98.2,
    });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toMatchObject({
      name: 'Disk Full',
      service: 'file-share',
      severity: 'critical',
      status: 'active',
    });
    expect(res.body.data).toHaveProperty('id');
    alertId = res.body.data.id;

    // Prove real persistence, not just the in-memory mirror.
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringMatching(/INSERT INTO alerts/i),
      expect.arrayContaining([alertId])
    );
  });

  it('GET /api/alerts lists alerts and includes the created one', async () => {
    const res = await request(app).get('/api/alerts');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.some((a) => a.id === alertId)).toBe(true);
  });

  it('GET /api/alerts?status=active filters correctly', async () => {
    const res = await request(app).get('/api/alerts').query({ status: 'active' });
    expect(res.status).toBe(200);
    expect(res.body.data.every((a) => a.status === 'active')).toBe(true);
    expect(res.body.data.some((a) => a.id === alertId)).toBe(true);
  });

  it('GET /api/alerts/:alertId retrieves the created alert from the DB path', async () => {
    const res = await request(app).get(`/api/alerts/${alertId}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ id: alertId, name: 'Disk Full' });
    // Type regression: createdAt/updatedAt must stay numbers over HTTP too.
    expect(typeof res.body.data.createdAt).toBe('number');
    expect(typeof res.body.data.updatedAt).toBe('number');
  });

  it('GET /api/alerts/:alertId 404s for an unknown id', async () => {
    const res = await request(app).get('/api/alerts/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Alert not found');
  });

  it('POST /api/alerts/:alertId/acknowledge acknowledges and persists via the DB path', async () => {
    const res = await request(app)
      .post(`/api/alerts/${alertId}/acknowledge`)
      .send({ acknowledgedBy: 'oncall@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      id: alertId,
      status: 'acknowledged',
      acknowledgedBy: 'oncall@example.com',
    });
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringMatching(/UPDATE alerts/i),
      expect.arrayContaining([alertId])
    );

    const reread = await request(app).get(`/api/alerts/${alertId}`);
    expect(reread.body.data.status).toBe('acknowledged');
  });

  it('POST /api/alerts/:alertId/acknowledge 404s for an unknown id', async () => {
    const res = await request(app).post('/api/alerts/does-not-exist/acknowledge').send({});
    expect(res.status).toBe(404);
  });

  it('DELETE /api/alerts/:alertId removes it via the DB path', async () => {
    const res = await request(app).delete(`/api/alerts/${alertId}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const reread = await request(app).get(`/api/alerts/${alertId}`);
    expect(reread.status).toBe(404);
  });
});
