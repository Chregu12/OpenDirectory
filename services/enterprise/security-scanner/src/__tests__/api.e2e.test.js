'use strict';

/**
 * E2E API tests for security-scanner — P0 auth fix verification.
 *
 * Context: this service previously had ZERO HTTP authentication (only
 * helmet()/cors()/rate-limiting were mounted) — see
 * src/middleware/oidcAuth.js for the full rationale. Anyone who could reach
 * the service over the network could trigger an unlimited number of
 * fleet-wide GPO/AD/device exposure scans (POST /api/scanner/scan), install
 * a persistent cron-scheduled scan (POST /api/scanner/schedule), and read
 * every finding/risk-score/trend the scanner has ever produced.
 *
 * This suite drives the REAL oidcAuth/requireAdmin middleware (not a
 * reimplemented stand-in) against the real Express app, following the same
 * pattern as services/enterprise/antivirus-protection/src/__tests__/
 * api.e2e.test.js and services/core/identity-service/src/__tests__/
 * api.e2e.test.js:
 *
 *   - `jose` is mocked with a fake jwtVerify() that decodes a base64url JSON
 *     payload instead of doing real signature verification, so tests can
 *     hand any {sub, roles} identity they need without a live JWKS/IdP.
 *   - `@opendirectory/grpc-event-bus` is mocked (virtual) even though the
 *     real local package resolves at services/../../packages/grpc-event-bus
 *     — nothing in the constructor path touches the network (EventBusClient
 *     connects lazily), and start()/connectBus() are never called by this
 *     suite (supertest talks to the Express app directly), but the mock
 *     keeps the test hermetic and mirrors the pattern used elsewhere in the
 *     fleet.
 *   - security-scanner keeps all state in-memory (no pg/DB dependency), so
 *     no database mock is needed.
 *
 * Matrix asserted:
 *   - GET /health                        -> reachable with no token (skipPath)
 *   - read endpoints (findings, scan
 *     status, risk-score, trends,
 *     benchmarks)                        -> 401 no token, pass with any valid token
 *   - POST /api/scanner/scan             -> 401 no token, 403 non-admin, pass as admin
 *   - POST /api/scanner/schedule         -> 401 no token, 403 non-admin, pass as admin
 *   - garbage / expired bearer tokens    -> 403 / 401, never reach a handler
 */

process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';
process.env.PORT = '0';

// ─── Mock the gRPC event bus (virtual) ─────────────────────────────────────
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// ─── Fake jose: drives the real oidcAuth/requireAdmin logic ───────────────
jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn(() => ({})),
  jwtVerify: jest.fn(async (token) => {
    if (token === 'expired') {
      const err = new Error('expired'); err.code = 'ERR_JWT_EXPIRED'; throw err;
    }
    if (token === 'garbage') {
      throw new Error('invalid signature');
    }
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
const userToken = makeToken({ sub: 'user-1', roles: ['user'] });

const admin = (req) => req.set('Authorization', `Bearer ${adminToken}`);
const asUser = (req) => req.set('Authorization', `Bearer ${userToken}`);

// ─── Now require the app ───────────────────────────────────────────────────

const request = require('supertest');
let app;

beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  const SecurityScannerService = require('../index');
  const service = new SecurityScannerService();
  app = service.app;
});

afterAll(() => {
  jest.restoreAllMocks();
});

// ─── Health (skipPaths) ─────────────────────────────────────────────────────

describe('GET /health', () => {
  it('is reachable with no auth token', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy' });
  });
});

// ─── /metrics (skipPaths) ───────────────────────────────────────────────────
//
// Regression coverage, two bugs at once:
//   1. GET /metrics was never actually registered as a route (only
//      referenced in the rate-limiter's `skip` check), so it always
//      401'd/404'd regardless of auth — a dead reference. Added in
//      src/index.js, matching the exact JSON shape used by
//      device-lifecycle/auto-remediation/graph-explorer/policy-simulator's
//      /metrics.
//   2. Now that it exists, it must be public like those siblings — it's a
//      Prometheus scrape target (see infrastructure/monitoring/
//      prometheus.yml, whose scrape_configs never send a bearer token) and
//      carries no secrets (process uptime/memory/cpu only).
describe('GET /metrics — public Prometheus scrape target (skipPaths)', () => {
  it('is reachable with no auth token', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('uptime');
  });
});

// ─── Auth matrix: reads require a valid JWT, no particular role ───────────

describe('Read endpoints require authentication', () => {
  const reads = [
    '/api/scanner/findings',
    '/api/scanner/risk-score',
    '/api/scanner/benchmarks',
    '/api/scanner/trends',
    '/api/scanner/risk-score/device/some-device-id',
    '/api/scanner/scan/nonexistent-scan-id',
    '/api/scanner/findings/nonexistent-finding-id',
  ];

  it.each(reads)('GET %s -> 401 with no token', async (path) => {
    const res = await request(app).get(path);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'unauthorized');
  });

  it.each(reads)('GET %s -> reaches the handler (not 401/403) with any valid (non-admin) token', async (path) => {
    const res = await asUser(request(app).get(path));
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });

  it('rejects a garbage bearer token with 403', async () => {
    const res = await request(app).get('/api/scanner/findings').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'invalid_token');
  });

  it('rejects an expired bearer token with 401', async () => {
    const res = await request(app).get('/api/scanner/findings').set('Authorization', 'Bearer expired');
    expect(res.status).toBe(401);
  });

  it('unknown routes also require a token (only /health is a skip path)', async () => {
    const res = await request(app).get('/api/scanner/does-not-exist');
    expect(res.status).toBe(401);
    expect((await asUser(request(app).get('/api/scanner/does-not-exist'))).status).toBe(404);
  });
});

// ─── POST /api/scanner/scan — admin-only: triggers a fleet-wide scan ──────

describe('POST /api/scanner/scan (unauthenticated scan trigger — the headline finding)', () => {
  it('401s with no token — an unauthenticated caller can no longer start a scan', async () => {
    const res = await request(app).post('/api/scanner/scan').send({ type: 'full' });
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'unauthorized');
  });

  it('403s for an authenticated non-admin token', async () => {
    const res = await asUser(request(app).post('/api/scanner/scan').send({ type: 'full' }));
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'forbidden');
  });

  it('succeeds (202) for an admin token', async () => {
    const res = await admin(request(app).post('/api/scanner/scan').send({ type: 'full' }));
    expect(res.status).toBe(202);
    expect(res.body).toHaveProperty('scanId');
    expect(res.body).toMatchObject({ message: 'Scan started' });
  });

  it('validation errors still surface for an admin caller (auth does not swallow 400s)', async () => {
    const res = await admin(request(app).post('/api/scanner/scan').send({ type: 'not-a-real-type' }));
    expect(res.status).toBe(400);
  });
});

// ─── POST /api/scanner/schedule — admin-only: persists a recurring scan ───

describe('POST /api/scanner/schedule (unauthenticated scheduling — the second headline finding)', () => {
  it('401s with no token', async () => {
    const res = await request(app).post('/api/scanner/schedule').send({ name: 'weekly' });
    expect(res.status).toBe(401);
  });

  it('403s for an authenticated non-admin token', async () => {
    const res = await asUser(request(app).post('/api/scanner/schedule').send({ name: 'weekly' }));
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'forbidden');
  });

  it('succeeds (201) for an admin token', async () => {
    const res = await admin(request(app).post('/api/scanner/schedule').send({ name: 'weekly', cron: '0 2 * * 0' }));
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ message: 'Scan scheduled', success: true });
    expect(res.body.data).toHaveProperty('id');
  });
});

// ─── End-to-end sanity: an admin-started scan is readable by a plain user ──

describe('cross-check: admin-started scan status is readable by any authenticated user', () => {
  it('GET /api/scanner/scan/:scanId as a non-admin returns the admin-created scan', async () => {
    const startRes = await admin(request(app).post('/api/scanner/scan').send({ type: 'gpo', gpoData: { gpos: [] } }));
    expect(startRes.status).toBe(202);
    const { scanId } = startRes.body;

    const statusRes = await asUser(request(app).get(`/api/scanner/scan/${scanId}`));
    expect(statusRes.status).toBe(200);
    expect(statusRes.body.data).toHaveProperty('id', scanId);
  });
});
