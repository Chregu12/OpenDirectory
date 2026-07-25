'use strict';

/**
 * E2E API tests for antivirus-protection.
 *
 * Context: this service previously had ZERO HTTP authentication (only
 * helmet()/cors() were mounted) — see src/middleware/oidcAuth.js for the
 * full rationale. Anyone who could reach the service over the network could
 * un-quarantine malware (POST .../quarantine/:fileId/restore), permanently
 * destroy quarantine evidence (DELETE .../quarantine/:fileId), dispatch an
 * arbitrary fleet-wide run_av_scan MDM command (POST .../scan), or trigger a
 * signature update (POST .../signatures/update) with no credentials at all.
 *
 * This suite drives the REAL oidcAuth/requireAdmin middleware (not a
 * reimplemented stand-in) against the real Express app, following the same
 * pattern as services/core/identity-service/src/__tests__/api.e2e.test.js:
 *
 *   - `jose` is mocked with a fake jwtVerify() that decodes a base64url JSON
 *     payload instead of doing real signature verification, so tests can
 *     hand any {sub, roles} identity they need without a live JWKS/IdP.
 *   - `pg` is mocked to always reject, so the service runs entirely on its
 *     in-memory (ScanOrchestrator/QuarantineManager/SignatureManager/
 *     ThreatIntelligence) seed data — the same "DB down" fallback path the
 *     production code already falls back to.
 *   - `@opendirectory/grpc-event-bus` is mocked (virtual) since the real
 *     package isn't a declared dependency here and would otherwise try to
 *     dial a real broker transport at module-load time
 *     (`new EventBusClient(...)` runs synchronously when src/index.js is
 *     required).
 *   - `global.fetch` is stubbed so POST /scan's per-device MDM dispatch
 *     doesn't attempt a real network call to OAUTH_PROVIDER_URL.
 *
 * Scope: covers the full auth matrix (skip / read-auth / admin-gated
 * mutation / agent-enrollment-token) named in the audit, not every business
 * rule of every route.
 */

process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';
process.env.DEVICE_ENROLLMENT_TOKEN = 'test-enrollment-token';
process.env.PORT = '0';

// ─── Mock pg BEFORE requiring the app ─────────────────────────────────────
jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    connect: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

// ─── Mock the gRPC event bus (virtual — not an installed dependency here) ──
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
const withEnrollmentToken = (req, token = 'test-enrollment-token') => req.set('x-enrollment-token', token);

// ─── Now require the app ───────────────────────────────────────────────────

const request = require('supertest');
let app;
let originalFetch;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  originalFetch = global.fetch;
  global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

  const AntivirusProtectionService = require('../index');
  const service = new AntivirusProtectionService();
  app = service.app;

  // give any fire-and-forget init a tick to settle
  await new Promise(resolve => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
  global.fetch = originalFetch;
});

// ─── Health (skipPaths) ─────────────────────────────────────────────────────

describe('GET /health', () => {
  it('is reachable with no auth token', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy' });
  });
});

// ─── Auth matrix: reads require a valid JWT, no particular role ───────────

describe('Read endpoints require authentication', () => {
  const reads = [
    '/api/antivirus/scans',
    '/api/antivirus/devices',
    '/api/antivirus/threats',
    '/api/antivirus/quarantine',
    '/api/antivirus/signatures',
    '/api/antivirus/statistics',
    '/api/antivirus/dashboard',
    '/api/antivirus/schedules',
    '/api/antivirus/docs',
  ];

  it.each(reads)('GET %s -> 401 with no token', async (path) => {
    const res = await request(app).get(path);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'unauthorized');
  });

  it.each(reads)('GET %s -> 200 with any valid (non-admin) token', async (path) => {
    const res = await asUser(request(app).get(path));
    expect(res.status).toBe(200);
  });

  it('rejects a garbage bearer token with 403', async () => {
    const res = await request(app).get('/api/antivirus/quarantine').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'invalid_token');
  });

  it('rejects an expired bearer token with 401', async () => {
    const res = await request(app).get('/api/antivirus/quarantine').set('Authorization', 'Bearer expired');
    expect(res.status).toBe(401);
  });

  it('GET / and GET /metrics also require a token (only /health is a skip path)', async () => {
    const rootRes = await request(app).get('/');
    expect(rootRes.status).toBe(401);
    const metricsRes = await request(app).get('/metrics');
    expect(metricsRes.status).toBe(401);

    expect((await asUser(request(app).get('/'))).status).toBe(200);
    expect((await asUser(request(app).get('/metrics'))).status).toBe(200);
  });
});

// ─── Un-quarantine (restore) — the headline finding: admin-only ───────────

describe('POST /api/antivirus/quarantine/:fileId/restore (un-quarantine)', () => {
  let fileId;

  beforeAll(async () => {
    const list = await admin(request(app).get('/api/antivirus/quarantine'));
    expect(list.status).toBe(200);
    const quarantined = list.body.quarantine.find(f => f.status === 'quarantined');
    expect(quarantined).toBeDefined();
    fileId = quarantined.fileId;
  });

  it('401s with no token — an unauthenticated caller can no longer un-quarantine malware', async () => {
    const res = await request(app).post(`/api/antivirus/quarantine/${fileId}/restore`);
    expect(res.status).toBe(401);
  });

  it('403s for an authenticated non-admin token', async () => {
    const res = await asUser(request(app).post(`/api/antivirus/quarantine/${fileId}/restore`));
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'forbidden');
  });

  it('succeeds for an admin token', async () => {
    const res = await admin(request(app).post(`/api/antivirus/quarantine/${fileId}/restore`));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ fileId, status: 'restored' });
  });
});

describe('DELETE /api/antivirus/quarantine/:fileId (permanent delete)', () => {
  let fileId;

  beforeAll(async () => {
    const list = await admin(request(app).get('/api/antivirus/quarantine'));
    const quarantined = list.body.quarantine.find(f => f.status === 'quarantined');
    expect(quarantined).toBeDefined();
    fileId = quarantined.fileId;
  });

  it('401s with no token', async () => {
    const res = await request(app).delete(`/api/antivirus/quarantine/${fileId}`);
    expect(res.status).toBe(401);
  });

  it('403s for a non-admin token', async () => {
    const res = await asUser(request(app).delete(`/api/antivirus/quarantine/${fileId}`));
    expect(res.status).toBe(403);
  });

  it('succeeds for an admin token', async () => {
    const res = await admin(request(app).delete(`/api/antivirus/quarantine/${fileId}`));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ fileId, status: 'deleted' });
  });
});

// ─── Fleet-wide MDM command dispatch: admin-only ──────────────────────────

describe('POST /api/antivirus/scan (fleet AV-command dispatch)', () => {
  it('401s with no token', async () => {
    const res = await request(app).post('/api/antivirus/scan').send({ scanType: 'quick' });
    expect(res.status).toBe(401);
  });

  it('403s for a non-admin token', async () => {
    const res = await asUser(request(app).post('/api/antivirus/scan')).send({ scanType: 'quick' });
    expect(res.status).toBe(403);
  });

  it('succeeds for an admin token', async () => {
    const res = await admin(request(app).post('/api/antivirus/scan')).send({ scanType: 'quick', deviceIds: ['dev-test-1'] });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('dispatched');
  });
});

// ─── Signature/definition update dispatch: admin-only ─────────────────────

describe('POST /api/antivirus/signatures/update', () => {
  it('401s with no token', async () => {
    const res = await request(app).post('/api/antivirus/signatures/update').send({});
    expect(res.status).toBe(401);
  });

  it('403s for a non-admin token', async () => {
    const res = await asUser(request(app).post('/api/antivirus/signatures/update')).send({});
    expect(res.status).toBe(403);
  });

  it('succeeds for an admin token', async () => {
    const res = await admin(request(app).post('/api/antivirus/signatures/update')).send({});
    expect(res.status).toBe(202);
    expect(res.body).toHaveProperty('jobId');
  });
});

// ─── Scheduled fleet scan creation: admin-only ────────────────────────────

describe('POST /api/antivirus/schedule', () => {
  const payload = { name: 'Nightly Full Scan', cronExpression: '0 2 * * *', scanType: 'full' };

  it('401s with no token', async () => {
    const res = await request(app).post('/api/antivirus/schedule').send(payload);
    expect(res.status).toBe(401);
  });

  it('403s for a non-admin token', async () => {
    const res = await asUser(request(app).post('/api/antivirus/schedule')).send(payload);
    expect(res.status).toBe(403);
  });

  it('succeeds for an admin token', async () => {
    const res = await admin(request(app).post('/api/antivirus/schedule')).send(payload);
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('scheduleId');
  });
});

// ─── Agent-facing report endpoints: enrollment-token, not user JWT ────────

describe('POST /api/antivirus/devices/:deviceId/report (agent scan report)', () => {
  const body = { threats: [], rawOutput: 'clean', clean: true, platform: 'linux' };

  it('401s with no credentials at all', async () => {
    const res = await request(app).post('/api/antivirus/devices/dev-agent-1/report').send(body);
    expect(res.status).toBe(401);
  });

  it('401s with a wrong enrollment token', async () => {
    const res = await withEnrollmentToken(
      request(app).post('/api/antivirus/devices/dev-agent-1/report').send(body),
      'wrong-token'
    );
    expect(res.status).toBe(401);
  });

  it('succeeds with the correct x-enrollment-token and no user JWT', async () => {
    const res = await withEnrollmentToken(
      request(app).post('/api/antivirus/devices/dev-agent-1/report').send(body)
    );
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ received: true });
    expect(res.body).toHaveProperty('scanId');
  });

  it('also succeeds with a normal admin/user JWT (agents aren\'t the only allowed caller)', async () => {
    const res = await admin(request(app).post('/api/antivirus/devices/dev-agent-1/report')).send(body);
    expect(res.status).toBe(200);
  });
});

describe('POST /api/antivirus/devices/:deviceId/status (agent status report)', () => {
  const body = { platform: 'windows', clamavVersion: '0.104.3', sigVersion: '27180', realtimeEnabled: true };

  it('401s with no credentials', async () => {
    const res = await request(app).post('/api/antivirus/devices/dev-agent-2/status').send(body);
    expect(res.status).toBe(401);
  });

  it('succeeds with the correct x-enrollment-token', async () => {
    const res = await withEnrollmentToken(
      request(app).post('/api/antivirus/devices/dev-agent-2/status').send(body)
    );
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ received: true });
  });
});

describe('The enrollment-token bypass is scoped to report/status only', () => {
  it('does NOT grant access to the generic device list route', async () => {
    const res = await withEnrollmentToken(request(app).get('/api/antivirus/devices'));
    // No Authorization header presented either, so this falls through to the
    // ordinary JWT branch -> 401 (the enrollment header is simply ignored).
    expect(res.status).toBe(401);
  });

  it('does NOT grant access to quarantine restore', async () => {
    const res = await withEnrollmentToken(request(app).post('/api/antivirus/quarantine/qf-doesnotmatter/restore'));
    expect(res.status).toBe(401);
  });

  it('does NOT grant access to fleet scan dispatch', async () => {
    const res = await withEnrollmentToken(request(app).post('/api/antivirus/scan').send({}));
    expect(res.status).toBe(401);
  });
});
