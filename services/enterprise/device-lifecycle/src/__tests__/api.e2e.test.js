'use strict';

/**
 * E2E API tests for device-lifecycle — P0 auth fix verification.
 *
 * Background: this service previously had ZERO HTTP authentication on any
 * of its /api/lifecycle/* routes (only helmet/cors/compression/rate-limit
 * were mounted). Worst finding: any unauthenticated caller could drive a
 * device — or, via POST /api/lifecycle/bulk-transition, an arbitrary batch
 * of devices — straight to the 'Retiring'/'Retired' lifecycle state, i.e.
 * unauthenticated mass device decommissioning. See
 * src/middleware/oidcAuth.js for the fix.
 *
 * This suite drives the REAL Express app (supertest) through the REAL
 * oidcAuth/requireAdmin middleware — nothing about the auth *logic* is
 * mocked away. What IS mocked (all genuinely external dependencies):
 *   - `jose` — a fake jwtVerify() decodes a base64url JSON payload instead
 *     of doing real RSA signature verification (same pattern as
 *     services/core/identity-service's and
 *     services/core/network-infrastructure's e2e suites). This sidesteps
 *     standing up a real JWKS server.
 *   - `@opendirectory/grpc-event-bus` — device-lifecycle has no database at
 *     all (in-memory Map via LifecycleManager, seeded with demo devices), so
 *     there is nothing to mock there; the only other external dependency is
 *     the gRPC event bus client used to publish/subscribe lifecycle events.
 *     Mocked (virtual, matching services/core/identity-service's e2e suite)
 *     so connect()/publish()/subscribe() never try to dial a real broker.
 *
 * Route matrix is derived by walking the real Express app's route table
 * (app._router.stack) rather than hand-copied, so every route actually
 * registered in src/index.js gets the correct assertion automatically:
 *   - GET /health                         -> reachable with no token (skipPaths)
 *   - MUTATION_ROUTES (single + bulk device-lifecycle transitions, which
 *     includes retire/decommission)       -> no token: 401, non-admin: 403, admin: passes
 *   - every other route (reads, incl. /, /metrics)
 *                                          -> no token: 401, any authenticated
 *                                             token (admin or not): passes
 */

process.env.PORT = '0'; // ephemeral port
process.env.HOST = '127.0.0.1';
process.env.EVENT_BUS_TRANSPORT = 'memory';
process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';

// ─── Mocked event bus (no real broker in the test environment) ────────────
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
    subscribe: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// ─── Fake jose: drives the real oidcAuth/requireAdmin logic ───────────────
jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn(() => ({})),
  jwtVerify: jest.fn(async (token) => {
    if (token === 'expired-sentinel') {
      const err = new Error('expired'); err.code = 'ERR_JWT_EXPIRED'; throw err;
    }
    if (token === 'garbage-sentinel') {
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

const adminToken = makeToken({ sub: 'admin-e2e', roles: ['admin'] });
const userToken = makeToken({ sub: 'user-e2e', roles: ['user'] });
const expiredToken = 'expired-sentinel';
const garbageToken = 'garbage-sentinel';

const request = require('supertest');
const bearer = (token) => ({ Authorization: `Bearer ${token}` });

// ─── Require the app synchronously (route table needed before jest
// collects describe/test.each below) ────────────────────────────────────
const mod = require('../index');
const app = mod.app;

let httpServer;

beforeAll(async () => {
  const origLog = console.log, origWarn = console.warn, origError = console.error;
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};
  try {
    httpServer = await mod.start();
  } finally {
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;
  }
}, 30000);

afterAll(async () => {
  if (httpServer) await new Promise((resolve) => httpServer.close(resolve));
});

// ─── Derive the route matrix from the real, live Express app ──────────────

function getAllRoutes(expressApp) {
  const routes = [];
  expressApp._router.stack.forEach((layer) => {
    if (!layer.route) return;
    const routePath = layer.route.path;
    Object.keys(layer.route.methods).forEach((method) => {
      if (method === '_all') return;
      routes.push({ method: method.toUpperCase(), path: routePath });
    });
  });
  return routes;
}

// Device-lifecycle mutation routes: single-device and bulk state
// transitions. This is where retire/decommission lives — a verified JWT
// alone isn't enough here, the caller must also hold the admin role/scope
// (see requireAdmin in src/middleware/oidcAuth.js).
const MUTATION_ROUTES = new Set([
  'POST /api/lifecycle/devices/:id/transition',
  'POST /api/lifecycle/bulk-transition',
]);

function concretePath(routePath) {
  return routePath.replace(/:[^/]+/g, 'dev-001');
}

function supertestCall(method, path) {
  const fn = method.toLowerCase();
  let req = request(app)[fn](path);
  if (['post', 'put', 'patch'].includes(fn)) req = req.send({});
  return req;
}

describe('GET /health — public liveness probe (skipPaths)', () => {
  test('reachable with no token at all', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'device-lifecycle-manager' });
  });
});

describe('every non-mutation route requires at least authentication', () => {
  const routes = getAllRoutes(app).filter(
    (r) => `${r.method} ${r.path}` !== 'GET /health' && !MUTATION_ROUTES.has(`${r.method} ${r.path}`)
  );

  test('sanity: the route table was not accidentally emptied', () => {
    expect(routes.length).toBeGreaterThan(3);
  });

  test.each(routes)('$method $path -> 401 with no token', async ({ method, path }) => {
    const res = await supertestCall(method, concretePath(path));
    expect(res.status).toBe(401);
  });

  test.each(routes)('$method $path -> passes with an authenticated (non-admin) token', async ({ method, path }) => {
    const res = await supertestCall(method, concretePath(path)).set(bearer(userToken));
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });

  test.each(routes)('$method $path -> passes with an admin token too', async ({ method, path }) => {
    const res = await supertestCall(method, concretePath(path)).set(bearer(adminToken));
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});

describe('expired / garbage tokens are never silently accepted', () => {
  test('expired token -> 401', async () => {
    const res = await request(app).get('/api/lifecycle/devices').set(bearer(expiredToken));
    expect(res.status).toBe(401);
  });

  test('garbage bearer token -> 401 or 403, never reaches the handler', async () => {
    const res = await request(app).get('/api/lifecycle/devices').set(bearer(garbageToken));
    expect([401, 403]).toContain(res.status);
  });
});

describe('device-lifecycle mutation routes (single + bulk transition, incl. retire/decommission) require admin', () => {
  const routes = [...MUTATION_ROUTES].map((key) => {
    const [method, ...pathParts] = key.split(' ');
    return { method, path: pathParts.join(' ') };
  });

  test('all expected mutation routes are registered on the app', () => {
    const registered = new Set(getAllRoutes(app).map((r) => `${r.method} ${r.path}`));
    for (const key of MUTATION_ROUTES) {
      expect(registered.has(key)).toBe(true);
    }
  });

  test.each(routes)('$method $path: no token -> 401', async ({ method, path }) => {
    const res = await supertestCall(method, concretePath(path));
    expect(res.status).toBe(401);
  });

  test.each(routes)('$method $path: authenticated non-admin token -> 403', async ({ method, path }) => {
    const res = await supertestCall(method, concretePath(path)).set(bearer(userToken));
    expect(res.status).toBe(403);
  });

  test.each(routes)('$method $path: admin token -> passes auth (reaches handler)', async ({ method, path }) => {
    const res = await supertestCall(method, concretePath(path)).set(bearer(adminToken));
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});

// ─── Functional proof: an admin token can actually retire a device via both
// the single-device and bulk-transition endpoints (not just "auth passes",
// but the intended mutation happens) ────────────────────────────────────

describe('functional: admin can retire devices through both mutation routes', () => {
  test('single-device transition: Enrolled -> Retiring succeeds for an admin', async () => {
    const res = await request(app)
      .post('/api/lifecycle/devices/dev-002/transition')
      .set(bearer(adminToken))
      .send({ targetState: 'Retiring', performedBy: 'admin-e2e', reason: 'e2e test' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.device.currentState).toBe('Retiring');
  });

  test('bulk-transition: multiple devices -> Retiring succeeds for an admin', async () => {
    const res = await request(app)
      .post('/api/lifecycle/bulk-transition')
      .set(bearer(adminToken))
      .send({ deviceIds: ['dev-005'], targetState: 'Retiring', performedBy: 'admin-e2e', reason: 'e2e bulk test' });
    expect(res.status).toBe(200);
    expect(res.body.summary.succeeded).toBe(1);
  });

  test('bulk-transition: a non-admin token is rejected before touching any device', async () => {
    const res = await request(app)
      .post('/api/lifecycle/bulk-transition')
      .set(bearer(userToken))
      .send({ deviceIds: ['dev-001', 'dev-003'], targetState: 'Retiring' });
    expect(res.status).toBe(403);
  });
});
