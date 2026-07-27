'use strict';

/**
 * E2E API tests for auto-remediation — P0 auth fix verification.
 *
 * Background: this service previously had ZERO HTTP authentication on any
 * of its ~12 Express routes — including POST /api/remediation/execute/:id
 * (which accepts a `force=true` body flag that bypasses the approval
 * workflow entirely) and POST /api/remediation/bulk-execute. Any
 * unauthenticated caller could trigger remediation actions that change real
 * systems (BitLocker enablement, firewall reconfiguration, agent installs,
 * password resets, ...) on managed devices. See src/middleware/oidcAuth.js
 * for the fix.
 *
 * This suite drives the REAL Express app (supertest) through the REAL
 * oidcAuth/requireAdmin middleware — nothing about the auth *logic* is
 * mocked away. What IS mocked (genuinely external dependencies):
 *   - `jose` — a fake jwtVerify() decodes a base64url JSON payload instead
 *     of doing real RSA signature verification (same pattern used across
 *     the fleet's other e2e suites, e.g.
 *     services/core/network-infrastructure/src/__tests__/api.e2e.test.js
 *     and services/core/identity-service's). This sidesteps standing up a
 *     real JWKS server.
 *   - Nothing else: this service keeps all state in-memory (see
 *     src/services/remediationEngine.js — no database), and
 *     EVENT_BUS_TRANSPORT=memory (set below) makes the real grpc-event-bus
 *     package use its in-memory transport, so connectBus()/publish()/
 *     subscribe() never try to dial a real RabbitMQ broker.
 *
 * Route matrix is derived by walking the real Express app's route table
 * (app._router.stack, including the nested '/api/remediation' router)
 * rather than hand-copied, so every route actually registered in
 * src/index.js gets the correct assertion automatically:
 *   - GET /health, GET /metrics             -> reachable with no token (skipPaths —
 *                                              /metrics is a Prometheus scrape
 *                                              target, see the skipPaths comment
 *                                              on oidcAuth() in src/index.js)
 *   - ADMIN_ROUTES (execute/:id incl. force, bulk-execute, playbook create)
 *                                           -> no token: 401, non-admin: 403, admin: passes
 *   - every other route                    -> no token: 401, any authenticated
 *                                              token (admin or not): passes
 */

process.env.EVENT_BUS_TRANSPORT = 'memory';
process.env.PORT = '0'; // OS-assigned — avoid clashing with a real instance
process.env.JWKS_URI = 'https://idp.test/jwks'; // unused (jose mocked below) but read at module load
process.env.OIDC_ISSUER = 'https://idp.test';
process.env.LOG_LEVEL = 'error'; // quiet the request-logging middleware during the run

// ─── Fake jose: drives the real oidcAuth/requireAdmin logic ───────────────
// (see file header for why real JWKS verification isn't used here)
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

// ─── Require the app synchronously (needed so the route table is ready
// before jest collects describe/test.each below) ───────────────────────────
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

const request = require('supertest');
const bearer = (token) => ({ Authorization: `Bearer ${token}` });

// ─── Derive the route matrix from the real, live Express app ──────────────
// Top-level routes (/, /health, /metrics) sit directly on app._router.stack;
// the remediation API is a nested router mounted at '/api/remediation' (see
// `this.app.use('/api/remediation', router)` in src/index.js) — walk into
// it too so the matrix reflects exactly what's registered, not a hand-typed
// copy that could silently drift from the real route table.
function getAllRoutes(expressApp) {
  const routes = [];
  function walk(stack, prefix) {
    stack.forEach((layer) => {
      if (layer.route) {
        Object.keys(layer.route.methods).forEach((method) => {
          if (method === '_all') return;
          routes.push({ method: method.toUpperCase(), path: prefix + layer.route.path });
        });
      } else if (layer.name === 'router' && layer.handle && layer.handle.stack) {
        walk(layer.handle.stack, prefix + '/api/remediation');
      }
    });
  }
  walk(expressApp._router.stack, '');
  return routes;
}

// Remediation-mutating routes: execute (incl. the force-bypass), bulk
// execute, and playbook creation. A verified JWT alone isn't enough here —
// the caller must also hold the admin role/scope (see requireAdmin in
// src/middleware/oidcAuth.js), since these change real managed systems.
const ADMIN_ROUTES = new Set([
  'POST /api/remediation/execute/:issueId',
  'POST /api/remediation/bulk-execute',
  'POST /api/remediation/playbooks',
]);

function concretePath(routePath) {
  // Replace Express path params (:id, :issueId, …) with a literal test
  // value so supertest can hit the route directly.
  return routePath.replace(/:[^/]+/g, 'test-id');
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
  });
});

describe('GET /metrics — public Prometheus scrape target (skipPaths)', () => {
  // Regression coverage: /metrics used to be gated behind oidcAuth like
  // every other route, inconsistent with how Prometheus actually scrapes
  // this fleet (no bearer token — see infrastructure/monitoring/
  // prometheus.yml) and with siblings that already treated /metrics as
  // public (oauth-provider, app-store, identity-service, ...).
  test('reachable with no token at all', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('uptime');
  });
});

describe('every non-admin route requires at least authentication', () => {
  const routes = getAllRoutes(app).filter(
    (r) => `${r.method} ${r.path}` !== 'GET /health' && `${r.method} ${r.path}` !== 'GET /metrics' && !ADMIN_ROUTES.has(`${r.method} ${r.path}`)
  );

  test('sanity: the route table was not accidentally emptied', () => {
    // Was >= 8 before /metrics moved to skipPaths (and out of this "requires
    // auth" set) alongside /health.
    expect(routes.length).toBeGreaterThanOrEqual(7);
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
    const res = await request(app).get('/api/remediation/issues').set(bearer(expiredToken));
    expect(res.status).toBe(401);
  });

  test('garbage bearer token -> 401 or 403, never reaches the handler', async () => {
    const res = await request(app).get('/api/remediation/issues').set(bearer(garbageToken));
    expect([401, 403]).toContain(res.status);
  });
});

describe('remediation-mutating routes (execute, bulk-execute, playbook creation) require admin', () => {
  const routes = [...ADMIN_ROUTES].map((key) => {
    const [method, ...pathParts] = key.split(' ');
    return { method, path: pathParts.join(' ') };
  });

  // Make sure the app really did register all of them — guards against a
  // typo in ADMIN_ROUTES silently testing nothing.
  test('all expected admin routes are registered on the app', () => {
    const registered = new Set(getAllRoutes(app).map((r) => `${r.method} ${r.path}`));
    for (const key of ADMIN_ROUTES) {
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

describe('P0 finding: POST /api/remediation/execute/:issueId with force=true (approval-workflow bypass)', () => {
  // issue-001 (bitlocker-disabled, severity=critical) is one of the seeded
  // demo issues in remediationEngine.js — normally requires approval, which
  // is exactly why the force flag is the highest-value target here: it
  // skips that workflow and executes immediately.
  const target = '/api/remediation/execute/issue-001';

  test('no token -> 401 (force flag never reached)', async () => {
    const res = await request(app).post(target).send({ force: true });
    expect(res.status).toBe(401);
  });

  test('authenticated non-admin token -> 403 (force flag never reached)', async () => {
    const res = await request(app).post(target).set(bearer(userToken)).send({ force: true });
    expect(res.status).toBe(403);
  });

  test('admin token -> passes auth and reaches the remediation engine', async () => {
    const res = await request(app).post(target).set(bearer(adminToken)).send({ force: true });
    // Whichever business-logic outcome the (already-executed-by-earlier-
    // tests / random-success-simulation) engine returns, it must not be an
    // auth rejection — 200 (executed), 404 (already consumed by a prior
    // test's run), and 409 (conflict - already executing) are all "reached
    // the handler" outcomes.
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});

describe('P0 finding: POST /api/remediation/bulk-execute (force-bypass, batched)', () => {
  const target = '/api/remediation/bulk-execute';
  const body = { issueIds: ['issue-002', 'issue-003'], force: true };

  test('no token -> 401', async () => {
    const res = await request(app).post(target).send(body);
    expect(res.status).toBe(401);
  });

  test('authenticated non-admin token -> 403', async () => {
    const res = await request(app).post(target).set(bearer(userToken)).send(body);
    expect(res.status).toBe(403);
  });

  test('admin token -> passes auth and reaches the remediation engine', async () => {
    const res = await request(app).post(target).set(bearer(adminToken)).send(body);
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});
