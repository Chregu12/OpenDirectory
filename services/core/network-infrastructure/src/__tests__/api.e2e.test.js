'use strict';

/**
 * E2E API tests for network-infrastructure — P0 auth fix verification.
 *
 * Background: this service previously had ZERO HTTP authentication on any
 * of its ~60 Express routes (DNS record/zone CRUD, DHCP lease/reservation/
 * scope CRUD, VLAN CRUD, firewall rule CRUD, SMB share CRUD, VPN/bandwidth/
 * load-balancer/policy/compliance endpoints). The only "auth" in the file
 * was a WebSocket-level mock-token check that never covered the HTTP
 * surface. See src/middleware/oidcAuth.js for the fix.
 *
 * This suite drives the REAL Express app (supertest) through the REAL
 * oidcAuth/requireAdmin middleware — nothing about the auth *logic* is
 * mocked away. What IS mocked (all genuinely external dependencies):
 *   - `jose` — a fake jwtVerify() decodes a base64url JSON payload instead
 *     of doing real RSA signature verification (same pattern as
 *     services/core/identity-service's e2e suite). This sidesteps standing
 *     up a real network JWKS server purely so the route table can be
 *     derived from the live Express app (see getAllRoutes() below) at
 *     module-eval time, before any async beforeAll has run — jest collects
 *     `describe`/`test.each` synchronously, so the app has to exist
 *     (synchronously) before that point.
 *   - pg.Pool (PostgreSQL) — no real DB in the test environment. A generic
 *     mock (SELECT/DELETE/…RETURNING* -> synthetic row, everything else ->
 *     empty) is enough here: this suite proves the *auth* matrix, not
 *     persistence round-tripping (that's the separate persistence audit's
 *     job) — every manager class in src/services/*.js opens its own `new
 *     Pool()`, all intercepted by the same jest.mock('pg', ...).
 *   - Nothing else: EVENT_BUS_TRANSPORT=memory (set below) makes the real
 *     grpc-event-bus package use its in-memory transport, so connectBus()/
 *     publish() never try to dial a real RabbitMQ broker — no mock needed.
 *
 * Route matrix is derived by walking the real Express app's route table
 * (app._router.stack) rather than hand-copied, so every route actually
 * registered in src/index.js gets the correct assertion automatically:
 *   - GET /health                        -> reachable with no token (skipPaths)
 *   - ADMIN_ROUTES (firewall/VLAN mutations, DNS zone creation)
 *                                         -> no token: 401, non-admin: 403, admin: passes
 *   - every other route                  -> no token: 401, any authenticated
 *                                            token (admin or not): passes
 */

process.env.EVENT_BUS_TRANSPORT = 'memory';
process.env.WEBSOCKET_PORT = '0'; // OS-assigned — avoid clashing with a real instance
process.env.PORT = '0';
process.env.CLUSTER_MAX_WORKERS = '1';
process.env.JWKS_URI = 'https://idp.test/jwks'; // unused (jose mocked below) but read at module load
process.env.OIDC_ISSUER = 'https://idp.test';

// ─── Generic mocked pg.Pool ─────────────────────────────────────────────────
// Every manager (db.js, dnsManager.js, dhcpManager.js, fileShareManager.js,
// networkDiscovery.js) opens its own `new Pool(...)`; jest.mock intercepts
// all of them identically.
jest.mock('pg', () => {
  function genericRow() {
    return {
      id: 'test-id-1',
      name: 'test',
      type: 'A',
      value: '10.0.0.1',
      zone: 'opendirectory.local',
      ttl: 300,
      mac_address: 'AA:BB:CC:DD:EE:FF',
      ip_address: '10.0.0.50',
      hostname: 'test-host',
      status: 'active',
      subnet: '10.0.0.0/24',
      gateway: '10.0.0.1',
      description: 'test',
      created_at: new Date(),
      updated_at: new Date(),
    };
  }

  class MockPool {
    async query(sql) {
      const text = typeof sql === 'string' ? sql : (sql && sql.text) || '';
      const upper = text.trim().toUpperCase();
      if (upper.startsWith('DELETE')) return { rows: [], rowCount: 1 };
      // INSERT/UPDATE ... RETURNING * — return a synthetic, fully-populated
      // row so handlers that read rows[0].<col> straight after a write
      // don't 500 on the mock. Plain SELECTs (no RETURNING) return an empty
      // set — handlers just render an empty list, still proving the
      // request reached business logic (i.e. got past auth).
      if (/RETURNING/i.test(text)) return { rows: [genericRow()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
    connect() {
      return Promise.resolve({ query: this.query.bind(this), release() {} });
    }
    end() { return Promise.resolve(); }
    on() {}
  }

  return { Pool: MockPool };
});

// ─── Fake jose: drives the real oidcAuth/requireAdmin logic ───────────────
// (see file header for why real network JWKS verification isn't used here)
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
    httpServer = await mod.start(0);
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

// Network-critical routes: firewall rules, VLANs, DNS zone creation. A
// verified JWT alone isn't enough here — the caller must also hold the
// admin role/scope (see requireAdmin in src/middleware/oidcAuth.js).
const ADMIN_ROUTES = new Set([
  'POST /api/network/dns/zones',
  'POST /api/network/vlans',
  'PUT /api/network/vlans/:id',
  'DELETE /api/network/vlans/:id',
  'POST /api/network/firewall/rules',
  'PUT /api/network/firewall/rules/:id',
  'DELETE /api/network/firewall/rules/:id',
  'POST /api/network/firewall/block',
]);

function concretePath(routePath) {
  // Replace Express path params (:id, :principal, …) with a literal test
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

describe('every non-admin route requires at least authentication', () => {
  const routes = getAllRoutes(app).filter(
    (r) => `${r.method} ${r.path}` !== 'GET /health' && !ADMIN_ROUTES.has(`${r.method} ${r.path}`)
  );

  test('sanity: the route table was not accidentally emptied', () => {
    expect(routes.length).toBeGreaterThan(40);
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
    const res = await request(app).get('/api/network/dns/records').set(bearer(expiredToken));
    expect(res.status).toBe(401);
  });

  test('garbage bearer token -> 401 or 403, never reaches the handler', async () => {
    const res = await request(app).get('/api/network/dns/records').set(bearer(garbageToken));
    expect([401, 403]).toContain(res.status);
  });
});

describe('network-critical routes (firewall/VLAN mutations, DNS zone creation) require admin', () => {
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
