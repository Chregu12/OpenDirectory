'use strict';

/**
 * E2E API tests for app-store.
 *
 * app-store was previously completely unauthenticated (see the auth audit:
 * src/index.js only mounted helmet()/cors(), no bearer-token check at all).
 * Any caller could publish a catalog entry, upload an arbitrary installer
 * binary, and push a "deploy" command onto any set of target devices — an
 * unauthenticated supply-chain attack against the whole fleet. This suite
 * drives the REAL app (../index.js), through the REAL oidcAuth/requireAdmin
 * middleware (src/middleware/oidcAuth.js) — not a bypass — via supertest, to
 * prove:
 *   - every mutating/deploy endpoint 401s with no token and 403s for a
 *     valid-but-non-admin token
 *   - an admin token gets past the auth gate (never 401/403) on those routes
 *   - plain reads (catalog browsing, status, stats) only need *any* valid
 *     token, not admin
 *   - the two genuine device/agent-facing routes (install-status callback,
 *     package download) are reachable with the shared APPSTORE_AGENT_TOKEN
 *     and are NOT reachable without it or with a garbage token
 *
 * `pg` is mocked the same lightweight way as services/core/device-service's
 * suite (every query resolves to `{ rows: [], rowCount: 0 }`) — this suite
 * is about the auth gate, not full business-logic round-trips, so it
 * deliberately does not assert specific 2xx payload shapes for routes that
 * depend on real Postgres state; it asserts the auth-relevant status codes
 * (401/403 vs. "got past the gate") plus a handful of true round trips
 * where the route's own graceful DB-optional fallback (see index.js's
 * `catch (_) { /* DB optional *\/ }` pattern on /api/appstore/*) makes a
 * real 2xx observable without a stateful DB fake.
 *
 * `jose` is mocked with a fake jwtVerify() that decodes a base64url JSON
 * payload instead of doing real signature verification — this lets the
 * suite drive the real oidcAuth/requireAdmin logic without a real IdP/JWKS.
 */

process.env.PORT = '0'; // ephemeral port — supertest wraps the exported app directly
process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';
process.env.APPSTORE_AGENT_TOKEN = 'test-agent-shared-secret';
process.env.PACKAGES_DIR = require('path').join(__dirname, '.tmp-packages');

// ─── Mock external dependencies BEFORE any require ────────────────────────

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => ({
    query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    connect: jest.fn().mockResolvedValue({
      query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      release: jest.fn(),
    }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  })),
}));

// grpc-event-bus isn't installed as a real npm dependency here; index.js
// falls back to a relative-path require when '@opendirectory/grpc-event-bus'
// isn't resolvable. jest.mock with virtual:true intercepts the bare
// specifier so the try/catch in index.js picks up this mock directly and
// never touches a real transport (which would try to dial rabbitmq/redis).
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// Fake jose: drives the real oidcAuth/requireAdmin logic instead of bypassing it.
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

// ─── Now require the app ───────────────────────────────────────────────────

const request = require('supertest');
const fs = require('fs');
let app;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  app = require('../index');
  // Let start()'s fire-and-forget async setup (pool.connect, migrations,
  // ensureAppstoreTables/ensurePackagesTable, hydrateAppstoreCatalog,
  // connectBus) settle before the suite starts issuing requests.
  await new Promise(resolve => setTimeout(resolve, 100));
});

afterAll(() => {
  jest.restoreAllMocks();
  fs.rmSync(process.env.PACKAGES_DIR, { recursive: true, force: true });
});

const admin = (req) => req.set('Authorization', `Bearer ${adminToken}`);
const user = (req) => req.set('Authorization', `Bearer ${userToken}`);
const notBlocked = (res) => {
  expect(res.status).not.toBe(401);
  expect(res.status).not.toBe(403);
};

// ─── Health / metrics — skipPaths, reachable with no token ─────────────────

describe('GET /health', () => {
  it('is reachable with no auth token', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'app-store' });
  });
});

describe('GET /metrics', () => {
  it('is reachable with no auth token', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
  });
});

// ─── Auth enforcement matrix: admin-gated mutation/deploy endpoints ────────
//
// Every route below was reachable with ZERO authentication before this fix.
// For each: no token -> 401, valid non-admin token -> 403, valid admin
// token -> past the auth gate (never 401/403).

describe('Auth enforcement — catalog management (requireAdmin)', () => {
  it('POST /api/store/catalog: 401 with no token', async () => {
    const res = await request(app).post('/api/store/catalog').send({ name: 'x' });
    expect(res.status).toBe(401);
  });
  it('POST /api/store/catalog: 403 for a non-admin token', async () => {
    const res = await user(request(app).post('/api/store/catalog')).send({ name: 'x' });
    expect(res.status).toBe(403);
  });
  it('POST /api/store/catalog: not blocked for an admin token', async () => {
    const res = await admin(request(app).post('/api/store/catalog')).send({ name: 'x', display_name: 'X' });
    notBlocked(res);
  });

  it('PUT /api/store/catalog/:id: 401/403/pass matrix', async () => {
    expect((await request(app).put('/api/store/catalog/app-1').send({})).status).toBe(401);
    expect((await user(request(app).put('/api/store/catalog/app-1')).send({})).status).toBe(403);
    notBlocked(await admin(request(app).put('/api/store/catalog/app-1')).send({}));
  });

  it('DELETE /api/store/catalog/:id: 401/403/pass matrix', async () => {
    expect((await request(app).delete('/api/store/catalog/app-1')).status).toBe(401);
    expect((await user(request(app).delete('/api/store/catalog/app-1'))).status).toBe(403);
    notBlocked(await admin(request(app).delete('/api/store/catalog/app-1')));
  });

  it('POST /api/store/catalog/:id/assign: 401/403/pass matrix', async () => {
    const body = { targets: [{ target_type: 'device', target_id: 'd1' }] };
    expect((await request(app).post('/api/store/catalog/app-1/assign').send(body)).status).toBe(401);
    expect((await user(request(app).post('/api/store/catalog/app-1/assign')).send(body)).status).toBe(403);
    notBlocked(await admin(request(app).post('/api/store/catalog/app-1/assign')).send(body));
  });

  it('DELETE /api/store/catalog/:id/assign/:assignId: 401/403/pass matrix', async () => {
    expect((await request(app).delete('/api/store/catalog/app-1/assign/a1')).status).toBe(401);
    expect((await user(request(app).delete('/api/store/catalog/app-1/assign/a1'))).status).toBe(403);
    notBlocked(await admin(request(app).delete('/api/store/catalog/app-1/assign/a1')));
  });

  it('POST /api/store/catalog/seed: 401/403/pass matrix', async () => {
    expect((await request(app).post('/api/store/catalog/seed')).status).toBe(401);
    expect((await user(request(app).post('/api/store/catalog/seed'))).status).toBe(403);
    notBlocked(await admin(request(app).post('/api/store/catalog/seed')));
  });

  it('POST /api/store/shares/:id/scan: 401/403/pass matrix (shells out to smbclient — admin only)', async () => {
    expect((await request(app).post('/api/store/shares/share-1/scan')).status).toBe(401);
    expect((await user(request(app).post('/api/store/shares/share-1/scan'))).status).toBe(403);
    notBlocked(await admin(request(app).post('/api/store/shares/share-1/scan')));
  });
});

describe('Auth enforcement — "App-Deploy auf Geräte" (audit-flagged, requireAdmin)', () => {
  it('POST /api/store/install (index.js:~310 in the audit): 401/403/pass matrix', async () => {
    const body = { appId: 'app-1', deviceId: 'device-1' };
    expect((await request(app).post('/api/store/install').send(body)).status).toBe(401);
    expect((await user(request(app).post('/api/store/install')).send(body)).status).toBe(403);
    notBlocked(await admin(request(app).post('/api/store/install')).send(body));
  });

  it('POST /api/store/uninstall: 401/403/pass matrix', async () => {
    const body = { appId: 'app-1', deviceId: 'device-1' };
    expect((await request(app).post('/api/store/uninstall').send(body)).status).toBe(401);
    expect((await user(request(app).post('/api/store/uninstall')).send(body)).status).toBe(403);
    notBlocked(await admin(request(app).post('/api/store/uninstall')).send(body));
  });

  it('POST /api/appstore/apps/:id/deploy (index.js:~676 in the audit): 401/403/201 for admin', async () => {
    const body = { targets: [{ id: 'device-1', type: 'device' }] };
    expect((await request(app).post('/api/appstore/apps/slack/deploy').send(body)).status).toBe(401);
    expect((await user(request(app).post('/api/appstore/apps/slack/deploy')).send(body)).status).toBe(403);
    const res = await admin(request(app).post('/api/appstore/apps/slack/deploy')).send(body);
    // /api/appstore/* is DB-optional (in-memory fallback) so this is a real round trip.
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('deploymentId');
  });

  it('PUT /api/appstore/deployments/:id/cancel: 401/403/pass matrix', async () => {
    expect((await request(app).put('/api/appstore/deployments/does-not-exist/cancel')).status).toBe(401);
    expect((await user(request(app).put('/api/appstore/deployments/does-not-exist/cancel'))).status).toBe(403);
    notBlocked(await admin(request(app).put('/api/appstore/deployments/does-not-exist/cancel')));
  });
});

describe('Auth enforcement — catalog publish/update (requireAdmin)', () => {
  it('POST /api/appstore/apps: 401/403/201 for admin (real round trip, DB-optional)', async () => {
    const body = { id: 'testapp-1', name: 'Test App', version: '1.0.0' };
    expect((await request(app).post('/api/appstore/apps').send(body)).status).toBe(401);
    expect((await user(request(app).post('/api/appstore/apps')).send(body)).status).toBe(403);
    const res = await admin(request(app).post('/api/appstore/apps')).send(body);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ id: 'testapp-1', name: 'Test App' });
  });

  it('PUT /api/appstore/apps/:id: 401/403/200 for admin', async () => {
    expect((await request(app).put('/api/appstore/apps/slack').send({ version: '5.0.0' })).status).toBe(401);
    expect((await user(request(app).put('/api/appstore/apps/slack')).send({ version: '5.0.0' })).status).toBe(403);
    const res = await admin(request(app).put('/api/appstore/apps/slack')).send({ version: '5.0.0' });
    expect(res.status).toBe(200);
  });
});

describe('Auth enforcement — Installer-Upload (requireAdmin, before multer)', () => {
  it('POST /api/appstore/apps/:id/packages: 401 with no token (rejected before multer runs)', async () => {
    const res = await request(app)
      .post('/api/appstore/apps/slack/packages')
      .attach('file', Buffer.from('MZ-fake-installer-bytes'), 'setup.exe');
    expect(res.status).toBe(401);
  });

  it('POST /api/appstore/apps/:id/packages: 403 for a non-admin token', async () => {
    const res = await user(request(app).post('/api/appstore/apps/slack/packages'))
      .attach('file', Buffer.from('MZ-fake-installer-bytes'), 'setup.exe');
    expect(res.status).toBe(403);
  });

  it('POST /api/appstore/apps/:id/packages: 201 for admin (real round trip, file written to disk)', async () => {
    const res = await admin(request(app).post('/api/appstore/apps/slack/packages'))
      .field('version', '1.2.3')
      .attach('file', Buffer.from('MZ-fake-installer-bytes'), 'setup.exe');
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ app_id: 'slack', platform: 'windows', version: '1.2.3' });
  });

  it('DELETE /api/appstore/packages/:packageId: 401/403/pass matrix', async () => {
    expect((await request(app).delete('/api/appstore/packages/pkg-1')).status).toBe(401);
    expect((await user(request(app).delete('/api/appstore/packages/pkg-1'))).status).toBe(403);
    notBlocked(await admin(request(app).delete('/api/appstore/packages/pkg-1')));
  });
});

// ─── Reads: any authenticated user, no admin role required ────────────────

describe('Auth enforcement — reads (oidcAuth only, no requireAdmin)', () => {
  it('GET /api/store/catalog: 401 with no token, not blocked for a non-admin token', async () => {
    expect((await request(app).get('/api/store/catalog')).status).toBe(401);
    notBlocked(await user(request(app).get('/api/store/catalog')));
  });

  it('GET /api/store/categories: 401 with no token, not blocked for a non-admin token', async () => {
    expect((await request(app).get('/api/store/categories')).status).toBe(401);
    notBlocked(await user(request(app).get('/api/store/categories')));
  });

  it('GET /api/store/stats: 401 with no token, not blocked for a non-admin token', async () => {
    expect((await request(app).get('/api/store/stats')).status).toBe(401);
    notBlocked(await user(request(app).get('/api/store/stats')));
  });

  it('GET /api/appstore/apps: 401 with no token, 200 (real catalog) for a non-admin token', async () => {
    expect((await request(app).get('/api/appstore/apps')).status).toBe(401);
    const res = await user(request(app).get('/api/appstore/apps'));
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.apps)).toBe(true);
  });

  it('rejects a garbage bearer token with 403', async () => {
    const res = await request(app).get('/api/appstore/apps').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
  });

  it('rejects an expired bearer token with 401', async () => {
    const res = await request(app).get('/api/appstore/apps').set('Authorization', 'Bearer expired');
    expect(res.status).toBe(401);
  });
});

// ─── Device/agent callbacks: APPSTORE_AGENT_TOKEN bypass, no OIDC JWT ──────

describe('Device/agent callback — PUT /api/store/install/:installId/status', () => {
  it('401s with no token and no agent token', async () => {
    const res = await request(app).put('/api/store/install/install-1/status').send({ status: 'installed' });
    expect(res.status).toBe(401);
  });

  it('401s with a wrong agent token', async () => {
    const res = await request(app)
      .put('/api/store/install/install-1/status')
      .set('x-appstore-agent-token', 'not-the-right-secret')
      .send({ status: 'installed' });
    expect(res.status).toBe(401);
  });

  it('reaches the handler with the correct APPSTORE_AGENT_TOKEN header (device agent, no user JWT)', async () => {
    const res = await request(app)
      .put('/api/store/install/install-1/status')
      .set('x-appstore-agent-token', 'test-agent-shared-secret')
      .send({ status: 'installed' });
    notBlocked(res);
  });

  it('a normal admin/user Bearer JWT also works (not agent-only)', async () => {
    notBlocked(await user(request(app).put('/api/store/install/install-1/status')).send({ status: 'installed' }));
  });
});

describe('Device/agent callback — GET /api/appstore/packages/:packageId/download', () => {
  it('401s with no token at all', async () => {
    const res = await request(app).get('/api/appstore/packages/pkg-does-not-exist/download');
    expect(res.status).toBe(401);
  });

  it('401s with a wrong agent token', async () => {
    const res = await request(app)
      .get('/api/appstore/packages/pkg-does-not-exist/download')
      .set('x-appstore-agent-token', 'wrong');
    expect(res.status).toBe(401);
  });

  it('reaches the handler via the x-appstore-agent-token header (device agent flow)', async () => {
    const res = await request(app)
      .get('/api/appstore/packages/pkg-does-not-exist/download')
      .set('x-appstore-agent-token', 'test-agent-shared-secret');
    // Past the auth gate; 404 because the package doesn't exist — proves the
    // route handler ran, not the auth layer.
    expect(res.status).toBe(404);
  });

  it('reaches the handler via ?agent_token= query param (bare download URL — device-service hands agents a plain URL with no header control)', async () => {
    const res = await request(app)
      .get('/api/appstore/packages/pkg-does-not-exist/download?agent_token=test-agent-shared-secret');
    expect(res.status).toBe(404);
  });

  it('a normal Bearer JWT also works (admin console manual download)', async () => {
    const res = await admin(request(app).get('/api/appstore/packages/pkg-does-not-exist/download'));
    expect(res.status).toBe(404);
  });

  it('does NOT let the agent-token bypass leak onto the admin-only DELETE route', async () => {
    // '*/download' must not also match '/api/appstore/packages/:packageId' (DELETE).
    const res = await request(app)
      .delete('/api/appstore/packages/pkg-1')
      .set('x-appstore-agent-token', 'test-agent-shared-secret');
    expect(res.status).toBe(401);
  });
});

// ─── Pure unit coverage for the middleware's role/token logic ─────────────

describe('middleware/oidcAuth — hasAdminAccess / isValidAgentToken', () => {
  const { hasAdminAccess, isValidAgentToken } = require('../middleware/oidcAuth');

  it('hasAdminAccess: true for roles: ["admin"]', () => {
    expect(hasAdminAccess({ roles: ['admin'] })).toBe(true);
  });
  it('hasAdminAccess: true for realm_access.roles admin (Keycloak shape)', () => {
    expect(hasAdminAccess({ realm_access: { roles: ['admin'] } })).toBe(true);
  });
  it('hasAdminAccess: true for scope string containing appstore.admin', () => {
    expect(hasAdminAccess({ scope: 'openid appstore.admin' })).toBe(true);
  });
  it('hasAdminAccess: false for a plain user', () => {
    expect(hasAdminAccess({ roles: ['user'] })).toBe(false);
  });
  it('hasAdminAccess: false for malformed/missing input (fails closed)', () => {
    expect(hasAdminAccess(null)).toBe(false);
    expect(hasAdminAccess(undefined)).toBe(false);
    expect(hasAdminAccess({})).toBe(false);
  });

  it('isValidAgentToken: false when APPSTORE_AGENT_TOKEN is unset', () => {
    const prev = process.env.APPSTORE_AGENT_TOKEN;
    delete process.env.APPSTORE_AGENT_TOKEN;
    expect(isValidAgentToken('anything')).toBe(false);
    process.env.APPSTORE_AGENT_TOKEN = prev;
  });
  it('isValidAgentToken: false for a wrong-length or wrong-value candidate', () => {
    expect(isValidAgentToken('short')).toBe(false);
    expect(isValidAgentToken('test-agent-shared-secreT')).toBe(false);
  });
  it('isValidAgentToken: true for the exact configured secret', () => {
    expect(isValidAgentToken('test-agent-shared-secret')).toBe(true);
  });
});

// ─── WebSocket auth on /ws/store (was: none) ───────────────────────────────
//
// P0 fix: /ws/store previously had NO authentication at all — while every
// HTTP route in this service is gated behind oidcAuth(), an unauthenticated
// caller could open this WebSocket directly and receive live install-status
// / distribution events for the entire fleet. The fix (src/index.js) verifies
// a token — from the `?token=` query param or the first
// `Sec-WebSocket-Protocol` value — using the exact same verifyToken() (jose +
// JWKS) the HTTP middleware uses (middleware/oidcAuth.js), and closes an
// unauthenticated/invalid connection with app-defined close code 4401.
//
// This suite drives a REAL `ws` client against the REAL http.Server
// (`app.server`, attached at the bottom of src/index.js specifically so
// tests can reach it) — supertest can't exercise this at all, since it spins
// its own ephemeral server per request and never touches the WS upgrade
// path.
describe('WebSocket auth on /ws/store (was: none)', () => {
  const WebSocketClient = require('ws');

  function wsUrl(query = '') {
    const port = app.server.address().port;
    return `ws://127.0.0.1:${port}/ws/store${query}`;
  }

  it('rejects a connection with no token at all (close code 4401)', (done) => {
    const client = new WebSocketClient(wsUrl());
    client.on('close', (code) => {
      expect(code).toBe(4401);
      done();
    });
    client.on('error', () => {}); // the close assertion above is the real check
  });

  it('rejects a connection with an invalid/garbage token (close code 4401)', (done) => {
    const client = new WebSocketClient(wsUrl('?token=garbage'));
    client.on('close', (code) => {
      expect(code).toBe(4401);
      done();
    });
    client.on('error', () => {});
  });

  it('accepts a connection with a valid token via the ?token= query param', (done) => {
    const client = new WebSocketClient(wsUrl(`?token=${userToken}`));
    client.on('close', (code) => {
      if (code === 4401) done(new Error('a valid token via query param was rejected'));
    });
    client.on('open', () => {
      setTimeout(() => {
        expect(client.readyState).toBe(WebSocketClient.OPEN);
        client.close();
        done();
      }, 50);
    });
    client.on('error', done);
  });

  it('accepts a connection with a valid token via the Sec-WebSocket-Protocol header', (done) => {
    const client = new WebSocketClient(wsUrl(), [userToken]);
    client.on('close', (code) => {
      if (code === 4401) done(new Error('a valid token via Sec-WebSocket-Protocol was rejected'));
    });
    client.on('open', () => {
      setTimeout(() => {
        expect(client.readyState).toBe(WebSocketClient.OPEN);
        client.close();
        done();
      }, 50);
    });
    client.on('error', done);
  });
});
