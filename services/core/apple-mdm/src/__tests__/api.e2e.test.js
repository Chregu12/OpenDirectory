'use strict';

/**
 * E2E API tests for apple-mdm — P0 fix verification.
 *
 * Runs with Node's built-in test runner (no jest in this service):
 *   node --test src/__tests__/
 *
 * Background: apple-mdm previously had ZERO HTTP authentication (only
 * helmet()/cors()/prometheus metrics were mounted). Any unauthenticated
 * caller could POST /api/mdm/devices/:udid/wipe (Apple EraseDevice — full
 * remote destruction of an enrolled device), .../lock (DeviceLock), and
 * ~13 further mutating endpoints. This suite proves the fix end-to-end
 * through the real Express app (supertest), using REAL JWT verification
 * (jose) against a local JWKS server — no auth logic is mocked away. The
 * only genuinely external dependency mocked is pg.Pool (PostgreSQL) — no
 * real DB in the test environment. APNs (@parse/node-apn) is never
 * initialised because APNS_CERT/APNS_KEY/APNS_TOPIC are left unset, so push
 * notifications no-op safely (see sendMdmPush / initApns in src/index.js).
 *
 * Matrix asserted for every admin-gated /api/mdm/* route:
 *   - no token                    -> 401
 *   - valid token, non-admin role -> 403
 *   - valid token, admin role     -> reaches the handler (not 401/403)
 *
 * Plus: the Apple MDM protocol endpoints under /mdm/* (enrollment profile
 * download, device check-in, command polling) MUST remain reachable with
 * NO token at all — real Apple devices cannot present an OIDC JWT (see
 * middleware/oidcAuth.js for why).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

// ─── Mock pg BEFORE requiring the app ──────────────────────────────────────
// Mutate the cached 'pg' module's exported Pool in place (not a full
// jest-style module mock — this service doesn't use jest) so that when
// src/index.js does `const { Pool } = require('pg'); new Pool(...)`, it
// picks up this mock. Must run before `require('../index')`.
const pg = require('pg');

function genericDeviceRow(udid) {
  return {
    udid,
    push_token: null, // no push token -> sendMdmPush no-ops cleanly
    device_name: 'Test iPhone',
    model: 'iPhone15,2',
    os_version: '17.4',
    enrolled_at: new Date(),
    last_seen: new Date(),
    status: 'active',
  };
}

class MockPool {
  async query(sql, params) {
    const text = typeof sql === 'string' ? sql : (sql && sql.text) || '';
    const upper = text.trim().toUpperCase();
    if (upper === 'SELECT 1') return { rows: [{ '?column?': 1 }], rowCount: 1 };
    if (upper.startsWith('CREATE')) return { rows: [], rowCount: 0 };
    // Device lookups (getDevice / upsertDevice ... RETURNING, listDevices) —
    // return one synthetic active device so handlers that require an
    // existing device don't 404 before reaching business logic.
    if (upper.startsWith('SELECT') && upper.includes('MDM_DEVICES')) {
      const udid = (params && params[0]) || 'TEST-UDID-0001';
      return { rows: [genericDeviceRow(udid)], rowCount: 1 };
    }
    if (upper.startsWith('INSERT') || upper.startsWith('UPDATE')) {
      return { rows: [genericDeviceRow((params && params[0]) || 'TEST-UDID-0001')], rowCount: 1 };
    }
    if (upper.startsWith('DELETE')) return { rows: [{ id: 'deleted' }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  }
  connect() {
    return Promise.resolve({ query: this.query.bind(this), release() {} });
  }
  end() { return Promise.resolve(); }
  on() {}
}
pg.Pool = MockPool;

// ─── Mock the RabbitMQ event bus BEFORE requiring the app ─────────────────
// src/index.js resolves EventBusClient via
// require('../../../../packages/grpc-event-bus/src') (the published
// '@opendirectory/grpc-event-bus' package name isn't installed in this
// service's node_modules) and fire-and-forgets connectBus() at startup.
// The real transport needs a running RabbitMQ broker, which doesn't exist
// in this test environment and isn't relevant to the auth fix under test.
// Pre-populate the module cache for that resolved path with a no-op stub
// (same shape as packages/grpc-event-bus's EventBusClient: connect/publish/
// close/isConnected) so start() resolves cleanly.
const path = require('path');
const eventBusPath = require.resolve(path.join(__dirname, '..', '..', '..', '..', '..', 'packages', 'grpc-event-bus', 'src'));
require.cache[eventBusPath] = {
  id: eventBusPath,
  filename: eventBusPath,
  loaded: true,
  exports: {
    EventBusClient: class NoopEventBusClient {
      constructor() {}
      async connect() {}
      async publish() { return false; }
      async subscribe() {}
      async close() {}
      isConnected() { return false; }
    },
  },
};

// ─── Real JWT verification against a local JWKS server (no jose mocking) ──
const { generateKeyPair, exportJWK, SignJWT } = require('jose');

const ISSUER = 'https://test-issuer.apple-mdm-e2e.local';
const KID = 'e2e-test-key-1';

let jwksServer;
let privateKey;
let app;
let httpServer;
let adminToken;
let userToken;
let expiredToken;

async function signToken(claims, { expiresInSeconds = 600 } = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setExpirationTime(Math.floor(Date.now() / 1000) + expiresInSeconds)
    .sign(privateKey);
}

before(async () => {
  const { publicKey, privateKey: privKey } = await generateKeyPair('RS256');
  privateKey = privKey;
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = KID;
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';

  jwksServer = http.createServer((req, res) => {
    if (req.url === '/jwks') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise(resolve => jwksServer.listen(0, '127.0.0.1', resolve));
  const jwksPort = jwksServer.address().port;

  process.env.JWKS_URI = `http://127.0.0.1:${jwksPort}/jwks`;
  process.env.OIDC_ISSUER = ISSUER;
  process.env.APPLE_MDM_PORT = '0'; // OS-assigned free port — avoids clashing with a real instance
  // Leave APNS_CERT/APNS_KEY/APNS_TOPIC unset so initApns() no-ops.

  adminToken = await signToken({ sub: 'admin-e2e', roles: ['admin'] });
  userToken = await signToken({ sub: 'user-e2e', roles: ['user'] });
  expiredToken = await signToken({ sub: 'expired-e2e', roles: ['admin'] }, { expiresInSeconds: -10 });

  const origLog = console.log, origWarn = console.warn;
  console.log = () => {};
  console.warn = () => {};
  try {
    const mod = require('../index');
    app = mod.app;
    httpServer = await mod.start();
  } finally {
    console.log = origLog;
    console.warn = origWarn;
  }
});

after(async () => {
  if (httpServer) await new Promise(resolve => httpServer.close(resolve));
  if (jwksServer) await new Promise(resolve => jwksServer.close(resolve));
});

const request = require('supertest');
const bearer = token => ({ Authorization: `Bearer ${token}` });

// ─── /health, /metrics: unauthenticated probes ─────────────────────────────

describe('unauthenticated probes', () => {
  test('GET /health is reachable with no token at all (skipPaths)', async () => {
    const res = await request(app).get('/health');
    assert.equal(res.status, 200);
  });

  test('GET /metrics is reachable with no token at all (skipPaths)', async () => {
    const res = await request(app).get('/metrics');
    assert.equal(res.status, 200);
  });
});

// ─── /mdm/*: Apple MDM protocol endpoints — MUST stay reachable without a
// user JWT, since real devices authenticate via enrollment cert, not OIDC.

describe('MDM protocol endpoints (/mdm/*) remain open to devices without a user JWT', () => {
  test('GET /mdm/enroll -> 200 with no token (enrollment profile download)', async () => {
    const res = await request(app).get('/mdm/enroll');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'] || '', /apple-aspen-config/);
  });

  test('PUT /mdm/checkin -> reachable with no token (device Authenticate check-in)', async () => {
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>MessageType</key><string>Authenticate</string>
<key>UDID</key><string>TEST-UDID-0001</string>
<key>DeviceName</key><string>Test iPhone</string>
</dict></plist>`;
    const res = await request(app)
      .put('/mdm/checkin')
      .set('Content-Type', 'application/x-apple-aspen-config')
      .send(plist);
    assert.equal(res.status, 200);
  });

  test('PUT /mdm/commands -> reachable with no token (device command poll)', async () => {
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>UDID</key><string>TEST-UDID-0001</string>
<key>Status</key><string>Idle</string>
</dict></plist>`;
    const res = await request(app)
      .put('/mdm/commands')
      .set('Content-Type', 'application/x-apple-aspen-config')
      .send(plist);
    assert.equal(res.status, 200);
  });
});

// ─── /api/mdm/*: read-only endpoints require at least authentication ──────

describe('/api/mdm read-only endpoints require at least authentication', () => {
  const reads = [
    ['GET', '/api/mdm/devices'],
    ['GET', '/api/mdm/blueprints/bp-1/apply-status'],
    ['GET', '/api/mdm/dep/devices'],
    ['GET', '/api/mdm/profiles'],
    ['GET', '/api/mdm/config'],
  ];

  for (const [method, urlPath] of reads) {
    test(`${method} ${urlPath} -> 401 with no token`, async () => {
      const res = await request(app)[method.toLowerCase()](urlPath);
      assert.equal(res.status, 401);
    });

    test(`${method} ${urlPath} -> passes with a plain authenticated (non-admin) token`, async () => {
      const res = await request(app)[method.toLowerCase()](urlPath).set(bearer(userToken));
      assert.notEqual(res.status, 401);
      assert.notEqual(res.status, 403);
    });
  }

  test('expired token -> 401, not silently accepted', async () => {
    const res = await request(app).get('/api/mdm/devices').set(bearer(expiredToken));
    assert.equal(res.status, 401);
  });

  test('garbage bearer token -> 401 or 403, never reaches the handler', async () => {
    const res = await request(app)
      .get('/api/mdm/devices')
      .set({ Authorization: 'Bearer not-a-real-jwt' });
    assert.ok([401, 403].includes(res.status));
  });
});

// ─── Admin-only mutating endpoints: the 401 / 403 / pass matrix ───────────

describe('admin-only /api/mdm mutations: unauth -> 401, non-admin -> 403, admin -> pass', () => {
  const adminRoutes = [
    {
      name: 'POST device wipe (EraseDevice — the P0 finding)',
      method: 'post',
      path: '/api/mdm/devices/TEST-UDID-0001/wipe',
      body: {},
    },
    {
      name: 'POST device lock (DeviceLock)',
      method: 'post',
      path: '/api/mdm/devices/TEST-UDID-0001/lock',
      body: {},
    },
    {
      name: 'POST device push (wake device)',
      method: 'post',
      path: '/api/mdm/devices/TEST-UDID-0001/push',
      body: {},
    },
    {
      name: 'POST install-app',
      method: 'post',
      path: '/api/mdm/devices/TEST-UDID-0001/install-app',
      body: { manifest_url: 'https://example.com/app.plist' },
    },
    {
      name: 'POST install-profile',
      method: 'post',
      path: '/api/mdm/devices/TEST-UDID-0001/install-profile',
      body: { profile_payload: 'base64stuff' },
    },
    {
      name: 'POST remove-profile',
      method: 'post',
      path: '/api/mdm/devices/TEST-UDID-0001/remove-profile',
      body: { identifier: 'com.example.profile' },
    },
    {
      name: 'POST blueprint apply',
      method: 'post',
      path: '/api/mdm/blueprints/bp-1/apply',
      body: { deviceIds: ['TEST-UDID-0001'] },
    },
    {
      name: 'POST DEP assign',
      method: 'post',
      path: '/api/mdm/dep/assign',
      body: { serialNumbers: ['C02XG1ZHJGH7'], blueprintId: 'bp-1' },
    },
    {
      name: 'POST create profile',
      method: 'post',
      path: '/api/mdm/profiles',
      body: { name: 'Wi-Fi Profile', payload_type: 'com.apple.wifi.managed', payload: {} },
    },
    {
      name: 'DELETE profile',
      method: 'delete',
      path: '/api/mdm/profiles/profile-id-1',
      body: undefined,
    },
    {
      name: 'POST MDM config (APNs push cert config)',
      method: 'post',
      path: '/api/mdm/config',
      body: { orgName: 'Acme Corp' },
    },
  ];

  for (const route of adminRoutes) {
    test(`${route.name}: no token -> 401`, async () => {
      let req = request(app)[route.method](route.path);
      if (route.body !== undefined) req = req.send(route.body);
      const res = await req;
      assert.equal(res.status, 401, `expected 401, got ${res.status}: ${JSON.stringify(res.body)}`);
    });

    test(`${route.name}: authenticated non-admin token -> 403`, async () => {
      let req = request(app)[route.method](route.path).set(bearer(userToken));
      if (route.body !== undefined) req = req.send(route.body);
      const res = await req;
      assert.equal(res.status, 403, `expected 403, got ${res.status}: ${JSON.stringify(res.body)}`);
    });

    test(`${route.name}: admin token -> passes auth (reaches handler)`, async () => {
      let req = request(app)[route.method](route.path).set(bearer(adminToken));
      if (route.body !== undefined) req = req.send(route.body);
      const res = await req;
      assert.ok(
        res.status !== 401 && res.status !== 403,
        `admin token should not be rejected by auth, got ${res.status}: ${JSON.stringify(res.body)}`
      );
    });
  }
});
