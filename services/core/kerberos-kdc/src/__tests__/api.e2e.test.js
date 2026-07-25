'use strict';

/**
 * E2E API tests for kerberos-kdc — P0 fix verification.
 *
 * Runs with Node's built-in test runner (no jest in this service):
 *   node --test src/__tests__/
 *
 * Background: kerberos-kdc previously had ZERO HTTP authentication (only
 * helmet()/cors() were mounted — requireDb() is a DB-availability gate, not
 * an auth check). Any unauthenticated caller could set the password of ANY
 * Kerberos principal (realm takeover), mint keytabs, and configure
 * delegation. This suite proves the fix end-to-end through the real Express
 * app (supertest), using REAL JWT verification (jose) against a local JWKS
 * server — no auth logic is mocked away. The only things mocked are the two
 * genuinely external dependencies:
 *   - child_process.execSync (kadmin.local) — never actually exec'd.
 *   - pg.Pool (PostgreSQL) — no real DB in the test environment.
 *
 * Matrix asserted for every sensitive route:
 *   - no token                          -> 401
 *   - valid token, non-admin role       -> 403
 *   - valid token, admin role           -> reaches the handler (not 401/403)
 * Plus the sync-user special case (server-to-server internal-token bypass).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');

const REALM = 'OPENDIRECTORY.LOCAL';

// ─── Mock pg BEFORE requiring the app ──────────────────────────────────────
// Mutate the cached 'pg' module's exported Pool in place (not a full
// jest-style module mock — this service doesn't use jest) so that when
// src/index.js does `const { Pool } = require('pg'); new Pool(...)`, it
// picks up this mock. Must run before `require('../index')`.
const pg = require('pg');

function genericRow() {
  return {
    principal: 'REALM_DEFAULT',
    max_ticket_life: 36000,
    max_renew_life: 604800,
    forwardable: true,
    proxiable: false,
    renewable: true,
    no_address: true,
    created_at: new Date(),
    updated_at: new Date(),
    service_principal: 'http/test.example.com',
    resource_principal: 'http/test.example.com',
    allowed_targets: [],
    allowed_delegators: [],
    protocol: 'kerberos-only',
    user_principal: 'alice@' + REALM,
    added_by: null,
    added_at: new Date(),
  };
}

class MockPool {
  async query(sql) {
    const text = typeof sql === 'string' ? sql : (sql && sql.text) || '';
    const upper = text.trim().toUpperCase();
    if (upper === 'SELECT 1') return { rows: [{ '?column?': 1 }], rowCount: 1 };
    if (upper.startsWith('DELETE')) return { rows: [], rowCount: 1 };
    // INSERT/UPDATE ... RETURNING * — return one synthetic, fully-populated
    // row so handlers that read rows[0].<col> straight after a write don't
    // 500 on the mock. Read-only SELECTs without a RETURNING clause return
    // an empty set (handlers 404 — still proves the request reached
    // business logic, i.e. got past auth).
    if (/RETURNING/i.test(text)) return { rows: [genericRow()], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  }
  connect() {
    return Promise.resolve({ query: this.query.bind(this), release() {} });
  }
  end() { return Promise.resolve(); }
  on() {}
}
pg.Pool = MockPool;

// ─── Mock child_process.execSync (kadmin.local) BEFORE requiring the app ──
const cp = require('child_process');
cp.execSync = (cmd) => {
  const ktadd = /ktadd -k (\S+)/.exec(cmd);
  if (ktadd) {
    // Actually materialize the keytab file the route immediately reads back
    // with fs.readFileSync + fs.unlinkSync, so the keytab-issuance route
    // resolves deterministically instead of depending on incidental ENOENT
    // handling.
    fs.writeFileSync(ktadd[1], Buffer.from('fake-keytab-bytes'));
    return 'Entry for principal added to keytab.';
  }
  if (cmd.includes('listprincs')) {
    return [
      `Authenticating as principal admin/admin@${REALM} with password.`,
      `admin/admin@${REALM}`,
      `krbtgt/${REALM}@${REALM}`,
      `alice@${REALM}`,
    ].join('\n');
  }
  if (cmd.includes('getprinc')) {
    return [
      `Principal: alice@${REALM}`,
      'Expiration date: [never]',
      'Last password change: [never]',
    ].join('\n');
  }
  // addprinc / cpw / delprinc / anything else: succeed with a generic ack.
  return 'OK';
};

// ─── Real JWT verification against a local JWKS server (no jose mocking) ──
const { generateKeyPair, exportJWK, SignJWT } = require('jose');

const ISSUER = 'https://test-issuer.kdc-e2e.local';
const KID = 'e2e-test-key-1';
const INTERNAL_TOKEN = 'e2e-kdc-internal-secret';

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
  process.env.KDC_INTERNAL_TOKEN = INTERNAL_TOKEN;
  process.env.KDC_API_PORT = '0'; // OS-assigned free port — avoids clashing with a real instance
  process.env.KRB5_REALM = REALM;

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

// ─── /health: unauthenticated liveness probe ───────────────────────────────

describe('GET /health', () => {
  test('is reachable with no token at all (skipPaths)', async () => {
    const res = await request(app).get('/health');
    assert.equal(res.status, 200);
  });
});

// ─── Auth-only reads (any authenticated caller) ────────────────────────────

describe('read-only endpoints require at least authentication', () => {
  const reads = [
    ['GET', '/api/kerberos/principals'],
    ['GET', '/api/kerberos/principals/alice'],
    ['GET', '/api/ticket-policy'],
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
    const res = await request(app).get('/api/kerberos/principals').set(bearer(expiredToken));
    assert.equal(res.status, 401);
  });

  test('garbage bearer token -> 401 or 403, never reaches the handler', async () => {
    const res = await request(app)
      .get('/api/kerberos/principals')
      .set({ Authorization: 'Bearer not-a-real-jwt' });
    assert.ok([401, 403].includes(res.status));
  });
});

// ─── Admin-only mutating/sensitive endpoints: the 401 / 403 / pass matrix ──

describe('admin-only endpoints: unauth -> 401, non-admin -> 403, admin -> pass', () => {
  const adminRoutes = [
    {
      name: 'PUT principal password (realm-takeover endpoint)',
      method: 'put',
      path: '/api/kerberos/principals/alice/password',
      body: { password: 'NewPassw0rd!23' },
    },
    {
      name: 'POST keytab issuance',
      method: 'post',
      path: '/api/kerberos/keytabs/http-web',
      body: {},
    },
    {
      name: 'POST create principal',
      method: 'post',
      path: '/api/kerberos/principals',
      body: { name: 'svc-new', password: 'Passw0rd!23' },
    },
    {
      name: 'DELETE principal',
      method: 'delete',
      path: '/api/kerberos/principals/svc-old',
      body: undefined,
    },
    {
      name: 'PUT realm ticket policy',
      method: 'put',
      path: '/api/ticket-policy',
      body: { maxTicketLife: 36000 },
    },
    {
      name: 'POST constrained delegation',
      method: 'post',
      path: '/api/delegation/constrained',
      body: { servicePrincipal: 'http/web.example.com', allowedTargets: ['cifs/file.example.com'] },
    },
    {
      name: 'DELETE constrained delegation',
      method: 'delete',
      path: '/api/delegation/constrained/http%2Fweb.example.com',
      body: undefined,
    },
    {
      name: 'POST RBCD',
      method: 'post',
      path: '/api/delegation/rbcd',
      body: { resourcePrincipal: 'cifs/file.example.com', allowedDelegators: ['http/web.example.com'] },
    },
    {
      name: 'POST unconstrained delegation (highest-risk toggle)',
      method: 'post',
      path: '/api/delegation/unconstrained',
      body: { principal: 'http/legacy.example.com', enabled: true },
    },
    {
      name: 'GET delegation list (attack-surface disclosure)',
      method: 'get',
      path: '/api/delegation',
      body: undefined,
    },
    {
      name: 'GET unconstrained delegation audit',
      method: 'get',
      path: '/api/delegation/unconstrained',
      body: undefined,
    },
    {
      name: 'GET delegation audit log',
      method: 'get',
      path: '/api/delegation/audit',
      body: undefined,
    },
    {
      name: 'POST add Protected Users member',
      method: 'post',
      path: '/api/protected-users',
      body: { userPrincipal: 'alice@' + REALM },
    },
    {
      name: 'GET Protected Users list',
      method: 'get',
      path: '/api/protected-users',
      body: undefined,
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

// ─── POST /api/kerberos/sync-user: internal-service-token bypass ──────────

describe('POST /api/kerberos/sync-user (authentication-service server-to-server sync)', () => {
  const path = '/api/kerberos/sync-user';
  const body = { username: 'bob', password: 'SyncedPassw0rd!23' };

  test('no token, no internal header -> 401', async () => {
    const res = await request(app).post(path).send(body);
    assert.equal(res.status, 401);
  });

  test('wrong internal-service token -> 401', async () => {
    const res = await request(app)
      .post(path)
      .set({ 'x-kdc-internal-token': 'wrong-secret' })
      .send(body);
    assert.equal(res.status, 401);
  });

  test('correct internal-service token, no JWT -> passes (this is the authentication-service call path)', async () => {
    const res = await request(app)
      .post(path)
      .set({ 'x-kdc-internal-token': INTERNAL_TOKEN })
      .send(body);
    assert.notEqual(res.status, 401);
    assert.notEqual(res.status, 403);
  });

  test('authenticated non-admin JWT, no internal token -> 403 (as sensitive as the password-set endpoint)', async () => {
    const res = await request(app).post(path).set(bearer(userToken)).send(body);
    assert.equal(res.status, 403);
  });

  test('admin JWT, no internal token -> passes', async () => {
    const res = await request(app).post(path).set(bearer(adminToken)).send(body);
    assert.notEqual(res.status, 401);
    assert.notEqual(res.status, 403);
  });
});
