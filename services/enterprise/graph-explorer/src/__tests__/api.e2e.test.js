'use strict';

/**
 * E2E API tests for graph-explorer.
 *
 * Context: this service previously had ZERO HTTP authentication — only
 * helmet()/cors() were mounted. Any unauthenticated caller could read the
 * full AD/Intune relationship graph, enumerate BloodHound-style attack
 * paths and shadow-admin findings (privilege-escalation recon data), run
 * arbitrary Cypher-like queries (POST /api/graph/query), and — most
 * consequentially — force a full graph rebuild that broadcasts to every
 * connected WebSocket client (POST /api/graph/refresh). See
 * src/middleware/oidcAuth.js for the full rationale and the fix.
 *
 * This suite drives the REAL oidcAuth/requireAdmin middleware (not a
 * reimplemented stand-in) against the real Express app, following the same
 * pattern as services/core/identity-service/src/__tests__/api.e2e.test.js
 * and services/enterprise/antivirus-protection/src/__tests__/api.e2e.test.js:
 *
 *   - `jose` is mocked with a fake jwtVerify() that decodes a base64url JSON
 *     payload instead of doing real signature verification, so tests can
 *     hand any {sub, roles} identity they need without a live JWKS/IdP.
 *
 * No pg/DB and no gRPC event bus are involved in this service — GraphBuilder
 * runs entirely in-memory and demo data is only seeded from start()
 * (never called here), so these tests exercise the auth matrix against an
 * (intentionally) empty graph.
 */

process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';
process.env.PORT = '0'; // ephemeral port — supertest wraps the exported app directly

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

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  const GraphExplorerService = require('../index');
  const service = new GraphExplorerService();
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
    expect(res.body).toHaveProperty('status');
  });
});

// ─── Auth matrix: reads require a valid JWT, no particular role ───────────

describe('Read endpoints require authentication', () => {
  const reads = [
    '/api/graph/full',
    '/api/graph/attack-paths',
    '/api/graph/shadow-admins',
    '/api/graph/statistics',
    '/api/graph/docs',
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
    const res = await request(app).get('/api/graph/full').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'invalid_token');
  });

  it('rejects an expired bearer token with 401', async () => {
    const res = await request(app).get('/api/graph/full').set('Authorization', 'Bearer expired');
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

// ─── POST /api/graph/query — read-only query engine, self-service (Auth) ──

describe('POST /api/graph/query (Cypher-like query engine)', () => {
  const body = { query: 'MATCH (n:User) RETURN n' };

  it('returns 401 with no token', async () => {
    const res = await request(app).post('/api/graph/query').send(body);
    expect(res.status).toBe(401);
  });

  it('succeeds (200) with any valid non-admin token — it never mutates graph state', async () => {
    const res = await asUser(request(app).post('/api/graph/query')).send(body);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });
  });

  it('succeeds (200) for an admin token too', async () => {
    const res = await admin(request(app).post('/api/graph/query')).send(body);
    expect(res.status).toBe(200);
  });
});

// ─── POST /api/graph/refresh — the headline finding: admin-only ───────────

describe('POST /api/graph/refresh (rebuild + broadcast — admin only)', () => {
  it('returns 401 with no token', async () => {
    const res = await request(app).post('/api/graph/refresh');
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'unauthorized');
  });

  it('returns 403 for a valid non-admin token', async () => {
    const res = await asUser(request(app).post('/api/graph/refresh'));
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'forbidden');
  });

  it('returns 403 for a garbage bearer token (never reaches requireAdmin)', async () => {
    const res = await request(app).post('/api/graph/refresh').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'invalid_token');
  });

  it('succeeds (200) for an admin token and actually rebuilds the graph', async () => {
    const res = await admin(request(app).post('/api/graph/refresh'));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });
    expect(res.body.data).toHaveProperty('current');
  });

  it('also grants access via a realm_access.roles admin claim (Keycloak-style)', async () => {
    const realmAdminToken = makeToken({ sub: 'admin-2', realm_access: { roles: ['admin'] } });
    const res = await request(app)
      .post('/api/graph/refresh')
      .set('Authorization', `Bearer ${realmAdminToken}`);
    expect(res.status).toBe(200);
  });

  it('also grants access via a graph.admin scope claim', async () => {
    const scopedToken = makeToken({ sub: 'admin-3', scope: 'graph.admin' });
    const res = await request(app)
      .post('/api/graph/refresh')
      .set('Authorization', `Bearer ${scopedToken}`);
    expect(res.status).toBe(200);
  });
});
