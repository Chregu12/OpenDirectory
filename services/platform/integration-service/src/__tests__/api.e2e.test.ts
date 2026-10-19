/**
 * E2E API tests for integration-service — P0 auth-fix verification.
 *
 * Background: integration-service previously had ZERO HTTP authentication
 * (src/index.ts only mounted helmet()/cors()/rateLimit() — the only "Bearer"
 * usage in the whole service was outbound, e.g. LLDAPService attaching its
 * own admin token when calling LLDAP). Anyone who could reach the service
 * could read/write every Vault secret, mint/revoke Vault tokens, rewrite
 * Vault policies, and create/update/delete LLDAP directory users and groups.
 * This suite drives the REAL Express app (src/index.ts) through supertest,
 * exercising the real oidcAuth/requireAdmin middleware end to end — nothing
 * about auth is mocked away except 'jose' itself, which is replaced with a
 * fake jwtVerify() that decodes a base64url JSON payload instead of doing
 * real RS256 signature verification (same technique used by
 * services/core/identity-service/src/__tests__/api.e2e.test.js, the closest
 * precedent for a jest-based suite in this monorepo). Downstream calls to
 * the real Vault/LLDAP/Grafana/Prometheus backends are NOT mocked: none of
 * those services are running in the test environment, so calls fail with
 * ECONNREFUSED, which the route handlers already catch and turn into
 * 500/503 JSON responses. That's fine for this suite's purpose — it only
 * needs to prove requests get PAST (or are correctly stopped BY) the auth
 * gate, not that the downstream integration succeeds.
 *
 * Matrix asserted for every sensitive route:
 *   - no token                          -> 401
 *   - valid token, non-admin role       -> 403 (admin-gated routes only)
 *   - valid token, admin role           -> reaches the handler (not 401/403)
 *   - valid token, non-admin role       -> reaches the handler (auth-only routes)
 */

// ─── Fake jose: drives the real oidcAuth/requireAdmin logic, no real IdP ──
// Must be declared before anything requires '../middleware/oidcAuth' (which
// happens transitively as soon as '../index' is required below).
jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn(() => ({})),
  jwtVerify: jest.fn(async (token: string) => {
    if (token === 'expired') {
      const err: any = new Error('expired');
      err.code = 'ERR_JWT_EXPIRED';
      throw err;
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

process.env.PORT = '0'; // OS-assigned ephemeral port — avoids clashing with a real instance
process.env.JWKS_URI = 'https://idp.test/jwks';
process.env.OIDC_ISSUER = 'https://idp.test';

function makeToken(claims: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(claims)).toString('base64url');
}
const adminToken = makeToken({ sub: 'admin-1', roles: ['admin'] });
const userToken = makeToken({ sub: 'user-1', roles: ['user'] });

// eslint-disable-next-line @typescript-eslint/no-var-requires
const request = require('supertest');

let app: import('express').Express;
let server: import('http').Server;

beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  const mod = require('../index');
  app = mod.default;
  server = mod.server;
});

afterAll((done) => {
  jest.restoreAllMocks();
  if (server) server.close(done);
  else done();
});

const admin = (req: any) => req.set('Authorization', `Bearer ${adminToken}`);
const user = (req: any) => req.set('Authorization', `Bearer ${userToken}`);

// ─── /health: unauthenticated liveness probe (skipPaths) ─────────────────

describe('GET /health*', () => {
  it('GET /health is reachable with no token', async () => {
    const res = await request(app).get('/health');
    expect([200, 207, 503]).toContain(res.status); // downstream services are down in test env
  });

  it('GET /health/live is reachable with no token', async () => {
    const res = await request(app).get('/health/live');
    expect(res.status).toBe(200);
  });
});

// ─── Token validity edge cases (any protected route) ──────────────────────

describe('token validation', () => {
  it('rejects a garbage bearer token with 403', async () => {
    const res = await request(app).get('/api/lldap/users').set('Authorization', 'Bearer garbage');
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'invalid_token');
  });

  it('rejects an expired bearer token with 401', async () => {
    const res = await request(app).get('/api/lldap/users').set('Authorization', 'Bearer expired');
    expect(res.status).toBe(401);
  });

  it('rejects a non-Bearer Authorization header with 401', async () => {
    const res = await request(app).get('/api/lldap/users').set('Authorization', 'Basic foo');
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'unauthorized');
  });
});

// ─── Vault: every route is requireAdmin ────────────────────────────────────

describe('Vault routes (admin-only, full stop)', () => {
  const cases: Array<[string, string, any?]> = [
    ['get', '/api/vault/secrets'],
    ['get', '/api/vault/secrets/foo/bar'],
    ['put', '/api/vault/secrets/foo/bar', { data: { k: 'v' } }],
    ['delete', '/api/vault/secrets/foo/bar'],
    ['get', '/api/vault/policies'],
    ['get', '/api/vault/policies/default'],
    ['put', '/api/vault/policies/default', { policy: 'path "secret/*" {}' }],
    ['delete', '/api/vault/policies/default'],
    ['post', '/api/vault/auth/tokens', {}],
    ['delete', '/api/vault/auth/tokens/sometoken'],
    ['get', '/api/vault/sys/health'],
    ['get', '/api/vault/status'],
  ];

  for (const [method, path, body] of cases) {
    it(`${method.toUpperCase()} ${path} -> 401 with no token`, async () => {
      const req = (request(app) as any)[method](path);
      const res = body ? await req.send(body) : await req;
      expect(res.status).toBe(401);
    });

    it(`${method.toUpperCase()} ${path} -> 403 for a valid non-admin token`, async () => {
      const req = user((request(app) as any)[method](path));
      const res = body ? await req.send(body) : await req;
      expect(res.status).toBe(403);
      expect(res.body).toHaveProperty('error', 'forbidden');
    });

    it(`${method.toUpperCase()} ${path} -> passes auth for a valid admin token`, async () => {
      const req = admin((request(app) as any)[method](path));
      const res = body ? await req.send(body) : await req;
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
    });
  }
});

// ─── LLDAP: reads are auth-only, CRUD mutations are admin-only ────────────

describe('LLDAP reads (auth-only)', () => {
  const reads = ['/api/lldap/users', '/api/lldap/groups', '/api/lldap/schema', '/api/lldap/stats'];

  for (const path of reads) {
    it(`GET ${path} -> 401 with no token`, async () => {
      const res = await request(app).get(path);
      expect(res.status).toBe(401);
    });

    it(`GET ${path} -> passes for a valid non-admin token`, async () => {
      const res = await user(request(app).get(path));
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
    });
  }
});

describe('LLDAP mutations (admin-only)', () => {
  const cases: Array<[string, string, any?]> = [
    ['post', '/api/lldap/users', { email: 'x@example.com' }],
    ['put', '/api/lldap/users/123', { email: 'x@example.com' }],
    ['delete', '/api/lldap/users/123'],
    ['post', '/api/lldap/groups/g1/members', { userId: 'u1' }],
    ['delete', '/api/lldap/groups/g1/members/u1'],
    ['post', '/api/lldap/auth/validate', { username: 'a', password: 'b' }],
  ];

  for (const [method, path, body] of cases) {
    it(`${method.toUpperCase()} ${path} -> 401 with no token`, async () => {
      const req = (request(app) as any)[method](path);
      const res = body ? await req.send(body) : await req;
      expect(res.status).toBe(401);
    });

    it(`${method.toUpperCase()} ${path} -> 403 for a valid non-admin token`, async () => {
      const req = user((request(app) as any)[method](path));
      const res = body ? await req.send(body) : await req;
      expect(res.status).toBe(403);
      expect(res.body).toHaveProperty('error', 'forbidden');
    });

    it(`${method.toUpperCase()} ${path} -> passes auth for a valid admin token`, async () => {
      const req = admin((request(app) as any)[method](path));
      const res = body ? await req.send(body) : await req;
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
    });
  }
});

// ─── Grafana: content mutations are auth-only, infra-affecting are admin ──

describe('Grafana reads and content mutations (auth-only)', () => {
  it('GET /api/grafana/dashboards -> 401 with no token', async () => {
    const res = await request(app).get('/api/grafana/dashboards');
    expect(res.status).toBe(401);
  });

  it('GET /api/grafana/dashboards -> passes for a valid non-admin token', async () => {
    const res = await user(request(app).get('/api/grafana/dashboards'));
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });

  it('POST /api/grafana/dashboards -> passes for a valid non-admin token', async () => {
    const res = await user(request(app).post('/api/grafana/dashboards')).send({ dashboard: {} });
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});

describe('Grafana infra-affecting mutations (admin-only)', () => {
  const cases: Array<[string, string, any?]> = [
    ['post', '/api/grafana/datasources', { name: 'x' }],
    ['get', '/api/grafana/proxy/api/admin/users'],
    ['post', '/api/grafana/setup/opendirectory'],
  ];

  for (const [method, path, body] of cases) {
    it(`${method.toUpperCase()} ${path} -> 401 with no token`, async () => {
      const req = (request(app) as any)[method](path);
      const res = body ? await req.send(body) : await req;
      expect(res.status).toBe(401);
    });

    it(`${method.toUpperCase()} ${path} -> 403 for a valid non-admin token`, async () => {
      const req = user((request(app) as any)[method](path));
      const res = body ? await req.send(body) : await req;
      expect(res.status).toBe(403);
    });

    it(`${method.toUpperCase()} ${path} -> passes auth for a valid admin token`, async () => {
      const req = admin((request(app) as any)[method](path));
      const res = body ? await req.send(body) : await req;
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
    });
  }
});

// ─── Config: module toggle is admin-only, reads are auth-only ────────────

describe('Config routes', () => {
  it('GET /api/config/modules -> 401 with no token', async () => {
    const res = await request(app).get('/api/config/modules');
    expect(res.status).toBe(401);
  });

  it('GET /api/config/modules -> passes for a valid non-admin token', async () => {
    const res = await user(request(app).get('/api/config/modules'));
    expect(res.status).toBe(200);
  });

  it('POST /api/config/modules/:id -> 401 with no token', async () => {
    const res = await request(app).post('/api/config/modules/vault').send({ enabled: false });
    expect(res.status).toBe(401);
  });

  it('POST /api/config/modules/:id -> 403 for a valid non-admin token', async () => {
    const res = await user(request(app).post('/api/config/modules/vault')).send({ enabled: false });
    expect(res.status).toBe(403);
  });

  it('POST /api/config/modules/:id -> passes auth for a valid admin token', async () => {
    const res = await admin(request(app).post('/api/config/modules/secrets-management')).send({ enabled: false });
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});

// ─── Services status: auth-only ────────────────────────────────────────────

describe('GET /api/services', () => {
  it('-> 401 with no token', async () => {
    const res = await request(app).get('/api/services');
    expect(res.status).toBe(401);
  });

  it('-> passes for a valid non-admin token', async () => {
    const res = await user(request(app).get('/api/services'));
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});
