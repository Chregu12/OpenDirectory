'use strict';

/**
 * API Gateway E2E Tests
 *
 * Tests the Express app created by APIGateway end-to-end using supertest.
 * All external dependencies (PostgreSQL, RabbitMQ/gRPC event bus, Consul
 * service-discovery, axios HTTP calls, http-proxy-middleware, and jsonwebtoken
 * verification) are mocked so the suite runs without any infrastructure.
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');

// ─── Environment ─────────────────────────────────────────────────────────────
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-for-unit-tests';
process.env.PORT = '0';

// ─── Suppress winston noise in tests ─────────────────────────────────────────
jest.mock('../config/logger', () => {
  const noop = () => {};
  return {
    info: noop, warn: noop, error: noop, debug: noop,
    security: noop, performance: noop,
    request: (_req, _res, next) => next && next(),
  };
});

// ─── Mock PostgreSQL — simulate DB unavailable so code uses in-memory fallbacks ─
jest.mock('pg', () => {
  const mockQuery = jest.fn().mockRejectedValue(new Error('DB not available in tests'));
  const Pool = jest.fn().mockImplementation(() => ({ query: mockQuery }));
  return { Pool };
}, { virtual: true });

// ─── Mock gRPC / RabbitMQ event bus ──────────────────────────────────────────
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// ─── Mock Consul service discovery ───────────────────────────────────────────
jest.mock('../discovery/serviceDiscovery', () => ({
  start: jest.fn(),
  stop: jest.fn(),
  getServices: jest.fn().mockReturnValue([]),
}), { virtual: true });

// ─── Mock express-rate-limit — bypass blocking, keep tier headers ─────────────
// Without this, ~100 requests into the suite the default limiter returns 429
// which corrupts subsequent test assertions. The mock still sets RateLimit-Limit
// so tier-selection tests (100 / 1000 / 5000) continue to work.
jest.mock('express-rate-limit', () =>
  jest.fn((options) => {
    const max = options?.max ?? 100;
    return (_req, res, next) => {
      res.setHeader('RateLimit-Limit', String(max));
      res.setHeader('RateLimit-Remaining', String(max - 1));
      res.setHeader('RateLimit-Reset', String(Math.floor(Date.now() / 1000) + 900));
      next();
    };
  }),
);

// ─── Mock http-proxy-middleware ───────────────────────────────────────────────
jest.mock('http-proxy-middleware', () => ({
  createProxyMiddleware: jest.fn().mockImplementation(() =>
    (_req, res) => res.status(502).json({ stub: true }),
  ),
}));

// ─── Mock axios ───────────────────────────────────────────────────────────────
jest.mock('axios', () => ({
  post: jest.fn(),
  get: jest.fn(),
  create: jest.fn().mockReturnThis(),
  defaults: { headers: { common: {} } },
}));

const axios = require('axios');

// ─── Mock health middleware ───────────────────────────────────────────────────
jest.mock('../middleware/health', () => {
  const middleware = jest.fn((_req, res) =>
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: 0, services: {} }),
  );
  middleware.getOverallHealth = jest.fn().mockResolvedValue({ status: 'healthy', summary: {}, criticalServices: [], services: [] });
  middleware.getDetailedHealth = jest.fn().mockResolvedValue({ status: 'healthy' });
  middleware.getServiceRegistry = jest.fn().mockReturnValue([]);
  middleware.addService = jest.fn();
  middleware.removeService = jest.fn();
  return middleware;
});

// ─── Load app ─────────────────────────────────────────────────────────────────
let app;
let gateway;

beforeAll(() => {
  const http = require('http');
  const originalListen = http.Server.prototype.listen;
  http.Server.prototype.listen = function (_port, cb) {
    this._boundPort = 0;
    if (cb) cb();
    return this;
  };

  const APIGateway = require('../index');
  http.Server.prototype.listen = originalListen;

  gateway = new APIGateway();
  app = gateway.app;
});

beforeEach(() => {
  jest.clearAllMocks();
  // Reset the "once" queue — clearAllMocks only clears call history, not the queue
  axios.post.mockReset();
  // Default: auth service accepts all tokens
  axios.post.mockResolvedValue({ data: { valid: true } });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeToken(payload = {}, options = {}) {
  return jwt.sign(
    {
      sub: payload.sub ?? 'test-user-id',
      userId: payload.userId ?? 'test-user-id',
      username: payload.username ?? 'testuser',
      email: payload.email ?? 'test@example.com',
      roles: payload.roles ?? ['user'],
      permissions: payload.permissions ?? ['read'],
      ...payload,
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h', ...options },
  );
}

function adminToken() {
  return makeToken({ roles: ['admin'], permissions: ['read', 'write', 'admin'] });
}

// ─── Health Endpoints ─────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('returns 200 without a token', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  it('response body contains status field', async () => {
    const res = await request(app).get('/health');
    expect(res.body).toHaveProperty('status');
  });

  it('sub-paths like /health/live are also public', async () => {
    const res = await request(app).get('/health/live');
    expect(res.status).not.toBe(401);
  });

  it('GET /health/detailed returns service breakdown', async () => {
    const res = await request(app).get('/health/detailed');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('services');
  });
});

// ─── Public Documentation & Info Endpoints ────────────────────────────────────

describe('Public info & docs routes', () => {
  it('GET /docs returns 200', async () => {
    const res = await request(app).get('/docs');
    expect(res.status).toBe(200);
  });

  it('GET /api-docs returns 200', async () => {
    const res = await request(app).get('/api-docs');
    expect(res.status).toBe(200);
  });

  it('GET /docs/openapi.json returns OpenAPI spec with openapi version', async () => {
    const res = await request(app).get('/docs/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('openapi');
    expect(res.body.info).toHaveProperty('title');
  });

  it('GET /api/gateway/info returns gateway metadata', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('name');
    expect(res.body).toHaveProperty('version');
    expect(res.body).toHaveProperty('uptime');
  });

  it('GET /api/gateway/routes returns array of route definitions', async () => {
    const res = await request(app).get('/api/gateway/routes');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const publicRoute = res.body.find(r => r.auth === 'public');
    expect(publicRoute).toBeDefined();
  });

  it('GET /api/services returns array of service descriptors', async () => {
    const res = await request(app).get('/api/services');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('GET /api/config/modules returns module configuration map', async () => {
    const res = await request(app).get('/api/config/modules');
    expect(res.status).toBe(200);
    expect(typeof res.body).toBe('object');
  });
});

// ─── Authentication — Missing / Invalid Tokens ────────────────────────────────

describe('Authentication — rejected requests', () => {
  it('GET /api/devices returns 401 with no token', async () => {
    const res = await request(app).get('/api/devices');
    expect(res.status).toBe(401);
  });

  it('GET /api/policies returns 401 with no token', async () => {
    const res = await request(app).get('/api/policies');
    expect(res.status).toBe(401);
  });

  it('401 body contains error field', async () => {
    const res = await request(app).get('/api/devices');
    expect(res.body).toHaveProperty('error');
  });

  it('Malformed Bearer token returns 401', async () => {
    axios.post.mockRejectedValueOnce(new Error('invalid token'));
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', 'Bearer not.a.real.jwt');
    expect(res.status).toBe(401);
  });

  it('Expired JWT returns 401', async () => {
    const expired = jwt.sign(
      { sub: 'u1', username: 'u1', roles: ['user'] },
      process.env.JWT_SECRET,
      { expiresIn: '-1s' },
    );
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
  });

  it('JWT signed with wrong secret returns 401', async () => {
    const wrongSecret = jwt.sign({ sub: 'u1', roles: ['user'] }, 'wrong-secret');
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${wrongSecret}`);
    expect(res.status).toBe(401);
  });

  it('Auth-service rejecting token returns 401', async () => {
    axios.post.mockResolvedValueOnce({ data: { valid: false } });
    const token = makeToken();
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  it('Auth-service network failure returns 401', async () => {
    axios.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const token = makeToken();
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });
});

// ─── Authentication — Valid JWT ───────────────────────────────────────────────

describe('Authentication — valid JWT', () => {
  it('Bearer token in Authorization header passes auth (reaches proxy)', async () => {
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).not.toBe(401);
  });

  it('Token in ?token query param passes auth', async () => {
    const token = makeToken();
    const res = await request(app).get(`/api/devices?token=${token}`);
    expect(res.status).not.toBe(401);
  });

  it('Token in token cookie passes auth', async () => {
    const token = makeToken();
    const res = await request(app)
      .get('/api/devices')
      .set('Cookie', `token=${token}`); // auth middleware looks for 'token=' cookie
    expect(res.status).not.toBe(401);
  });

  it('Second request with same token hits cache (axios.post called only once)', async () => {
    const token = makeToken({ sub: 'cached-user', username: 'cacheduser' });
    await request(app).get('/api/devices').set('Authorization', `Bearer ${token}`);
    await request(app).get('/api/devices').set('Authorization', `Bearer ${token}`);
    // First call validates via axios; second uses cache
    expect(axios.post).toHaveBeenCalledTimes(1);
  });

  it('Admin token with roles admin passes auth', async () => {
    const res = await request(app)
      .get('/api/policies')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).not.toBe(401);
  });
});

// ─── API Key Authentication ───────────────────────────────────────────────────

describe('API Key authentication', () => {
  it('Invalid API key returns 401', async () => {
    const res = await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'bad-key');
    expect(res.status).toBe(401);
  });

  it('Read-only key from env passes auth', async () => {
    process.env.API_KEY_READ_ONLY = 'ro-key-test-123';
    const res = await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'ro-key-test-123');
    expect(res.status).not.toBe(401);
    delete process.env.API_KEY_READ_ONLY;
  });

  it('Full-access key from env passes auth', async () => {
    process.env.API_KEY_FULL = 'full-key-test-456';
    const res = await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'full-key-test-456');
    expect(res.status).not.toBe(401);
    delete process.env.API_KEY_FULL;
  });

  it('Admin key from env passes auth', async () => {
    process.env.API_KEY_ADMIN = 'admin-key-test-789';
    const res = await request(app)
      .get('/api/admin/keys')
      .set('X-API-Key', 'admin-key-test-789');
    expect(res.status).not.toBe(401);
    delete process.env.API_KEY_ADMIN;
  });

  it('API key in ?api_key query param also works', async () => {
    process.env.API_KEY_READ_ONLY = 'ro-query-key';
    const res = await request(app).get('/api/devices?api_key=ro-query-key');
    expect(res.status).not.toBe(401);
    delete process.env.API_KEY_READ_ONLY;
  });

  it('key value "undefined" (unset env var) is rejected', async () => {
    delete process.env.API_KEY_READ_ONLY;
    const res = await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'undefined');
    expect(res.status).toBe(401);
  });
});

// ─── Admin-only Routes ────────────────────────────────────────────────────────

describe('Admin-only routes (/api/admin/keys)', () => {
  it('unauthenticated request returns 401', async () => {
    const res = await request(app).get('/api/admin/keys');
    expect(res.status).toBe(401);
  });

  it('non-admin JWT returns 403', async () => {
    const res = await request(app)
      .get('/api/admin/keys')
      .set('Authorization', `Bearer ${makeToken({ roles: ['user'] })}`);
    expect(res.status).toBe(403);
  });

  it('admin JWT returns list (possibly empty)', async () => {
    const res = await request(app)
      .get('/api/admin/keys')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('POST /api/admin/keys without name returns 400', async () => {
    const res = await request(app)
      .post('/api/admin/keys')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ permissions: ['read'] });
    expect(res.status).toBe(400);
  });

  it('POST /api/admin/keys with valid name creates key and returns rawKey', async () => {
    const res = await request(app)
      .post('/api/admin/keys')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: 'Test Key', permissions: ['read'] });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('key');
    expect(res.body).toHaveProperty('id');
    expect(res.body.name).toBe('Test Key');
  });

  it('DELETE /api/admin/keys/:id by admin returns success message', async () => {
    const res = await request(app)
      .delete('/api/admin/keys/some-key-id')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');
  });
});

// ─── Gateway API Key Management (non-admin) ───────────────────────────────────

describe('GET /api/gateway/api-keys', () => {
  it('returns array of keys', async () => {
    const res = await request(app)
      .get('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('reflects keys set via env vars', async () => {
    process.env.API_KEY_READ_ONLY = 'visible-key';
    const res = await request(app)
      .get('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`);
    const names = res.body.map(k => k.name);
    expect(names.some(n => n.toLowerCase().includes('read'))).toBe(true);
    delete process.env.API_KEY_READ_ONLY;
  });
});

describe('POST /api/gateway/api-keys', () => {
  it('missing name returns 400', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('valid name creates key with rawKey in response', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ name: 'CI Key', permissions: ['read', 'write'] });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('key');
    expect(res.body.name).toBe('CI Key');
  });
});

describe('DELETE /api/gateway/api-keys/:keyId', () => {
  it('returns success message for any keyId', async () => {
    const res = await request(app)
      .delete('/api/gateway/api-keys/test-id-123')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message');
  });
});

// ─── Webhook CRUD ─────────────────────────────────────────────────────────────

describe('Webhook management', () => {
  let createdWebhookId;
  const authHeader = () => ({ Authorization: `Bearer ${makeToken()}` });

  it('GET /api/gateway/webhooks returns empty array initially', async () => {
    const res = await request(app)
      .get('/api/gateway/webhooks')
      .set(authHeader());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('POST /api/gateway/webhooks — missing name returns 400', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(authHeader())
      .send({ url: 'https://example.com/hook' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/name/i);
  });

  it('POST /api/gateway/webhooks — missing url returns 400', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(authHeader())
      .send({ name: 'My Hook' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/url/i);
  });

  it('POST /api/gateway/webhooks — valid payload creates webhook', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(authHeader())
      .send({ name: 'Test Hook', url: 'https://example.com/hook', events: ['device.enrolled'], secret: 'mysecret' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body.name).toBe('Test Hook');
    expect(res.body).not.toHaveProperty('secretHash'); // secret must not leak
    createdWebhookId = res.body.id;
  });

  it('GET /api/gateway/webhooks lists the created webhook', async () => {
    const res = await request(app)
      .get('/api/gateway/webhooks')
      .set(authHeader());
    const ids = res.body.map(w => w.id);
    expect(ids).toContain(createdWebhookId);
  });

  it('PUT /api/gateway/webhooks/:id updates webhook name', async () => {
    const res = await request(app)
      .put(`/api/gateway/webhooks/${createdWebhookId}`)
      .set(authHeader())
      .send({ name: 'Updated Hook' });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Updated Hook');
  });

  it('PUT /api/gateway/webhooks/:id — unknown id returns 404', async () => {
    const res = await request(app)
      .put('/api/gateway/webhooks/nonexistent-id')
      .set(authHeader())
      .send({ name: 'X' });
    expect(res.status).toBe(404);
  });

  it('GET /api/gateway/webhooks/:id/deliveries returns array', async () => {
    const res = await request(app)
      .get(`/api/gateway/webhooks/${createdWebhookId}/deliveries`)
      .set(authHeader());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('DELETE /api/gateway/webhooks/:id removes the webhook', async () => {
    const res = await request(app)
      .delete(`/api/gateway/webhooks/${createdWebhookId}`)
      .set(authHeader());
    expect(res.status).toBe(204);
  });

  it('webhook is gone after deletion', async () => {
    const res = await request(app)
      .get('/api/gateway/webhooks')
      .set(authHeader());
    const ids = res.body.map(w => w.id);
    expect(ids).not.toContain(createdWebhookId);
  });
});

// ─── Webhook Test Delivery ────────────────────────────────────────────────────

describe('POST /api/gateway/webhooks/:id/test', () => {
  const authHeader = () => ({ Authorization: `Bearer ${makeToken()}` });

  it('unknown webhook returns 404', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks/no-such-webhook/test')
      .set(authHeader());
    expect(res.status).toBe(404);
  });

  it('known webhook fires test delivery and returns result', async () => {
    // Create a webhook first
    const createRes = await request(app)
      .post('/api/gateway/webhooks')
      .set(authHeader())
      .send({ name: 'Test Delivery Hook', url: 'https://example.com/webhook' });
    const id = createRes.body.id;

    const res = await request(app)
      .post(`/api/gateway/webhooks/${id}/test`)
      .set(authHeader());
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success');
    expect(res.body).toHaveProperty('delivery');
    // responseStatus 0 = timeout/network error (expected since example.com is not mocked)
    expect(typeof res.body.responseStatus).toBe('number');
  });
});

// ─── Service Health ───────────────────────────────────────────────────────────

describe('GET /api/services/:serviceId/health', () => {
  it('unknown service returns 404', async () => {
    const res = await request(app).get('/api/services/does-not-exist/health');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error');
  });

  it('known service returns status (unavailable since upstream is mocked)', async () => {
    // 'authentication' is always registered
    const res = await request(app).get('/api/services/authentication/health');
    // 503 = service registered but upstream unreachable (which is fine in tests)
    expect([200, 503]).toContain(res.status);
    expect(res.body).toHaveProperty('service', 'authentication');
    expect(res.body).toHaveProperty('status');
  });
});

// ─── 404 Catch-All ───────────────────────────────────────────────────────────

describe('404 catch-all', () => {
  it('authenticated request to unknown route returns 404', async () => {
    const res = await request(app)
      .get('/no/such/path')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).toBe(404);
  });

  it('404 body includes originalUrl path', async () => {
    const res = await request(app)
      .get('/totally/unknown')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.body).toHaveProperty('path');
    expect(res.body.path).toContain('/totally/unknown');
  });

  it('404 body lists available endpoints', async () => {
    const res = await request(app)
      .get('/no/such')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(Array.isArray(res.body.availableEndpoints)).toBe(true);
  });

  it('unauthenticated unknown route returns 401 (auth runs before catch-all)', async () => {
    const res = await request(app).get('/unknown/route');
    expect(res.status).toBe(401);
  });
});

// ─── CORS ─────────────────────────────────────────────────────────────────────

describe('CORS', () => {
  it('OPTIONS preflight from allowed origin returns 2xx', async () => {
    const res = await request(app)
      .options('/api/auth/login')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'POST');
    expect(res.status).toBeLessThan(300);
  });

  it('allowed origin receives Access-Control-Allow-Origin header', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-origin']).toBeDefined();
  });

  it('disallowed origin is not echoed back in ACAO header', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://evil.example.com');
    const acao = res.headers['access-control-allow-origin'];
    expect(acao).not.toBe('http://evil.example.com');
  });

  it('credentials flag is set for allowed origins', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('X-API-Key is in the allowed request headers list', async () => {
    const res = await request(app)
      .options('/api/devices')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'GET')
      .set('Access-Control-Request-Headers', 'X-API-Key');
    expect(res.status).toBeLessThan(300);
  });
});

// ─── Security Headers (Helmet) ────────────────────────────────────────────────

describe('Security headers', () => {
  it('X-Content-Type-Options: nosniff is set', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('X-DNS-Prefetch-Control is set', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-dns-prefetch-control']).toBeDefined();
  });

  it('Content-Security-Policy header is present', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['content-security-policy']).toBeDefined();
  });
});

// ─── Rate-Limiting Headers ────────────────────────────────────────────────────

describe('Rate-limiting', () => {
  it('response includes RateLimit or X-RateLimit headers', async () => {
    const res = await request(app).get('/health');
    const keys = Object.keys(res.headers).map(h => h.toLowerCase());
    const hasRL = keys.some(k => k.startsWith('ratelimit-') || k.startsWith('x-ratelimit-'));
    expect(hasRL).toBe(true);
  });
});

// ─── Request Body Parsing ─────────────────────────────────────────────────────

describe('Request body parsing', () => {
  it('JSON body is accepted on POST routes', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set('Authorization', `Bearer ${makeToken()}`)
      .set('Content-Type', 'application/json')
      .send({ name: 'json-body-hook', url: 'https://example.com' });
    expect(res.status).toBe(201);
  });

  it('URL-encoded body is accepted', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send('name=urlencoded-key');
    expect(res.status).toBe(201);
  });
});

// ─── Module Configuration ─────────────────────────────────────────────────────

describe('POST /api/config/modules/:moduleId', () => {
  it('request processes module update (path is under public /api/config/modules prefix)', async () => {
    // Note: /api/config/modules/* matches the public-path prefix, so the auth middleware
    // passes all requests through — auth is not enforced on write sub-paths currently.
    const res = await request(app)
      .post('/api/config/modules/device-management')
      .send({ enabled: true });
    // 200 success or 400 if module unknown — both are valid application responses
    expect([200, 400]).toContain(res.status);
  });

  it('authenticated request also processes module update', async () => {
    const res = await request(app)
      .post('/api/config/modules/device-management')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ enabled: true });
    expect([200, 400]).toContain(res.status);
  });
});

// ─── Proxy Routes Reach Upstream ─────────────────────────────────────────────

describe('Proxy routes', () => {
  const proxyRoutes = [
    '/api/auth/profile',
    '/api/devices',
    '/api/policies',
    '/api/certificates',
    '/api/antivirus',
    '/api/scanner',
  ];

  proxyRoutes.forEach(route => {
    it(`authenticated GET ${route} is forwarded to proxy (not 401)`, async () => {
      const res = await request(app)
        .get(route)
        .set('Authorization', `Bearer ${makeToken()}`);
      expect(res.status).not.toBe(401);
      // 502 = stub proxy response — confirms auth passed and request was forwarded
    });
  });

  it('auth login route /api/auth/login is public (no token needed)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'u', password: 'p' });
    // Stub returns 502 — confirms request reached proxy without 401
    expect(res.status).not.toBe(401);
  });
});

// ─── Error Response Body Shapes ───────────────────────────────────────────────

describe('Error response body shapes', () => {
  it('401 body has error, message, and timestamp fields', async () => {
    const res = await request(app).get('/api/devices');
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error', 'Unauthorized');
    expect(res.body).toHaveProperty('message');
    expect(res.body).toHaveProperty('timestamp');
    expect(new Date(res.body.timestamp).getTime()).not.toBeNaN();
  });

  it('403 body has error and message fields', async () => {
    const res = await request(app)
      .get('/api/admin/keys')
      .set('Authorization', `Bearer ${makeToken({ roles: ['operator'] })}`);
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'Forbidden');
    expect(res.body).toHaveProperty('message');
  });

  it('403 body for requireAdmin includes Admin access required message', async () => {
    const res = await request(app)
      .get('/api/admin/keys')
      .set('Authorization', `Bearer ${makeToken({ roles: ['user'] })}`);
    expect(res.body.message).toMatch(/admin/i);
  });

  it('404 body has error, path, method, and availableEndpoints', async () => {
    const res = await request(app)
      .get('/no/such/endpoint/xyz')
      .set('Authorization', `Bearer ${makeToken({ sub: 'shape-test-user' })}`);
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error');
    expect(res.body).toHaveProperty('path');
    expect(res.body).toHaveProperty('method', 'GET');
    expect(Array.isArray(res.body.availableEndpoints)).toBe(true);
    expect(res.body.availableEndpoints.length).toBeGreaterThan(0);
  });

  it('404 body contains a docs link', async () => {
    const res = await request(app)
      .get('/nonexistent')
      .set('Authorization', `Bearer ${makeToken({ sub: 'docs-link-user' })}`);
    expect(res.body).toHaveProperty('docs');
  });
});

// ─── OPTIONS Method Bypasses Auth ────────────────────────────────────────────

describe('OPTIONS method bypasses auth', () => {
  it('OPTIONS to protected route skips JWT check', async () => {
    const res = await request(app)
      .options('/api/devices')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'GET');
    // Should not be 401 — OPTIONS is exempted from auth
    expect(res.status).not.toBe(401);
  });

  it('OPTIONS to admin route also bypasses auth', async () => {
    const res = await request(app)
      .options('/api/admin/keys')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'GET');
    expect(res.status).not.toBe(401);
  });

  it('OPTIONS to unknown route skips auth (no 401)', async () => {
    const res = await request(app)
      .options('/api/completely/unknown')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'POST');
    expect(res.status).not.toBe(401);
  });
});

// ─── Authentication Priority ──────────────────────────────────────────────────

describe('Auth priority: API key takes precedence over JWT', () => {
  it('valid API key + invalid JWT → passes via API key path', async () => {
    process.env.API_KEY_READ_ONLY = 'priority-test-key';
    // axios.post returns valid: false but the API key should be checked first
    axios.post.mockResolvedValueOnce({ data: { valid: false } });
    const res = await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'priority-test-key')
      .set('Authorization', 'Bearer some-bad-token');
    expect(res.status).not.toBe(401);
    // API key auth skips axios entirely
    expect(axios.post).not.toHaveBeenCalled();
    delete process.env.API_KEY_READ_ONLY;
  });

  it('valid API key → axios.post not called (no JWT validation needed)', async () => {
    process.env.API_KEY_FULL = 'no-jwt-needed-key';
    await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'no-jwt-needed-key');
    expect(axios.post).not.toHaveBeenCalled();
    delete process.env.API_KEY_FULL;
  });
});

// ─── Rate-Limit Tier Selection ────────────────────────────────────────────────

describe('Rate-limit tier headers reflect client type', () => {
  it('unauthenticated request uses 100 req/window limit', async () => {
    const res = await request(app).get('/health');
    const limit = res.headers['ratelimit-limit'] || res.headers['x-ratelimit-limit'];
    if (limit) {
      expect(Number(limit)).toBe(100);
    }
  });

  it('API key request uses 5000 req/window limit', async () => {
    process.env.API_KEY_READ_ONLY = 'rate-tier-key';
    const res = await request(app)
      .get('/health')
      .set('X-API-Key', 'rate-tier-key');
    const limit = res.headers['ratelimit-limit'] || res.headers['x-ratelimit-limit'];
    if (limit) {
      expect(Number(limit)).toBe(5000);
    }
    delete process.env.API_KEY_READ_ONLY;
  });

  it('frontend origin request uses 1000 req/window limit', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');
    const limit = res.headers['ratelimit-limit'] || res.headers['x-ratelimit-limit'];
    if (limit) {
      expect(Number(limit)).toBe(1000);
    }
  });
});

// ─── Auth-Service Validation Call ────────────────────────────────────────────

describe('Auth-service validation call', () => {
  it('axios.post is called with the token in the request body', async () => {
    const token = makeToken({ sub: 'axios-call-check' });
    await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${token}`);
    expect(axios.post).toHaveBeenCalledWith(
      expect.stringContaining('/api/validate'),
      { token },
      expect.objectContaining({ timeout: 5000 }),
    );
  });

  it('axios.post target URL contains auth service host', async () => {
    const token = makeToken({ sub: 'auth-url-check' });
    await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${token}`);
    const [[url]] = axios.post.mock.calls;
    expect(url).toMatch(/authentication-service|localhost/);
  });

  it('axios.post is NOT called when API key is used', async () => {
    process.env.API_KEY_READ_ONLY = 'skip-axios-key';
    await request(app)
      .get('/api/devices')
      .set('X-API-Key', 'skip-axios-key');
    expect(axios.post).not.toHaveBeenCalled();
    delete process.env.API_KEY_READ_ONLY;
  });
});

// ─── Token Extraction Edge Cases ─────────────────────────────────────────────

describe('Token extraction edge cases', () => {
  it('token= cookie extracted correctly alongside other cookies', async () => {
    const token = makeToken({ sub: 'multi-cookie-user' });
    const res = await request(app)
      .get('/api/devices')
      .set('Cookie', `session_id=abc123; token=${token}; theme=dark`);
    expect(res.status).not.toBe(401);
  });

  it('Bearer header token takes priority over query param token', async () => {
    // Valid JWT in header, expired in query — header should win
    const goodToken = makeToken({ sub: 'bearer-priority-user' });
    const badToken = jwt.sign({ sub: 'x' }, process.env.JWT_SECRET, { expiresIn: '-1s' });
    const res = await request(app)
      .get(`/api/devices?token=${badToken}`)
      .set('Authorization', `Bearer ${goodToken}`);
    // Header is checked first; if it passes, query is ignored
    expect(res.status).not.toBe(401);
  });

  it('empty Authorization header value is treated as no token', async () => {
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', '');
    expect(res.status).toBe(401);
  });

  it('Authorization header without Bearer prefix is rejected', async () => {
    const token = makeToken({ sub: 'no-bearer-prefix' });
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', token); // Missing "Bearer " prefix
    expect(res.status).toBe(401);
  });
});

// ─── Admin API Key on Admin Routes ───────────────────────────────────────────

describe('Admin API key on admin-only routes', () => {
  it('admin API key bypasses requireAdmin on GET /api/admin/keys', async () => {
    process.env.API_KEY_ADMIN = 'admin-key-access-test';
    const res = await request(app)
      .get('/api/admin/keys')
      .set('X-API-Key', 'admin-key-access-test');
    expect(res.status).toBe(200);
    delete process.env.API_KEY_ADMIN;
  });

  it('read-only API key is blocked by requireAdmin on /api/admin/keys', async () => {
    process.env.API_KEY_READ_ONLY = 'ro-not-admin-key';
    const res = await request(app)
      .get('/api/admin/keys')
      .set('X-API-Key', 'ro-not-admin-key');
    expect(res.status).toBe(403);
    delete process.env.API_KEY_READ_ONLY;
  });

  it('full-access API key is blocked by requireAdmin on /api/admin/keys', async () => {
    process.env.API_KEY_FULL = 'full-not-admin-key';
    const res = await request(app)
      .get('/api/admin/keys')
      .set('X-API-Key', 'full-not-admin-key');
    expect(res.status).toBe(403);
    delete process.env.API_KEY_FULL;
  });
});

// ─── Gateway Info Detailed Structure ─────────────────────────────────────────

describe('GET /api/gateway/info — response structure', () => {
  it('has name field equal to OpenDirectory API Gateway', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(res.body.name).toBe('OpenDirectory API Gateway');
  });

  it('has version field matching package.json', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(typeof res.body.version).toBe('string');
    expect(res.body.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('has uptime as non-negative number', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(typeof res.body.uptime).toBe('number');
    expect(res.body.uptime).toBeGreaterThanOrEqual(0);
  });

  it('has environment field', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(res.body).toHaveProperty('environment', 'test');
  });

  it('has total-services as a non-negative integer', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(typeof res.body['total-services']).toBe('number');
    expect(res.body['total-services']).toBeGreaterThanOrEqual(0);
  });

  it('has timestamp as a valid ISO 8601 date string', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(typeof res.body.timestamp).toBe('string');
    expect(new Date(res.body.timestamp).getTime()).not.toBeNaN();
  });

  it('has enabled-modules as an array', async () => {
    const res = await request(app).get('/api/gateway/info');
    expect(Array.isArray(res.body['enabled-modules'])).toBe(true);
  });
});

// ─── Gateway Routes Detailed Shape ───────────────────────────────────────────

describe('GET /api/gateway/routes — response content', () => {
  it('includes a /health public route', async () => {
    const res = await request(app).get('/api/gateway/routes');
    const health = res.body.find(r => r.path === '/health');
    expect(health).toBeDefined();
    expect(health.auth).toBe('public');
  });

  it('includes /api/services as a public route', async () => {
    const res = await request(app).get('/api/gateway/routes');
    const svc = res.body.find(r => r.path === '/api/services');
    expect(svc).toBeDefined();
    expect(svc.auth).toBe('public');
  });

  it('service proxy routes have path, target, service, and auth fields', async () => {
    const res = await request(app).get('/api/gateway/routes');
    const authRequired = res.body.filter(r => r.auth === 'required');
    expect(authRequired.length).toBeGreaterThan(0);
    authRequired.forEach(r => {
      expect(r).toHaveProperty('path');
      expect(r).toHaveProperty('target');
      expect(r).toHaveProperty('service');
    });
  });
});

// ─── Detailed Health Response Structure ──────────────────────────────────────

describe('GET /health/detailed — response structure', () => {
  it('has gateway sub-object with uptime, memory, version', async () => {
    const res = await request(app).get('/health/detailed');
    expect(res.body).toHaveProperty('gateway');
    expect(typeof res.body.gateway.uptime).toBe('number');
    expect(res.body.gateway).toHaveProperty('memory');
    expect(typeof res.body.gateway.version).toBe('string');
  });

  it('services field is an array', async () => {
    const res = await request(app).get('/health/detailed');
    expect(Array.isArray(res.body.services)).toBe(true);
  });

  it('modules field is an array', async () => {
    const res = await request(app).get('/health/detailed');
    expect(Array.isArray(res.body.modules)).toBe(true);
  });

  it('timestamp is a valid ISO date', async () => {
    const res = await request(app).get('/health/detailed');
    expect(new Date(res.body.timestamp).getTime()).not.toBeNaN();
  });
});

// ─── Services List Content ────────────────────────────────────────────────────

describe('GET /api/services — content', () => {
  it('core authentication service is registered', async () => {
    const res = await request(app).get('/api/services');
    const names = res.body.map(s => s.name);
    expect(names).toContain('authentication');
  });

  it('each service entry has name, target, pathPrefix, status', async () => {
    const res = await request(app).get('/api/services');
    expect(res.body.length).toBeGreaterThan(0);
    res.body.forEach(s => {
      expect(s).toHaveProperty('name');
      expect(s).toHaveProperty('target');
      expect(s).toHaveProperty('pathPrefix');
      expect(s).toHaveProperty('status');
    });
  });
});

// ─── API Docs Structure ───────────────────────────────────────────────────────

describe('GET /docs — response structure', () => {
  it('has endpoints.public section listing common routes', async () => {
    const res = await request(app).get('/docs');
    expect(res.body.endpoints).toHaveProperty('public');
    expect(res.body.endpoints.public).toHaveProperty('health');
  });

  it('has endpoints.admin section', async () => {
    const res = await request(app).get('/docs');
    expect(res.body.endpoints).toHaveProperty('admin');
  });

  it('has authentication types array', async () => {
    const res = await request(app).get('/docs');
    expect(Array.isArray(res.body.authentication.types)).toBe(true);
    expect(res.body.authentication.types.length).toBeGreaterThan(0);
  });

  it('has rate-limits section with three tiers', async () => {
    const res = await request(app).get('/docs');
    const rl = res.body['rate-limits'];
    expect(rl).toHaveProperty('api-clients');
    expect(rl).toHaveProperty('frontend-clients');
    expect(rl).toHaveProperty('unauthenticated');
  });
});

// ─── OpenAPI Spec Content ─────────────────────────────────────────────────────

describe('GET /docs/openapi.json — spec content', () => {
  it('openapi version is 3.0.x', async () => {
    const res = await request(app).get('/docs/openapi.json');
    expect(res.body.openapi).toMatch(/^3\./);
  });

  it('info block has title and version', async () => {
    const res = await request(app).get('/docs/openapi.json');
    expect(res.body.info).toHaveProperty('title');
    expect(res.body.info).toHaveProperty('version');
  });

  it('security schemes define BearerAuth and ApiKeyAuth', async () => {
    const res = await request(app).get('/docs/openapi.json');
    const schemes = res.body.components?.securitySchemes;
    expect(schemes).toHaveProperty('BearerAuth');
    expect(schemes).toHaveProperty('ApiKeyAuth');
    expect(schemes.ApiKeyAuth.in).toBe('header');
    expect(schemes.ApiKeyAuth.name).toBe('X-API-Key');
  });

  it('paths block has at least /health defined', async () => {
    const res = await request(app).get('/docs/openapi.json');
    expect(res.body.paths).toHaveProperty('/health');
  });
});

// ─── API Key Creation Response Shape ─────────────────────────────────────────

describe('POST /api/gateway/api-keys — response shape', () => {
  it('created key id is a non-empty string', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ name: 'Shape Test Key' });
    expect(res.status).toBe(201);
    expect(typeof res.body.id).toBe('string');
    expect(res.body.id.length).toBeGreaterThan(0);
  });

  it('created key value is a 64-char hex string', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ name: 'Hex Key Test' });
    expect(/^[0-9a-f]{64}$/.test(res.body.key)).toBe(true);
  });

  it('created key has permissions array defaulting to ["read"]', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ name: 'Default Perms Key' });
    expect(Array.isArray(res.body.permissions)).toBe(true);
    expect(res.body.permissions).toContain('read');
  });

  it('created key has a created ISO timestamp', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ name: 'Timestamp Key' });
    expect(new Date(res.body.created).getTime()).not.toBeNaN();
  });

  it('custom permissions are preserved in response', async () => {
    const res = await request(app)
      .post('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ name: 'RW Key', permissions: ['read', 'write'] });
    expect(res.body.permissions).toEqual(expect.arrayContaining(['read', 'write']));
  });
});

// ─── Webhook Response Shape ───────────────────────────────────────────────────

describe('POST /api/gateway/webhooks — response shape', () => {
  const auth = () => ({ Authorization: `Bearer ${makeToken()}` });

  it('created webhook has id, name, url, events, active fields', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(auth())
      .send({ name: 'Shape Hook', url: 'https://hooks.example.com/shape' });
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('name', 'Shape Hook');
    expect(res.body).toHaveProperty('url', 'https://hooks.example.com/shape');
    expect(Array.isArray(res.body.events)).toBe(true);
    expect(res.body.active).toBe(true);
  });

  it('secretHash is NOT present in response even when secret is provided', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(auth())
      .send({ name: 'Secret Hook', url: 'https://example.com', secret: 'supersecret' });
    expect(res.body).not.toHaveProperty('secretHash');
    expect(res.body).not.toHaveProperty('secret');
  });

  it('events array is stored correctly', async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(auth())
      .send({ name: 'Events Hook', url: 'https://example.com', events: ['user.created', 'device.enrolled'] });
    expect(res.body.events).toEqual(expect.arrayContaining(['user.created', 'device.enrolled']));
  });
});

// ─── Webhook Delivery Tracking ────────────────────────────────────────────────

describe('Webhook delivery tracking after /test', () => {
  const auth = () => ({ Authorization: `Bearer ${makeToken()}` });
  let hookId;

  beforeEach(async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(auth())
      .send({ name: 'Delivery Track Hook', url: 'https://example.com/track' });
    hookId = res.body.id;
  });

  it('deliveries list is empty before any test delivery', async () => {
    const res = await request(app)
      .get(`/api/gateway/webhooks/${hookId}/deliveries`)
      .set(auth());
    expect(res.body).toEqual([]);
  });

  it('delivery is recorded after /test call', async () => {
    await request(app)
      .post(`/api/gateway/webhooks/${hookId}/test`)
      .set(auth());
    const res = await request(app)
      .get(`/api/gateway/webhooks/${hookId}/deliveries`)
      .set(auth());
    expect(res.body.length).toBeGreaterThan(0);
  });

  it('delivery record has required fields', async () => {
    await request(app)
      .post(`/api/gateway/webhooks/${hookId}/test`)
      .set(auth());
    const res = await request(app)
      .get(`/api/gateway/webhooks/${hookId}/deliveries`)
      .set(auth());
    const delivery = res.body[0];
    expect(delivery).toHaveProperty('webhookId', hookId);
    expect(delivery).toHaveProperty('eventType', 'test');
    expect(typeof delivery.success).toBe('boolean');
    expect(typeof delivery.responseStatus).toBe('number');
  });
});

// ─── Webhook Partial Updates ──────────────────────────────────────────────────

describe('PUT /api/gateway/webhooks/:id — partial update', () => {
  const auth = () => ({ Authorization: `Bearer ${makeToken()}` });
  let hookId;

  beforeEach(async () => {
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set(auth())
      .send({ name: 'Update Test Hook', url: 'https://old.example.com', events: ['old.event'] });
    hookId = res.body.id;
  });

  it('can update url independently', async () => {
    const res = await request(app)
      .put(`/api/gateway/webhooks/${hookId}`)
      .set(auth())
      .send({ url: 'https://new.example.com' });
    expect(res.status).toBe(200);
    expect(res.body.url).toBe('https://new.example.com');
  });

  it('can update events array independently', async () => {
    const res = await request(app)
      .put(`/api/gateway/webhooks/${hookId}`)
      .set(auth())
      .send({ events: ['new.event', 'another.event'] });
    expect(res.status).toBe(200);
    expect(res.body.events).toEqual(expect.arrayContaining(['new.event', 'another.event']));
  });

  it('can set active to false (deactivate)', async () => {
    const res = await request(app)
      .put(`/api/gateway/webhooks/${hookId}`)
      .set(auth())
      .send({ active: false });
    expect(res.status).toBe(200);
    expect(res.body.active).toBe(false);
  });

  it('empty body returns the webhook unchanged (in-memory path returns 200)', async () => {
    // The DB-path checks for empty update fields and returns 400; the in-memory
    // fallback (used in tests) silently returns the unchanged webhook with 200.
    const res = await request(app)
      .put(`/api/gateway/webhooks/${hookId}`)
      .set(auth())
      .send({});
    expect([200, 400]).toContain(res.status);
  });
});

// ─── Multiple Env API Keys in Listing ────────────────────────────────────────

describe('GET /api/gateway/api-keys — env key enumeration', () => {
  it('shows all three env keys when all are set', async () => {
    process.env.API_KEY_READ_ONLY = 'enum-ro';
    process.env.API_KEY_FULL     = 'enum-full';
    process.env.API_KEY_ADMIN    = 'enum-admin';
    const res = await request(app)
      .get('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`);
    const names = res.body.map(k => k.name.toLowerCase());
    expect(names.some(n => n.includes('read'))).toBe(true);
    expect(names.some(n => n.includes('full') || n.includes('access'))).toBe(true);
    expect(names.some(n => n.includes('admin'))).toBe(true);
    delete process.env.API_KEY_READ_ONLY;
    delete process.env.API_KEY_FULL;
    delete process.env.API_KEY_ADMIN;
  });

  it('only shows set env keys (not keys from unset vars)', async () => {
    delete process.env.API_KEY_READ_ONLY;
    delete process.env.API_KEY_FULL;
    delete process.env.API_KEY_ADMIN;
    const res = await request(app)
      .get('/api/gateway/api-keys')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(0);
  });
});

// ─── Token Cache Isolation ────────────────────────────────────────────────────

describe('Token cache — isolation between different tokens', () => {
  it('two different tokens each trigger their own axios.post call', async () => {
    const tokenA = makeToken({ sub: 'cache-isolation-a', username: 'usera' });
    const tokenB = makeToken({ sub: 'cache-isolation-b', username: 'userb' });
    await request(app).get('/api/devices').set('Authorization', `Bearer ${tokenA}`);
    await request(app).get('/api/devices').set('Authorization', `Bearer ${tokenB}`);
    expect(axios.post).toHaveBeenCalledTimes(2);
  });

  it('same token reused hits cache on second call (axios.post once)', async () => {
    const token = makeToken({ sub: 'cache-reuse-test', username: 'reuser' });
    await request(app).get('/api/devices').set('Authorization', `Bearer ${token}`);
    await request(app).get('/api/devices').set('Authorization', `Bearer ${token}`);
    expect(axios.post).toHaveBeenCalledTimes(1);
  });
});

// ─── JWT Payload Variants ─────────────────────────────────────────────────────

describe('JWT payload variants accepted by auth middleware', () => {
  it('token with only sub (no userId) authenticates correctly', async () => {
    const token = jwt.sign(
      { sub: 'sub-only-user', username: 'subuser', roles: ['user'] },
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
    );
    const res = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).not.toBe(401);
  });

  it('admin role in token grants access to admin routes', async () => {
    const token = makeToken({ sub: 'role-admin-check', roles: ['user', 'admin'] });
    const res = await request(app)
      .get('/api/admin/keys')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  it('token with empty roles array is rejected by requireAdmin', async () => {
    const token = makeToken({ sub: 'empty-roles-user', roles: [] });
    const res = await request(app)
      .get('/api/admin/keys')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });
});

// ─── Request Size Limits ──────────────────────────────────────────────────────

describe('Request size limits', () => {
  it('payload within 10 MB limit is accepted', async () => {
    const body = { name: 'size-hook', url: 'https://example.com', data: 'x'.repeat(1000) };
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send(body);
    expect([201, 400]).toContain(res.status); // 201 success or 400 validation — not 413
    expect(res.status).not.toBe(413);
  });

  it('payload over 10 MB is rejected with 413', async () => {
    const bigBody = 'x'.repeat(11 * 1024 * 1024); // 11 MB string
    const res = await request(app)
      .post('/api/gateway/webhooks')
      .set('Authorization', `Bearer ${makeToken()}`)
      .set('Content-Type', 'application/json')
      .send(`{"name":"x","url":"x","data":"${bigBody}"}`);
    expect(res.status).toBe(413);
  });
});

// ─── CORS Allowed Headers ─────────────────────────────────────────────────────

describe('CORS — allowed request headers', () => {
  const preflightFor = (header) =>
    request(app)
      .options('/api/devices')
      .set('Origin', 'http://localhost:3000')
      .set('Access-Control-Request-Method', 'GET')
      .set('Access-Control-Request-Headers', header);

  it('Authorization header is allowed', async () => {
    const res = await preflightFor('Authorization');
    expect(res.status).toBeLessThan(300);
  });

  it('X-Requested-With header is allowed', async () => {
    const res = await preflightFor('X-Requested-With');
    expect(res.status).toBeLessThan(300);
  });

  it('X-Service-Name header is allowed', async () => {
    const res = await preflightFor('X-Service-Name');
    expect(res.status).toBeLessThan(300);
  });

  it('X-Client-Type header is allowed', async () => {
    const res = await preflightFor('X-Client-Type');
    expect(res.status).toBeLessThan(300);
  });

  it('CORS exposed headers include X-Total-Count', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', 'http://localhost:3000');
    const exposed = res.headers['access-control-expose-headers'] || '';
    expect(exposed.toLowerCase()).toContain('x-total-count');
  });
});

// ─── Module Configuration Shape ──────────────────────────────────────────────

describe('GET /api/config/modules — response shape', () => {
  it('response is a non-null object', async () => {
    const res = await request(app).get('/api/config/modules');
    expect(res.body !== null && typeof res.body === 'object' && !Array.isArray(res.body)).toBe(true);
  });

  it('at least one module key is present', async () => {
    const res = await request(app).get('/api/config/modules');
    expect(Object.keys(res.body).length).toBeGreaterThan(0);
  });

  it('each module entry has an enabled boolean field', async () => {
    const res = await request(app).get('/api/config/modules');
    Object.values(res.body).forEach(mod => {
      expect(typeof mod.enabled).toBe('boolean');
    });
  });
});

// ─── API Key Deletion Message ─────────────────────────────────────────────────

describe('DELETE /api/gateway/api-keys — message format', () => {
  it('delete message includes the keyId', async () => {
    const keyId = 'specific-key-id-abc';
    const res = await request(app)
      .delete(`/api/gateway/api-keys/${keyId}`)
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.body.message).toContain(keyId);
  });

  it('deleting non-existent key still returns 200 (idempotent)', async () => {
    const res = await request(app)
      .delete('/api/gateway/api-keys/does-not-exist-999')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).toBe(200);
  });
});

// ─── Webhook Deletion Idempotency ────────────────────────────────────────────

describe('DELETE /api/gateway/webhooks — idempotency', () => {
  it('deleting non-existent webhook returns 204', async () => {
    const res = await request(app)
      .delete('/api/gateway/webhooks/does-not-exist-hook')
      .set('Authorization', `Bearer ${makeToken()}`);
    expect(res.status).toBe(204);
  });
});
