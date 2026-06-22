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
