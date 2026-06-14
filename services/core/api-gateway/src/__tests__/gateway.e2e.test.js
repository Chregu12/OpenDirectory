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

// ─── Environment ────────────────────────────────────────────────────────────
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-for-unit-tests';
process.env.PORT = '0'; // let the OS pick a free port

// ─── Suppress winston file-transport noise in tests ─────────────────────────
jest.mock('../config/logger', () => {
  const noop = () => {};
  const logger = {
    info: noop,
    warn: noop,
    error: noop,
    debug: noop,
    security: noop,
    performance: noop,
    request: (_req, _res, next) => next && next(),
  };
  return logger;
});

// ─── Mock PostgreSQL pool – never actually connect ───────────────────────────
// pg is used in index.js but not declared in package.json, so use virtual:true
jest.mock('pg', () => {
  const query = jest.fn().mockResolvedValue({ rows: [] });
  const Pool = jest.fn().mockImplementation(() => ({ query }));
  return { Pool };
}, { virtual: true });

// ─── Mock the gRPC / RabbitMQ event bus ─────────────────────────────────────
jest.mock('@opendirectory/grpc-event-bus', () => ({
  EventBusClient: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
  })),
}), { virtual: true });

// ─── Mock Consul service discovery ──────────────────────────────────────────
jest.mock('../discovery/serviceDiscovery', () => ({
  start: jest.fn(),
  stop: jest.fn(),
  getServices: jest.fn().mockReturnValue([]),
}), { virtual: true });

// ─── Mock http-proxy-middleware (prevent actual upstream proxying) ────────────
jest.mock('http-proxy-middleware', () => ({
  createProxyMiddleware: jest.fn().mockImplementation(() =>
    // A simple stub that returns 502 to signal "proxied (but stubbed)"
    (_req, res) => res.status(502).json({ stub: true }),
  ),
}));

// ─── Mock axios (used by auth middleware to call the auth-service) ────────────
jest.mock('axios', () => ({
  post: jest.fn(),
  get: jest.fn(),
  create: jest.fn().mockReturnThis(),
  defaults: { headers: { common: {} } },
}));

const axios = require('axios');

// ─── Mock health-check polling so it never fires real HTTP requests ───────────
jest.mock('../middleware/health', () => {
  // Return a plain middleware function (the health endpoint response is
  // verified via the route handler in index.js, not via the middleware class).
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

// ─── Load the app ────────────────────────────────────────────────────────────
// We import APIGateway *after* all mocks are set up.  The module immediately
// creates a gateway instance and calls gateway.start(), but because we mocked
// pg/amqplib/consul nothing actually binds to a real external resource.
// We grab the underlying Express app from the class so supertest can drive it
// without occupying a port.

let app;

beforeAll(() => {
  // Prevent the module-level `gateway.start()` from binding a server port.
  // We do this by temporarily replacing http.Server.listen with a no-op before
  // requiring the module.
  const http = require('http');
  const originalListen = http.Server.prototype.listen;
  http.Server.prototype.listen = function (_port, cb) {
    // Still store a reference so .close() doesn't throw
    this._boundPort = 0;
    if (cb) cb();
    return this;
  };

  const APIGateway = require('../index');

  // Restore listen so supertest can create its own ephemeral server
  http.Server.prototype.listen = originalListen;

  // APIGateway exports the class; instantiate a fresh one for testing
  const gw = new APIGateway();
  app = gw.app;
});

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Generate a signed JWT that the auth middleware will accept locally.
 * After local verification the middleware also calls the auth-service via
 * axios – we mock that to return { valid: true }.
 */
function makeToken(payload = {}) {
  return jwt.sign(
    {
      sub: 'test-user-id',
      userId: 'test-user-id',
      username: 'testuser',
      email: 'test@example.com',
      roles: ['user'],
      permissions: ['read'],
      ...payload,
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' },
  );
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('API Gateway E2E', () => {
  // ── Health endpoint ────────────────────────────────────────────────────────

  describe('GET /health', () => {
    it('returns 200 without any authentication token', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
    });

    it('response body contains a status field', async () => {
      const res = await request(app).get('/health');
      expect(res.body).toHaveProperty('status');
    });
  });

  // ── Authentication enforcement ─────────────────────────────────────────────

  describe('Protected routes - no token', () => {
    it('GET /api/devices returns 401 without a token', async () => {
      const res = await request(app).get('/api/devices');
      expect(res.status).toBe(401);
    });

    it('GET /api/policies returns 401 without a token', async () => {
      const res = await request(app).get('/api/policies');
      expect(res.status).toBe(401);
    });

    it('response body includes an error field', async () => {
      const res = await request(app).get('/api/devices');
      expect(res.body).toHaveProperty('error');
    });
  });

  // ── Authentication with a valid token ─────────────────────────────────────

  describe('Protected routes - valid token', () => {
    beforeEach(() => {
      // Auth middleware verifies JWT locally, then calls auth-service via axios.
      axios.post.mockResolvedValue({ data: { valid: true } });
    });

    it('GET /api/devices with a valid token reaches the proxy (not 401)', async () => {
      const token = makeToken();
      const res = await request(app)
        .get('/api/devices')
        .set('Authorization', `Bearer ${token}`);

      // The proxy is stubbed to return 502; what matters is that auth passed (not 401)
      expect(res.status).not.toBe(401);
    });

    it('GET /api/policies with a valid token passes authentication', async () => {
      const token = makeToken({ roles: ['admin'], permissions: ['read', 'write'] });
      const res = await request(app)
        .get('/api/policies')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).not.toBe(401);
    });
  });

  // ── Public info routes (no token required) ─────────────────────────────────

  describe('Public gateway info routes', () => {
    it('GET /api/gateway/info returns 200', async () => {
      const res = await request(app).get('/api/gateway/info');
      expect(res.status).toBe(200);
    });

    it('GET /api/gateway/routes returns 200', async () => {
      const res = await request(app).get('/api/gateway/routes');
      expect(res.status).toBe(200);
    });

    it('GET /api/services returns 200', async () => {
      const res = await request(app).get('/api/services');
      expect(res.status).toBe(200);
    });

    it('GET /docs returns 200', async () => {
      const res = await request(app).get('/docs');
      expect(res.status).toBe(200);
    });
  });

  // ── 404 for unknown routes ────────────────────────────────────────────────
  // Note: the auth middleware runs before the catch-all route handler, so an
  // unauthenticated request to an unknown path returns 401.  To exercise the
  // actual 404 handler we must supply a valid token.

  describe('Unknown routes', () => {
    beforeEach(() => {
      axios.post.mockResolvedValue({ data: { valid: true } });
    });

    it('authenticated GET /this/does/not/exist returns 404', async () => {
      const token = makeToken();
      const res = await request(app)
        .get('/this/does/not/exist')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(404);
    });

    it('404 response body includes the path', async () => {
      const token = makeToken();
      const res = await request(app)
        .get('/totally/unknown/route')
        .set('Authorization', `Bearer ${token}`);
      expect(res.body).toHaveProperty('path');
    });
  });

  // ── CORS headers ──────────────────────────────────────────────────────────

  describe('CORS', () => {
    it('OPTIONS preflight from an allowed origin returns 2xx', async () => {
      const res = await request(app)
        .options('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST');

      expect(res.status).toBeLessThan(300);
    });

    it('allowed origin gets Access-Control-Allow-Origin header', async () => {
      const res = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:3000');

      // CORS header should be present for allowed origins
      expect(res.headers['access-control-allow-origin']).toBeDefined();
    });

    it('disallowed origin does not get the origin echoed back', async () => {
      const res = await request(app)
        .get('/health')
        .set('Origin', 'http://evil.example.com');

      // The allow-origin header must NOT reflect the disallowed origin
      const allowOrigin = res.headers['access-control-allow-origin'];
      expect(allowOrigin).not.toBe('http://evil.example.com');
    });
  });

  // ── Rate-limiting headers ─────────────────────────────────────────────────

  describe('Rate-limiting', () => {
    it('response includes RateLimit headers', async () => {
      const res = await request(app).get('/health');
      // express-rate-limit v7 emits RateLimit-* or X-RateLimit-* headers
      const headers = Object.keys(res.headers).map(h => h.toLowerCase());
      const hasRateLimit = headers.some(h =>
        h.startsWith('ratelimit-') || h.startsWith('x-ratelimit-'),
      );
      expect(hasRateLimit).toBe(true);
    });
  });

  // ── API Key authentication ────────────────────────────────────────────────

  describe('API Key authentication', () => {
    it('request with invalid API key returns 401', async () => {
      const res = await request(app)
        .get('/api/devices')
        .set('X-API-Key', 'totally-invalid-key');

      expect(res.status).toBe(401);
    });

    it('request with valid API key (from env) passes authentication', async () => {
      process.env.API_KEY_READ_ONLY = 'test-read-only-key-from-env';
      const res = await request(app)
        .get('/api/devices')
        .set('X-API-Key', 'test-read-only-key-from-env');

      // Should reach the (stubbed) proxy, not return 401
      expect(res.status).not.toBe(401);
      delete process.env.API_KEY_READ_ONLY;
    });
  });
});
