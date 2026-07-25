'use strict';

/**
 * E2E API tests for the certificate-authority service.
 *
 * Boots the real src/index.js module in-process (supertest against its
 * exported Express `app`) with external infrastructure faked at the module
 * boundary:
 *   - 'pg'  → query() always rejects, so dbReady stays false. initCA() then
 *             takes its "DB unavailable" fallback path (generate in-memory,
 *             don't persist) — the persistence logic itself is covered
 *             separately and thoroughly in
 *             src/services/__tests__/rootCaService.test.js against a real
 *             fake Pool; this file is about auth + route wiring.
 *   - EVENT_BUS_TRANSPORT=memory → the real (in-process, no network)
 *     MemoryTransport from @opendirectory/grpc-event-bus, so connectBus()/
 *     publish() work without RabbitMQ.
 *   - middleware/oidcAuth → mocked so this suite doesn't depend on a live
 *     JWKS endpoint (jose's jwtVerify would otherwise try a real HTTP
 *     fetch). The mock preserves the actual skipPaths contract: unlisted
 *     paths require `Authorization: Bearer valid-test-token`, mirroring
 *     what the real middleware does for a JWT that does/doesn't verify.
 *
 * Covers the two P0 auth requirements:
 *   (a) POST /ca/issue with no token -> 401
 *   (b) POST /ca/issue with a valid token -> 200/201
 * plus that the intentionally-public PKI discovery routes (root cert, CRL)
 * stay public, and that the other sensitive endpoints (GET /ca/certificates,
 * POST /ca/revoke/:id) are gated too.
 */

// node-forge does RSA keygen in pure JS (root CA: 4096-bit at boot, each
// issued leaf cert: 2048-bit per request) which can comfortably exceed
// Jest's default 5s test timeout on a loaded/sandboxed CPU.
jest.setTimeout(30000);

process.env.CA_PORT = '0'; // ephemeral port — avoid clashing with a real instance
process.env.EVENT_BUS_TRANSPORT = 'memory';
process.env.OIDC_ISSUER = 'https://test-issuer.example';
process.env.JWKS_URI = 'https://test-issuer.example/jwks';

jest.mock('../middleware/oidcAuth', () => ({
  oidcAuth: ({ skipPaths = [] } = {}) => (req, res, next) => {
    if (skipPaths.some(p => req.path === p || req.path.startsWith(p))) return next();
    if (req.headers.authorization === 'Bearer valid-test-token') {
      req.user = { sub: 'test-user' };
      return next();
    }
    return res.status(401).json({ error: 'unauthorized' });
  },
}));

jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

const request = require('supertest');

let app;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  app = require('../index');

  // index.js's boot sequence (initDb -> initCA -> listen) is async at module
  // scope and involves real RSA-4096 keygen (node-forge, pure JS — can take
  // longer than any fixed sleep), so await the readiness promise it exposes
  // (app.ready) rather than guessing a timeout.
  await app.ready;
}, 30000);

afterAll(() => {
  jest.restoreAllMocks();
});

describe('GET /health', () => {
  it('is public and reports the CA as ready', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
    expect(res.body).toHaveProperty('caReady', true);
  });
});

describe('GET /ca/root (public PKI discovery)', () => {
  it('returns the root CA cert with no Authorization header', async () => {
    const res = await request(app).get('/ca/root');
    expect(res.status).toBe(200);
    expect(res.text).toContain('BEGIN CERTIFICATE');
  });
});

describe('GET /ca/root/json (public PKI discovery)', () => {
  it('returns the root CA cert as JSON with no Authorization header', async () => {
    const res = await request(app).get('/ca/root/json');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('certificate');
    expect(res.body.certificate).toContain('BEGIN CERTIFICATE');
  });
});

describe('GET /ca/crl (public PKI discovery)', () => {
  it('is reachable with no Authorization header', async () => {
    const res = await request(app).get('/ca/crl');
    expect(res.status).toBe(200);
  });
});

describe('POST /ca/issue (P0: was completely unauthenticated)', () => {
  it('returns 401 with no Authorization header', async () => {
    const res = await request(app)
      .post('/ca/issue')
      .send({ commonName: 'test.opendirectory.local' });
    expect(res.status).toBe(401);
  });

  it('returns 401 with an invalid/garbage token', async () => {
    const res = await request(app)
      .post('/ca/issue')
      .set('Authorization', 'Bearer not-a-valid-token')
      .send({ commonName: 'test.opendirectory.local' });
    expect(res.status).toBe(401);
  });

  it('issues a certificate when a valid bearer token is presented', async () => {
    const res = await request(app)
      .post('/ca/issue')
      .set('Authorization', 'Bearer valid-test-token')
      .send({ commonName: 'test.opendirectory.local' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('certificate');
    expect(res.body.certificate).toContain('BEGIN CERTIFICATE');
    expect(res.body).toHaveProperty('privateKey');
    expect(res.body).toHaveProperty('caCertificate');
  });
});

describe('GET /ca/certificates (issued-cert inventory — sensitive, not public discovery)', () => {
  it('returns 401 with no Authorization header', async () => {
    const res = await request(app).get('/ca/certificates');
    expect(res.status).toBe(401);
  });

  it('returns 200 with a valid bearer token', async () => {
    const res = await request(app).get('/ca/certificates').set('Authorization', 'Bearer valid-test-token');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('POST /ca/revoke/:id (state-changing)', () => {
  it('returns 401 with no Authorization header', async () => {
    const res = await request(app).post('/ca/revoke/some-cert-id');
    expect(res.status).toBe(401);
  });

  it('returns 200 with a valid bearer token', async () => {
    const res = await request(app)
      .post('/ca/revoke/some-cert-id')
      .set('Authorization', 'Bearer valid-test-token');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success', true);
  });
});

describe('GET /metrics', () => {
  it('is public', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
  });
});
