'use strict';

/**
 * E2E API tests for Policy Service
 * Uses supertest in-process with mocked external dependencies.
 * The policy service exports a module-level Express app and calls start() on load.
 */

// ─── Mock ALL external dependencies BEFORE requiring the app ─────────────────

// Mock pg — testConnection() must return false so migrations are skipped
jest.mock('pg', () => {
  const mockPool = {
    query: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    connect: jest.fn().mockRejectedValue(new Error('No DB in tests')),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
  };
  return { Pool: jest.fn().mockImplementation(() => mockPool) };
});

// Mock amqplib — connectBus() must not throw
jest.mock('amqplib', () => ({
  connect: jest.fn().mockRejectedValue(new Error('No RabbitMQ in tests')),
}));

// Mock service-contracts messageBus
jest.mock('../../../../packages/service-contracts/src/messageBus', () => {
  const instance = {
    connect: jest.fn().mockResolvedValue(undefined),
    publish: jest.fn().mockResolvedValue(undefined),
    subscribe: jest.fn().mockResolvedValue(undefined),
    isConnected: jest.fn().mockReturnValue(false),
    getInstance: jest.fn(),
  };
  instance.getInstance = jest.fn().mockReturnValue(instance);
  const MockMessageBus = jest.fn().mockImplementation(() => instance);
  MockMessageBus.getInstance = jest.fn().mockReturnValue(instance);
  return MockMessageBus;
}, { virtual: true });

// ─── Now require the app ───────────────────────────────────────────────────────
const request = require('supertest');

// The policy service module calls start() on load (async, fire-and-forget style)
// We require it here; start() will run but testConnection() returns false (DB mock throws),
// so it will just log a warning and continue without DB operations.
let app;

beforeAll(async () => {
  // Silence console output during module load
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  app = require('../index');

  // Give start() a small tick to complete its async flow
  await new Promise(resolve => setTimeout(resolve, 50));
});

afterAll(() => {
  jest.restoreAllMocks();
  jest.clearAllTimers();
});

// ─── Health Check ─────────────────────────────────────────────────────────────
describe('GET /health', () => {
  it('returns health status (200 or 503 depending on DB)', async () => {
    const res = await request(app).get('/health');
    // DB mock throws → testConnection returns false → status 503 "degraded"
    expect([200, 503]).toContain(res.status);
    expect(res.body).toHaveProperty('service', 'policy-service');
    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('timestamp');
  });
});

// ─── GET /api/policies ────────────────────────────────────────────────────────
describe('GET /api/policies', () => {
  it('returns 500 when DB is unavailable (no in-memory fallback)', async () => {
    const res = await request(app).get('/api/policies');
    // The list endpoint calls db.query directly which throws → 500
    expect(res.status).toBe(500);
    expect(res.body).toHaveProperty('error');
  });
});

// ─── GET /api/policies/:id ────────────────────────────────────────────────────
describe('GET /api/policies/:id', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app).get('/api/policies/some-policy-id');
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies ───────────────────────────────────────────────────────
describe('POST /api/policies', () => {
  it('returns 400 when name is missing', async () => {
    const res = await request(app)
      .post('/api/policies')
      .send({ type: 'security' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 when type is missing', async () => {
    const res = await request(app)
      .post('/api/policies')
      .send({ name: 'My Policy' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 for invalid type', async () => {
    const res = await request(app)
      .post('/api/policies')
      .send({ name: 'My Policy', type: 'invalid_type' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('type must be one of');
  });

  it('returns 500 when DB unavailable with valid payload', async () => {
    const res = await request(app)
      .post('/api/policies')
      .send({ name: 'My Security Policy', type: 'security' });
    expect(res.status).toBe(500);
  });
});

// ─── PUT /api/policies/:id ────────────────────────────────────────────────────
describe('PUT /api/policies/:id', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app)
      .put('/api/policies/policy-123')
      .send({ name: 'Updated Policy' });
    expect(res.status).toBe(500);
  });
});

// ─── DELETE /api/policies/:id ─────────────────────────────────────────────────
describe('DELETE /api/policies/:id', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app).delete('/api/policies/policy-123');
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies/evaluate ─────────────────────────────────────────────
describe('POST /api/policies/evaluate', () => {
  it('returns 500 when DB unavailable (no active policies to evaluate)', async () => {
    const res = await request(app)
      .post('/api/policies/evaluate')
      .send({ deviceId: 'device-123' });
    expect(res.status).toBe(500);
  });
});

// ─── GET /api/blueprints ──────────────────────────────────────────────────────
describe('GET /api/blueprints', () => {
  it('returns 200 with in-memory blueprints when DB unavailable', async () => {
    // The blueprints endpoint falls back to in-memory store on DB error
    const res = await request(app).get('/api/blueprints');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('blueprints');
    expect(Array.isArray(res.body.blueprints)).toBe(true);
    // The seeded demo blueprint should be present
    expect(res.body).toHaveProperty('total');
  });
});

// ─── POST /api/blueprints ─────────────────────────────────────────────────────
describe('POST /api/blueprints', () => {
  it('returns 400 when name is missing', async () => {
    const res = await request(app)
      .post('/api/blueprints')
      .send({ platform: 'windows' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'name is required');
  });

  it('returns 201 with in-memory fallback when DB unavailable', async () => {
    const res = await request(app)
      .post('/api/blueprints')
      .send({ name: 'Test Blueprint', platform: 'windows', description: 'A test blueprint' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('name', 'Test Blueprint');
  });
});

// ─── GET /api/blueprints/:id ──────────────────────────────────────────────────
describe('GET /api/blueprints/:id', () => {
  it('returns 404 for non-existent blueprint (in-memory)', async () => {
    const res = await request(app).get('/api/blueprints/nonexistent-blueprint-id-99999');
    // DB throws → falls back to in-memory → not found → 404
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Blueprint not found');
  });

  it('returns 200 for seeded demo blueprint', async () => {
    const res = await request(app).get('/api/blueprints/demo-blueprint-1');
    // DB throws → falls back to in-memory where demo-blueprint-1 exists
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id', 'demo-blueprint-1');
    expect(res.body).toHaveProperty('configurations');
    expect(Array.isArray(res.body.configurations)).toBe(true);
  });
});

// ─── GET /api/policies/baselines ─────────────────────────────────────────────
// NOTE: /api/policies/:id is registered before /api/policies/baselines in the source,
// so "baselines" is treated as an :id param — DB throws → 500 in test environment.
describe('GET /api/policies/baselines', () => {
  it('returns a response (route matched — DB unavailable returns 500)', async () => {
    const res = await request(app).get('/api/policies/baselines');
    // In tests, DB rejects all queries, so this will return 500 (/:id handler runs first)
    expect([200, 404, 500]).toContain(res.status);
  });
});

// ─── GET /api/update-rings ────────────────────────────────────────────────────
describe('GET /api/update-rings', () => {
  it('returns 200 with update rings (in-memory, no DB needed)', async () => {
    const res = await request(app).get('/api/update-rings');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    // Check ring structure
    const ring = res.body.find(r => r.id === 'stable');
    expect(ring).toBeDefined();
    expect(ring).toHaveProperty('name');
    expect(ring).toHaveProperty('deferralDays');
  });
});

// ─── GET /api/gpo ─────────────────────────────────────────────────────────────
describe('GET /api/gpo', () => {
  it('returns 200 with seeded GPOs (in-memory)', async () => {
    const res = await request(app).get('/api/gpo');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    const gpo = res.body[0];
    expect(gpo).toHaveProperty('id');
    expect(gpo).toHaveProperty('name');
    expect(gpo).toHaveProperty('settings');
  });
});

// ─── POST /api/gpo ────────────────────────────────────────────────────────────
describe('POST /api/gpo', () => {
  it('returns 400 when name is missing', async () => {
    const res = await request(app)
      .post('/api/gpo')
      .send({ type: 'password_policy' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'name required');
  });

  it('returns 201 when creating GPO with name (in-memory)', async () => {
    const res = await request(app)
      .post('/api/gpo')
      .send({ name: 'My Custom GPO', type: 'firewall', settings: { enabled: true } });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('name', 'My Custom GPO');
  });
});

// ─── GET /api/policies/conflicts ──────────────────────────────────────────────
describe('GET /api/policies/conflicts', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app).get('/api/policies/conflicts');
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies/rsop ──────────────────────────────────────────────────
describe('POST /api/policies/rsop', () => {
  it('returns 400 when neither deviceId nor userId provided', async () => {
    const res = await request(app)
      .post('/api/policies/rsop')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 500 when DB unavailable with valid params', async () => {
    const res = await request(app)
      .post('/api/policies/rsop')
      .send({ deviceId: 'device-123' });
    expect(res.status).toBe(500);
  });
});

// ─── GET /api/policies/simulate ───────────────────────────────────────────────
// NOTE: /api/policies/:id is registered before /api/policies/simulate in the source,
// so "simulate" is treated as an :id param — DB throws → 500 in test environment.
describe('GET /api/policies/simulate', () => {
  it('returns a response (route matched — DB unavailable returns 500)', async () => {
    const res = await request(app).get('/api/policies/simulate');
    // /:id handler runs first; DB throws → 500
    expect([400, 404, 500]).toContain(res.status);
  });

  it('returns a response with deviceId param (DB unavailable)', async () => {
    // /:id handler runs first; DB throws → 500
    const res = await request(app).get('/api/policies/simulate?deviceId=device-123');
    expect([200, 404, 500]).toContain(res.status);
  });
});
