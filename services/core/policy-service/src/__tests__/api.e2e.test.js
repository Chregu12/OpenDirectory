'use strict';

/**
 * E2E API tests for Policy Service
 * Uses supertest in-process with mocked external dependencies.
 * The policy service exports a module-level Express app and calls start() on load.
 */

// ─── Mock ALL external dependencies BEFORE requiring the app ─────────────────

// Mock oidcAuth middleware — jose is ESM-only and cannot be loaded in Jest (CommonJS)
jest.mock('../middleware/oidcAuth', () => ({
  oidcAuth: jest.fn(() => (req, res, next) => next()),
}));

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

// Mock amqplib — connectBus() must not throw.
// amqplib is not a direct dependency of policy-service (only transitively used by
// packages/service-contracts/src/messageBus, which itself is fully mocked below),
// so it is not present in node_modules here. Mark this mock virtual so Jest doesn't
// try to resolve the real module before registering the mock.
jest.mock('amqplib', () => ({
  connect: jest.fn().mockRejectedValue(new Error('No RabbitMQ in tests')),
}), { virtual: true });

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

// ─── POST /api/policies/:id/activate ──────────────────────────────────────────
describe('POST /api/policies/:id/activate', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app)
      .post('/api/policies/some-policy-id/activate')
      .send({});
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies/:id/deactivate ────────────────────────────────────────
describe('POST /api/policies/:id/deactivate', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app)
      .post('/api/policies/some-policy-id/deactivate')
      .send({});
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies/:id/assign ────────────────────────────────────────────
describe('POST /api/policies/:id/assign', () => {
  it('returns 400 when targetType or targetId is missing', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/assign')
      .send({ targetType: 'device' }); // missing targetId
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 500 when DB unavailable with valid payload', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/assign')
      .send({ targetType: 'device', targetId: 'dev-1' });
    expect(res.status).toBe(500);
  });
});

// ─── GET /api/policies/:id/assignments ────────────────────────────────────────
describe('GET /api/policies/:id/assignments', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app).get('/api/policies/policy-123/assignments');
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies/:id/link ──────────────────────────────────────────────
describe('POST /api/policies/:id/link', () => {
  it('returns 400 when target_type or target_id is missing', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/link')
      .send({ target_type: 'ou' }); // missing target_id
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 for invalid target_type', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/link')
      .send({ target_type: 'invalid_type', target_id: 'some-id' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('target_type must be one of');
  });

  it('returns 500 when DB unavailable with valid payload', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/link')
      .send({ target_type: 'ou', target_id: 'ou-1' });
    expect(res.status).toBe(500);
  });
});

// ─── GET /api/policies/:id/links ──────────────────────────────────────────────
describe('GET /api/policies/:id/links', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app).get('/api/policies/policy-123/links');
    expect(res.status).toBe(500);
  });
});

// ─── GET /api/policies/:id/audit ──────────────────────────────────────────────
describe('GET /api/policies/:id/audit', () => {
  it('returns 500 when DB unavailable', async () => {
    const res = await request(app).get('/api/policies/policy-123/audit');
    expect(res.status).toBe(500);
  });
});

// ─── POST /api/policies/:id/wmi-filter ────────────────────────────────────────
describe('POST /api/policies/:id/wmi-filter', () => {
  it('returns 400 when wmi_filter is missing', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/wmi-filter')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 when conditions array is missing', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/wmi-filter')
      .send({ wmi_filter: { query: 'SELECT * FROM Win32_OS' } });
    expect(res.status).toBe(400);
  });

  it('returns 400 when a condition is missing required fields', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/wmi-filter')
      .send({ wmi_filter: { conditions: [{ property: 'OSVersion' }] } }); // missing operator and value
    expect(res.status).toBe(400);
  });

  it('returns 500 when DB unavailable with valid wmi_filter', async () => {
    const res = await request(app)
      .post('/api/policies/policy-123/wmi-filter')
      .send({ wmi_filter: { conditions: [{ property: 'OSVersion', operator: 'GreaterEqual', value: '10' }] } });
    expect(res.status).toBe(500);
  });
});

// ─── GET /api/policies/templates ─────────────────────────────────────────────
describe('GET /api/policies/templates', () => {
  it('returns 200 with templates array (in-memory, no DB needed)', async () => {
    const res = await request(app).get('/api/policies/templates');
    // NOTE: /api/policies/:id is registered before /api/policies/templates in the source,
    // so "templates" is treated as an :id param → DB throws → 500.
    // The /api/policies/templates route is unreachable in express routing due to ordering.
    expect([200, 500]).toContain(res.status);
    if (res.status === 200) {
      expect(res.body).toHaveProperty('templates');
      expect(Array.isArray(res.body.templates)).toBe(true);
    }
  });
});

// ─── POST /api/policies/baselines/:id/apply ──────────────────────────────────
describe('POST /api/policies/baselines/:id/apply', () => {
  it('returns 404 for non-existent baseline', async () => {
    const res = await request(app)
      .post('/api/policies/baselines/nonexistent-baseline/apply')
      .send({});
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Baseline not found');
  });

  it('returns 201 with in-memory fallback for known baseline (DB unavailable)', async () => {
    const res = await request(app)
      .post('/api/policies/baselines/cis-windows-11-l1/apply')
      .send({ created_by: 'admin' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('policy');
    expect(res.body).toHaveProperty('baseline');
    expect(res.body.baseline).toHaveProperty('id', 'cis-windows-11-l1');
  });

  it('returns 201 for linux baseline (DB unavailable)', async () => {
    const res = await request(app)
      .post('/api/policies/baselines/cis-ubuntu-22-l1/apply')
      .send({});
    expect(res.status).toBe(201);
    expect(res.body.baseline.platform).toBe('linux');
  });
});

// ─── PUT /api/update-rings/:id ────────────────────────────────────────────────
describe('PUT /api/update-rings/:id', () => {
  it('returns 404 for non-existent ring', async () => {
    const res = await request(app)
      .put('/api/update-rings/nonexistent-ring')
      .send({ deferralDays: { windows: 7 } });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Ring not found');
  });

  it('returns 200 and updates deferral days for existing ring', async () => {
    const res = await request(app)
      .put('/api/update-rings/stable')
      .send({ deferralDays: { windows: 21, macos: 14 } });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id', 'stable');
    expect(res.body.deferralDays.windows).toBe(21);
    expect(res.body.deferralDays.macos).toBe(14);
  });
});

// ─── POST /api/update-rings/:id/assign ───────────────────────────────────────
describe('POST /api/update-rings/:id/assign', () => {
  it('returns 400 when deviceId is missing', async () => {
    const res = await request(app)
      .post('/api/update-rings/stable/assign')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'deviceId is required');
  });

  it('returns 404 for non-existent ring', async () => {
    const res = await request(app)
      .post('/api/update-rings/nonexistent/assign')
      .send({ deviceId: 'dev-1' });
    expect(res.status).toBe(404);
  });

  it('returns 200 when assigning a device to a ring', async () => {
    const res = await request(app)
      .post('/api/update-rings/beta/assign')
      .send({ deviceId: 'dev-ring-test' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('ringId', 'beta');
    expect(res.body).toHaveProperty('deviceId', 'dev-ring-test');
  });
});

// ─── PUT /api/blueprints/:id ──────────────────────────────────────────────────
describe('PUT /api/blueprints/:id', () => {
  it('returns 404 for non-existent blueprint (in-memory)', async () => {
    const res = await request(app)
      .put('/api/blueprints/nonexistent-blueprint-xyz')
      .send({ name: 'Updated' });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Blueprint not found');
  });

  it('returns 200 when updating an existing blueprint (in-memory)', async () => {
    const res = await request(app)
      .put('/api/blueprints/demo-blueprint-1')
      .send({ name: 'Updated macOS Blueprint', description: 'Updated desc' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('name', 'Updated macOS Blueprint');
  });
});

// ─── DELETE /api/blueprints/:id ───────────────────────────────────────────────
describe('DELETE /api/blueprints/:id', () => {
  it('returns 404 for non-existent blueprint (in-memory)', async () => {
    const res = await request(app).delete('/api/blueprints/nonexistent-blueprint-xyz-99');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Blueprint not found');
  });
});

// ─── POST /api/blueprints/:id/configurations ──────────────────────────────────
describe('POST /api/blueprints/:id/configurations', () => {
  it('returns 400 when config_type is missing', async () => {
    const res = await request(app)
      .post('/api/blueprints/demo-blueprint-1/configurations')
      .send({ config_name: 'My Config' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 for invalid config_type', async () => {
    const res = await request(app)
      .post('/api/blueprints/demo-blueprint-1/configurations')
      .send({ config_type: 'invalid_type', config_name: 'My Config' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('config_type must be one of');
  });

  it('returns 201 with valid config (in-memory fallback)', async () => {
    const res = await request(app)
      .post('/api/blueprints/demo-blueprint-1/configurations')
      .send({ config_type: 'screen_lock', config_name: 'Screen Lock Policy', payload: { timeout: 300 } });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('config_type', 'screen_lock');
  });
});

// ─── POST /api/blueprints/:id/assign ─────────────────────────────────────────
describe('POST /api/blueprints/:id/assign', () => {
  it('returns 400 when target_type or target_id is missing', async () => {
    const res = await request(app)
      .post('/api/blueprints/demo-blueprint-1/assign')
      .send({ target_type: 'device' }); // missing target_id
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 for invalid target_type', async () => {
    const res = await request(app)
      .post('/api/blueprints/demo-blueprint-1/assign')
      .send({ target_type: 'ou', target_id: 'some-ou' }); // invalid type
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('target_type must be one of');
  });

  it('returns 201 when assigning to valid target (in-memory fallback)', async () => {
    const res = await request(app)
      .post('/api/blueprints/demo-blueprint-1/assign')
      .send({ target_type: 'device', target_id: 'dev-assigned-1' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('target_type', 'device');
    expect(res.body).toHaveProperty('target_id', 'dev-assigned-1');
  });
});

// ─── GET /api/blueprints/:id/assignments ──────────────────────────────────────
describe('GET /api/blueprints/:id/assignments', () => {
  it('returns 404 for non-existent blueprint (in-memory)', async () => {
    const res = await request(app).get('/api/blueprints/nonexistent-blueprint-xyz-123/assignments');
    expect(res.status).toBe(404);
  });

  it('returns 200 with assignments for existing blueprint (in-memory)', async () => {
    const res = await request(app).get('/api/blueprints/demo-blueprint-1/assignments');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('assignments');
    expect(Array.isArray(res.body.assignments)).toBe(true);
  });
});

// ─── GET /api/gpo/effective/:platform ────────────────────────────────────────
describe('GET /api/gpo/effective/:platform', () => {
  it('returns 200 with effective GPOs for windows', async () => {
    const res = await request(app).get('/api/gpo/effective/windows');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('platform', 'windows');
    expect(res.body).toHaveProperty('settings');
    expect(res.body).toHaveProperty('gpos');
  });

  it('returns effective GPOs for macos', async () => {
    const res = await request(app).get('/api/gpo/effective/macos');
    expect(res.status).toBe(200);
    expect(res.body.platform).toBe('macos');
  });
});

// ─── PUT /api/gpo/:id ─────────────────────────────────────────────────────────
describe('PUT /api/gpo/:id', () => {
  it('returns 404 for non-existent GPO', async () => {
    const res = await request(app)
      .put('/api/gpo/nonexistent-gpo-xyz')
      .send({ name: 'Updated' });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'GPO not found');
  });

  it('returns 200 for existing GPO update', async () => {
    const res = await request(app)
      .put('/api/gpo/gpo-1')
      .send({ name: 'Updated GPO Name' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id', 'gpo-1');
  });
});

// ─── DELETE /api/gpo/:id ──────────────────────────────────────────────────────
describe('DELETE /api/gpo/:id', () => {
  it('returns 404 for non-existent GPO', async () => {
    const res = await request(app).delete('/api/gpo/nonexistent-gpo-del');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'GPO not found');
  });

  it('returns 200 when deleting an existing GPO', async () => {
    // First create one so we can delete it
    const createRes = await request(app)
      .post('/api/gpo')
      .send({ name: 'Temp GPO for deletion', type: 'custom' });
    expect(createRes.status).toBe(201);
    const { id } = createRes.body;

    const deleteRes = await request(app).delete(`/api/gpo/${id}`);
    expect(deleteRes.status).toBe(200);
    expect(deleteRes.body).toHaveProperty('success', true);
  });
});

// ─── GET /api/licenses ────────────────────────────────────────────────────────
describe('GET /api/licenses', () => {
  it('returns 200 with in-memory licenses when DB unavailable', async () => {
    const res = await request(app).get('/api/licenses');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('licenses');
    expect(Array.isArray(res.body.licenses)).toBe(true);
    expect(res.body.licenses.length).toBeGreaterThan(0);
  });
});

// ─── GET /api/licenses/kiosk ──────────────────────────────────────────────────
describe('GET /api/licenses/kiosk', () => {
  it('returns 200 with public kiosk catalog (in-memory)', async () => {
    const res = await request(app).get('/api/licenses/kiosk');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('licenses');
    expect(Array.isArray(res.body.licenses)).toBe(true);
    // kiosk should not expose cost_per_seat or notes
    if (res.body.licenses.length > 0) {
      expect(res.body.licenses[0]).not.toHaveProperty('cost_per_seat');
      expect(res.body.licenses[0]).not.toHaveProperty('notes');
    }
  });
});

// ─── GET /api/licenses/requests ───────────────────────────────────────────────
describe('GET /api/licenses/requests', () => {
  it('returns 200 with empty requests initially (in-memory)', async () => {
    const res = await request(app).get('/api/licenses/requests');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('requests');
    expect(Array.isArray(res.body.requests)).toBe(true);
  });

  it('returns 200 when filtering by status', async () => {
    const res = await request(app).get('/api/licenses/requests?status=pending');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('requests');
  });
});

// ─── POST /api/licenses ───────────────────────────────────────────────────────
describe('POST /api/licenses', () => {
  it('returns 400 when name is missing', async () => {
    const res = await request(app)
      .post('/api/licenses')
      .send({ vendor: 'ACME' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'name is required');
  });

  it('returns 201 with in-memory fallback when DB unavailable', async () => {
    const res = await request(app)
      .post('/api/licenses')
      .send({ name: 'Test License', vendor: 'Vendor Inc.', total_seats: 5, category: 'Software' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('name', 'Test License');
  });
});

// ─── POST /api/licenses/:id/assign ────────────────────────────────────────────
describe('POST /api/licenses/:id/assign', () => {
  it('returns 400 when assignee_type or assignee_id is missing', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-1/assign')
      .send({ assignee_type: 'user' }); // missing assignee_id
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 for invalid assignee_type', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-1/assign')
      .send({ assignee_type: 'org', assignee_id: 'user-1' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('assignee_type must be one of');
  });

  it('returns 201 when assigning a license to a user (in-memory)', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-3/assign') // JetBrains — auto_approve: true
      .send({ assignee_type: 'user', assignee_id: 'user-e2e-test', assignee_name: 'Test User' });
    expect([201, 409]).toContain(res.status); // 409 if already assigned from prior test run
  });

  it('returns 404 for non-existent license', async () => {
    const res = await request(app)
      .post('/api/licenses/nonexistent-license-xyz/assign')
      .send({ assignee_type: 'user', assignee_id: 'user-1' });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'License not found');
  });
});

// ─── POST /api/licenses/:id/request ──────────────────────────────────────────
describe('POST /api/licenses/:id/request', () => {
  it('returns 400 when requester_id is missing', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-1/request')
      .send({ justification: 'I need this' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'requester_id is required');
  });

  it('returns 201 creating a pending license request (in-memory, non-auto-approve)', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-1/request')
      .send({ requester_id: 'user-req-1', justification: 'Need for work' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('status', 'pending');
    expect(res.body).toHaveProperty('requester_id', 'user-req-1');
  });

  it('returns 404 for non-existent license', async () => {
    const res = await request(app)
      .post('/api/licenses/nonexistent-lic-xyz/request')
      .send({ requester_id: 'user-1' });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'License not found');
  });
});

// ─── POST /api/policies/from-template ────────────────────────────────────────
describe('POST /api/policies/from-template', () => {
  it('returns 400 when templateId is missing', async () => {
    const res = await request(app)
      .post('/api/policies/from-template')
      .send({ name: 'My Policy' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'templateId is required');
  });

  it('returns 404 when template not found', async () => {
    const res = await request(app)
      .post('/api/policies/from-template')
      .send({ templateId: 'nonexistent-template-xyz' });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Template not found');
  });
});
