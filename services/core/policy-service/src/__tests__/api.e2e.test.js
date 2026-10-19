'use strict';

/**
 * E2E API tests for Policy Service
 * Uses supertest in-process with mocked external dependencies.
 */

// ─── Mock ALL external dependencies BEFORE requiring the app ─────────────────

jest.mock('../middleware/oidcAuth', () => ({
  oidcAuth: jest.fn(() => (req, res, next) => {
    const userId = require('./fixtures/licenseIdentities.cjs').userId('test-admin');
    const authTime = Math.floor(Date.now() / 1000);
    req.user = { iss: require('./fixtures/licenseIdentities.cjs').issuer, sub: 'test-admin', name: 'Test Admin', roles: ['admin'], actor_type: 'user',
      identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, auth_time: authTime, amr: ['pwd', 'otp'],
      mfa_authorization: { schemaVersion: 1, userId, revision: '1', methods: ['pwd', 'otp'], authTime } };
    req.user.token_use = 'access'; req.user.exp = authTime + 3600; req.user.iat = authTime; req.user.client_id = 'owned-api-client'; req.user.jti = 'owned-api-token'; req.headers.authorization = 'Bearer owned.api.proof';
    next();
  }),
}));

jest.mock('../licenses/GroupSnapshotClient', () => ({
  ...jest.requireActual('../licenses/GroupSnapshotClient'),
  GroupSnapshotClient: class {
    async subject(_authorization, expected) { return require('./fixtures/licenseIdentities.cjs').principal(expected.subject, expected.issuer); }
    async user(userId) { return { schemaVersion: 1, userId, revision: '1', enabled: true, deleted: false }; }
  },
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
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: () => async () => {} }));
const request = require('supertest');
const { userId } = require('./fixtures/licenseIdentities.cjs');

let app;
const previousLicenseDemoMode = process.env.LICENSE_DEMO_MODE;

beforeAll(() => {
  // Silence console output during module load
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  process.env.LICENSE_DEMO_MODE = 'true';
  app = require('../index');

});

afterAll(() => {
  if (previousLicenseDemoMode === undefined) delete process.env.LICENSE_DEMO_MODE;
  else process.env.LICENSE_DEMO_MODE = previousLicenseDemoMode;
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


const canonicalPolicyId = '11111111-1111-4111-8111-111111111111';
const why = { reason: 'Explicit unit contract policy change', acknowledgeScope: true };
const capturedTag = '"od-policy:' + canonicalPolicyId + ':1"';
const blueprintTag = '"od-blueprint:' + canonicalPolicyId + ':1"';
describe('persistent policy contracts never fall back to in-memory success', () => {
  test.each([
    ['get','/api/policies'], ['get','/api/policies/'+canonicalPolicyId], ['get','/api/policies/conflicts'],
    ['get','/api/policies/simulate?deviceId=owned-device'], ['get','/api/policies/inheritance/owned-ou'],
    ['get','/api/policies/'+canonicalPolicyId+'/audit'], ['get','/api/policies/'+canonicalPolicyId+'/assignments'],
    ['get','/api/policies/'+canonicalPolicyId+'/links'], ['get','/api/gpo'], ['get','/api/gpo/effective/windows'],
    ['get','/api/update-rings'], ['get','/api/blueprints'], ['get','/api/blueprints/'+canonicalPolicyId],
    ['get','/api/blueprints/'+canonicalPolicyId+'/assignments'],
    ['post','/api/policies',{name:'Owned draft',type:'security',settings:{},...why}],
    ['put','/api/policies/'+canonicalPolicyId,{settings:{},...why}],
    ['post','/api/policies/'+canonicalPolicyId+'/activate',{...why,publicationId:canonicalPolicyId}],
    ['post','/api/policies/'+canonicalPolicyId+'/deactivate',why],
    ['delete','/api/policies/'+canonicalPolicyId,why],
    ['post','/api/policies/'+canonicalPolicyId+'/assign',{targetType:'device',targetId:'known-device',...why}],
    ['post','/api/policies/'+canonicalPolicyId+'/link',{target_type:'group',target_id:canonicalPolicyId,...why}],
    ['post','/api/gpo',{name:'Owned GPO',settings:{},...why}],
    ['put','/api/gpo/'+canonicalPolicyId,{name:'Changed GPO',...why}],
    ['delete','/api/gpo/'+canonicalPolicyId,why],
    ['put','/api/update-rings/'+canonicalPolicyId,{deferralDays:{windows:1,macos:1,linux:0},...why}],
    ['post','/api/update-rings/'+canonicalPolicyId+'/assign',{deviceId:'known-device',...why}],
    ['post','/api/blueprints',{name:'Owned blueprint',platform:'windows',...why}],
    ['put','/api/blueprints/'+canonicalPolicyId,{name:'Changed blueprint',...why}],
    ['delete','/api/blueprints/'+canonicalPolicyId,why],
    ['post','/api/blueprints/'+canonicalPolicyId+'/configurations',{config_type:'wifi',config_name:'Owned wifi',payload:{},...why}],
    ['post','/api/blueprints/'+canonicalPolicyId+'/assign',{target_type:'device',target_id:'known-device',...why}],
  ].map(([method,path,body]) => [method,path,body]))('%s %s reports real storage unavailability', async (method,path,body) => {
    const response = await request(app)[method](path).set('If-Match',path.startsWith('/api/blueprints')?blueprintTag:capturedTag).send(body);
    expect(response.status).toBe(503); expect(response.body.error).toBe('policy_configuration_unavailable');
  });
  test.each([
    ['post','/api/policies/'+canonicalPolicyId+'/activate'],
    ['post','/api/policies/'+canonicalPolicyId+'/assign'],
    ['put','/api/policies/'+canonicalPolicyId], ['delete','/api/policies/'+canonicalPolicyId],
    ['post','/api/blueprints/'+canonicalPolicyId+'/configurations'], ['delete','/api/blueprints/'+canonicalPolicyId],
  ])('missing preconditions stop %s %s without inventing a record', async (method,path) => {
    expect((await request(app)[method](path).send(why)).status).toBe(428);
  });
  test.each(['/api/policies/templates','/api/policies/baselines'])('static recipe metadata is reachable but is not an active deployment: %s', async path => {
    const response=await request(app).get(path); expect(response.status).toBe(200);
    const rows=response.body.templates||response.body.baselines; expect(rows.length).toBeGreaterThan(0); expect(rows.every(row=>/^[a-f0-9]{64}$/.test(row.definitionHash))).toBe(true);
  });
  test.each([{name:'Owned policy',type:'security'}, {name:'Owned policy',type:'unknown',...why}, {name:'Owned policy',type:'security',created_by:'forged',...why}])('requires exact acknowledged and attributable creation fields', async body => {
    expect((await request(app).post('/api/policies').send(body)).status).toBe(400);
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
      .send({ assignee_type: 'user', assignee_id: userId('user-e2e-test'), assignee_name: 'Test User' });
    expect([201, 409]).toContain(res.status); // 409 if already assigned from prior test run
  });

  it('returns 404 for non-existent license', async () => {
    const res = await request(app)
      .post('/api/licenses/nonexistent-license-xyz/assign')
      .send({ assignee_type: 'user', assignee_id: userId('user-1') });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'License not found');
  });
});

// ─── POST /api/licenses/:id/request ──────────────────────────────────────────
describe('POST /api/licenses/:id/request', () => {
  it('uses the authenticated identity without a requester_id in the body', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-1/request')
      .send({ justification: 'I need this' });
    expect(res.status).toBe(201);
    expect(res.body.requester_id).toBe(userId('test-admin'));
  });

  it('returns the existing pending request for the authenticated requester on retry', async () => {
    const res = await request(app)
      .post('/api/licenses/lic-demo-1/request')
      .send({ requester_id: 'user-req-1', justification: 'Need for work' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'pending');
    expect(res.body).toHaveProperty('requester_id', userId('test-admin'));
  });

  it('returns 404 for non-existent license', async () => {
    const res = await request(app)
      .post('/api/licenses/nonexistent-lic-xyz/request')
      .send({ requester_id: 'user-1' });
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'License not found');
  });
});
