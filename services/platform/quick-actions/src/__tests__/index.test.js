'use strict';

// Set JWT_SECRET before loading the app so authMiddleware can verify tokens
process.env.JWT_SECRET = 'test-jwt-secret-for-quick-actions';

// Mock all orchestrators before requiring the app
jest.mock('../orchestrators/servicePrincipalOrchestrator');
jest.mock('../orchestrators/deviceEnrollmentOrchestrator');
jest.mock('../orchestrators/userOnboardingOrchestrator');
jest.mock('../orchestrators/policyOrchestrator');
jest.mock('../utils/serviceClient.js');

const jwt     = require('jsonwebtoken');
const request = require('supertest');
const app     = require('../index');

const servicePrincipalOrchestrator = require('../orchestrators/servicePrincipalOrchestrator');
const deviceEnrollmentOrchestrator = require('../orchestrators/deviceEnrollmentOrchestrator');
const userOnboardingOrchestrator   = require('../orchestrators/userOnboardingOrchestrator');
const policyOrchestrator           = require('../orchestrators/policyOrchestrator');
const { ping, SERVICES }           = require('../utils/serviceClient.js');

// Generate a valid Bearer token for protected routes
function authHeader() {
  const token = jwt.sign(
    { sub: 'test-user', role: 'admin' },
    process.env.JWT_SECRET,
    { expiresIn: '1h' },
  );
  return `Bearer ${token}`;
}

beforeEach(() => {
  jest.clearAllMocks();

  // Default: healthy ping
  ping.mockResolvedValue({ healthy: true, latencyMs: 5 });

  // Default orchestrator responses
  servicePrincipalOrchestrator.createServicePrincipal.mockResolvedValue({
    success: true,
    clientId: 'aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee',
    clientSecret: 'a'.repeat(64),
    spn: 'app/testApp',
    serviceAccountDn: 'CN=testApp$,CN=Computers,DC=opendirectory,DC=local',
    permissions: [],
    completedSteps: [],
  });

  servicePrincipalOrchestrator.listServicePrincipals.mockResolvedValue({
    success: true,
    data: [{ clientId: 'c1' }, { clientId: 'c2' }],
  });

  servicePrincipalOrchestrator.getServicePrincipalDetails.mockResolvedValue({
    success: true,
    clientId: 'test-id',
    account: { name: 'testApp' },
    permissions: [],
    warnings: [],
  });

  servicePrincipalOrchestrator.deleteServicePrincipal.mockResolvedValue({
    success: true,
    clientId: 'test-id',
    deletedAt: new Date().toISOString(),
    completedSteps: [],
  });

  servicePrincipalOrchestrator.rotateServicePrincipalSecret.mockResolvedValue({
    success: true,
    clientId: 'test-id',
    newClientSecret: 'b'.repeat(64),
    rotatedAt: new Date().toISOString(),
    completedSteps: [],
  });

  deviceEnrollmentOrchestrator.enrollDevice.mockResolvedValue({
    success: true,
    deviceId: 'dev-123',
    computerDn: 'CN=TestDevice,CN=Computers,DC=opendirectory,DC=local',
    platform: 'macos',
    enrollmentUrl: null,
    platformConfig: {},
    nextSteps: [],
    completedSteps: [],
  });

  deviceEnrollmentOrchestrator.bulkEnroll.mockResolvedValue({
    total: 2,
    succeeded: 2,
    failed: 0,
    results: [],
  });

  deviceEnrollmentOrchestrator.getEnrollmentStatus.mockResolvedValue({
    success: true,
    deviceId: 'dev-123',
    device: {},
    mdmStatus: {},
    warnings: [],
  });

  deviceEnrollmentOrchestrator.unenrollDevice.mockResolvedValue({
    success: true,
    deviceId: 'dev-123',
    wiped: false,
    unenrolledAt: new Date().toISOString(),
    completedSteps: [],
  });

  userOnboardingOrchestrator.onboardUser.mockResolvedValue({
    success: true,
    userId: 'u-abc',
    userDn: 'CN=Alice Smith,OU=Engineering,OU=Users,DC=opendirectory,DC=local',
    email: 'alice@example.com',
    temporaryPassword: 'Temp@1234',
    assignedDevice: null,
    groupMemberships: ['Engineering'],
    policiesApplied: [],
    completedSteps: [],
  });

  userOnboardingOrchestrator.offboardUser.mockResolvedValue({
    disabled: true,
    userId: 'u-abc',
    devicesRevoked: [],
    groupsRemoved: [],
    offboardedAt: new Date().toISOString(),
    completedSteps: [],
  });

  policyOrchestrator.deployPolicy.mockResolvedValue({
    success: true,
    deployed: true,
    deploymentId: 'dep-123',
    policyId: 'pol-1',
    affectedTargets: 1,
    appliedSettings: [],
    completedSteps: [],
  });

  policyOrchestrator.getPolicyDeploymentStatus.mockResolvedValue({
    success: true,
    deploymentId: 'dep-123',
    policyId: 'pol-1',
    status: 'deployed',
  });

  policyOrchestrator.rollbackPolicy.mockResolvedValue({
    success: true,
    deploymentId: 'dep-123',
    policyId: 'pol-1',
    rolledBack: true,
    rolledBackAt: new Date().toISOString(),
    completedSteps: [],
  });

  policyOrchestrator.getComplianceSnapshot.mockResolvedValue({
    success: true,
    snapshot: {
      total: 100,
      compliant: 90,
      nonCompliant: 10,
      complianceRate: 90,
      topViolations: [],
      generatedAt: new Date().toISOString(),
    },
    warnings: [],
  });
});

// ── Health ─────────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  test('returns 200 with status: healthy', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
  });

  test('response includes service and timestamp', async () => {
    const res = await request(app).get('/health');
    expect(res.body.service).toBe('quick-actions');
    expect(res.body.timestamp).toBeDefined();
  });
});

// ── Status ─────────────────────────────────────────────────────────────────────

describe('GET /api/quick/status', () => {
  test('returns 200 with services object', async () => {
    ping.mockResolvedValue({ healthy: true, latencyMs: 2 });

    const res = await request(app).get('/api/quick/status');
    expect(res.status).toBe(200);
    expect(res.body.services).toBeDefined();
    expect(typeof res.body.services).toBe('object');
  });

  test('includes overall health status', async () => {
    ping.mockResolvedValue({ healthy: true, latencyMs: 2 });

    const res = await request(app).get('/api/quick/status');
    expect(['healthy', 'degraded', 'unhealthy']).toContain(res.body.overall);
  });

  test('all services healthy → overall: healthy', async () => {
    ping.mockResolvedValue({ healthy: true, latencyMs: 2 });

    const res = await request(app).get('/api/quick/status');
    expect(res.body.overall).toBe('healthy');
  });

  test('one service unhealthy → overall: degraded', async () => {
    let callCount = 0;
    ping.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return Promise.resolve({ healthy: false, latencyMs: 0, error: 'down' });
      return Promise.resolve({ healthy: true, latencyMs: 2 });
    });

    const res = await request(app).get('/api/quick/status');
    expect(['degraded', 'unhealthy']).toContain(res.body.overall);
  });
});

// ── Service Principals ─────────────────────────────────────────────────────────

describe('POST /api/quick/service-principals', () => {
  test('success → 201 with clientId and clientSecret', async () => {
    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({ appName: 'testApp', description: 'Test', permissions: [] });

    expect(res.status).toBe(201);
    expect(res.body.clientId).toBeTruthy();
    expect(res.body.clientSecret).toBeTruthy();
  });

  test('partial failure → 207', async () => {
    servicePrincipalOrchestrator.createServicePrincipal.mockResolvedValue({
      success: false,
      clientId: 'c1',
      clientSecret: null,
      failedAt: 'create-ad-account',
      completedSteps: [],
    });

    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({ appName: 'testApp' });

    expect(res.status).toBe(207);
  });

  test('orchestrator throws → 500', async () => {
    servicePrincipalOrchestrator.createServicePrincipal.mockRejectedValue(
      new Error('appName is required')
    );

    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({});

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });
});

describe('GET /api/quick/service-principals', () => {
  test('returns 200 with data array', async () => {
    const res = await request(app)
      .get('/api/quick/service-principals')
      .set('Authorization', authHeader());
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });
});

describe('GET /api/quick/service-principals/:id', () => {
  test('returns 200 with account details', async () => {
    const res = await request(app)
      .get('/api/quick/service-principals/test-id')
      .set('Authorization', authHeader());
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.clientId).toBe('test-id');
  });
});

describe('DELETE /api/quick/service-principals/:id', () => {
  test('returns 200 on success', async () => {
    const res = await request(app)
      .delete('/api/quick/service-principals/test-id')
      .set('Authorization', authHeader());
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

describe('POST /api/quick/service-principals/:id/rotate-secret', () => {
  test('returns 200 with newClientSecret', async () => {
    const res = await request(app)
      .post('/api/quick/service-principals/test-id/rotate-secret')
      .set('Authorization', authHeader())
      .send();

    expect(res.status).toBe(200);
    expect(res.body.newClientSecret).toBeTruthy();
  });
});

// ── Device Enrollment ──────────────────────────────────────────────────────────

describe('POST /api/quick/devices/enroll', () => {
  test('success → 201 with deviceId', async () => {
    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .set('Authorization', authHeader())
      .send({ platform: 'macos', deviceName: 'MacBook-01' });

    expect(res.status).toBe(201);
    expect(res.body.deviceId).toBeTruthy();
  });

  test('partial failure → 207', async () => {
    deviceEnrollmentOrchestrator.enrollDevice.mockResolvedValue({
      success: false,
      deviceId: 'dev-456',
      failedAt: 'create-device-record',
      completedSteps: [],
    });

    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .set('Authorization', authHeader())
      .send({ platform: 'macos', deviceName: 'Mac' });

    expect(res.status).toBe(207);
  });

  test('orchestrator throws → 500', async () => {
    deviceEnrollmentOrchestrator.enrollDevice.mockRejectedValue(new Error('platform is required'));

    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .set('Authorization', authHeader())
      .send({});

    expect(res.status).toBe(500);
  });
});

describe('POST /api/quick/devices/bulk-enroll', () => {
  test('returns 200 with array results', async () => {
    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .set('Authorization', authHeader())
      .send({ devices: [{ platform: 'macos', deviceName: 'Mac-01' }] });

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(2);
  });

  test('empty devices array → 400', async () => {
    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .set('Authorization', authHeader())
      .send({ devices: [] });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('missing devices → 400', async () => {
    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .set('Authorization', authHeader())
      .send({});

    expect(res.status).toBe(400);
  });
});

describe('GET /api/quick/devices/:id/enrollment-status', () => {
  test('returns 200 with enrollment status', async () => {
    const res = await request(app)
      .get('/api/quick/devices/dev-123/enrollment-status')
      .set('Authorization', authHeader());
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deviceId).toBe('dev-123');
  });
});

describe('POST /api/quick/devices/:id/unenroll', () => {
  test('returns 200 on success', async () => {
    const res = await request(app)
      .post('/api/quick/devices/dev-123/unenroll')
      .set('Authorization', authHeader())
      .send({ wipe: false });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('wipe: true → passed to orchestrator', async () => {
    await request(app)
      .post('/api/quick/devices/dev-123/unenroll')
      .set('Authorization', authHeader())
      .send({ wipe: true });

    expect(deviceEnrollmentOrchestrator.unenrollDevice).toHaveBeenCalledWith(
      'dev-123',
      { wipe: true }
    );
  });
});

// ── User Lifecycle ─────────────────────────────────────────────────────────────

describe('POST /api/quick/users/onboard', () => {
  test('success → 201 with userId and temporaryPassword', async () => {
    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({
        firstName: 'Alice',
        lastName: 'Smith',
        email: 'alice@example.com',
        department: 'Engineering',
      });

    expect(res.status).toBe(201);
    expect(res.body.userId).toBeTruthy();
    expect(res.body.temporaryPassword).toBeTruthy();
  });

  test('partial failure → 207', async () => {
    userOnboardingOrchestrator.onboardUser.mockResolvedValue({
      success: false,
      userId: 'u-1',
      failedAt: 'create-ad-user',
      completedSteps: [],
    });

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ firstName: 'Bob', lastName: 'Jones', email: 'bob@example.com' });

    expect(res.status).toBe(207);
  });

  test('orchestrator throws → 500', async () => {
    userOnboardingOrchestrator.onboardUser.mockRejectedValue(new Error('firstName and lastName are required'));

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ email: 'no-name@example.com' });

    expect(res.status).toBe(500);
  });
});

describe('POST /api/quick/users/:id/offboard', () => {
  test('returns 200 with disabled: true', async () => {
    const res = await request(app)
      .post('/api/quick/users/u-abc/offboard')
      .set('Authorization', authHeader())
      .send({ revokeDevices: true });

    expect(res.status).toBe(200);
    expect(res.body.disabled).toBe(true);
  });

  test('orchestrator called with correct userId and options', async () => {
    await request(app)
      .post('/api/quick/users/user-42/offboard')
      .set('Authorization', authHeader())
      .send({ revokeDevices: false, transferFilesTo: 'manager@example.com' });

    expect(userOnboardingOrchestrator.offboardUser).toHaveBeenCalledWith(
      'user-42',
      expect.objectContaining({ revokeDevices: false, transferFilesTo: 'manager@example.com' })
    );
  });
});

// ── Policy ─────────────────────────────────────────────────────────────────────

describe('POST /api/quick/policies/deploy', () => {
  test('success → 200 with deploymentId', async () => {
    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId: 'pol-1', targetType: 'ou', targetId: 'OU=IT' });

    expect(res.status).toBe(200);
    expect(res.body.deploymentId).toBeTruthy();
  });

  test('partial failure → 207', async () => {
    policyOrchestrator.deployPolicy.mockResolvedValue({
      success: false,
      deploymentId: 'dep-fail',
      failedAt: 'fetch-policy',
      completedSteps: [],
    });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId: 'bad-pol', targetType: 'ou' });

    expect(res.status).toBe(207);
  });

  test('dry run response includes dryRunReport', async () => {
    policyOrchestrator.deployPolicy.mockResolvedValue({
      success: true,
      deployed: false,
      deploymentId: 'dep-dry',
      policyId: 'pol-1',
      dryRun: true,
      dryRunReport: { targetType: 'ou', wouldApply: [] },
      completedSteps: [],
    });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId: 'pol-1', targetType: 'ou', dryRun: true });

    expect(res.status).toBe(200);
    expect(res.body.dryRunReport).toBeDefined();
  });
});

describe('GET /api/quick/policies/deployments/:id', () => {
  test('existing deployment → 200', async () => {
    const res = await request(app)
      .get('/api/quick/policies/deployments/dep-123')
      .set('Authorization', authHeader());
    expect(res.status).toBe(200);
    expect(res.body.deploymentId).toBe('dep-123');
  });

  test('unknown deployment → 404', async () => {
    policyOrchestrator.getPolicyDeploymentStatus.mockResolvedValue({
      success: false,
      deploymentId: 'unknown',
      error: 'not found',
    });

    const res = await request(app)
      .get('/api/quick/policies/deployments/unknown')
      .set('Authorization', authHeader());
    expect(res.status).toBe(404);
  });
});

describe('POST /api/quick/policies/deployments/:id/rollback', () => {
  test('returns 200 with rolledBack: true', async () => {
    const res = await request(app)
      .post('/api/quick/policies/deployments/dep-123/rollback')
      .set('Authorization', authHeader())
      .send();

    expect(res.status).toBe(200);
    expect(res.body.rolledBack).toBe(true);
  });
});

describe('GET /api/quick/compliance/snapshot', () => {
  test('returns 200 with snapshot', async () => {
    const res = await request(app)
      .get('/api/quick/compliance/snapshot')
      .set('Authorization', authHeader());
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.snapshot).toBeDefined();
    expect(res.body.snapshot.total).toBe(100);
    expect(res.body.snapshot.complianceRate).toBe(90);
  });
});

// ── 404 fallback ───────────────────────────────────────────────────────────────

describe('404 fallback', () => {
  test('unknown route → 404', async () => {
    const res = await request(app)
      .get('/api/quick/nonexistent')
      .set('Authorization', authHeader());
    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
  });
});

// ── Auth middleware ────────────────────────────────────────────────────────────

describe('Auth middleware', () => {
  test('missing token → 401', async () => {
    const res = await request(app).get('/api/quick/service-principals');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('invalid token → 403', async () => {
    const res = await request(app)
      .get('/api/quick/service-principals')
      .set('Authorization', 'Bearer invalid.token.value');
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('service-account bypass with correct SERVICE_TOKEN → 200', async () => {
    process.env.SERVICE_TOKEN = 'test-svc-token';
    const res = await request(app)
      .get('/api/quick/service-principals')
      .set('Authorization', 'Bearer svc-test-svc-token');
    delete process.env.SERVICE_TOKEN;
    expect(res.status).toBe(200);
  });

  test('/health is public (no token needed)', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  test('/api/quick/status is public (no token needed)', async () => {
    const res = await request(app).get('/api/quick/status');
    expect(res.status).toBe(200);
  });
});
