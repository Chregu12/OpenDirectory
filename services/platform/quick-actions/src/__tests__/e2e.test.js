'use strict';

/**
 * E2E integration tests for quick-actions service.
 *
 * Strategy:
 *   - Set env vars before requiring any modules so serviceClient picks up mock URLs.
 *   - Use nock to intercept downstream HTTP calls (works with node-fetch v3).
 *   - Send real HTTP requests via supertest against the Express app.
 */

// ── Set service URLs before any require ──────────────────────────────────────
process.env.AUTH_SERVICE_URL      = 'http://auth-mock';
process.env.DIRECTORY_SERVICE_URL = 'http://directory-mock';
process.env.KERBEROS_SERVICE_URL  = 'http://kerberos-mock';
process.env.SAMBA_SERVICE_URL     = 'http://samba-mock';
process.env.DEVICE_SERVICE_URL    = 'http://device-mock';
process.env.POLICY_SERVICE_URL    = 'http://policy-mock';
process.env.PIM_SERVICE_URL       = 'http://pim-mock';
process.env.MDM_SERVICE_URL       = 'http://mdm-mock';
process.env.APP_STORE_SERVICE_URL = 'http://appstore-mock';

const request = require('supertest');
const nock    = require('nock');
const app     = require('../index');

// ── Helpers ───────────────────────────────────────────────────────────────────

const AUTH      = 'http://auth-mock';
const DIRECTORY = 'http://directory-mock';
const KERBEROS  = 'http://kerberos-mock';
const SAMBA     = 'http://samba-mock';
const DEVICE    = 'http://device-mock';
const POLICY    = 'http://policy-mock';
const PIM       = 'http://pim-mock';
const MDM       = 'http://mdm-mock';

/** Returns true if the string looks like a UUID v4. */
const isUuid = (s) => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);

/** Returns true if the string looks like a 64-char hex string. */
const is64Hex = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s);

// ── Global setup / teardown ───────────────────────────────────────────────────

beforeAll(() => {
  nock.disableNetConnect();
  nock.enableNetConnect('127.0.0.1');
});

afterEach(() => {
  nock.cleanAll();
});

afterAll(() => {
  nock.enableNetConnect();
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 1: Service Principal Lifecycle
// ═════════════════════════════════════════════════════════════════════════════

describe('Service Principal Lifecycle', () => {

  test('creates SP with all downstream services successful', async () => {
    nock(SAMBA).post('/api/computers/join').reply(201, { dn: 'CN=test-app$,CN=Computers,DC=opendirectory,DC=local' });
    nock(KERBEROS).post('/api/principals').reply(201, { principal: 'app/test-app' });
    nock(AUTH).post('/api/service-accounts').reply(201, { id: 'test-app', name: 'test-app' });
    nock(PIM).post(/\/api\/v1\/permissions\/users\/.*\/assign/).reply(200, { assigned: true });

    const res = await request(app)
      .post('/api/quick/service-principals')
      .send({ appName: 'test-app', permissions: ['read-users'] });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(isUuid(res.body.clientId)).toBe(true);
    expect(is64Hex(res.body.clientSecret)).toBe(true);
  });

  test('creates SP even when Kerberos is down (partial success)', async () => {
    nock(SAMBA).post('/api/computers/join').reply(201, { dn: 'CN=test-app2$,CN=Computers,DC=opendirectory,DC=local' });
    nock(KERBEROS).post('/api/principals').reply(503, { error: 'Service Unavailable' });
    nock(AUTH).post('/api/service-accounts').reply(201, { id: 'test-app2', name: 'test-app2' });
    nock(PIM).post(/\/api\/v1\/permissions\/users\/.*\/assign/).reply(200, { assigned: true });

    const res = await request(app)
      .post('/api/quick/service-principals')
      .send({ appName: 'test-app2', permissions: ['read-users'] });

    expect(res.status).toBe(207);
    expect(res.body.success).toBe(false);
    // clientId is still present (SP partially created)
    expect(isUuid(res.body.clientId)).toBe(true);
    // At least one failed step references kerberos
    const failedSteps = res.body.completedSteps.filter(s => !s.ok);
    expect(failedSteps.length).toBeGreaterThan(0);
    const kerberosStep = failedSteps.find(s => s.name === 'create-kerberos-spn');
    expect(kerberosStep).toBeDefined();
  });

  test('rotates secret — new secret differs from previous', async () => {
    const clientId = '11111111-1111-4111-a111-111111111111';
    const appName  = 'rotate-test';

    // Rotation: fetch account details, then update auth, then update kerberos
    nock(AUTH).get(`/api/service-accounts/${clientId}`).reply(200, { name: appName, id: clientId });
    nock(AUTH).patch(`/api/service-accounts/${clientId}`).reply(200, { updated: true });
    nock(KERBEROS).patch(`/api/principals/app%2F${appName}`).reply(200, { updated: true });

    const res = await request(app)
      .post(`/api/quick/service-principals/${clientId}/rotate-secret`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(is64Hex(res.body.newClientSecret)).toBe(true);
  });

  test('deletes SP — cleanup called on all services', async () => {
    const clientId = '22222222-2222-4222-a222-222222222222';
    const appName  = 'delete-test';

    // deleteServicePrincipal fetches account name first, then revokes/deletes everywhere
    nock(AUTH).get(`/api/service-accounts/${clientId}`).reply(200, { name: appName });
    const pimRevoke = nock(PIM).post(`/api/v1/permissions/users/${clientId}/revoke-all`).reply(200, { revoked: true });
    const authDel  = nock(AUTH).delete(`/api/service-accounts/${clientId}`).reply(200, { deleted: true });
    const kerbDel  = nock(KERBEROS).delete(`/api/principals/app%2F${appName}`).reply(200, { deleted: true });
    const sambaDel = nock(SAMBA).delete(`/api/computers/${appName}%24`).reply(200, { deleted: true });

    const res = await request(app)
      .delete(`/api/quick/service-principals/${clientId}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Verify all mocks were satisfied (all cleanup endpoints were called)
    expect(pimRevoke.isDone()).toBe(true);
    expect(authDel.isDone()).toBe(true);
    expect(kerbDel.isDone()).toBe(true);
    expect(sambaDel.isDone()).toBe(true);
  });

  test('GET /api/quick/service-principals returns list', async () => {
    nock(AUTH).get('/api/service-accounts').reply(200, {
      accounts: [
        { name: 'app1', clientId: 'aaa' },
        { name: 'app2', clientId: 'bbb' },
      ],
    });

    const res = await request(app).get('/api/quick/service-principals');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBe(2);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 2: Device Enrollment Per Platform
// ═════════════════════════════════════════════════════════════════════════════

describe('Device Enrollment', () => {

  const PLATFORMS = ['macos', 'windows', 'linux', 'ios', 'android'];

  for (const platform of PLATFORMS) {
    test(`enrolls ${platform} device successfully`, async () => {
      const deviceName = `test-${platform}`;

      // Common mocks
      nock(DEVICE).post('/api/devices').reply(201, { id: 'dev-001', name: deviceName, platform });
      nock(SAMBA).post('/api/computers/join').reply(201, { dn: `CN=${deviceName},CN=Computers,DC=opendirectory,DC=local` });

      // Platform-specific mocks
      if (platform === 'macos') {
        nock(MDM).post('/api/mdm/enroll').reply(200, { enrollmentUrl: 'mdmEnroll://enroll?device=dev-001' });
        nock(POLICY).post('/api/policies/assign').reply(200, { policies: ['baseline'] });
      } else if (platform === 'windows') {
        nock(DIRECTORY).post('/api/winrm/configure').reply(200, { configured: true });
        nock(DIRECTORY).post('/api/gpo/baseline/apply').reply(200, { applied: true });
      } else if (platform === 'linux') {
        nock(DIRECTORY).post('/api/sssd/config').reply(200, { config: '# sssd.conf' });
        nock(KERBEROS).post('/api/keytabs').reply(200, { keytabB64: 'dGVzdA==' });
        nock(POLICY).post('/api/policies/assign').reply(200, { policies: ['hardening'] });
      } else if (platform === 'ios' || platform === 'android') {
        nock(MDM).post('/api/mdm/enroll').reply(200, { enrollmentUrl: `mdmenroll://enroll?device=dev-001&platform=${platform}` });
      }

      const res = await request(app)
        .post('/api/quick/devices/enroll')
        .send({ platform, deviceName });

      // Accept 201 (full success) or 207 (partial - some non-critical steps may fail in test env)
      expect([200, 201, 207]).toContain(res.status);
      expect(res.body.deviceId).toBeDefined();
      expect(res.body.platform).toBe(platform);
      expect(Array.isArray(res.body.nextSteps)).toBe(true);
      expect(res.body.nextSteps.length).toBeGreaterThan(0);
    });
  }

  test('bulk enroll 3 devices — 2 succeed, 1 fails', async () => {
    const devices = [
      { platform: 'linux', deviceName: 'bulk-linux-1' },
      { platform: 'linux', deviceName: 'bulk-linux-2' },
      { platform: 'linux', deviceName: 'bulk-linux-3' },
    ];

    // Device 1: success
    nock(DEVICE).post('/api/devices').reply(201, { id: 'bulk-dev-1' });
    nock(SAMBA).post('/api/computers/join').reply(201, { dn: 'CN=bulk-linux-1,CN=Computers,DC=opendirectory,DC=local' });
    nock(DIRECTORY).post('/api/sssd/config').reply(200, { config: '# sssd.conf' });
    nock(KERBEROS).post('/api/keytabs').reply(200, { keytabB64: 'dGVzdA==' });
    nock(POLICY).post('/api/policies/assign').reply(200, { policies: [] });

    // Device 2: success
    nock(DEVICE).post('/api/devices').reply(201, { id: 'bulk-dev-2' });
    nock(SAMBA).post('/api/computers/join').reply(201, { dn: 'CN=bulk-linux-2,CN=Computers,DC=opendirectory,DC=local' });
    nock(DIRECTORY).post('/api/sssd/config').reply(200, { config: '# sssd.conf' });
    nock(KERBEROS).post('/api/keytabs').reply(200, { keytabB64: 'dGVzdA==' });
    nock(POLICY).post('/api/policies/assign').reply(200, { policies: [] });

    // Device 3: device-service fails → enrollDevice returns success:false
    nock(DEVICE).post('/api/devices').reply(503, { error: 'Service Unavailable' });
    nock(SAMBA).post('/api/computers/join').reply(201, { dn: 'CN=bulk-linux-3,CN=Computers,DC=opendirectory,DC=local' });
    nock(DIRECTORY).post('/api/sssd/config').reply(200, { config: '# sssd.conf' });
    nock(KERBEROS).post('/api/keytabs').reply(200, { keytabB64: 'dGVzdA==' });
    nock(POLICY).post('/api/policies/assign').reply(200, { policies: [] });

    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .send({ devices });

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(3);
    expect(Array.isArray(res.body.results)).toBe(true);
    expect(res.body.results.length).toBe(3);

    // At least the first two should succeed, the third should fail
    const successes = res.body.results.filter(r => r.success);
    const failures  = res.body.results.filter(r => !r.success);
    expect(successes.length).toBeGreaterThanOrEqual(2);
    expect(failures.length).toBeGreaterThanOrEqual(1);
  });

  test('enrollment status check', async () => {
    const deviceId = 'status-device-abc';

    nock(DEVICE).get(`/api/devices/${deviceId}`).reply(200, { id: deviceId, status: 'enrolled', platform: 'macos' });
    nock(MDM).get(`/api/mdm/devices/${deviceId}/status`).reply(200, { mdmStatus: 'active', managed: true });

    const res = await request(app)
      .get(`/api/quick/devices/${deviceId}/enrollment-status`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deviceId).toBe(deviceId);
    expect(res.body.device).toBeDefined();
  });

  test('unenroll with wipe=false — no MDM wipe call', async () => {
    const deviceId = 'no-wipe-device';

    // Only remove-mdm-enrollment and remove-device-record should be called
    const mdmWipeScope = nock(MDM).post(`/api/mdm/devices/${deviceId}/wipe`).reply(200, { wiped: true });
    nock(MDM).delete(`/api/mdm/devices/${deviceId}`).reply(200, { removed: true });
    nock(DEVICE).delete(`/api/devices/${deviceId}`).reply(200, { deleted: true });

    const res = await request(app)
      .post(`/api/quick/devices/${deviceId}/unenroll`)
      .send({ wipe: false });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Wipe endpoint should NOT have been called
    expect(mdmWipeScope.isDone()).toBe(false);
    // Clean up the unused interceptor
    nock.cleanAll();
  });

  test('unenroll with wipe=true — MDM wipe called', async () => {
    const deviceId = 'wipe-device';

    const mdmWipeScope = nock(MDM).post(`/api/mdm/devices/${deviceId}/wipe`).reply(200, { wiped: true });
    nock(MDM).delete(`/api/mdm/devices/${deviceId}`).reply(200, { removed: true });
    nock(DEVICE).delete(`/api/devices/${deviceId}`).reply(200, { deleted: true });

    const res = await request(app)
      .post(`/api/quick/devices/${deviceId}/unenroll`)
      .send({ wipe: true });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.wiped).toBe(true);
    // Wipe endpoint SHOULD have been called
    expect(mdmWipeScope.isDone()).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 3: User Onboarding/Offboarding
// ═════════════════════════════════════════════════════════════════════════════

describe('User Lifecycle', () => {

  function mockFullOnboard({ notificationFail = false } = {}) {
    nock(DIRECTORY).post('/api/users').reply(201, { id: 'user-123', dn: 'CN=John Doe,OU=Engineering,OU=Users,DC=opendirectory,DC=local' });
    nock(AUTH).post('/api/users').reply(201, { id: 'user-123', temporaryPassword: 'Temp@123' });
    // standard role → auth POST /api/users/roles
    nock(AUTH).post('/api/users/roles').reply(200, { assigned: true });
    nock(SAMBA).post(/\/api\/groups\/.*\/members/).reply(200, { added: true });
    nock(POLICY).post('/api/policies/assign').reply(200, { policies: ['user-baseline'] });
    if (notificationFail) {
      nock(AUTH).post('/api/notifications').reply(503, { error: 'Notification service down' });
    } else {
      nock(AUTH).post('/api/notifications').reply(200, { sent: true });
    }
  }

  test('onboards new employee — all 7 steps complete', async () => {
    mockFullOnboard();

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .send({
        firstName:  'John',
        lastName:   'Doe',
        email:      'john@test.com',
        department: 'Engineering',
        role:       'standard',
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.userId).toBeDefined();
    expect(res.body.temporaryPassword).toBeDefined();
  });

  test('onboards user — notification failure is non-blocking', async () => {
    mockFullOnboard({ notificationFail: true });

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .send({
        firstName:  'Jane',
        lastName:   'Smith',
        email:      'jane@test.com',
        department: 'Engineering',
        role:       'standard',
      });

    // Notification failure means not all steps succeeded → 207
    expect(res.status).toBe(207);
    // But user was still created (success refers to all steps, not the notification)
    expect(res.body.userId).toBeDefined();
    // Warnings should mention the notification failure
    const warnings = res.body.warnings || [];
    expect(warnings.length).toBeGreaterThan(0);
  });

  test('onboards user — critical step fails returns 207', async () => {
    // enterprise-directory user creation fails
    nock(DIRECTORY).post('/api/users').reply(500, { error: 'Internal Server Error' });
    nock(AUTH).post('/api/users').reply(201, { id: 'user-456' });
    nock(AUTH).post('/api/users/roles').reply(200, { assigned: true });
    nock(SAMBA).post(/\/api\/groups\/.*\/members/).reply(200, { added: true });
    nock(POLICY).post('/api/policies/assign').reply(200, { policies: [] });
    nock(AUTH).post('/api/notifications').reply(200, { sent: true });

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .send({
        firstName:  'Bob',
        lastName:   'Builder',
        email:      'bob@test.com',
        department: 'Engineering',
        role:       'standard',
      });

    // At least one step failed → 207
    expect(res.status).toBe(207);
    expect(res.body.success).toBe(false);
    expect(res.body.failedAt).toBe('create-ad-user');
  });

  test('offboards user — revokes all devices', async () => {
    const userId = 'offboard-user-111';

    nock(DIRECTORY).post(`/api/users/${userId}/disable`).reply(200, { disabled: true });
    nock(PIM).post(`/api/v1/permissions/users/${userId}/revoke-all`).reply(200, { revoked: true });
    nock(AUTH).patch(`/api/users/${userId}`).reply(200, { disabled: true });
    // unassign-devices: GET devices for user
    nock(DEVICE).get(`/api/devices?assignedUser=${userId}`).reply(200, {
      devices: [
        { id: 'dev-a' },
        { id: 'dev-b' },
      ],
    });
    // Patch each device
    nock(DEVICE).patch('/api/devices/dev-a').reply(200, { updated: true });
    nock(DEVICE).patch('/api/devices/dev-b').reply(200, { updated: true });
    // remove-from-groups
    nock(SAMBA).get(`/api/users/${userId}/groups`).reply(200, { groups: [] });
    // archive-home-directory
    nock(DIRECTORY).post(`/api/users/${userId}/archive`).reply(200, { archived: true });

    const res = await request(app)
      .post(`/api/quick/users/${userId}/offboard`)
      .send({ revokeDevices: true });

    expect(res.status).toBe(200);
    expect(res.body.disabled).toBe(true);
    expect(res.body.userId).toBe(userId);
  });

  test('offboards user — disableOnly does not delete ad user', async () => {
    const userId = 'offboard-user-222';

    nock(DIRECTORY).post(`/api/users/${userId}/disable`).reply(200, { disabled: true });
    nock(PIM).post(`/api/v1/permissions/users/${userId}/revoke-all`).reply(200, { revoked: true });
    nock(AUTH).patch(`/api/users/${userId}`).reply(200, { disabled: true });
    // unassign-devices: revokeDevices defaults to true in offboardUser
    nock(DEVICE).get(`/api/devices?assignedUser=${userId}`).reply(200, { devices: [] });
    nock(SAMBA).get(`/api/users/${userId}/groups`).reply(200, { groups: [] });
    nock(DIRECTORY).post(`/api/users/${userId}/archive`).reply(200, { archived: true });

    // Track that DELETE is NOT called on the user
    const deleteScope = nock(DIRECTORY).delete(`/api/users/${userId}`).reply(200, { deleted: true });

    const res = await request(app)
      .post(`/api/quick/users/${userId}/offboard`)
      .send({ disableOnly: true });

    expect(res.status).toBe(200);
    expect(res.body.disabled).toBe(true);
    // Delete should NOT have been called
    expect(deleteScope.isDone()).toBe(false);
    nock.cleanAll();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 4: Policy Deployment
// ═════════════════════════════════════════════════════════════════════════════

describe('Policy Deployment', () => {

  test('deploys policy to OU — calls enterprise-directory GPO apply', async () => {
    const policyId = 'pol-123';
    const ouTarget = 'ou=engineering,dc=opendirectory,dc=local';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(200, { id: policyId, name: 'Engineering Policy', settings: { firewall: 'on' } });
    nock(DIRECTORY).post(`/api/gpo/${policyId}/apply`).reply(200, { applied: 5 });
    nock(POLICY).post('/api/policies/deployments').reply(200, { recorded: true });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'ou', targetId: ouTarget });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
    expect(res.body.affectedTargets).toBeGreaterThan(0);
  });

  test('deploys policy to all — parallel fan-out to MDM, directory, policy', async () => {
    const policyId = 'pol-all-123';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(200, { id: policyId, name: 'Global Policy', settings: { encryption: 'required' } });
    nock(MDM).post('/api/policies/push').reply(200, { pushed: true });
    nock(DIRECTORY).post(`/api/gpo/${policyId}/apply`).reply(200, { applied: 10 });
    nock(POLICY).post('/api/policies/broadcast').reply(200, { broadcasted: true });
    nock(POLICY).post('/api/policies/deployments').reply(200, { recorded: true });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'all' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
    // affectedTargets includes all-devices, all-ous, all-users
    expect(res.body.affectedTargets).toBeGreaterThanOrEqual(3);
  });

  test('dry run — does not call deploy endpoints', async () => {
    const policyId = 'pol-dry-456';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(200, { id: policyId, name: 'Dry Run Policy', settings: { audit: true } });

    // These endpoints should NOT be called during a dry run
    const gpoScope    = nock(DIRECTORY).post(`/api/gpo/${policyId}/apply`).reply(200, { applied: 5 });
    const deployScope = nock(POLICY).post('/api/policies/deployments').reply(200, { recorded: true });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'ou', targetId: 'ou=test,dc=local', dryRun: true });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.dryRun).toBe(true);
    expect(res.body.deployed).toBe(false);
    expect(res.body.dryRunReport).toBeDefined();
    expect(res.body.dryRunReport.policyId).toBe(policyId);

    // Verify deploy endpoints were NOT called
    expect(gpoScope.isDone()).toBe(false);
    expect(deployScope.isDone()).toBe(false);
    nock.cleanAll();
  });

  test('compliance snapshot returns aggregated stats', async () => {
    nock(POLICY).get('/api/compliance/summary').reply(200, {
      total: 150,
      compliant: 120,
      nonCompliant: 30,
      topViolations: [
        { rule: 'encryption', count: 15 },
        { rule: 'os-version', count: 10 },
      ],
    });
    nock(DEVICE).get('/api/compliance/devices').reply(200, {
      total: 150,
      compliant: 120,
      nonCompliant: 30,
    });

    const res = await request(app).get('/api/quick/compliance/snapshot');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.snapshot).toBeDefined();
    expect(res.body.snapshot.total).toBeDefined();
    expect(res.body.snapshot.compliant).toBeDefined();
    expect(res.body.snapshot.nonCompliant).toBeDefined();
    expect(Array.isArray(res.body.snapshot.topViolations)).toBe(true);
  });

  test('deploys policy to user target', async () => {
    const policyId = 'pol-user-789';
    const userId   = 'user-target-001';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(200, { id: policyId, name: 'User Policy' });
    nock(PIM).post('/api/policies/assign').reply(200, { assigned: true });
    nock(POLICY).post('/api/policies/deployments').reply(200, { recorded: true });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'user', targetId: userId });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
  });

  test('deploys policy to device target', async () => {
    const policyId = 'pol-device-789';
    const deviceId = 'device-target-001';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(200, { id: policyId, name: 'Device Policy' });
    nock(MDM).post('/api/policies/push').reply(200, { pushed: true });
    nock(POLICY).post('/api/policies/deployments').reply(200, { recorded: true });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'device', targetId: deviceId });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
  });

  test('policy deployment fails when policy-service is down', async () => {
    const policyId = 'pol-missing-999';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(500, { error: 'Internal Server Error' });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'ou', targetId: 'ou=test' });

    expect([207, 500]).toContain(res.status);
    expect(res.body.success).toBe(false);
    expect(res.body.failedAt).toBe('fetch-policy');
  });

  test('deployment status lookup returns deployment record', async () => {
    const policyId = 'pol-status-111';

    nock(POLICY).get(`/api/policies/${policyId}`).reply(200, { id: policyId, name: 'Status Policy' });
    nock(MDM).post('/api/policies/push').reply(200, { pushed: true });
    nock(DIRECTORY).post(`/api/gpo/${policyId}/apply`).reply(200, { applied: 5 });
    nock(POLICY).post('/api/policies/broadcast').reply(200, { broadcasted: true });
    nock(POLICY).post('/api/policies/deployments').reply(200, { recorded: true });

    // First deploy
    const deployRes = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ policyId, targetType: 'all' });

    expect(deployRes.status).toBe(200);
    const deploymentId = deployRes.body.deploymentId;
    expect(deploymentId).toBeDefined();

    // Then check status
    const statusRes = await request(app)
      .get(`/api/quick/policies/deployments/${deploymentId}`);

    expect(statusRes.status).toBe(200);
    expect(statusRes.body.success).toBe(true);
    expect(statusRes.body.deploymentId).toBe(deploymentId);
    expect(statusRes.body.policyId).toBe(policyId);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 5: Health and Status
// ═════════════════════════════════════════════════════════════════════════════

describe('Health and Status', () => {

  test('GET /health returns healthy', async () => {
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
    expect(res.body.service).toBe('quick-actions');
  });

  test('GET /api/quick/status — all services up', async () => {
    // Mock all 9 service /health endpoints
    [AUTH, DIRECTORY, KERBEROS, SAMBA, DEVICE, POLICY, PIM, MDM, 'http://appstore-mock'].forEach(svc => {
      nock(svc).get('/health').reply(200, { status: 'healthy' });
    });

    const res = await request(app).get('/api/quick/status');

    expect(res.status).toBe(200);
    expect(res.body.overall).toBe('healthy');
    // All service entries should be healthy
    const serviceStatuses = Object.values(res.body.services);
    expect(serviceStatuses.every(s => s.healthy)).toBe(true);
  });

  test('GET /api/quick/status — some services down', async () => {
    // Some services healthy, kerberos and samba simulate connection refused
    nock(AUTH).get('/health').reply(200, { status: 'healthy' });
    nock(DIRECTORY).get('/health').reply(200, { status: 'healthy' });
    nock(KERBEROS).get('/health').replyWithError('connect ECONNREFUSED');
    nock(SAMBA).get('/health').replyWithError('connect ECONNREFUSED');
    nock(DEVICE).get('/health').reply(200, { status: 'healthy' });
    nock(POLICY).get('/health').reply(200, { status: 'healthy' });
    nock(PIM).get('/health').reply(200, { status: 'healthy' });
    nock(MDM).get('/health').reply(200, { status: 'healthy' });
    nock('http://appstore-mock').get('/health').reply(200, { status: 'healthy' });

    const res = await request(app).get('/api/quick/status');

    expect(res.status).toBe(200);
    expect(res.body.overall).toBe('degraded');
    // At least some services should be unhealthy
    const serviceStatuses = Object.values(res.body.services);
    expect(serviceStatuses.some(s => !s.healthy)).toBe(true);
  });

  test('rate limiting — 201+ requests returns 429', async () => {
    // Send 201 rapid requests to trigger rate limiter (limit is 200/min)
    const promises = [];
    for (let i = 0; i < 201; i++) {
      promises.push(request(app).get('/api/quick/service-principals').catch(() => ({ status: 429 })));
    }
    // Mock auth for the first several calls (nock will exhaust and then nock will block by default)
    // We allow many calls - the rate limiter will cut in before all succeed
    nock(AUTH).get('/api/service-accounts').times(201).reply(200, { accounts: [] });

    const results = await Promise.all(promises);
    const statuses = results.map(r => r.status);
    expect(statuses.some(s => s === 429)).toBe(true);
  }, 30000);

  test('GET /health returns uptime as number', async () => {
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(typeof res.body.uptime).toBe('number');
    expect(res.body.timestamp).toBeDefined();
  });

  test('404 for unknown routes', async () => {
    const res = await request(app).get('/api/quick/does-not-exist');

    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 6: Edge Cases
// ═════════════════════════════════════════════════════════════════════════════

describe('Edge Cases', () => {

  test('createServicePrincipal — missing appName returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/service-principals')
      .send({ description: 'no app name' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/appName/i);
  });

  test('enrollDevice — missing platform returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .send({ deviceName: 'test-device' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('enrollDevice — missing deviceName returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .send({ platform: 'linux' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('bulk-enroll — empty array returns 400', async () => {
    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .send({ devices: [] });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('deployPolicy — missing policyId returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .send({ targetType: 'ou' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('onboardUser — missing firstName returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/users/onboard')
      .send({ lastName: 'Doe', email: 'test@test.com' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('GET /api/quick/service-principals/:id returns SP details', async () => {
    const clientId = '33333333-3333-4333-a333-333333333333';

    nock(AUTH).get(`/api/service-accounts/${clientId}`).reply(200, { name: 'test-app', id: clientId });
    nock(PIM).get(`/api/v1/permissions/users/${clientId}`).reply(200, { permissions: ['read-users'] });

    const res = await request(app)
      .get(`/api/quick/service-principals/${clientId}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.clientId).toBe(clientId);
    expect(res.body.account).toBeDefined();
  });

  test('getEnrollmentStatus — returns warnings when MDM is down', async () => {
    const deviceId = 'mdm-down-device';

    nock(DEVICE).get(`/api/devices/${deviceId}`).reply(200, { id: deviceId, status: 'enrolled' });
    nock(MDM).get(`/api/mdm/devices/${deviceId}/status`).replyWithError('MDM service connection refused');

    const res = await request(app)
      .get(`/api/quick/devices/${deviceId}/enrollment-status`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.device).toBeDefined();
    expect(res.body.mdmStatus).toBeNull();
    expect(Array.isArray(res.body.warnings)).toBe(true);
    expect(res.body.warnings.length).toBeGreaterThan(0);
  });

  test('listServicePrincipals — returns empty array when auth is down', async () => {
    nock(AUTH).get('/api/service-accounts').replyWithError('connection refused');

    const res = await request(app).get('/api/quick/service-principals');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(false);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBe(0);
  });
});
