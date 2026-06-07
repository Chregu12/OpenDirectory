'use strict';

/**
 * E2E integration tests for quick-actions service.
 *
 * Strategy:
 *   - jest.mock('../utils/serviceClient') to intercept all downstream HTTP calls.
 *     (The orchestrators use `const { call } = require(...)` so jest.spyOn on the
 *      module export object would not affect the local binding — we need jest.mock.)
 *   - jest.mock oidcAuth so tests don't require a real JWKS endpoint.
 *   - Send real HTTP requests via supertest against the Express app.
 */

// ── Mock oidcAuth before loading the app so authMiddleware uses a no-op verifier ─
jest.mock('../../../../shared/oidcAuth', () => ({
  verifyToken: jest.fn().mockResolvedValue({ sub: 'test-e2e-user', role: 'admin', scope: 'openid roles' }),
}));

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
// Use a distinct port to avoid EADDRINUSE when multiple test files load index.js.
// index.js uses: parseInt(process.env.PORT, 10) || 3950
process.env.PORT = '3951';

const request = require('supertest');

// ── Mock serviceClient before the app is loaded ───────────────────────────────
jest.mock('../utils/serviceClient', () => ({
  call: jest.fn(),
  ping: jest.fn(),
  SERVICES: {
    auth:      'http://auth-mock',
    directory: 'http://directory-mock',
    kerberos:  'http://kerberos-mock',
    samba:     'http://samba-mock',
    device:    'http://device-mock',
    policy:    'http://policy-mock',
    pim:       'http://pim-mock',
    mdm:       'http://mdm-mock',
    appStore:  'http://appstore-mock',
  },
}));

const serviceClient = require('../utils/serviceClient');
const { call, ping } = serviceClient;
const app = require('../index');

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Return a Bearer token string (value doesn't matter — verifyToken is mocked) */
function authHeader() {
  return 'Bearer test-e2e-token';
}

const isUuid  = (s) => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const is64Hex = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s);

/** Make an HTTP error as the real serviceClient would throw */
function httpErr(service, status, method, path) {
  const err = new Error(`Service "${service}" returned ${status} for ${method} ${path}`);
  err.status = status;
  return err;
}

/**
 * Build a mock implementation for `call(service, method, path, body)`.
 *
 * routes: Array of { service?, method?, pathPattern, response, times? }
 *   pathPattern : exact string or RegExp
 *   response    : resolve value, or Error to throw
 */
function buildCallMock(routes) {
  const counters = routes.map(() => 0);
  return jest.fn(async (service, method, path) => {
    for (let i = 0; i < routes.length; i++) {
      const r = routes[i];
      if (counters[i] >= (r.times ?? Infinity)) continue;
      const svcMatch  = !r.service || r.service === service;
      const methMatch = !r.method  || r.method.toUpperCase() === method.toUpperCase();
      const pathMatch = r.pathPattern instanceof RegExp
        ? r.pathPattern.test(path)
        : path === r.pathPattern;
      if (svcMatch && methMatch && pathMatch) {
        counters[i]++;
        if (r.response instanceof Error) throw r.response;
        return r.response;
      }
    }
    throw new Error(`[mock] No route for: ${service} ${method} ${path}`);
  });
}

// ── Reset mocks between tests ─────────────────────────────────────────────────

beforeEach(() => {
  call.mockReset();
  ping.mockReset();
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 1: Service Principal Lifecycle
// ═════════════════════════════════════════════════════════════════════════════

describe('Service Principal Lifecycle', () => {

  test('creates SP with all downstream services successful', async () => {
    call.mockImplementation(buildCallMock([
      { service: 'samba',    method: 'POST', pathPattern: '/api/computers/join',                              response: { dn: 'CN=test-app$,CN=Computers,DC=opendirectory,DC=local' } },
      { service: 'kerberos', method: 'POST', pathPattern: '/api/principals',                                   response: { principal: 'app/test-app' } },
      { service: 'auth',     method: 'POST', pathPattern: '/api/service-accounts',                             response: { id: 'test-app', name: 'test-app' } },
      { service: 'pim',      method: 'POST', pathPattern: /\/api\/v1\/permissions\/users\/.*\/assign/,         response: { assigned: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({ appName: 'test-app', permissions: ['read-users'] });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(isUuid(res.body.clientId)).toBe(true);
    expect(is64Hex(res.body.clientSecret)).toBe(true);
  });

  test('creates SP even when Kerberos is down (partial success)', async () => {
    call.mockImplementation(buildCallMock([
      { service: 'samba',    method: 'POST', pathPattern: '/api/computers/join',                      response: { dn: 'CN=app2$,CN=Computers,DC=opendirectory,DC=local' } },
      { service: 'kerberos', method: 'POST', pathPattern: '/api/principals',                           response: httpErr('kerberos', 503, 'POST', '/api/principals') },
      { service: 'auth',     method: 'POST', pathPattern: '/api/service-accounts',                     response: { id: 'app2', name: 'app2' } },
      { service: 'pim',      method: 'POST', pathPattern: /\/api\/v1\/permissions\/users\/.*\/assign/, response: { assigned: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({ appName: 'app2', permissions: ['read-users'] });

    expect(res.status).toBe(207);
    expect(res.body.success).toBe(false);
    expect(isUuid(res.body.clientId)).toBe(true);

    const failed = res.body.completedSteps.filter(s => !s.ok);
    expect(failed.length).toBeGreaterThan(0);
    expect(failed.find(s => s.name === 'create-kerberos-spn')).toBeDefined();
  });

  test('rotates secret — new secret is 64-char hex', async () => {
    const clientId = '11111111-1111-4111-a111-111111111111';
    const appName  = 'rotate-test';

    call.mockImplementation(buildCallMock([
      { service: 'auth',     method: 'GET',   pathPattern: `/api/service-accounts/${clientId}`, response: { name: appName, id: clientId } },
      { service: 'auth',     method: 'PATCH', pathPattern: `/api/service-accounts/${clientId}`, response: { updated: true } },
      { service: 'kerberos', method: 'PATCH', pathPattern: /\/api\/principals\/.+/,             response: { updated: true } },
    ]));

    const res = await request(app)
      .post(`/api/quick/service-principals/${clientId}/rotate-secret`)
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(is64Hex(res.body.newClientSecret)).toBe(true);
  });

  test('deletes SP — cleanup called on all services', async () => {
    const clientId    = '22222222-2222-4222-a222-222222222222';
    const appName     = 'delete-test';
    const pimRevoke   = jest.fn().mockResolvedValue({ revoked: true });
    const authDelete  = jest.fn().mockResolvedValue({ deleted: true });
    const kerbDelete  = jest.fn().mockResolvedValue({ deleted: true });
    const sambaDelete = jest.fn().mockResolvedValue({ deleted: true });

    call.mockImplementation(async (service, method, path) => {
      if (service === 'auth'     && method === 'GET'    && path.includes(clientId)) return { name: appName };
      if (service === 'pim'      && method === 'POST'   && path.includes('revoke-all')) return pimRevoke();
      if (service === 'auth'     && method === 'DELETE')                               return authDelete();
      if (service === 'kerberos' && method === 'DELETE')                               return kerbDelete();
      if (service === 'samba'    && method === 'DELETE')                               return sambaDelete();
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .delete(`/api/quick/service-principals/${clientId}`)
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(pimRevoke).toHaveBeenCalledTimes(1);
    expect(authDelete).toHaveBeenCalledTimes(1);
    expect(kerbDelete).toHaveBeenCalledTimes(1);
    expect(sambaDelete).toHaveBeenCalledTimes(1);
  });

  test('GET /api/quick/service-principals returns list', async () => {
    call.mockImplementation(buildCallMock([
      { service: 'auth', method: 'GET', pathPattern: '/api/service-accounts', response: {
        accounts: [{ name: 'app1', clientId: 'aaa' }, { name: 'app2', clientId: 'bbb' }],
      }},
    ]));

    const res = await request(app)
      .get('/api/quick/service-principals')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBe(2);
  });

  test('GET /api/quick/service-principals/:id returns SP details', async () => {
    const clientId = '33333333-3333-4333-a333-333333333333';

    call.mockImplementation(buildCallMock([
      { service: 'auth', method: 'GET', pathPattern: `/api/service-accounts/${clientId}`, response: { name: 'test-app', id: clientId } },
      { service: 'pim',  method: 'GET', pathPattern: /\/api\/v1\/permissions\/users\/.+/, response: { permissions: ['read-users'] } },
    ]));

    const res = await request(app)
      .get(`/api/quick/service-principals/${clientId}`)
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.clientId).toBe(clientId);
    expect(res.body.account).toBeDefined();
  });

  test('listServicePrincipals — returns empty array when auth is down', async () => {
    call.mockImplementation(() => { throw new Error('connect ECONNREFUSED'); });

    const res = await request(app)
      .get('/api/quick/service-principals')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(false);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBe(0);
  });

  test('creates SP with no permissions — skips PIM step', async () => {
    call.mockImplementation(buildCallMock([
      { service: 'samba',    method: 'POST', pathPattern: '/api/computers/join',   response: { dn: 'CN=no-perms$,CN=Computers,DC=opendirectory,DC=local' } },
      { service: 'kerberos', method: 'POST', pathPattern: '/api/principals',        response: { principal: 'app/no-perms' } },
      { service: 'auth',     method: 'POST', pathPattern: '/api/service-accounts',  response: { id: 'no-perms', name: 'no-perms' } },
    ]));

    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({ appName: 'no-perms' });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(isUuid(res.body.clientId)).toBe(true);
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
      const routes = [
        { service: 'device', method: 'POST', pathPattern: '/api/devices',        response: { id: 'dev-001', name: deviceName, platform } },
        { service: 'samba',  method: 'POST', pathPattern: '/api/computers/join', response: { dn: `CN=${deviceName},CN=Computers,DC=opendirectory,DC=local` } },
      ];

      if (platform === 'macos') {
        routes.push(
          { service: 'mdm',    method: 'POST', pathPattern: '/api/mdm/enroll',      response: { enrollmentUrl: 'mdmEnroll://enroll?device=dev-001' } },
          { service: 'policy', method: 'POST', pathPattern: '/api/policies/assign', response: { policies: ['baseline'] } },
        );
      } else if (platform === 'windows') {
        routes.push(
          { service: 'directory', method: 'POST', pathPattern: '/api/winrm/configure',    response: { configured: true } },
          { service: 'directory', method: 'POST', pathPattern: '/api/gpo/baseline/apply', response: { applied: true } },
        );
      } else if (platform === 'linux') {
        routes.push(
          { service: 'directory', method: 'POST', pathPattern: '/api/sssd/config',      response: { config: '# sssd.conf' } },
          { service: 'kerberos',  method: 'POST', pathPattern: '/api/keytabs',           response: { keytabB64: 'dGVzdA==' } },
          { service: 'policy',    method: 'POST', pathPattern: '/api/policies/assign',   response: { policies: ['hardening'] } },
        );
      } else if (platform === 'ios' || platform === 'android') {
        routes.push(
          { service: 'mdm', method: 'POST', pathPattern: '/api/mdm/enroll', response: { enrollmentUrl: `mdmenroll://enroll?device=dev-001&platform=${platform}` } },
        );
      }

      call.mockImplementation(buildCallMock(routes));

      const res = await request(app)
        .post('/api/quick/devices/enroll')
        .set('Authorization', authHeader())
        .send({ platform, deviceName });

      expect([200, 201, 207]).toContain(res.status);
      expect(res.body.deviceId).toBeDefined();
      expect(res.body.platform).toBe(platform);
      expect(Array.isArray(res.body.nextSteps)).toBe(true);
      expect(res.body.nextSteps.length).toBeGreaterThan(0);
    });
  }

  test('bulk enroll 3 devices — 2 succeed, 1 fails', async () => {
    let deviceCallCount = 0;

    call.mockImplementation(async (service, method, path) => {
      if (service === 'device' && method === 'POST') {
        deviceCallCount++;
        if (deviceCallCount === 3) throw httpErr('device', 503, 'POST', '/api/devices');
        return { id: `bulk-dev-${deviceCallCount}` };
      }
      if (service === 'samba'     && method === 'POST') return { dn: 'CN=x,CN=Computers,DC=opendirectory,DC=local' };
      if (service === 'directory' && method === 'POST') return { config: '# sssd.conf' };
      if (service === 'kerberos'  && method === 'POST') return { keytabB64: 'dGVzdA==' };
      if (service === 'policy'    && method === 'POST') return { policies: [] };
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .set('Authorization', authHeader())
      .send({ devices: [
        { platform: 'linux', deviceName: 'bulk-linux-1' },
        { platform: 'linux', deviceName: 'bulk-linux-2' },
        { platform: 'linux', deviceName: 'bulk-linux-3' },
      ]});

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(3);
    expect(Array.isArray(res.body.results)).toBe(true);
    expect(res.body.results.length).toBe(3);
    expect(res.body.results.filter(r => r.success).length).toBeGreaterThanOrEqual(2);
    expect(res.body.results.filter(r => !r.success).length).toBeGreaterThanOrEqual(1);
  });

  test('enrollment status check', async () => {
    const deviceId = 'status-device-abc';

    call.mockImplementation(buildCallMock([
      { service: 'device', method: 'GET', pathPattern: `/api/devices/${deviceId}`,            response: { id: deviceId, status: 'enrolled', platform: 'macos' } },
      { service: 'mdm',    method: 'GET', pathPattern: `/api/mdm/devices/${deviceId}/status`, response: { mdmStatus: 'active', managed: true } },
    ]));

    const res = await request(app)
      .get(`/api/quick/devices/${deviceId}/enrollment-status`)
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deviceId).toBe(deviceId);
    expect(res.body.device).toBeDefined();
  });

  test('unenroll with wipe=false — MDM wipe NOT called', async () => {
    const deviceId = 'no-wipe-device';
    const wipeCall = jest.fn().mockResolvedValue({ wiped: true });

    call.mockImplementation(async (service, method, path) => {
      if (service === 'mdm'    && method === 'POST'   && path.includes('/wipe')) return wipeCall();
      if (service === 'mdm'    && method === 'DELETE')                            return { removed: true };
      if (service === 'device' && method === 'DELETE')                            return { deleted: true };
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .post(`/api/quick/devices/${deviceId}/unenroll`)
      .set('Authorization', authHeader())
      .send({ wipe: false });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(wipeCall).not.toHaveBeenCalled();
  });

  test('unenroll with wipe=true — MDM wipe called', async () => {
    const deviceId = 'wipe-device';
    const wipeCall = jest.fn().mockResolvedValue({ wiped: true });

    call.mockImplementation(async (service, method, path) => {
      if (service === 'mdm'    && method === 'POST'   && path.includes('/wipe')) return wipeCall();
      if (service === 'mdm'    && method === 'DELETE')                            return { removed: true };
      if (service === 'device' && method === 'DELETE')                            return { deleted: true };
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .post(`/api/quick/devices/${deviceId}/unenroll`)
      .set('Authorization', authHeader())
      .send({ wipe: true });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.wiped).toBe(true);
    expect(wipeCall).toHaveBeenCalledTimes(1);
  });

  test('getEnrollmentStatus — warnings when MDM is down', async () => {
    const deviceId = 'mdm-down-device';

    call.mockImplementation(async (service, method) => {
      if (service === 'device' && method === 'GET') return { id: deviceId, status: 'enrolled' };
      if (service === 'mdm'    && method === 'GET') throw new Error('MDM service connection refused');
      throw new Error(`[mock] Unmatched: ${service} ${method}`);
    });

    const res = await request(app)
      .get(`/api/quick/devices/${deviceId}/enrollment-status`)
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.device).toBeDefined();
    expect(res.body.mdmStatus).toBeNull();
    expect(Array.isArray(res.body.warnings)).toBe(true);
    expect(res.body.warnings.length).toBeGreaterThan(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 3: User Onboarding/Offboarding
// ═════════════════════════════════════════════════════════════════════════════

describe('User Lifecycle', () => {

  function buildOnboardMock({ notificationFail = false, directoryFail = false } = {}) {
    return buildCallMock([
      {
        service: 'directory', method: 'POST', pathPattern: '/api/users',
        response: directoryFail
          ? httpErr('directory', 500, 'POST', '/api/users')
          : { id: 'user-123', dn: 'CN=John Doe,OU=Engineering,OU=Users,DC=opendirectory,DC=local' },
      },
      { service: 'auth',   method: 'POST', pathPattern: '/api/users',           response: { id: 'user-123' } },
      { service: 'auth',   method: 'POST', pathPattern: '/api/users/roles',     response: { assigned: true } },
      { service: 'samba',  method: 'POST', pathPattern: /\/api\/groups\/.*\/members/, response: { added: true } },
      { service: 'policy', method: 'POST', pathPattern: '/api/policies/assign', response: { policies: ['user-baseline'] } },
      {
        service: 'auth', method: 'POST', pathPattern: '/api/notifications',
        response: notificationFail
          ? httpErr('auth', 503, 'POST', '/api/notifications')
          : { sent: true },
      },
    ]);
  }

  test('onboards new employee — all steps complete', async () => {
    call.mockImplementation(buildOnboardMock());

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ firstName: 'John', lastName: 'Doe', email: 'john@test.com', department: 'Engineering', role: 'standard' });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.userId).toBeDefined();
    expect(res.body.temporaryPassword).toBeDefined();
  });

  test('onboards user — notification failure is non-blocking', async () => {
    call.mockImplementation(buildOnboardMock({ notificationFail: true }));

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ firstName: 'Jane', lastName: 'Smith', email: 'jane@test.com', department: 'Engineering', role: 'standard' });

    expect(res.status).toBe(207);
    expect(res.body.userId).toBeDefined();
    expect(Array.isArray(res.body.warnings)).toBe(true);
    expect(res.body.warnings.length).toBeGreaterThan(0);
  });

  test('onboards user — critical step (AD user) fails returns 207', async () => {
    call.mockImplementation(buildOnboardMock({ directoryFail: true }));

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ firstName: 'Bob', lastName: 'Builder', email: 'bob@test.com', department: 'Engineering', role: 'standard' });

    expect(res.status).toBe(207);
    expect(res.body.success).toBe(false);
    expect(res.body.failedAt).toBe('create-ad-user');
  });

  test('offboards user — revokes all devices', async () => {
    const userId = 'offboard-user-111';

    call.mockImplementation(buildCallMock([
      { service: 'directory', method: 'POST',  pathPattern: `/api/users/${userId}/disable`,                 response: { disabled: true } },
      { service: 'pim',       method: 'POST',  pathPattern: /\/api\/v1\/permissions\/users\/.*\/revoke-all/, response: { revoked: true } },
      { service: 'auth',      method: 'PATCH', pathPattern: `/api/users/${userId}`,                         response: { disabled: true } },
      { service: 'device',    method: 'GET',   pathPattern: /\/api\/devices\?assignedUser=.+/,              response: { devices: [{ id: 'dev-a' }, { id: 'dev-b' }] } },
      { service: 'device',    method: 'PATCH', pathPattern: '/api/devices/dev-a',                           response: { updated: true } },
      { service: 'device',    method: 'PATCH', pathPattern: '/api/devices/dev-b',                           response: { updated: true } },
      { service: 'samba',     method: 'GET',   pathPattern: `/api/users/${userId}/groups`,                  response: { groups: [] } },
      { service: 'directory', method: 'POST',  pathPattern: `/api/users/${userId}/archive`,                 response: { archived: true } },
    ]));

    const res = await request(app)
      .post(`/api/quick/users/${userId}/offboard`)
      .set('Authorization', authHeader())
      .send({ revokeDevices: true });

    expect(res.status).toBe(200);
    expect(res.body.disabled).toBe(true);
    expect(res.body.userId).toBe(userId);
  });

  test('offboards user — disableOnly does not call user DELETE', async () => {
    const userId       = 'offboard-user-222';
    const deleteUserFn = jest.fn().mockResolvedValue({ deleted: true });

    call.mockImplementation(async (service, method, path) => {
      if (service === 'directory' && method === 'DELETE' && path.includes(userId)) return deleteUserFn();
      if (service === 'directory' && method === 'POST'   && path.includes('disable')) return { disabled: true };
      if (service === 'directory' && method === 'POST'   && path.includes('archive')) return { archived: true };
      if (service === 'pim'       && method === 'POST'   && path.includes('revoke-all')) return { revoked: true };
      if (service === 'auth'      && method === 'PATCH')                                 return { disabled: true };
      if (service === 'device'    && method === 'GET')                                   return { devices: [] };
      if (service === 'samba'     && method === 'GET')                                   return { groups: [] };
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .post(`/api/quick/users/${userId}/offboard`)
      .set('Authorization', authHeader())
      .send({ disableOnly: true });

    expect(res.status).toBe(200);
    expect(res.body.disabled).toBe(true);
    expect(deleteUserFn).not.toHaveBeenCalled();
  });

  test('onboards user with elevated role — PIM endpoint called', async () => {
    const pimCall = jest.fn().mockResolvedValue({ assigned: true });

    call.mockImplementation(async (service, method, path) => {
      if (service === 'directory' && method === 'POST' && path === '/api/users') return { id: 'admin-user', dn: 'CN=x' };
      if (service === 'auth'      && method === 'POST' && path === '/api/users') return { id: 'admin-user' };
      if (service === 'pim'       && method === 'POST' && path.includes('/pim/roles')) return pimCall();
      if (service === 'samba'     && method === 'POST') return { added: true };
      if (service === 'policy'    && method === 'POST') return { policies: [] };
      if (service === 'auth'      && method === 'POST') return { sent: true };
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ firstName: 'Admin', lastName: 'User', email: 'admin@test.com', department: 'IT', role: 'admin' });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(pimCall).toHaveBeenCalledTimes(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 4: Policy Deployment
// ═════════════════════════════════════════════════════════════════════════════

describe('Policy Deployment', () => {

  test('deploys policy to OU — calls enterprise-directory GPO apply', async () => {
    const policyId = 'pol-123';

    call.mockImplementation(buildCallMock([
      { service: 'policy',    method: 'GET',  pathPattern: `/api/policies/${policyId}`,     response: { id: policyId, name: 'Eng Policy', settings: { firewall: 'on' } } },
      { service: 'directory', method: 'POST', pathPattern: `/api/gpo/${policyId}/apply`,    response: { applied: 5 } },
      { service: 'policy',    method: 'POST', pathPattern: '/api/policies/deployments',     response: { recorded: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'ou', targetId: 'ou=engineering,dc=opendirectory,dc=local' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
    expect(res.body.affectedTargets).toBeGreaterThan(0);
  });

  test('deploys policy to all — parallel fan-out', async () => {
    const policyId = 'pol-all-123';

    call.mockImplementation(buildCallMock([
      { service: 'policy',    method: 'GET',  pathPattern: `/api/policies/${policyId}`,   response: { id: policyId, name: 'Global', settings: { encryption: 'required' } } },
      { service: 'mdm',       method: 'POST', pathPattern: '/api/policies/push',          response: { pushed: true } },
      { service: 'directory', method: 'POST', pathPattern: `/api/gpo/${policyId}/apply`,  response: { applied: 10 } },
      { service: 'policy',    method: 'POST', pathPattern: '/api/policies/broadcast',     response: { broadcasted: true } },
      { service: 'policy',    method: 'POST', pathPattern: '/api/policies/deployments',   response: { recorded: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'all' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
    expect(res.body.affectedTargets).toBeGreaterThanOrEqual(3);
  });

  test('dry run — does not call deploy endpoints', async () => {
    const policyId = 'pol-dry-456';
    const gpoCall  = jest.fn().mockResolvedValue({ applied: 5 });
    const recCall  = jest.fn().mockResolvedValue({ recorded: true });

    call.mockImplementation(async (service, method, path) => {
      if (service === 'policy' && method === 'GET' && path.includes(policyId)) {
        return { id: policyId, name: 'Dry Run Policy', settings: { audit: true } };
      }
      if (service === 'directory' && method === 'POST') return gpoCall();
      if (service === 'policy'    && method === 'POST') return recCall();
      throw new Error(`[mock] Unmatched: ${service} ${method} ${path}`);
    });

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'ou', targetId: 'ou=test,dc=local', dryRun: true });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.dryRun).toBe(true);
    expect(res.body.deployed).toBe(false);
    expect(res.body.dryRunReport).toBeDefined();
    expect(res.body.dryRunReport.policyId).toBe(policyId);
    expect(gpoCall).not.toHaveBeenCalled();
    expect(recCall).not.toHaveBeenCalled();
  });

  test('compliance snapshot returns aggregated stats', async () => {
    call.mockImplementation(buildCallMock([
      { service: 'policy', method: 'GET', pathPattern: '/api/compliance/summary', response: {
        total: 150, compliant: 120, nonCompliant: 30,
        topViolations: [{ rule: 'encryption', count: 15 }, { rule: 'os-version', count: 10 }],
      }},
      { service: 'device', method: 'GET', pathPattern: '/api/compliance/devices', response: {
        total: 150, compliant: 120, nonCompliant: 30,
      }},
    ]));

    const res = await request(app)
      .get('/api/quick/compliance/snapshot')
      .set('Authorization', authHeader());

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.snapshot).toBeDefined();
    expect(res.body.snapshot.total).toBeGreaterThan(0);
    expect(res.body.snapshot.compliant).toBeDefined();
    expect(res.body.snapshot.nonCompliant).toBeDefined();
    expect(Array.isArray(res.body.snapshot.topViolations)).toBe(true);
  });

  test('deploys policy to user target', async () => {
    const policyId = 'pol-user-789';

    call.mockImplementation(buildCallMock([
      { service: 'policy', method: 'GET',  pathPattern: `/api/policies/${policyId}`, response: { id: policyId, name: 'User Policy' } },
      { service: 'pim',    method: 'POST', pathPattern: '/api/policies/assign',      response: { assigned: true } },
      { service: 'policy', method: 'POST', pathPattern: '/api/policies/deployments', response: { recorded: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'user', targetId: 'user-target-001' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
  });

  test('deploys policy to device target', async () => {
    const policyId = 'pol-device-789';

    call.mockImplementation(buildCallMock([
      { service: 'policy', method: 'GET',  pathPattern: `/api/policies/${policyId}`, response: { id: policyId, name: 'Device Policy' } },
      { service: 'mdm',    method: 'POST', pathPattern: '/api/policies/push',        response: { pushed: true } },
      { service: 'policy', method: 'POST', pathPattern: '/api/policies/deployments', response: { recorded: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'device', targetId: 'device-target-001' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
  });

  test('deploys policy to group target', async () => {
    const policyId = 'pol-group-555';

    call.mockImplementation(buildCallMock([
      { service: 'policy',    method: 'GET',  pathPattern: `/api/policies/${policyId}`,  response: { id: policyId, name: 'Group Policy' } },
      { service: 'directory', method: 'POST', pathPattern: '/api/policies/group/assign', response: { assigned: true } },
      { service: 'policy',    method: 'POST', pathPattern: '/api/policies/deployments',  response: { recorded: true } },
    ]));

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'group', targetId: 'engineering-group' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deployed).toBe(true);
  });

  test('policy deployment fails when policy-service is down', async () => {
    const policyId = 'pol-missing-999';
    call.mockRejectedValue(httpErr('policy', 500, 'GET', `/api/policies/${policyId}`));

    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'ou', targetId: 'ou=test' });

    expect([207, 500]).toContain(res.status);
    expect(res.body.success).toBe(false);
    expect(res.body.failedAt).toBe('fetch-policy');
  });

  test('deployment status lookup returns in-memory record', async () => {
    const policyId = 'pol-status-222';

    call.mockImplementation(buildCallMock([
      { service: 'policy',    method: 'GET',  pathPattern: `/api/policies/${policyId}`, response: { id: policyId, name: 'Status Policy' } },
      { service: 'mdm',       method: 'POST', pathPattern: '/api/policies/push',        response: { pushed: true } },
      { service: 'directory', method: 'POST', pathPattern: `/api/gpo/${policyId}/apply`,response: { applied: 5 } },
      { service: 'policy',    method: 'POST', pathPattern: '/api/policies/broadcast',   response: { broadcasted: true } },
      { service: 'policy',    method: 'POST', pathPattern: '/api/policies/deployments', response: { recorded: true } },
    ]));

    const deployRes = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId, targetType: 'all' });

    expect(deployRes.status).toBe(200);
    const deploymentId = deployRes.body.deploymentId;

    const statusRes = await request(app)
      .get(`/api/quick/policies/deployments/${deploymentId}`)
      .set('Authorization', authHeader());

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

  test('GET /health returns uptime as number and timestamp', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(typeof res.body.uptime).toBe('number');
    expect(res.body.timestamp).toBeDefined();
  });

  test('GET /api/quick/status — all services up', async () => {
    ping.mockResolvedValue({ healthy: true, latencyMs: 5 });

    const res = await request(app).get('/api/quick/status');

    expect(res.status).toBe(200);
    expect(res.body.overall).toBe('healthy');
    expect(Object.values(res.body.services).every(s => s.healthy)).toBe(true);
  });

  test('GET /api/quick/status — some services down', async () => {
    let pingCount = 0;
    ping.mockImplementation(async () => {
      pingCount++;
      return pingCount <= 2
        ? { healthy: false, latencyMs: 50, error: 'ECONNREFUSED' }
        : { healthy: true, latencyMs: 5 };
    });

    const res = await request(app).get('/api/quick/status');

    expect(res.status).toBe(200);
    expect(res.body.overall).toBe('degraded');
    expect(Object.values(res.body.services).some(s => !s.healthy)).toBe(true);
  });

  test('GET /api/quick/status — all services down returns unhealthy', async () => {
    ping.mockResolvedValue({ healthy: false, latencyMs: 100, error: 'ECONNREFUSED' });

    const res = await request(app).get('/api/quick/status');

    expect(res.status).toBe(200);
    expect(res.body.overall).toBe('unhealthy');
  });

  test('404 for unknown routes', async () => {
    const res = await request(app)
      .get('/api/quick/does-not-exist')
      .set('Authorization', authHeader());
    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 6: Input Validation / Edge Cases
// NOTE: These run AFTER the rate-limit stress test; use a distinct IP via
// X-Forwarded-For so they don't get throttled.
// ═════════════════════════════════════════════════════════════════════════════

describe('Edge Cases', () => {

  test('createServicePrincipal — missing appName returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/service-principals')
      .set('Authorization', authHeader())
      .send({ description: 'no app name' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/appName/i);
  });

  test('enrollDevice — missing platform returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .set('Authorization', authHeader())
      .send({ deviceName: 'test-device' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('enrollDevice — missing deviceName returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/devices/enroll')
      .set('Authorization', authHeader())
      .send({ platform: 'linux' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('bulk-enroll — empty devices array returns 400', async () => {
    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .set('Authorization', authHeader())
      .send({ devices: [] });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('bulk-enroll — missing devices field returns 400', async () => {
    const res = await request(app)
      .post('/api/quick/devices/bulk-enroll')
      .set('Authorization', authHeader())
      .send({ platform: 'linux' });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('deployPolicy — missing policyId returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ targetType: 'ou' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('deployPolicy — missing targetType returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/policies/deploy')
      .set('Authorization', authHeader())
      .send({ policyId: 'pol-123' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('onboardUser — missing firstName returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ lastName: 'Doe', email: 'test@test.com' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('onboardUser — missing email returns 500', async () => {
    const res = await request(app)
      .post('/api/quick/users/onboard')
      .set('Authorization', authHeader())
      .send({ firstName: 'John', lastName: 'Doe' });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Suite 7: Rate Limiting (must run LAST — exhausts the per-IP limit)
// ═════════════════════════════════════════════════════════════════════════════

describe('Rate Limiting', () => {

  test('200+ requests to /api/ endpoint returns 429', async () => {
    ping.mockResolvedValue({ healthy: true, latencyMs: 1 });

    const promises = [];
    for (let i = 0; i < 201; i++) {
      promises.push(request(app).get('/api/quick/status'));
    }
    const results  = await Promise.all(promises);
    const statuses = results.map(r => r.status);
    expect(statuses.some(s => s === 429)).toBe(true);
  }, 30000);
});
