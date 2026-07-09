'use strict';

// Tests for the api-backend -> device-service delegation on GET /api/devices
// and GET /api/devices/:id. Follows the pattern used in
// services/platform/quick-actions/src/__tests__/serviceClient.test.js: nock
// intercepts both the OAuth token endpoint (Client Credentials grant) and
// the downstream device-service HTTP calls, so no real network is used.

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-for-jest-not-for-production';
process.env.ADMIN_PASSWORD = 'TestAdmin123!';
process.env.API_BACKEND_CLIENT_SECRET = 'test-api-backend-secret';
process.env.OAUTH_TOKEN_URL = 'http://oauth-provider.test/oauth/token';
process.env.DEVICE_SERVICE_URL = 'http://device-service.test';

const nock = require('nock');
const request = require('supertest');

function mockTokenEndpoint({ times = 10, accessToken = 'test-service-token', expiresIn = 3600 } = {}) {
  return nock('http://oauth-provider.test')
    .post('/oauth/token')
    .times(times)
    .reply(200, { access_token: accessToken, token_type: 'Bearer', expires_in: expiresIn });
}

// Re-require server + serviceClient fresh for every test so the module-level
// token cache in serviceClient.js is reset between tests.
let app, userStore;
beforeEach(() => {
  jest.resetModules();
  nock.cleanAll();
  ({ app, userStore } = require('../server'));
});

afterEach(() => {
  nock.cleanAll();
});

async function getAdminCookie() {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username: 'admin', password: 'TestAdmin123!' });
  if (!res.headers['set-cookie']) throw new Error('Login failed in test helper');
  return res.headers['set-cookie'][0].split(';')[0];
}

describe('GET /api/devices — device-service delegation', () => {
  test('happy path: delegates to device-service and adapts the shape', async () => {
    mockTokenEndpoint();
    nock('http://device-service.test')
      .get('/api/devices')
      .reply(200, {
        success: true,
        data: [
          {
            id: 'dev-001',
            hostname: 'ws-alice-mbp',
            platform: 'macos',
            status: 'active',
            isCompliant: true,
            complianceViolations: [],
            complianceScore: 92,
            lastSeen: '2026-07-08T00:00:00.000Z',
            enrolledAt: '2026-06-01T00:00:00.000Z',
            os: 'macOS',
            osVersion: '14.5',
            ipAddress: '10.0.0.5',
            kernel: '23.5.0',
            packageManager: 'brew',
          },
        ],
      });

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toHaveLength(1);

    const device = res.body.data[0];
    // hostname -> name rename
    expect(device.name).toBe('ws-alice-mbp');
    expect(device).not.toHaveProperty('hostname');
    // core fields passed through
    expect(device.id).toBe('dev-001');
    expect(device.platform).toBe('macos');
    expect(device.status).toBe('active');
    expect(device.enrolledAt).toBe('2026-06-01T00:00:00.000Z');
    expect(device.lastSeen).toBe('2026-07-08T00:00:00.000Z');
    // new/nullable fields passed through when present
    expect(device.complianceScore).toBe(92);
    expect(device.os).toBe('macOS');
    expect(device.osVersion).toBe('14.5');
    expect(device.ipAddress).toBe('10.0.0.5');
    expect(device.kernel).toBe('23.5.0');
    expect(device.packageManager).toBe('brew');
  });

  test('omits (not null) nullable fields missing from an older device-service response', async () => {
    mockTokenEndpoint();
    nock('http://device-service.test')
      .get('/api/devices')
      .reply(200, {
        success: true,
        data: [
          { id: 'dev-002', hostname: 'ws-bob-win11', platform: 'windows', status: 'active', lastSeen: 'x', enrolledAt: 'y' },
        ],
      });

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices').set('Cookie', cookie);

    expect(res.status).toBe(200);
    const device = res.body.data[0];
    expect(device.name).toBe('ws-bob-win11');
    for (const field of ['complianceScore', 'os', 'osVersion', 'ipAddress', 'kernel', 'packageManager']) {
      expect(device).not.toHaveProperty(field);
    }
  });

  test('falls back to the local deviceStore on ECONNREFUSED', async () => {
    mockTokenEndpoint();
    nock('http://device-service.test')
      .get('/api/devices')
      .replyWithError(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // legacy deviceStore is empty in a fresh test process, but the important
    // thing is the request did NOT error out — it degraded gracefully.
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('falls back to the local deviceStore when the token is rejected (401)', async () => {
    mockTokenEndpoint();
    nock('http://device-service.test')
      .get('/api/devices')
      .reply(401, { error: 'invalid_token' });

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('falls back to the local deviceStore when the token endpoint itself is unreachable', async () => {
    nock('http://oauth-provider.test')
      .post('/oauth/token')
      .replyWithError(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('caches the service token: token endpoint is called once for two requests', async () => {
    const tokenScope = mockTokenEndpoint({ times: 1 });
    const devicesScope = nock('http://device-service.test')
      .get('/api/devices')
      .times(2)
      .reply(200, { success: true, data: [] });

    const cookie = await getAdminCookie();
    const res1 = await request(app).get('/api/devices').set('Cookie', cookie);
    const res2 = await request(app).get('/api/devices').set('Cookie', cookie);

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(tokenScope.isDone()).toBe(true);
    expect(devicesScope.isDone()).toBe(true);
    // If the token endpoint had been called a second time, the `.times(1)`
    // interceptor above would not have matched and nock would have thrown
    // (or left pending interceptors) — isDone() confirms exactly one call.
  });
});

describe('GET /api/devices/:id — device-service delegation', () => {
  test('happy path: delegates to device-service and adapts the shape', async () => {
    mockTokenEndpoint();
    nock('http://device-service.test')
      .get('/api/devices/dev-001')
      .reply(200, {
        success: true,
        data: {
          id: 'dev-001',
          hostname: 'ws-alice-mbp',
          platform: 'macos',
          status: 'active',
          complianceScore: 92,
          lastSeen: '2026-07-08T00:00:00.000Z',
          enrolledAt: '2026-06-01T00:00:00.000Z',
        },
      });

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices/dev-001').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe('ws-alice-mbp');
    expect(res.body.data.id).toBe('dev-001');
    expect(res.body.data.complianceScore).toBe(92);
  });

  test('falls back to the local deviceStore (404) when device-service is unreachable and the device is unknown locally', async () => {
    mockTokenEndpoint();
    nock('http://device-service.test')
      .get('/api/devices/unknown-device')
      .replyWithError(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));

    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/devices/unknown-device').set('Cookie', cookie);

    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
  });
});
