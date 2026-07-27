'use strict';

// Golden-master characterization tests for the endpoints backing the four
// stores that server.js is moving from pure in-memory to DB-first with an
// in-memory fallback (users, devices, enrollment tokens, setup config).
//
// These tests run over real HTTP (supertest) against the exported `app`,
// exactly like auth.test.js / deviceDelegation.test.js, and assert on
// response shape + status codes only — the contract the frontend depends
// on. They intentionally do NOT set DATABASE_URL, so they exercise the
// in-memory fallback path both before and after the persistence work
// lands; the point is that this file's assertions must stay green whether
// or not `db.isAvailable()` is true, proving the DB wiring didn't change
// observable behavior.
//
// Each top-level describe block gets its own fresh require('../server')
// (jest.resetModules(), mirroring deviceDelegation.test.js) so that the
// per-username login rate limiter (5 attempts / 15 min — see
// server.js loginRateLimit) and the in-memory stores don't accumulate
// state across unrelated flows in this same file.

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-for-jest-not-for-production';
process.env.ADMIN_PASSWORD = 'TestAdmin123!';

const request = require('supertest');

function freshApp() {
  jest.resetModules();
  return require('../server').app;
}

async function getAdminCookie(app) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username: 'admin', password: 'TestAdmin123!' });
  if (!res.headers['set-cookie']) throw new Error('Login failed in test helper');
  return res.headers['set-cookie'][0].split(';')[0];
}

describe('GET /api/users (list)', () => {
  test('returns array without passwordHash on any entry', async () => {
    const app = freshApp();
    const cookie = await getAdminCookie(app);
    const res = await request(app).get('/api/users').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    const admin = res.body.data.find(u => u.id === 'admin');
    expect(admin).toBeDefined();
    expect(admin.passwordHash).toBeUndefined();
    expect(admin.username).toBe('admin');
  });
});

describe('PUT /api/users/:id and DELETE /api/users/:id', () => {
  let app, adminCookie, createdId;

  beforeAll(async () => {
    app = freshApp();
    adminCookie = await getAdminCookie(app);
    const res = await request(app)
      .post('/api/users')
      .set('Cookie', adminCookie)
      .send({ username: 'persistuser', password: 'ValidPass123!', email: 'persistuser@opendirectory.local' });
    createdId = res.body.data.id;
  });

  test('returns 404 for unknown id', async () => {
    const res = await request(app).put('/api/users/does-not-exist').set('Cookie', adminCookie).send({ name: 'x' });
    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
  });

  test('updates allowed fields and returns the updated user without passwordHash', async () => {
    const res = await request(app)
      .put(`/api/users/${createdId}`)
      .set('Cookie', adminCookie)
      .send({ name: 'Persist User', role: 'Manager', groups: ['user', 'managers'], active: true });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.id).toBe(createdId);
    expect(res.body.data.name).toBe('Persist User');
    expect(res.body.data.role).toBe('Manager');
    expect(res.body.data.groups).toEqual(['user', 'managers']);
    expect(res.body.data.passwordHash).toBeUndefined();
  });

  test('cannot delete the default admin user', async () => {
    const res = await request(app).delete('/api/users/admin').set('Cookie', adminCookie);
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('deletes a non-admin user and it disappears from the list', async () => {
    const del = await request(app).delete(`/api/users/${createdId}`).set('Cookie', adminCookie);
    expect(del.status).toBe(200);
    expect(del.body.success).toBe(true);

    const list = await request(app).get('/api/users').set('Cookie', adminCookie);
    expect(list.body.data.find(u => u.id === createdId)).toBeUndefined();

    const del2 = await request(app).delete(`/api/users/${createdId}`).set('Cookie', adminCookie);
    expect(del2.status).toBe(404);
  });
});

describe('PUT /api/auth/profile and POST /api/auth/change-password', () => {
  let app, adminCookie;

  beforeAll(async () => {
    app = freshApp();
    adminCookie = await getAdminCookie(app);
  });

  test('profile update only applies valid name/email', async () => {
    const res = await request(app)
      .put('/api/auth/profile')
      .set('Cookie', adminCookie)
      .send({ name: 'Admin Renamed', email: 'not-an-email' });
    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe('Admin Renamed');
    // invalid email silently ignored (pre-existing behavior)
    expect(res.body.data.email).not.toBe('not-an-email');
    expect(res.body.data.passwordHash).toBeUndefined();
  });

  test('change-password rejects wrong current password', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Cookie', adminCookie)
      .send({ currentPassword: 'WrongPassword1!', newPassword: 'NewValidPass123!' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('change-password succeeds with correct current password and new login works', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Cookie', adminCookie)
      .send({ currentPassword: 'TestAdmin123!', newPassword: 'NewValidPass123!' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'NewValidPass123!' });
    expect(login.status).toBe(200);
  });
});

describe('Device enrollment token + enrollment flow', () => {
  let app, adminCookie, token, deviceId;

  beforeAll(async () => {
    app = freshApp();
    adminCookie = await getAdminCookie(app);
  });

  test('POST /api/devices/enroll/token requires auth', async () => {
    const res = await request(app).post('/api/devices/enroll/token');
    expect(res.status).toBe(401);
  });

  test('POST /api/devices/enroll/token issues a token', async () => {
    const res = await request(app).post('/api/devices/enroll/token').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(typeof res.body.data.token).toBe('string');
    expect(res.body.data.token.length).toBeGreaterThan(10);
    expect(typeof res.body.data.expiresAt).toBe('string');
    token = res.body.data.token;
  });

  test('POST /api/devices/enroll rejects invalid token', async () => {
    const res = await request(app).post('/api/devices/enroll').send({ token: 'bogus', hostname: 'host-x' });
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('POST /api/devices/enroll rejects missing hostname', async () => {
    const res = await request(app).post('/api/devices/enroll').send({ token });
    expect(res.status).toBe(400);
  });

  test('POST /api/devices/enroll succeeds with a valid token and returns the created device', async () => {
    const res = await request(app)
      .post('/api/devices/enroll')
      .send({ token, hostname: 'persist-host-01', platform: 'linux', os: 'Ubuntu', osVersion: '22.04' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.deviceId).toMatch(/^DEV-/);
    expect(res.body.data.device.name).toBe('persist-host-01');
    expect(res.body.data.device.platform).toBe('linux');
    expect(res.body.data.device.status).toBe('online');
    deviceId = res.body.data.deviceId;
  });

  test('the same token cannot be reused', async () => {
    const res = await request(app)
      .post('/api/devices/enroll')
      .send({ token, hostname: 'persist-host-02' });
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('GET /api/devices/:id returns the enrolled device (local fallback path)', async () => {
    const res = await request(app).get(`/api/devices/${deviceId}`).set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.id).toBe(deviceId);
    expect(res.body.data.name).toBe('persist-host-01');
  });

  test('GET /api/devices includes the enrolled device (local fallback path)', async () => {
    const res = await request(app).get('/api/devices').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.some(d => d.id === deviceId)).toBe(true);
  });

  test('POST /api/devices/:id/refresh on a non-CT2001 device is a no-op success', async () => {
    const res = await request(app).post(`/api/devices/${deviceId}/refresh`).set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.id).toBe(deviceId);
  });

  test('POST /api/devices/:id/refresh on unknown device is 404', async () => {
    const res = await request(app).post('/api/devices/NOPE-0000/refresh').set('Cookie', adminCookie);
    expect(res.status).toBe(404);
  });

  test('POST /api/devices/:id/apps/install on a non-CT2001 device returns 400', async () => {
    const res = await request(app)
      .post(`/api/devices/${deviceId}/apps/install`)
      .set('Cookie', adminCookie)
      .send({ appId: 'docker', appName: 'Docker', version: '1.0' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('POST /api/devices/:id/apps/install with unknown appId returns 400', async () => {
    const res = await request(app)
      .post(`/api/devices/${deviceId}/apps/install`)
      .set('Cookie', adminCookie)
      .send({ appId: 'not-a-real-app', appName: 'X', version: '1.0' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('DELETE /api/devices/:id/apps/:appId on a non-CT2001 device returns 400', async () => {
    const res = await request(app).delete(`/api/devices/${deviceId}/apps/docker`).set('Cookie', adminCookie);
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});

describe('Setup wizard config flow', () => {
  let app;

  beforeAll(() => {
    app = freshApp();
  });

  test('GET /api/config/setup-status is public and reports first-run before setup', async () => {
    const res = await request(app).get('/api/config/setup-status');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.isFirstRun).toBe(true);
    expect(res.body.data.config).toBeNull();
  });

  test('GET /api/config/wizard/available-modules returns the fixed module list', async () => {
    const res = await request(app).get('/api/config/wizard/available-modules');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.map(m => m.id)).toEqual(
      expect.arrayContaining(['network', 'printers', 'monitoring', 'security', 'lifecycle'])
    );
  });

  test('POST /api/config/wizard/setup persists config and setup-status reflects it', async () => {
    const completedAt = new Date().toISOString();
    const setupRes = await request(app)
      .post('/api/config/wizard/setup')
      .send({ orgName: 'Persist Org', modules: ['network', 'security'], devices: 3, completedAt });
    expect(setupRes.status).toBe(200);
    expect(setupRes.body.success).toBe(true);
    expect(setupRes.body.data.orgName).toBe('Persist Org');

    const statusRes = await request(app).get('/api/config/setup-status');
    expect(statusRes.status).toBe(200);
    expect(statusRes.body.data.isFirstRun).toBe(false);
    expect(statusRes.body.data.config.orgName).toBe('Persist Org');
    expect(statusRes.body.data.config.modules).toEqual(['network', 'security']);
    expect(statusRes.body.data.config.devices).toBe(3);
  });
});

describe('GET /api/health reflects current counts', () => {
  test('shape is unchanged and counts are non-negative integers', async () => {
    const app = freshApp();
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.status).toBe('healthy');
    expect(res.body.data.services).toEqual({ database: 'connected', ldap: 'connected', monitoring: 'active' });
    expect(Number.isInteger(res.body.data.stats.devices)).toBe(true);
    expect(Number.isInteger(res.body.data.stats.users)).toBe(true);
    expect(res.body.data.stats.users).toBeGreaterThanOrEqual(1);
  });
});
