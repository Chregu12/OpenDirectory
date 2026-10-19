'use strict';

// Runs with Node's built-in test runner (no jest in this service):
//   node --test src/middleware/__tests__/
//
// Regression coverage for the enrollment-token path matching. The bug this
// guards against: a bare startsWith('/api/computers/join') let the low-trust
// enrollment token reach '/api/computers/joinPWNED/reset-machine-password'
// and any computer whose NetBIOS name starts with "join" — a full auth
// bypass to the strictly-JWT-only LAPS/BitLocker/reset endpoints.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { oidcAuth, requireDeviceAdmin, hasDeviceAdminAccess } = require('../oidcAuth');

const ENROLL = 'test-enrollment-secret';

function runMiddleware(mw, reqPath, headers = {}) {
  return new Promise(resolve => {
    const req = { path: reqPath, url: reqPath, headers };
    const res = {
      status(code) {
        return { json: () => resolve({ outcome: 'rejected', code }) };
      },
    };
    mw(req, res, () => resolve({ outcome: 'next' }));
  });
}

function withEnrollToken(fn) {
  const prev = process.env.DEVICE_ENROLLMENT_TOKEN;
  process.env.DEVICE_ENROLLMENT_TOKEN = ENROLL;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.DEVICE_ENROLLMENT_TOKEN;
    else process.env.DEVICE_ENROLLMENT_TOKEN = prev;
  });
}

const mw = oidcAuth({ skipPaths: ['/health'], enrollmentPaths: ['/api/computers/join'] });

test('exact enrollment path accepts a valid enrollment token', () =>
  withEnrollToken(async () => {
    const r = await runMiddleware(mw, '/api/computers/join', { 'x-enrollment-token': ENROLL });
    assert.equal(r.outcome, 'next');
  }));

test('prefix-smuggled path does NOT get the enrollment bypass', () =>
  withEnrollToken(async () => {
    // Would have passed with a bare startsWith(); must now be rejected.
    const r = await runMiddleware(
      mw, '/api/computers/joinPWNED/reset-machine-password', { 'x-enrollment-token': ENROLL }
    );
    assert.equal(r.outcome, 'rejected');
    assert.equal(r.code, 401);
  }));

test('a computer named "JOINERY-PC" cannot be reached via the join bypass', () =>
  withEnrollToken(async () => {
    const r = await runMiddleware(
      mw, '/api/computers/JOINERY-PC/laps-password', { 'x-enrollment-token': ENROLL }
    );
    assert.equal(r.outcome, 'rejected');
  }));

test('skip path (/health) bypasses auth entirely', async () => {
  const r = await runMiddleware(mw, '/health', {});
  assert.equal(r.outcome, 'next');
});

test('a present Bearer token is never downgraded to the enrollment path', () =>
  withEnrollToken(async () => {
    // Bogus bearer on the enrollment path → verified as JWT (fails), never
    // silently accepted via the enrollment token also present.
    const r = await runMiddleware(mw, '/api/computers/join', {
      authorization: 'Bearer not-a-real-jwt',
      'x-enrollment-token': ENROLL,
    });
    assert.equal(r.outcome, 'rejected'); // 403/401 from JWT verify, not next()
  }));

test('enrollment bypass fails closed when DEVICE_ENROLLMENT_TOKEN is unset', async () => {
  const prev = process.env.DEVICE_ENROLLMENT_TOKEN;
  delete process.env.DEVICE_ENROLLMENT_TOKEN;
  try {
    const r = await runMiddleware(mw, '/api/computers/join', { 'x-enrollment-token': ENROLL });
    assert.equal(r.outcome, 'rejected');
  } finally {
    if (prev !== undefined) process.env.DEVICE_ENROLLMENT_TOKEN = prev;
  }
});

// ---------------------------------------------------------------------------
// requireDeviceAdmin / hasDeviceAdminAccess
//
// Regression coverage for the LAPS/BitLocker/reset/unjoin authorization gap:
// oidcAuth alone only proves a caller presented a valid JWT, not that they
// hold a role/scope entitled to device secrets. Any authenticated user could
// previously read LAPS cleartext passwords and BitLocker recovery keys.
// ---------------------------------------------------------------------------

function runRoleMiddleware(user) {
  return new Promise(resolve => {
    const req = { user };
    const res = {
      status(code) {
        return { json: () => resolve({ outcome: 'rejected', code }) };
      },
    };
    requireDeviceAdmin(req, res, () => resolve({ outcome: 'next' }));
  });
}

test('requireDeviceAdmin: valid token WITHOUT admin/helpdesk role -> 403', async () => {
  const r = await runRoleMiddleware({ sub: 'user-1', roles: ['user'] });
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('requireDeviceAdmin: valid token WITH admin role -> next()', async () => {
  const r = await runRoleMiddleware({ sub: 'admin-1', roles: ['admin'] });
  assert.equal(r.outcome, 'next');
});

test('requireDeviceAdmin: valid token WITH helpdesk role -> next()', async () => {
  const r = await runRoleMiddleware({ sub: 'helpdesk-1', roles: ['helpdesk', 'user'] });
  assert.equal(r.outcome, 'next');
});

test('requireDeviceAdmin: valid token WITH device.admin scope (space-delimited string) -> next()', async () => {
  const r = await runRoleMiddleware({ sub: 'svc-1', scope: 'openid profile device.admin' });
  assert.equal(r.outcome, 'next');
});

test('requireDeviceAdmin: valid token WITH device.admin in scopes array -> next()', async () => {
  const r = await runRoleMiddleware({ sub: 'svc-2', scopes: ['device.admin'] });
  assert.equal(r.outcome, 'next');
});

test('requireDeviceAdmin: realm_access.roles (Keycloak-style) admin role -> next()', async () => {
  const r = await runRoleMiddleware({ sub: 'kc-1', realm_access: { roles: ['admin'] } });
  assert.equal(r.outcome, 'next');
});

test('requireDeviceAdmin: token with no roles/scopes at all -> 403 (fail closed)', async () => {
  const r = await runRoleMiddleware({ sub: 'user-2' });
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('requireDeviceAdmin: missing req.user entirely -> 403 (fail closed)', async () => {
  const r = await runRoleMiddleware(undefined);
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('hasDeviceAdminAccess: irrelevant scope string does not grant access', () => {
  assert.equal(hasDeviceAdminAccess({ sub: 'x', scope: 'openid profile email' }), false);
});

test('hasDeviceAdminAccess: non-array roles claim (malformed token) does not throw / does not grant access', () => {
  assert.equal(hasDeviceAdminAccess({ sub: 'x', roles: 'admin' }), false);
});
