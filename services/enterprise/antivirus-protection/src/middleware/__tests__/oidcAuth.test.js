'use strict';

// Unit tests for antivirus-protection's oidcAuth middleware (the P0 fix —
// this service previously had zero HTTP authentication). Mirrors the sibling
// suites at services/core/device-service/src/middleware/__tests__/oidcAuth.test.js
// and services/core/kerberos-kdc/src/middleware/__tests__/oidcAuth.test.js.
// Covers:
//   - matchesEnrollmentPath(): prefix vs. suffix ('*...') matching for the
//     ClamAV agent's report/status endpoints
//   - isValidEnrollmentToken(): constant-time compare + fail-closed cases
//   - hasAdminAccess()/requireAdmin(): role/scope gate for the
//     quarantine-restore/delete, fleet-scan, signature-update, and
//     schedule-creation endpoints
//   - the oidcAuth middleware itself for the branches that don't require a
//     live JWKS endpoint (missing/invalid token paths, skipPaths, enrollment
//     bypass)

const {
  oidcAuth,
  requireAdmin,
  hasAdminAccess,
  isValidEnrollmentToken,
  matchesEnrollmentPath,
} = require('../oidcAuth');

describe('matchesEnrollmentPath', () => {
  const patterns = ['*/report', '*/status'];

  test('matches the agent report/status suffix routes regardless of deviceId', () => {
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/devices/dev-abc123/report')).toBe(true);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/devices/dev-abc123/status')).toBe(true);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/devices/host.example.com/report')).toBe(true);
  });

  test('does NOT match the generic device/quarantine/scan CRUD routes', () => {
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/devices')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/devices/dev-abc123')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/quarantine/qf-1/restore')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/quarantine/qf-1')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/scan')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/signatures/update')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/schedule')).toBe(false);
  });

  test('does not false-positive on unrelated paths that merely contain the suffix text', () => {
    expect(matchesEnrollmentPath(patterns, '/api/antivirus/devices/status-report')).toBe(false);
  });
});

describe('isValidEnrollmentToken', () => {
  const OLD_ENV = process.env.DEVICE_ENROLLMENT_TOKEN;
  afterEach(() => {
    if (OLD_ENV === undefined) delete process.env.DEVICE_ENROLLMENT_TOKEN;
    else process.env.DEVICE_ENROLLMENT_TOKEN = OLD_ENV;
  });

  test('returns false when DEVICE_ENROLLMENT_TOKEN is unset/empty (fail closed)', () => {
    delete process.env.DEVICE_ENROLLMENT_TOKEN;
    expect(isValidEnrollmentToken('anything')).toBe(false);

    process.env.DEVICE_ENROLLMENT_TOKEN = '';
    expect(isValidEnrollmentToken('anything')).toBe(false);
  });

  test('returns false when the header is missing or not a string', () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'secret-token-123';
    expect(isValidEnrollmentToken(undefined)).toBe(false);
    expect(isValidEnrollmentToken(null)).toBe(false);
    expect(isValidEnrollmentToken(42)).toBe(false);
  });

  test('returns true only for an exact match', () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'secret-token-123';
    expect(isValidEnrollmentToken('secret-token-123')).toBe(true);
    expect(isValidEnrollmentToken('secret-token-124')).toBe(false);
  });

  test('handles length mismatches without throwing (timingSafeEqual guard)', () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'secret-token-123';
    expect(() => isValidEnrollmentToken('short')).not.toThrow();
    expect(isValidEnrollmentToken('short')).toBe(false);
    expect(() => isValidEnrollmentToken('a-much-longer-value-than-the-token')).not.toThrow();
    expect(isValidEnrollmentToken('a-much-longer-value-than-the-token')).toBe(false);
  });
});

describe('hasAdminAccess / requireAdmin', () => {
  test('hasAdminAccess is false for missing/malformed users (fail closed)', () => {
    expect(hasAdminAccess(undefined)).toBe(false);
    expect(hasAdminAccess(null)).toBe(false);
    expect(hasAdminAccess('not-an-object')).toBe(false);
    expect(hasAdminAccess({})).toBe(false);
    expect(hasAdminAccess({ roles: 'admin' })).toBe(false); // not an array
  });

  test('hasAdminAccess is true for roles: ["admin"]', () => {
    expect(hasAdminAccess({ roles: ['admin'] })).toBe(true);
  });

  test('hasAdminAccess is true for Keycloak-style realm_access.roles', () => {
    expect(hasAdminAccess({ realm_access: { roles: ['admin'] } })).toBe(true);
  });

  test('hasAdminAccess is true for the antivirus.admin scope (space-delimited string or array)', () => {
    expect(hasAdminAccess({ scope: 'antivirus.admin other.scope' })).toBe(true);
    expect(hasAdminAccess({ scopes: ['antivirus.admin'] })).toBe(true);
  });

  test('hasAdminAccess is false for a non-admin authenticated user', () => {
    expect(hasAdminAccess({ sub: 'user-1', roles: ['user'] })).toBe(false);
  });

  function makeReqRes(user) {
    const req = { user };
    const res = {
      statusCode: null,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    return { req, res };
  }

  test('requireAdmin calls next() for an admin user', () => {
    const { req, res } = makeReqRes({ roles: ['admin'] });
    const next = jest.fn();
    requireAdmin(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBeNull();
  });

  test('requireAdmin returns 403 for a non-admin user', () => {
    const { req, res } = makeReqRes({ roles: ['user'] });
    const next = jest.fn();
    requireAdmin(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  test('requireAdmin returns 403 when req.user is missing entirely', () => {
    const { req, res } = makeReqRes(undefined);
    const next = jest.fn();
    requireAdmin(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

describe('oidcAuth middleware', () => {
  const OLD_ENV = process.env.DEVICE_ENROLLMENT_TOKEN;
  afterEach(() => {
    if (OLD_ENV === undefined) delete process.env.DEVICE_ENROLLMENT_TOKEN;
    else process.env.DEVICE_ENROLLMENT_TOKEN = OLD_ENV;
  });

  function makeReqRes({ path, headers = {} }) {
    const req = { path, headers };
    const res = {
      statusCode: null,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    return { req, res };
  }

  test('skipPaths bypass auth entirely', async () => {
    const mw = oidcAuth({ skipPaths: ['/health'] });
    const { req, res } = makeReqRes({ path: '/health' });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBeNull();
  });

  test('a path that merely starts with a skipPath text is NOT bypassed (segment-boundary check)', async () => {
    const mw = oidcAuth({ skipPaths: ['/health'] });
    const { req, res } = makeReqRes({ path: '/healthXYZ' });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('enrollment path + valid x-enrollment-token bypasses JWT verification', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['*/report'] });
    const { req, res } = makeReqRes({
      path: '/api/antivirus/devices/dev-1/report',
      headers: { 'x-enrollment-token': 'my-enroll-token' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.enrolledViaToken).toBe(true);
    expect(res.statusCode).toBeNull();
  });

  test('enrollment path + wrong x-enrollment-token -> 401, next not called', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['*/status'] });
    const { req, res } = makeReqRes({
      path: '/api/antivirus/devices/dev-1/status',
      headers: { 'x-enrollment-token': 'wrong' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('enrollment path but token env unset -> 401 (bypass never silently allowed)', async () => {
    delete process.env.DEVICE_ENROLLMENT_TOKEN;
    const mw = oidcAuth({ enrollmentPaths: ['*/report'] });
    const { req, res } = makeReqRes({ path: '/api/antivirus/devices/dev-1/report', headers: {} });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('generic device CRUD routes are NOT covered by enrollmentPaths and require a JWT', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['*/report', '*/status'] });
    const { req, res } = makeReqRes({
      path: '/api/antivirus/devices',
      headers: { 'x-enrollment-token': 'my-enroll-token' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401); // no Authorization header either -> falls through to JWT branch -> 401
  });

  test('a Bearer token on an enrollment path is verified as a normal JWT, not the enrollment bypass', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['*/report'] });
    const { req, res } = makeReqRes({
      path: '/api/antivirus/devices/dev-1/report',
      headers: { authorization: 'Bearer not-a-real-jwt', 'x-enrollment-token': 'my-enroll-token' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    // Falls through to jwtVerify(), which rejects a malformed token -- never
    // reaches next() via the enrollment bypass despite a valid enrollment header.
    expect(next).not.toHaveBeenCalled();
    expect(req.enrolledViaToken).toBeUndefined();
    expect([401, 403]).toContain(res.statusCode);
  });

  test('missing Authorization header on a non-enrollment path -> 401', async () => {
    const mw = oidcAuth({});
    const { req, res } = makeReqRes({ path: '/api/antivirus/quarantine', headers: {} });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });
});
