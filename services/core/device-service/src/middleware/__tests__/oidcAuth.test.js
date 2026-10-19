'use strict';

// Unit tests for the enrollment-token bypass added to oidcAuth (see
// middleware/oidcAuth.js "ENROLLMENT-CONTRACT" — mirrors
// services/core/samba-ad-dc/src/middleware/oidcAuth.js). Covers:
//   - matchesEnrollmentPath(): prefix vs. suffix ('*...') matching
//   - isValidEnrollmentToken(): constant-time compare + fail-closed cases
//   - the middleware itself for the branches that don't require a live JWKS
//     endpoint (missing/invalid token paths, skipPaths, enrollment bypass).

const { oidcAuth, isValidEnrollmentToken, matchesEnrollmentPath } = require('../oidcAuth');

describe('matchesEnrollmentPath', () => {
  const patterns = [
    '/api/devices/report-hardware',
    '*/driver-recommendations',
    '*/detect-drivers',
  ];

  test('matches the report-hardware prefix and its sub-paths', () => {
    expect(matchesEnrollmentPath(patterns, '/api/devices/report-hardware')).toBe(true);
    expect(matchesEnrollmentPath(patterns, '/api/devices/report-hardware/some-key')).toBe(true);
  });

  test('matches variable-segment driver-recommendations / detect-drivers via suffix', () => {
    expect(matchesEnrollmentPath(patterns, '/api/devices/abc-123/driver-recommendations')).toBe(true);
    expect(matchesEnrollmentPath(patterns, '/api/devices/abc-123/detect-drivers')).toBe(true);
    expect(matchesEnrollmentPath(patterns, '/api/devices/host.example.com/driver-recommendations')).toBe(true);
  });

  test('does NOT match the generic device/driver CRUD routes', () => {
    expect(matchesEnrollmentPath(patterns, '/api/devices')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/devices/abc-123')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/drivers')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/drivers/abc-123')).toBe(false);
    expect(matchesEnrollmentPath(patterns, '/api/drivers/upload')).toBe(false);
  });

  test('does not false-positive on unrelated paths that merely contain the suffix text', () => {
    expect(matchesEnrollmentPath(patterns, '/api/devices/driver-recommendations-export')).toBe(false);
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

  test('enrollment path + valid x-enrollment-token bypasses JWT verification', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['/api/devices/report-hardware'] });
    const { req, res } = makeReqRes({
      path: '/api/devices/report-hardware',
      headers: { 'x-enrollment-token': 'my-enroll-token' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.enrolledViaToken).toBe(true);
    expect(res.statusCode).toBeNull();
  });

  test('enrollment path + wrong x-enrollment-token → 401, next not called', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['/api/devices/report-hardware'] });
    const { req, res } = makeReqRes({
      path: '/api/devices/report-hardware',
      headers: { 'x-enrollment-token': 'wrong' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('enrollment path but token env unset → 401 (bypass never silently allowed)', async () => {
    delete process.env.DEVICE_ENROLLMENT_TOKEN;
    const mw = oidcAuth({ enrollmentPaths: ['/api/devices/report-hardware'] });
    const { req, res } = makeReqRes({ path: '/api/devices/report-hardware', headers: {} });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('generic CRUD device/driver routes are NOT covered by enrollmentPaths and require a JWT', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({
      enrollmentPaths: ['/api/devices/report-hardware', '*/driver-recommendations', '*/detect-drivers'],
    });
    const { req, res } = makeReqRes({
      path: '/api/devices',
      headers: { 'x-enrollment-token': 'my-enroll-token' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401); // no Authorization header either → falls through to JWT branch → 401
  });

  test('a Bearer token on an enrollment path is verified as a normal JWT, not the enrollment bypass', async () => {
    process.env.DEVICE_ENROLLMENT_TOKEN = 'my-enroll-token';
    const mw = oidcAuth({ enrollmentPaths: ['/api/devices/report-hardware'] });
    const { req, res } = makeReqRes({
      path: '/api/devices/report-hardware',
      headers: { authorization: 'Bearer not-a-real-jwt', 'x-enrollment-token': 'my-enroll-token' },
    });
    const next = jest.fn();
    await mw(req, res, next);
    // Falls through to jwtVerify(), which rejects a malformed token — never
    // reaches next() via the enrollment bypass despite a valid enrollment header.
    expect(next).not.toHaveBeenCalled();
    expect(req.enrolledViaToken).toBeUndefined();
    expect([401, 403]).toContain(res.statusCode);
  });

  test('missing Authorization header on a non-enrollment path → 401', async () => {
    const mw = oidcAuth({});
    const { req, res } = makeReqRes({ path: '/api/devices', headers: {} });
    const next = jest.fn();
    await mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });
});
