'use strict';

// Runs with Node's built-in test runner (no jest in this service):
//   node --test src/middleware/__tests__/
//
// Unit coverage for kerberos-kdc's oidcAuth middleware — the P0 fix for a
// service that previously had ZERO HTTP authentication (only helmet()/
// cors()). Covers:
//   - matchesPath()-driven internal-service-token bypass, restricted to
//     POST /api/kerberos/sync-user (authentication-service's server-to-
//     server registration/password-change calls).
//   - isValidInternalToken(): constant-time compare + fail-closed cases.
//   - the middleware itself for the branches that don't require a live JWKS
//     endpoint (missing/invalid token, skipPaths, internal-token bypass).
//   - requireKdcAdmin / requireKdcAdminOrInternal role gating.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  oidcAuth,
  requireKdcAdmin,
  requireKdcAdminOrInternal,
  hasKdcAdminAccess,
  isValidInternalToken,
} = require('../oidcAuth');

const INTERNAL_TOKEN = 'test-internal-secret';

function runMiddleware(mw, reqPath, headers = {}) {
  return new Promise(resolve => {
    const req = { path: reqPath, url: reqPath, headers };
    const res = {
      status(code) {
        return { json: () => resolve({ outcome: 'rejected', code }) };
      },
    };
    mw(req, res, () => resolve({ outcome: 'next', req }));
  });
}

function withInternalToken(fn) {
  const prev = process.env.KDC_INTERNAL_TOKEN;
  process.env.KDC_INTERNAL_TOKEN = INTERNAL_TOKEN;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.KDC_INTERNAL_TOKEN;
    else process.env.KDC_INTERNAL_TOKEN = prev;
  });
}

const mw = oidcAuth({
  skipPaths: ['/health'],
  internalServicePaths: ['/api/kerberos/sync-user'],
});

test('missing Authorization header on a normal route -> 401', async () => {
  const r = await runMiddleware(mw, '/api/kerberos/principals', {});
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 401);
});

test('bogus Bearer token -> rejected (401/403), never next()', async () => {
  const r = await runMiddleware(mw, '/api/kerberos/principals', {
    authorization: 'Bearer not-a-real-jwt',
  });
  assert.equal(r.outcome, 'rejected');
  assert.ok([401, 403].includes(r.code));
});

test('skip path (/health) bypasses auth entirely', async () => {
  const r = await runMiddleware(mw, '/health', {});
  assert.equal(r.outcome, 'next');
});

test('sync-user accepts a valid internal-service token', () =>
  withInternalToken(async () => {
    const r = await runMiddleware(mw, '/api/kerberos/sync-user', {
      'x-kdc-internal-token': INTERNAL_TOKEN,
    });
    assert.equal(r.outcome, 'next');
    assert.equal(r.req.internalService, true);
  }));

test('sync-user rejects a wrong internal-service token', () =>
  withInternalToken(async () => {
    const r = await runMiddleware(mw, '/api/kerberos/sync-user', {
      'x-kdc-internal-token': 'wrong',
    });
    assert.equal(r.outcome, 'rejected');
    assert.equal(r.code, 401);
  }));

test('internal-service bypass fails closed when KDC_INTERNAL_TOKEN is unset', async () => {
  const prev = process.env.KDC_INTERNAL_TOKEN;
  delete process.env.KDC_INTERNAL_TOKEN;
  try {
    const r = await runMiddleware(mw, '/api/kerberos/sync-user', {
      'x-kdc-internal-token': INTERNAL_TOKEN,
    });
    assert.equal(r.outcome, 'rejected');
  } finally {
    if (prev !== undefined) process.env.KDC_INTERNAL_TOKEN = prev;
  }
});

test('a present Bearer token on sync-user is never downgraded to the internal-token path', () =>
  withInternalToken(async () => {
    const r = await runMiddleware(mw, '/api/kerberos/sync-user', {
      authorization: 'Bearer not-a-real-jwt',
      'x-kdc-internal-token': INTERNAL_TOKEN,
    });
    assert.equal(r.outcome, 'rejected'); // JWT verify fails, not silently accepted via internal token
  }));

test('prefix-smuggled path does NOT get the internal-token bypass', () =>
  withInternalToken(async () => {
    // Would pass with a bare startsWith(); must be rejected with the
    // path-segment-boundary check.
    const r = await runMiddleware(mw, '/api/kerberos/sync-userPWNED', {
      'x-kdc-internal-token': INTERNAL_TOKEN,
    });
    assert.equal(r.outcome, 'rejected');
    assert.equal(r.code, 401);
  }));

test('other mutating routes (e.g. principal password) are NOT covered by the internal-token bypass', () =>
  withInternalToken(async () => {
    const r = await runMiddleware(mw, '/api/kerberos/principals/admin/password', {
      'x-kdc-internal-token': INTERNAL_TOKEN,
    });
    assert.equal(r.outcome, 'rejected');
    assert.equal(r.code, 401); // falls through to the JWT branch, no Authorization header -> 401
  }));

// ---------------------------------------------------------------------------
// isValidInternalToken
// ---------------------------------------------------------------------------

test('isValidInternalToken: fails closed when KDC_INTERNAL_TOKEN is unset/empty', () => {
  const prev = process.env.KDC_INTERNAL_TOKEN;
  delete process.env.KDC_INTERNAL_TOKEN;
  try {
    assert.equal(isValidInternalToken('anything'), false);
    process.env.KDC_INTERNAL_TOKEN = '';
    assert.equal(isValidInternalToken('anything'), false);
  } finally {
    if (prev === undefined) delete process.env.KDC_INTERNAL_TOKEN;
    else process.env.KDC_INTERNAL_TOKEN = prev;
  }
});

test('isValidInternalToken: length-mismatch input does not throw', () => {
  const prev = process.env.KDC_INTERNAL_TOKEN;
  process.env.KDC_INTERNAL_TOKEN = 'secret-token-123';
  try {
    assert.doesNotThrow(() => isValidInternalToken('short'));
    assert.equal(isValidInternalToken('short'), false);
  } finally {
    if (prev === undefined) delete process.env.KDC_INTERNAL_TOKEN;
    else process.env.KDC_INTERNAL_TOKEN = prev;
  }
});

// ---------------------------------------------------------------------------
// requireKdcAdmin / hasKdcAdminAccess / requireKdcAdminOrInternal
//
// Regression coverage for the realm-takeover gap: without a role check,
// ANY authenticated caller (not just admins) could set any principal's
// password, mint keytabs, or configure delegation.
// ---------------------------------------------------------------------------

function runRoleMiddleware(mwFn, req) {
  return new Promise(resolve => {
    const res = {
      status(code) {
        return { json: () => resolve({ outcome: 'rejected', code }) };
      },
    };
    mwFn(req, res, () => resolve({ outcome: 'next' }));
  });
}

test('requireKdcAdmin: valid token WITHOUT admin role -> 403', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'user-1', roles: ['user'] } });
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('requireKdcAdmin: valid token WITH admin role -> next()', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'admin-1', roles: ['admin'] } });
  assert.equal(r.outcome, 'next');
});

test('requireKdcAdmin: valid token WITH kdc.admin scope (space-delimited string) -> next()', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'svc-1', scope: 'openid profile kdc.admin' } });
  assert.equal(r.outcome, 'next');
});

test('requireKdcAdmin: valid token WITH kdc.admin in scopes array -> next()', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'svc-2', scopes: ['kdc.admin'] } });
  assert.equal(r.outcome, 'next');
});

test('requireKdcAdmin: realm_access.roles (Keycloak-style) admin role -> next()', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'kc-1', realm_access: { roles: ['admin'] } } });
  assert.equal(r.outcome, 'next');
});

test('requireKdcAdmin: helpdesk role alone is NOT sufficient (deliberately stricter than device secrets)', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'help-1', roles: ['helpdesk'] } });
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('requireKdcAdmin: token with no roles/scopes at all -> 403 (fail closed)', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, { user: { sub: 'user-2' } });
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('requireKdcAdmin: missing req.user entirely -> 403 (fail closed)', async () => {
  const r = await runRoleMiddleware(requireKdcAdmin, {});
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('hasKdcAdminAccess: non-array roles claim (malformed token) does not throw / does not grant access', () => {
  assert.equal(hasKdcAdminAccess({ sub: 'x', roles: 'admin' }), false);
});

test('requireKdcAdminOrInternal: internalService flag passes through without a user at all', async () => {
  const r = await runRoleMiddleware(requireKdcAdminOrInternal, { internalService: true });
  assert.equal(r.outcome, 'next');
});

test('requireKdcAdminOrInternal: no internalService flag AND non-admin user -> 403', async () => {
  const r = await runRoleMiddleware(requireKdcAdminOrInternal, { user: { sub: 'user-3', roles: ['user'] } });
  assert.equal(r.outcome, 'rejected');
  assert.equal(r.code, 403);
});

test('requireKdcAdminOrInternal: no internalService flag but admin user -> next()', async () => {
  const r = await runRoleMiddleware(requireKdcAdminOrInternal, { user: { sub: 'admin-2', roles: ['admin'] } });
  assert.equal(r.outcome, 'next');
});
