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

const { oidcAuth } = require('../oidcAuth');

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
