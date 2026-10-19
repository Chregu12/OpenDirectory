'use strict';

/**
 * MFA subsystem unification — end-to-end proof.
 *
 * There are two MFA "subsystems" in this service:
 *   - the class-based `mfaService` (setup / verify-setup / status / disable),
 *     driven from src/routes/mfa.js and backed by MFAService
 *     (src/services/mfaService.js);
 *   - a login-time TOTP challenge, read inline by src/routes/auth.js's login
 *     handler (and duplicated as a standalone check at
 *     POST /api/auth/mfa/validate in src/routes/mfa.js) directly off
 *     `global.__od_userMfaSecrets` / `global.__od_speakeasy`.
 *
 * A stale comment in src/routes/mfa.js used to claim that nothing writes
 * into `global.__od_userMfaSecrets`, i.e. that a user who completes the
 * class-based setup flow could never satisfy the login-time challenge.
 * That claim does not match the actual code: MFAService.enableMFA()
 * (src/services/mfaService.js) already does
 * `global.__od_userMfaSecrets.set(uid, secret)` on successful setup
 * verification — and routes/mfa.js's own route-factory function creates
 * `global.__od_userMfaSecrets` (if it doesn't exist yet) BEFORE any setup
 * call, so both sides share the exact same Map instance by reference. The
 * two subsystems were already unified; this suite locks that behavior in
 * with a real, unmocked MFAService + real speakeasy TOTP codes, and
 * exercises the actual HTTP surface end-to-end: setup → verify-setup
 * (enable) → login (mfaRequired challenge → correct/incorrect TOTP code).
 */

const request = require('supertest');
const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const speakeasy = require('speakeasy');

const { createMfaRoutes } = require('../routes/mfa');
const { createAuthRoutes } = require('../routes/auth');
const MFAService = require('../services/mfaService');

// ─── Auth stub reused from mfaPasswordCharacterization.test.js's pattern ───────
function stubRequireAuth() {
  return (req, res, next) => {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    try {
      req.user = JSON.parse(Buffer.from(h.slice(7), 'base64').toString('utf8'));
      return next();
    } catch {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  };
}
function bearer(user) {
  return 'Bearer ' + Buffer.from(JSON.stringify(user)).toString('base64');
}

// ─── Minimal real 'local' passport strategy for this file only. Jest gives
//     each test file its own module registry, so registering a strategy on
//     the shared `passport` singleton here does not leak into other test
//     files or production code. ────────────────────────────────────────────
const KNOWN_USERS = new Map([
  ['mfa-login-user-1', { id: 'mfa-login-user-1', username: 'mfalogin', password: 'CorrectHorseBatteryStaple1!', roles: ['user'], permissions: [] }],
]);

passport.use('local', new LocalStrategy(
  { usernameField: 'username', passwordField: 'password' },
  (username, password, done) => {
    const match = [...KNOWN_USERS.values()].find(u => u.username === username);
    if (!match || match.password !== password) {
      return done(null, false, { message: 'Invalid credentials' });
    }
    const { password: _pw, ...safe } = match;
    return done(null, safe);
  },
));

function buildApp() {
  const mfaService = new MFAService(); // real, unmocked — same class production wires

  const tokenService = {
    generateAccessToken: jest.fn().mockResolvedValue('access-tok'),
    generateRefreshToken: jest.fn().mockResolvedValue('refresh-tok'),
    generateTempToken: jest.fn().mockResolvedValue('temp-tok'),
  };
  const sessionManager = {
    createSession: jest.fn().mockResolvedValue({ id: 'session-1', expiresAt: new Date().toISOString() }),
  };
  const auditService = {
    logFailedAuth: jest.fn().mockResolvedValue(undefined),
    logSuccessfulAuth: jest.fn().mockResolvedValue(undefined),
    logSecurityEvent: jest.fn().mockResolvedValue(undefined),
  };

  const services = {
    authManager: {}, // unused by routes/auth.js's login handler directly (real strategy is stubbed above)
    tokenService,
    mfaService,
    sessionManager,
    auditService,
    zeroTrust: {}, // unused by routes/auth.js (zero-trust evaluation lives in index.js's passport wiring, not here)
    loginAttemptsCounter: null,
    userService: { getUserById: jest.fn() },
    requireAuth: stubRequireAuth,
  };

  const app = express();
  app.use(express.json());
  app.use(createMfaRoutes(services));
  app.use(passport.initialize());
  app.use(createAuthRoutes(services));

  return { app, services };
}

describe('MFA subsystem unification — setup/enable feeds the login-time TOTP challenge', () => {
  it('a user who never sets up MFA logs in normally, without any TOTP challenge', async () => {
    const { app } = buildApp();

    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'mfalogin', password: 'CorrectHorseBatteryStaple1!' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success', true);
  });

  it('setup alone (no verify-setup) does NOT gate login — a pending, unconfirmed secret must not challenge the user', async () => {
    const { app } = buildApp();
    const user = KNOWN_USERS.get('mfa-login-user-1');

    await request(app)
      .post('/api/auth/mfa/setup')
      .set('Authorization', bearer({ id: user.id }))
      .send({});

    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'mfalogin', password: 'CorrectHorseBatteryStaple1!' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success', true);
  });

  it('setup -> verify-setup (enable) -> login now requires + accepts the TOTP code, and rejects a wrong one', async () => {
    const { app, services } = buildApp();
    const user = KNOWN_USERS.get('mfa-login-user-1');

    // 1) Setup — mints a secret (class-based mfaService).
    const setupRes = await request(app)
      .post('/api/auth/mfa/setup')
      .set('Authorization', bearer({ id: user.id }))
      .send({});
    expect(setupRes.status).toBe(200);
    const secret = setupRes.body.secret;

    // 2) Verify-setup with a correct code — this is what calls
    //    mfaService.enableMFA(), which writes the secret into
    //    global.__od_userMfaSecrets, the exact Map routes/auth.js's login
    //    handler reads from.
    const enableCode = speakeasy.totp({ secret, encoding: 'base32' });
    const verifyRes = await request(app)
      .post('/api/auth/mfa/verify-setup')
      .set('Authorization', bearer({ id: user.id }))
      .send({ code: enableCode });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body).toEqual({ valid: true });
    expect(services.auditService.logSecurityEvent).toHaveBeenCalledWith('mfa_enabled', user.id, expect.anything());

    // 3) Login without an mfaCode — must now be challenged (202, mfaRequired).
    const challengeRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'mfalogin', password: 'CorrectHorseBatteryStaple1!' });
    expect(challengeRes.status).toBe(202);
    expect(challengeRes.body).toEqual({ mfaRequired: true, userId: user.id });

    // 4) Login with a WRONG TOTP code — must be rejected.
    const wrongRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'mfalogin', password: 'CorrectHorseBatteryStaple1!', mfaCode: '000000' });
    expect(wrongRes.status).toBe(401);
    expect(wrongRes.body).toEqual({ error: 'Ungültiger TOTP-Code' });

    // 5) Login with the CORRECT TOTP code (freshly generated — a code can
    //    only be reused across steps 2-5 if the clock step hasn't rolled
    //    over, so generate it fresh here) — must succeed.
    const loginCode = speakeasy.totp({ secret, encoding: 'base32' });
    const okRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'mfalogin', password: 'CorrectHorseBatteryStaple1!', mfaCode: loginCode });
    expect(okRes.status).toBe(200);
    expect(okRes.body).toHaveProperty('success', true);
    expect(okRes.body.tokens).toHaveProperty('accessToken', 'access-tok');
    expect(services.auditService.logSuccessfulAuth).toHaveBeenCalledWith(user.id, expect.anything(), 'local');
  });

  it('the same shared state also gates the standalone POST /api/auth/mfa/validate endpoint identically', async () => {
    const { app } = buildApp();
    const user = KNOWN_USERS.get('mfa-login-user-1');

    const setupRes = await request(app)
      .post('/api/auth/mfa/setup')
      .set('Authorization', bearer({ id: user.id }))
      .send({});
    const secret = setupRes.body.secret;
    const enableCode = speakeasy.totp({ secret, encoding: 'base32' });
    await request(app)
      .post('/api/auth/mfa/verify-setup')
      .set('Authorization', bearer({ id: user.id }))
      .send({ code: enableCode });

    const validateCode = speakeasy.totp({ secret, encoding: 'base32' });
    const validateRes = await request(app)
      .post('/api/auth/mfa/validate')
      .send({ userId: user.id, token: validateCode });

    expect(validateRes.status).toBe(200);
    expect(validateRes.body).toEqual({ valid: true });
  });
});
