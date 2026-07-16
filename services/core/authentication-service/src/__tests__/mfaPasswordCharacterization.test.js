'use strict';

/**
 * GOLDEN MASTER characterization tests for the live MFA and Password HTTP
 * endpoints (routes/mfa.js + the password sub-routes of routes/users.js).
 *
 * These tests mount the REAL route factories (createMfaRoutes / createUserRoutes)
 * — the exact modules index.js wires into the running app — behind supertest,
 * with a lightweight in-memory replacement for the DDD user repository and for
 * requireAuth/requireAdmin (which normally come from passport). This avoids
 * booting the full app (Redis/OIDC/session/passport stack) while still
 * exercising real production code: UserAggregate, UserService,
 * AuthenticationManager, the legacy MFAService, and (after wiring)
 * MFAApplicationService / PasswordApplicationService.
 *
 * Purpose: pin down CURRENT observable behavior (status codes + body shapes,
 * including pre-existing quirks/bugs) before any DDD re-wiring, so that after
 * the wiring these same assertions still pass unchanged.
 */

const request = require('supertest');
const express = require('express');
const speakeasy = require('speakeasy');

const { createMfaRoutes } = require('../routes/mfa');
const { createUserRoutes } = require('../routes/users');

const UserAggregate = require('../domain/aggregates/UserAggregate');
const UserService = require('../services/userService');
const AuthenticationManager = require('../services/authenticationManager');
const MFAService = require('../services/mfaService');
const PasswordApplicationService = require('../application/PasswordApplicationService');
const InMemoryTtlCache = require('../infrastructure/cache/InMemoryTtlCache');

// ─── Fake in-memory user repository (implements the IUserRepository surface
//     used by UserService / AuthenticationManager / the DDD application
//     services) ──────────────────────────────────────────────────────────────
class FakeUserRepository {
  constructor() {
    this._byId = new Map();
    this._mfaSecrets = new Map();
  }
  async findById(id) { return this._byId.get(id) || null; }
  async findByUsername(username) {
    for (const u of this._byId.values()) if (u.username === username) return u;
    return null;
  }
  async findByEmail(email) {
    for (const u of this._byId.values()) if (u.email === email) return u;
    return null;
  }
  async save(user) { this._byId.set(user.id, user); return user; }
  async delete(id) { this._byId.delete(id); }
  async exists(id) { return this._byId.has(id); }
  async findAll() { return [...this._byId.values()]; }
  // Extra surface used by the repo-aware branch of the legacy MFAService /
  // by PostgresUserRepository — implemented for completeness even though
  // production does not currently wire a repository into MFAService.
  async saveMFASecret(userId, secret, hashedCodes) {
    this._mfaSecrets.set(userId, { totp_secret: secret, recovery_codes: JSON.stringify(hashedCodes), enabled: false });
  }
  async getMFASecret(userId) { return this._mfaSecrets.get(userId) || null; }
  async disableMFA(userId) { this._mfaSecrets.delete(userId); }
}

function seedUser(repo, overrides = {}) {
  const user = new UserAggregate({
    id: overrides.id || `user-${Math.random().toString(36).slice(2)}`,
    username: overrides.username || 'alice',
    email: overrides.email || 'alice@example.com',
    passwordHash: overrides.passwordHash || '$2a$12$fakehashfakehashfakehashfakehashfakehashfake',
    roles: overrides.roles || ['user'],
    ...overrides,
  });
  repo._byId.set(user.id, user);
  return user;
}

// ─── Auth stubs (substitute for passport, whose only job here is to attach
//     req.user / reject unauthenticated requests) ───────────────────────────
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
function stubRequireAdmin() {
  return [stubRequireAuth(), (req, res, next) => {
    if (!req.user.roles?.includes('admin')) return res.status(403).json({ error: 'Admin access required' });
    next();
  }];
}
function bearer(user) {
  return 'Bearer ' + Buffer.from(JSON.stringify(user)).toString('base64');
}

// ─── Services bag builder ────────────────────────────────────────────────────
function buildServices() {
  const repo = new FakeUserRepository();
  const logger = { info() {}, warn() {}, error() {}, debug() {} };

  const userService = new UserService({ userRepository: repo, logger });
  const authManager = new AuthenticationManager({ userRepository: repo, logger });
  // Matches production wiring exactly: `new MFAService()` — no repository injected.
  const mfaService = new MFAService();

  const auditService = {
    logSecurityEvent: jest.fn().mockResolvedValue(undefined),
    logUserEvent: jest.fn().mockResolvedValue(undefined),
    logFailedAuth: jest.fn().mockResolvedValue(undefined),
    logSuccessfulAuth: jest.fn().mockResolvedValue(undefined),
    logAdminAction: jest.fn().mockResolvedValue(undefined),
  };
  const sessionManager = {
    revokeAllUserSessions: jest.fn().mockResolvedValue(undefined),
    revokeSession: jest.fn().mockResolvedValue(undefined),
    createSession: jest.fn().mockResolvedValue({ id: 'session-1', expiresAt: new Date().toISOString() }),
    getUserSessions: jest.fn().mockResolvedValue([]),
  };

  // Post-wiring collaborator: routes/users.js's password-reset endpoints call
  // this instead of the ad-hoc in-file Map. Built the same way index.js wires
  // it (same token format, same in-memory TTL cache semantics) so that this
  // characterization suite exercises the real wiring, not a stand-in for it.
  const passwordResetCache = new InMemoryTtlCache();
  const passwordAppService = new PasswordApplicationService({
    userRepository: repo,
    cache: passwordResetCache,
    messageBus: null,
    logger,
    tokenGenerator: () => require('crypto').randomBytes(32).toString('hex'),
  });

  const services = {
    authManager,
    userService,
    mfaService,
    auditService,
    sessionManager,
    passwordAppService,
    requireAuth: stubRequireAuth,
    requireAdmin: stubRequireAdmin,
  };

  return { services, repo };
}

function buildApp(router) {
  const app = express();
  app.use(express.json());
  app.use(router);
  return app;
}

describe('MFA + Password live endpoints — GOLDEN MASTER characterization', () => {
  // ═══════════════════════════════════════════════════════════════════════
  // MFA routes (src/routes/mfa.js)
  // ═══════════════════════════════════════════════════════════════════════

  describe('POST /api/auth/mfa/setup', () => {
    it('returns 401 when unauthenticated', async () => {
      const { services } = buildServices();
      const app = buildApp(createMfaRoutes(services));
      const res = await request(app).post('/api/auth/mfa/setup').send({});
      expect(res.status).toBe(401);
    });

    it('returns 200 with secret/qrCode/recoveryCodes/instructions for an authenticated user', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-setup-user-1' });
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .post('/api/auth/mfa/setup')
        .set('Authorization', bearer({ id: user.id }))
        .send({});

      expect(res.status).toBe(200);
      expect(typeof res.body.secret).toBe('string');
      expect(res.body.secret.length).toBeGreaterThan(0);
      expect(res.body.qrCode).toMatch(/^data:image\//);
      expect(Array.isArray(res.body.recoveryCodes)).toBe(true);
      expect(res.body.recoveryCodes).toHaveLength(10);
      expect(res.body).toHaveProperty('instructions');
    });

    it('returns 500 when the MFA service throws', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-setup-user-err' });
      jest.spyOn(services.mfaService, 'setupMFA').mockRejectedValueOnce(new Error('boom'));
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .post('/api/auth/mfa/setup')
        .set('Authorization', bearer({ id: user.id }))
        .send({});

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'MFA setup failed' });
    });
  });

  describe('POST /api/auth/mfa/verify', () => {
    it('returns 401 when unauthenticated', async () => {
      const { services } = buildServices();
      const app = buildApp(createMfaRoutes(services));
      const res = await request(app).post('/api/auth/mfa/verify').send({ code: '123456' });
      expect(res.status).toBe(401);
    });

    it('returns 200 { valid: false } for a wrong/unknown OTP code (no prior setup)', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-verify-user-wrong' });
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .post('/api/auth/mfa/verify')
        .set('Authorization', bearer({ id: user.id }))
        .send({ code: '000000' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ valid: false });
      expect(services.auditService.logSecurityEvent).not.toHaveBeenCalled();
    });

    it('returns 200 { valid: true }, enables MFA, and audits on a correct TOTP code', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-verify-user-correct' });
      const app = buildApp(createMfaRoutes(services));

      // Perform setup first to register a secret for this user id.
      const setupRes = await request(app)
        .post('/api/auth/mfa/setup')
        .set('Authorization', bearer({ id: user.id }))
        .send({});
      const secret = setupRes.body.secret;
      const code = speakeasy.totp({ secret, encoding: 'base32' });

      const res = await request(app)
        .post('/api/auth/mfa/verify')
        .set('Authorization', bearer({ id: user.id }))
        .send({ code });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ valid: true });
      expect(services.auditService.logSecurityEvent).toHaveBeenCalledWith('mfa_enabled', user.id, expect.anything());
    });

    it('returns 500 when the MFA service throws', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-verify-user-err' });
      jest.spyOn(services.mfaService, 'verifyCode').mockRejectedValueOnce(new Error('boom'));
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .post('/api/auth/mfa/verify')
        .set('Authorization', bearer({ id: user.id }))
        .send({ code: '123456' });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'MFA verification failed' });
    });
  });

  describe('POST /api/auth/mfa/disable', () => {
    it('returns 401 when unauthenticated', async () => {
      const { services } = buildServices();
      const app = buildApp(createMfaRoutes(services));
      const res = await request(app).post('/api/auth/mfa/disable').send({ password: 'x' });
      expect(res.status).toBe(401);
    });

    // NOTE — pre-existing behavior being pinned down here, not a desired spec:
    // UserService._toPublic() never includes the password hash (by design, to
    // avoid leaking it through the profile/user-read APIs). This route reads
    // the user via userService.getUserById() and then checks
    // authManager.verifyPassword(password, user.password) — but `user.password`
    // is therefore always undefined, so verifyPassword short-circuits to
    // `false` unconditionally. The route currently returns 401 "Invalid
    // password" for ANY password value, correct or not, whenever the user
    // exists. This characterization intentionally captures that as current
    // ground truth.
    it('returns 401 "Invalid password" even for a plausible password (existing user)', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-disable-user-1' });
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .post('/api/auth/mfa/disable')
        .set('Authorization', bearer({ id: user.id }))
        .send({ password: 'CorrectHorseBatteryStaple1!' });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Invalid password' });
    });

    it('returns 500 when the authenticated user id does not resolve to a user (unknown user)', async () => {
      const { services } = buildServices();
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .post('/api/auth/mfa/disable')
        .set('Authorization', bearer({ id: 'no-such-user' }))
        .send({ password: 'whatever' });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to disable MFA' });
    });
  });

  describe('GET /api/auth/mfa/recovery-codes', () => {
    it('returns 401 when unauthenticated', async () => {
      const { services } = buildServices();
      const app = buildApp(createMfaRoutes(services));
      const res = await request(app).get('/api/auth/mfa/recovery-codes');
      expect(res.status).toBe(401);
    });

    it('returns 200 with an empty list when MFA was never set up', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-codes-user-none' });
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .get('/api/auth/mfa/recovery-codes')
        .set('Authorization', bearer({ id: user.id }));

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ recoveryCodes: [] });
    });

    it('returns 200 with the 10 plaintext codes right after setup (pending, not yet enabled)', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-codes-user-pending' });
      const app = buildApp(createMfaRoutes(services));

      await request(app)
        .post('/api/auth/mfa/setup')
        .set('Authorization', bearer({ id: user.id }))
        .send({});

      const res = await request(app)
        .get('/api/auth/mfa/recovery-codes')
        .set('Authorization', bearer({ id: user.id }));

      expect(res.status).toBe(200);
      expect(res.body.recoveryCodes).toHaveLength(10);
    });

    it('returns 500 when the MFA service throws', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'mfa-codes-user-err' });
      jest.spyOn(services.mfaService, 'getRecoveryCodes').mockRejectedValueOnce(new Error('boom'));
      const app = buildApp(createMfaRoutes(services));

      const res = await request(app)
        .get('/api/auth/mfa/recovery-codes')
        .set('Authorization', bearer({ id: user.id }));

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to get recovery codes' });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Password routes (src/routes/users.js)
  // ═══════════════════════════════════════════════════════════════════════

  describe('POST /api/auth/change-password', () => {
    it('returns 401 when unauthenticated (auth middleware runs before validation)', async () => {
      const { services } = buildServices();
      const app = buildApp(createUserRoutes(services));
      const res = await request(app).post('/api/auth/change-password').send({});
      expect(res.status).toBe(401);
    });

    it('returns 400 when authenticated but body fails validation', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'cp-user-badbody' });
      const app = buildApp(createUserRoutes(services));

      const res = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', bearer({ id: user.id }))
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation failed');
    });

    // NOTE — pre-existing behavior being pinned down here, not a desired spec:
    // same root cause as MFA disable above — userService.getUserById() never
    // returns a password hash, so authManager.verifyPassword() is always
    // false. The endpoint therefore always answers 401 "Current password is
    // incorrect" for a valid, existing user, regardless of the submitted
    // currentPassword.
    it('returns 401 "Current password is incorrect" for a validly-shaped request (existing user)', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'cp-user-1' });
      const app = buildApp(createUserRoutes(services));

      const res = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', bearer({ id: user.id }))
        .send({ currentPassword: 'OldPassword1!', newPassword: 'NewPassword1!' });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Current password is incorrect' });
    });

    it('returns 500 when the authenticated user id does not resolve to a user (unknown user)', async () => {
      const { services } = buildServices();
      const app = buildApp(createUserRoutes(services));

      const res = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', bearer({ id: 'no-such-user' }))
        .send({ currentPassword: 'OldPassword1!', newPassword: 'NewPassword1!' });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to change password' });
    });
  });

  describe('POST /api/auth/reset-password', () => {
    it('returns 200 with a generic message for an unknown email (no user enumeration)', async () => {
      const { services } = buildServices();
      const app = buildApp(createUserRoutes(services));

      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({ email: 'nobody@example.com' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, message: 'If the email exists, a password reset link has been sent' });
    });

    it('returns the exact same 200 generic message for a known email (no user enumeration)', async () => {
      const { services, repo } = buildServices();
      seedUser(repo, { id: 'rp-user-1', email: 'known@example.com' });
      const app = buildApp(createUserRoutes(services));

      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({ email: 'known@example.com' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, message: 'If the email exists, a password reset link has been sent' });
      expect(services.auditService.logUserEvent).toHaveBeenCalledWith(
        'password_reset_requested', 'rp-user-1', expect.anything(),
      );
    });

    it('returns 200 even when the body has no email at all', async () => {
      const { services } = buildServices();
      const app = buildApp(createUserRoutes(services));

      const res = await request(app).post('/api/auth/reset-password').send({});

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });
  });

  describe('POST /api/auth/password-reset/confirm', () => {
    it('returns 400 when token or newPassword is missing', async () => {
      const { services } = buildServices();
      const app = buildApp(createUserRoutes(services));

      const res = await request(app).post('/api/auth/password-reset/confirm').send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'token and newPassword required' });
    });

    it('returns 400 for an unknown/invalid token', async () => {
      const { services } = buildServices();
      const app = buildApp(createUserRoutes(services));

      const res = await request(app)
        .post('/api/auth/password-reset/confirm')
        .send({ token: 'not-a-real-token', newPassword: 'NewPassword1!' });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'Ungültiger oder abgelaufener Token' });
    });

    it('returns 400 for an expired token', async () => {
      const { services, repo } = buildServices();
      seedUser(repo, { id: 'pr-user-expired', email: 'expired@example.com' });
      const app = buildApp(createUserRoutes(services));

      const crypto = require('crypto');
      const randSpy = jest.spyOn(crypto, 'randomBytes').mockReturnValueOnce(Buffer.from('e'.repeat(64), 'hex'));
      const nowSpy = jest.spyOn(Date, 'now');
      try {
        nowSpy.mockReturnValue(1_700_000_000_000);
        await request(app).post('/api/auth/reset-password').send({ email: 'expired@example.com' });

        // Advance well beyond the 1h TTL.
        nowSpy.mockReturnValue(1_700_000_000_000 + 3_700_000);

        const res = await request(app)
          .post('/api/auth/password-reset/confirm')
          .send({ token: 'e'.repeat(64), newPassword: 'NewPassword1!' });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ error: 'Ungültiger oder abgelaufener Token' });
      } finally {
        nowSpy.mockRestore();
        randSpy.mockRestore();
      }
    });

    it('returns 400 "Passwortrichtlinie nicht erfüllt" when a global password policy rejects the new password', async () => {
      const { services, repo } = buildServices();
      seedUser(repo, { id: 'pr-user-policy', email: 'policy@example.com' });
      const app = buildApp(createUserRoutes(services));

      const crypto = require('crypto');
      const randSpy = jest.spyOn(crypto, 'randomBytes').mockReturnValueOnce(Buffer.from('a'.repeat(64), 'hex'));
      global.__od_passwordPolicy = { minLength: 8, requireUppercase: true, requireNumbers: true, requireSymbols: true };
      try {
        await request(app).post('/api/auth/reset-password').send({ email: 'policy@example.com' });

        const res = await request(app)
          .post('/api/auth/password-reset/confirm')
          .send({ token: 'a'.repeat(64), newPassword: 'lowercaseonly' });

        expect(res.status).toBe(400);
        expect(res.body).toHaveProperty('error', 'Passwortrichtlinie nicht erfüllt');
        expect(res.body.details).toEqual(expect.arrayContaining([
          expect.stringContaining('Grossbuchstabe'),
        ]));
      } finally {
        delete global.__od_passwordPolicy;
        randSpy.mockRestore();
      }
    });

    it('returns 200 and resets the password for a valid token', async () => {
      const { services, repo } = buildServices();
      const user = seedUser(repo, { id: 'pr-user-success', email: 'success@example.com' });
      const app = buildApp(createUserRoutes(services));

      const crypto = require('crypto');
      const randSpy = jest.spyOn(crypto, 'randomBytes').mockReturnValueOnce(Buffer.from('b'.repeat(64), 'hex'));
      try {
        await request(app).post('/api/auth/reset-password').send({ email: 'success@example.com' });

        const res = await request(app)
          .post('/api/auth/password-reset/confirm')
          .send({ token: 'b'.repeat(64), newPassword: 'NewPassword1!' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Passwort erfolgreich zurückgesetzt' });
        expect(services.auditService.logUserEvent).toHaveBeenCalledWith(
          'password_reset_completed', user.id, expect.anything(),
        );

        // The token must be single-use.
        const replay = await request(app)
          .post('/api/auth/password-reset/confirm')
          .send({ token: 'b'.repeat(64), newPassword: 'AnotherPassword1!' });
        expect(replay.status).toBe(400);
      } finally {
        randSpy.mockRestore();
      }
    });
  });
});
