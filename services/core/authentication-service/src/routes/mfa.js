'use strict';
const { Router } = require('express');
const logger = require('../utils/logger');

function createMfaRoutes(services) {
  const router = Router();
  const { mfaService, userService, auditService, requireAuth } = services;
  const auth = requireAuth();

  // POST /api/auth/mfa/setup
  router.post('/api/auth/mfa/setup', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      const { secret, qrCode, recoveryCodes } = await mfaService.setupMFA(userId);

      res.json({
        secret,
        qrCode,
        recoveryCodes,
        instructions: 'Scan the QR code with your authenticator app and save the recovery codes'
      });
    } catch (error) {
      logger.error('MFA setup error:', error);
      res.status(500).json({ error: 'MFA setup failed' });
    }
  });

  // Shared handler for MFA setup verification. Registered under both
  // /api/auth/mfa/verify (legacy/internal path) and /api/auth/mfa/verify-setup
  // (the path the frontend actually calls — see routes below). Both routes
  // run behind the same real `auth` (requireAuth) middleware; this is a pure
  // alias, not a weaker/duplicate implementation.
  async function verifySetupHandler(req, res) {
    try {
      const userId = req.user.id;
      const { code, token } = req.body;

      const valid = await mfaService.verifyCode(userId, code || token);

      if (valid) {
        await mfaService.enableMFA(userId);
        await auditService.logSecurityEvent('mfa_enabled', userId, req);
      }

      res.json({ valid });
    } catch (error) {
      logger.error('MFA verification error:', error);
      res.status(500).json({ error: 'MFA verification failed' });
    }
  }

  // POST /api/auth/mfa/verify
  router.post('/api/auth/mfa/verify', auth, verifySetupHandler);

  // POST /api/auth/mfa/verify-setup
  // Alias for /api/auth/mfa/verify — the frontend's MFA setup flow calls this
  // path name specifically. Same handler, same requireAuth middleware.
  router.post('/api/auth/mfa/verify-setup', auth, verifySetupHandler);

  // POST /api/auth/mfa/disable
  router.post('/api/auth/mfa/disable', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { password } = req.body;

      // Verify password before disabling MFA.
      // NOTE: user.password is never populated — UserService._toPublic()
      // intentionally omits the password hash from every user object it
      // returns. Comparing against user.password here used to always be
      // `undefined`, so verifyPassword() short-circuited to false and this
      // endpoint returned 401 for every user regardless of the submitted
      // password. verifyCurrentPassword() fetches the hash internally and
      // never returns it, so the hash stays out of this route entirely.
      const user = await userService.getUserById(userId);
      if (!user) {
        // Falls into the catch block below -> 500 "Failed to disable MFA",
        // matching this route's existing behavior for an unresolvable user id
        // (previously an accidental TypeError from `user.password` on null).
        throw new Error('User not found');
      }
      const validPassword = await userService.verifyCurrentPassword(userId, password);

      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid password' });
      }

      await mfaService.disableMFA(userId);
      await auditService.logSecurityEvent('mfa_disabled', userId, req);

      res.json({
        success: true,
        message: 'MFA disabled successfully'
      });
    } catch (error) {
      logger.error('MFA disable error:', error);
      res.status(500).json({ error: 'Failed to disable MFA' });
    }
  });

  // GET /api/auth/mfa/status
  // The frontend polls this to know whether MFA is currently enabled for the
  // logged-in user. Behind the same real requireAuth middleware as every
  // other MFA route — no anonymous access.
  router.get('/api/auth/mfa/status', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      const user = await userService.getUserById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ enabled: Boolean(user.mfaEnabled) });
    } catch (error) {
      logger.error('MFA status error:', error);
      res.status(500).json({ error: 'Failed to get MFA status' });
    }
  });

  // GET /api/auth/mfa/recovery-codes
  router.get('/api/auth/mfa/recovery-codes', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      const codes = await mfaService.getRecoveryCodes(userId);

      res.json({ recoveryCodes: codes });
    } catch (error) {
      logger.error('Recovery codes error:', error);
      res.status(500).json({ error: 'Failed to get recovery codes' });
    }
  });

  // ─── Login-time TOTP challenge (restored, pre-god-file-split) ─────────────
  //
  // Separate subsystem from the class-based mfaService setup/verify-setup/
  // status routes above: a plain speakeasy secret keyed by userId, restored
  // from `git show 1617f2c^:services/core/authentication-service/src/
  // index.js` (~line 1685). Restoring it matters beyond just these two
  // routes: src/routes/auth.js's login handler already reads
  // `global.__od_userMfaSecrets` / `global.__od_speakeasy` to challenge for
  // a TOTP code mid-login (see its `hasTotpMfa` branch) — those globals were
  // never set anywhere after the god-file split, so that branch has been
  // permanently dead code. Setting them here (once, at route-factory init,
  // same lifetime as every other module-scoped store in this service) wires
  // it back up.
  //
  // UPDATE — the two MFA subsystems ARE unified, via this exact Map.
  // `mfaService.enableMFA()` (src/services/mfaService.js, called by the
  // verifySetupHandler above once a submitted TOTP code is confirmed) does
  // `global.__od_userMfaSecrets.set(uid, secret)` on success, and
  // `mfaService.disableMFA()` removes it again. Because `userMfaSecrets`
  // above reuses the existing `global.__od_userMfaSecrets` Map (creating one
  // only if none exists yet) rather than always allocating a fresh Map, and
  // this route factory runs once at app start — before any request can call
  // setup/verify — every write mfaService makes lands in this same Map by
  // reference. So a user who completes `/api/auth/mfa/setup` +
  // `/api/auth/mfa/verify-setup` DOES end up in a state where the
  // login-time challenge (`validate` below, and the identical inline check
  // in routes/auth.js's login handler) fires and accepts their TOTP code.
  // See src/__tests__/mfaLoginTimeUnification.test.js for an end-to-end
  // proof (setup → verify-setup → login mfaRequired → correct/incorrect
  // TOTP). An earlier version of this comment claimed no endpoint wrote
  // into this map — that was stale/incorrect by the time these two routes
  // were restored; mfaService.enableMFA()'s write predates this file.
  let speakeasy;
  try { speakeasy = require('speakeasy'); } catch { /* optional dependency not installed */ }
  const userMfaSecrets = global.__od_userMfaSecrets instanceof Map ? global.__od_userMfaSecrets : new Map();
  global.__od_userMfaSecrets = userMfaSecrets;
  global.__od_speakeasy = speakeasy;

  // POST /api/auth/mfa/validate
  // Deliberately UNAUTHENTICATED (no `auth` middleware): this is called
  // *during* the login flow, before the caller holds a session JWT — by
  // definition there is no Bearer token to require yet. It performs no
  // mutation; it only checks a submitted TOTP code against an
  // already-configured secret for the given userId, matching the pre-split
  // semantics exactly (400 for a missing field, 400 when the user has no
  // configured secret, 401 for a wrong code, 200 {valid:true} for a match).
  router.post('/api/auth/mfa/validate', async (req, res) => {
    if (!speakeasy) return res.status(501).json({ error: 'TOTP library not installed' });
    const { userId, token } = req.body;
    if (!userId || !token) return res.status(400).json({ error: 'userId and token required' });
    const secret = userMfaSecrets.get(userId);
    if (!secret) return res.status(400).json({ error: 'MFA not configured for user' });
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 2 });
    if (!valid) return res.status(401).json({ error: 'Ungültiger TOTP-Code' });
    res.json({ valid: true });
  });

  // DELETE /api/auth/mfa/disable
  // Clears the login-time TOTP secret (the Map above) for the authenticated
  // caller — distinct from POST /api/auth/mfa/disable above, which disables
  // the class-based mfaService MFA and requires re-verifying the current
  // password. This mirrors the pre-split behavior exactly (no password
  // check) and sits behind the same real requireAuth (real JWT
  // verification, not a presence check) as every other route in this file —
  // an unauthenticated request is rejected with 401 before ever touching
  // req.user.
  router.delete('/api/auth/mfa/disable', auth, (req, res) => {
    const userId = req.user.id;
    userMfaSecrets.delete(userId);
    res.json({ success: true });
  });

  return router;
}

module.exports = { createMfaRoutes };
