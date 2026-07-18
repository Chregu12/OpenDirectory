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

  // POST /api/auth/mfa/verify
  router.post('/api/auth/mfa/verify', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { code } = req.body;

      const valid = await mfaService.verifyCode(userId, code);

      if (valid) {
        await mfaService.enableMFA(userId);
        await auditService.logSecurityEvent('mfa_enabled', userId, req);
      }

      res.json({ valid });
    } catch (error) {
      logger.error('MFA verification error:', error);
      res.status(500).json({ error: 'MFA verification failed' });
    }
  });

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

  return router;
}

module.exports = { createMfaRoutes };
