'use strict';
const { Router } = require('express');
const logger = require('../utils/logger');

function createMfaRoutes(services) {
  const router = Router();
  const { mfaService, authManager, userService, auditService, requireAuth } = services;
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

      // Verify password before disabling MFA
      const user = await userService.getUserById(userId);
      const validPassword = await authManager.verifyPassword(password, user.password);

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
