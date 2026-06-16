'use strict';
const { Router } = require('express');
const config = require('../utils/config');
const logger = require('../utils/logger');

function createZeroTrustRoutes(services) {
  const router = Router();
  const { zeroTrust, auditService, requireAuth } = services;
  const auth = requireAuth();

  // POST /api/auth/verify-device
  router.post('/api/auth/verify-device', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { deviceId, deviceInfo } = req.body;

      const verified = await zeroTrust.verifyDevice(userId, deviceId, deviceInfo);

      res.json({ verified });
    } catch (error) {
      logger.error('Device verification error:', error);
      res.status(500).json({ error: 'Device verification failed' });
    }
  });

  // POST /api/auth/verify-location
  router.post('/api/auth/verify-location', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const location = {
        ip: req.ip,
        country: req.headers['cf-ipcountry'],
        ...req.body
      };

      const verified = await zeroTrust.verifyLocation(userId, location);

      res.json({ verified });
    } catch (error) {
      logger.error('Location verification error:', error);
      res.status(500).json({ error: 'Location verification failed' });
    }
  });

  // GET /api/auth/trust-score
  router.get('/api/auth/trust-score', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      const score = await zeroTrust.calculateTrustScore(req, req.user);

      res.json({
        score,
        factors: await zeroTrust.getTrustFactors(userId),
        threshold: config.zeroTrust.minTrustScore
      });
    } catch (error) {
      logger.error('Trust score error:', error);
      res.status(500).json({ error: 'Failed to calculate trust score' });
    }
  });

  // POST /api/auth/step-up
  router.post('/api/auth/step-up', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { method, value } = req.body;

      const result = await zeroTrust.performStepUp(userId, method, value);

      if (result.success) {
        await auditService.logSecurityEvent('step_up_success', userId, req);
      }

      res.json(result);
    } catch (error) {
      logger.error('Step-up auth error:', error);
      res.status(500).json({ error: 'Step-up authentication failed' });
    }
  });

  return router;
}

module.exports = { createZeroTrustRoutes };
