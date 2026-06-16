'use strict';
const { Router } = require('express');
const logger = require('../utils/logger');

function createAuditRoutes(services) {
  const router = Router();
  const { auditService, requireAuth, requireAdmin } = services;
  const auth = requireAuth();
  const admin = requireAdmin();

  // GET /api/auth/audit/login-history
  router.get('/api/auth/audit/login-history', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { limit = 50 } = req.query;

      const history = await auditService.getLoginHistory(userId, parseInt(limit));

      res.json({ history });
    } catch (error) {
      logger.error('Get login history error:', error);
      res.status(500).json({ error: 'Failed to get login history' });
    }
  });

  // GET /api/auth/audit/security-events  (admin only)
  router.get('/api/auth/audit/security-events', ...admin, async (req, res) => {
    try {
      const { userId, eventType, startDate, endDate, limit = 100 } = req.query;

      const events = await auditService.getSecurityEvents({
        userId,
        eventType,
        startDate,
        endDate,
        limit: parseInt(limit)
      });

      res.json({ events });
    } catch (error) {
      logger.error('Get security events error:', error);
      res.status(500).json({ error: 'Failed to get security events' });
    }
  });

  return router;
}

module.exports = { createAuditRoutes };
