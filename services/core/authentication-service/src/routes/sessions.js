'use strict';
const { Router } = require('express');
const logger = require('../utils/logger');

function createSessionRoutes(services) {
  const router = Router();
  const { sessionManager, auditService, requireAuth } = services;
  const auth = requireAuth();

  // GET /api/auth/sessions
  router.get('/api/auth/sessions', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      const sessions = await sessionManager.getUserSessions(userId);

      res.json({ sessions });
    } catch (error) {
      logger.error('Get sessions error:', error);
      res.status(500).json({ error: 'Failed to get sessions' });
    }
  });

  // DELETE /api/auth/sessions/:sessionId
  router.delete('/api/auth/sessions/:sessionId', auth, async (req, res) => {
    try {
      const { sessionId } = req.params;
      const userId = req.user.id;

      await sessionManager.revokeSession(sessionId, userId);
      await auditService.logSecurityEvent('session_revoked', userId, req);

      res.json({
        success: true,
        message: 'Session revoked'
      });
    } catch (error) {
      logger.error('Revoke session error:', error);
      res.status(500).json({ error: 'Failed to revoke session' });
    }
  });

  // POST /api/auth/sessions/revoke-all
  router.post('/api/auth/sessions/revoke-all', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      await sessionManager.revokeAllUserSessions(userId);
      await auditService.logSecurityEvent('all_sessions_revoked', userId, req);

      res.json({
        success: true,
        message: 'All sessions revoked'
      });
    } catch (error) {
      logger.error('Revoke all sessions error:', error);
      res.status(500).json({ error: 'Failed to revoke sessions' });
    }
  });

  return router;
}

module.exports = { createSessionRoutes };
