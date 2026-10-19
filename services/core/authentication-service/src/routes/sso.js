'use strict';
const { Router } = require('express');
const config = require('../utils/config');
const logger = require('../utils/logger');

function createSsoRoutes(services) {
  const router = Router();
  const { authManager } = services;

  // GET /api/auth/sso/providers
  router.get('/api/auth/sso/providers', async (req, res) => {
    try {
      const providers = await authManager.getSSOProviders();

      res.json({ providers });
    } catch (error) {
      logger.error('Get SSO providers error:', error);
      res.status(500).json({ error: 'Failed to get SSO providers' });
    }
  });

  // GET /api/auth/sso/:provider
  router.get('/api/auth/sso/:provider', async (req, res) => {
    try {
      const { provider } = req.params;

      const authUrl = await authManager.initiateSSOLogin(provider);

      res.redirect(authUrl);
    } catch (error) {
      logger.error('SSO login error:', error);
      res.status(500).json({ error: 'SSO login failed' });
    }
  });

  // GET /api/auth/sso/:provider/callback
  router.get('/api/auth/sso/:provider/callback', async (req, res) => {
    try {
      const { provider } = req.params;

      const result = await authManager.handleSSOCallback(provider, req.query);

      if (result.success) {
        res.redirect(`${config.frontend.url}/auth/success?token=${result.token}`);
      } else {
        res.redirect(`${config.frontend.url}/auth/error`);
      }
    } catch (error) {
      logger.error('SSO callback error:', error);
      res.redirect(`${config.frontend.url}/auth/error`);
    }
  });

  return router;
}

module.exports = { createSsoRoutes };
