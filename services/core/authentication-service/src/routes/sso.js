'use strict';
const { Router } = require('express');

function createSsoRoutes() {
  const router = Router();
  // Legacy callbacks did not validate state or ID tokens and put JWTs in redirect URLs.
  router.use('/api/auth/sso', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.status(410).json({ error: 'legacy_sso_retired', replacement: 'oauth-provider /oauth/authorize' });
  });
  return router;
}

module.exports = { createSsoRoutes };
