'use strict';

const { principalContext, requirePrincipal } = require('../licenses/LicensePrincipal');

function licenseBinding(source) {
  return async (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'GET' && req.path === '/kiosk') return next();
    const optional = req.method === 'GET' && req.path === '/access';
    try {
      const principal = await source.subject(req.headers.authorization, { issuer: req.user.iss, subject: req.user.sub });
      req.licenseIdentityState = !principal.userId ? 'unlinked' : principal.enabled ? 'active' : 'disabled';
      if (req.licenseIdentityState !== 'active') {
        if (optional) return next();
        return res.status(403).json({ error: 'A linked, enabled directory identity is required', identityState: req.licenseIdentityState });
      }
      req.licensePrincipal = requirePrincipal(principal);
      principalContext.run(principal, next);
    } catch {
      req.licenseIdentityState = 'unavailable';
      if (optional) return next();
      res.status(503).json({ error: 'Authoritative license identity unavailable', identityState: 'unavailable' });
    }
  };
}

module.exports = { licenseBinding };
