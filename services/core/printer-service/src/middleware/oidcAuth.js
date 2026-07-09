'use strict';

// OIDC bearer-token verification middleware (RS256 via JWKS).
// Mirrors services/core/device-service/src/middleware/oidcAuth.js so both
// services share the same auth contract and env var names.

const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

function oidcAuth({ skipPaths = [] } = {}) {
  return async (req, res, next) => {
    if (skipPaths.some(p => req.path === p || req.path.startsWith(p))) return next();
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    try {
      const { payload } = await jwtVerify(auth.slice(7), getJWKS(), { issuer: ISSUER });
      req.user = payload;
      next();
    } catch (err) {
      const status = err.code === 'ERR_JWT_EXPIRED' ? 401 : 403;
      res.status(status).json({ error: 'invalid_token', message: err.message });
    }
  };
}

module.exports = { oidcAuth };
