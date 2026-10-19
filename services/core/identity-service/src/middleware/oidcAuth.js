'use strict';

const { createRemoteJWKSet, jwtVerify } = require('jose');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const accessState = createAccessStateClient();

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

function matchesPath(list, path) {
  return list.includes(path);
}

/**
 * options.skipPaths - paths that bypass auth entirely (health probes).
 */
function oidcAuth({ skipPaths = [] } = {}) {
  return async (req, res, next) => {
    if (matchesPath(skipPaths, req.path)) return next();

    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    try {
      const { payload } = await jwtVerify(auth.slice(7), getJWKS(), { issuer: ISSUER, audience: process.env.OIDC_AUDIENCE || 'opendirectory-api', algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti'] });
      if (payload.token_use !== 'access') return res.status(403).json({ error: 'invalid_token_purpose' });
      await accessState(auth, payload);
      req.user = payload;
      next();
    } catch (err) {
      const status = err.status || (err.code === 'ERR_JWT_EXPIRED' || err.claim === 'sub' ? 401 : 403);
      res.status(status).json({ error: 'invalid_token', message: err.message });
    }
  };
}

module.exports = { oidcAuth };
