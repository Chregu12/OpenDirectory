'use strict';
const jwt = require('jsonwebtoken');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const { requireBearerAuth, requireAdminBearerAuth } = require('./bearerAuth');

const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';
const AUDIENCE = process.env.OIDC_AUDIENCE || 'opendirectory-api';
const JWKS_URI = process.env.JWKS_URI || 'http://oauth-provider:3010/.well-known/jwks.json';
const accessState = createAccessStateClient();
let jwks;

function getJwks() {
  if (!jwks) jwks = createRemoteJWKSet(new URL(JWKS_URI), { timeoutDuration: 2500, cooldownDuration: 1000, cacheMaxAge: 3600000 });
  return jwks;
}

function bearerAuth({ adminOnly = false } = {}) {
  const legacyAuth = adminOnly ? requireAdminBearerAuth : requireBearerAuth;
  return async (req, res, next) => {
    const match = /^Bearer\s+([A-Za-z0-9._~-]{1,16384})$/i.exec(req.headers.authorization || '');
    const decoded = match && jwt.decode(match[1], { complete: true });
    if (decoded?.header?.alg === 'HS256') return legacyAuth(req, res, next);
    if (decoded?.header?.alg !== 'RS256') return res.status(401).json({ error: 'Invalid or expired token' });

    try {
      const { payload, protectedHeader } = await jwtVerify(match[1], getJwks(), {
        issuer: ISSUER, audience: AUDIENCE, algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti'],
      });
      const roles = Array.isArray(payload.roles) ? payload.roles.filter(role => typeof role === 'string') : [];
      if ((protectedHeader.typ !== undefined && protectedHeader.typ !== 'JWT') || payload.token_use !== 'access' || payload.actor_type !== 'user'
        || typeof payload.sub !== 'string' || !payload.sub.trim()) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
      await accessState(req.headers.authorization, payload);
      if (adminOnly && !roles.includes('admin')) return res.status(403).json({ error: 'Admin access required' });
      req.user = { id: payload.sub, username: payload.preferred_username || payload.name || payload.sub, roles };
      return next();
    } catch (error) {
      const unavailable = error.status === 503 || ['ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code)
        || error instanceof TypeError;
      return res.status(unavailable ? 503 : 401).json({ error: unavailable ? 'Token verification source unavailable' : 'Invalid or expired token' });
    }
  };
}

module.exports = { verifiedBearerAuth: bearerAuth };
