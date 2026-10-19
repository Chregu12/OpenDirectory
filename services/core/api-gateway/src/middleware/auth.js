'use strict';

const { createRemoteJWKSet, jwtVerify } = require('jose');
const { isPublic, roles } = require('./gatewayAccess');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');

class GatewayAuthError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function createAuthenticator({ issuer = process.env.OIDC_ISSUER || 'https://opendirectory.local', audience = process.env.OIDC_AUDIENCE || 'opendirectory-api',
  jwksUri = process.env.JWKS_URI || 'http://oauth-provider:3010/.well-known/jwks.json', accessState = createAccessStateClient() } = {}) {
  if (!issuer || !audience || !jwksUri) throw new Error('Gateway issuer, API audience and JWKS are required');
  const url = new URL(jwksUri);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error('Invalid gateway JWKS URL');
  const jwks = createRemoteJWKSet(url, { timeoutDuration: 5000, cooldownDuration: 1000, cacheMaxAge: 3600000 });
  const authenticate = async req => {
    if (req.query && (Object.hasOwn(req.query, 'token') || Object.hasOwn(req.query, 'api_key'))) throw new GatewayAuthError(401, 'URL credentials are not accepted');
    const authorization = req.headers.authorization;
    if (req.headers['x-api-key'] || typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) throw new GatewayAuthError(401, 'An OIDC bearer access token is required');
    let payload;
    try {
      ({ payload } = await jwtVerify(authorization.slice(7), jwks, { algorithms: ['RS256'], issuer, audience, requiredClaims: ['sub', 'exp', 'iat', 'jti'] }));
    } catch (error) {
      if (['ERR_JWKS_TIMEOUT', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code)) throw new GatewayAuthError(503, 'Token verification source unavailable');
      throw new GatewayAuthError(401, 'Invalid or expired access token');
    }
    if (payload.token_use !== 'access' || typeof payload.sub !== 'string' || !payload.sub.trim() || payload.sub.length > 255
      || !Number.isFinite(payload.exp) || !Number.isFinite(payload.iat) || payload.exp <= payload.iat || payload.iat > Date.now() / 1000 + 30) throw new GatewayAuthError(401, 'Invalid access-token claims');
    await accessState(authorization, payload);
    return payload;
  };
  const middleware = async (req, res, next) => {
    if (isPublic(req)) return next();
    try {
      req.user = await authenticate(req);
      req.auth = { type: 'oidc', userId: req.user.sub, username: req.user.preferred_username || req.user.name || req.user.sub,
        roles: roles(req.user), permissions: Array.isArray(req.user.permissions) ? req.user.permissions.filter(permission => typeof permission === 'string') : [], isAdmin: roles(req.user).includes('admin') };
      next();
    } catch (error) {
      if (error.status === 401) res.set('WWW-Authenticate', 'Bearer');
      res.status(error.status || 503).json({ error: error.message || 'Token verification unavailable' });
    }
  };
  return { authenticate, middleware };
}

const auth = createAuthenticator();
module.exports = auth.middleware;
module.exports.authenticate = auth.authenticate;
module.exports.createAuthenticator = createAuthenticator;
module.exports.GatewayAuthError = GatewayAuthError;
module.exports.requireAdmin = () => (req, res, next) => roles(req.user).includes('admin') ? next() : res.status(403).json({ error: 'Admin access required' });
