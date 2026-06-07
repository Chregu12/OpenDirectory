'use strict';

const { verifyToken } = require('../../../../shared/oidcAuth');

// Paths that do not require authentication
const PUBLIC_PATHS = new Set([
  '/health',
  '/api/quick/health',
  '/api/quick/status',
]);

/**
 * Bearer-token authentication middleware for quick-actions.
 *
 * Accepts two token forms:
 *  1. Service-account bypass — "Bearer svc-<SERVICE_TOKEN>" where SERVICE_TOKEN
 *     matches process.env.SERVICE_TOKEN.  Grants role="service".
 *  2. OIDC JWT — verified against the JWKS endpoint (RS256) via shared oidcAuth.
 *     Decoded payload is attached to req.user.
 *
 * Public paths (/health, /api/quick/health, /api/quick/status) are always
 * allowed through without a token.
 *
 * Responses:
 *  401  — Authorization header missing or malformed / token expired
 *  403  — Token present but invalid / wrong issuer / bad signature
 */
async function authMiddleware(req, res, next) {
  // Let public paths through unconditionally
  if (PUBLIC_PATHS.has(req.path)) {
    return next();
  }

  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Bearer token required',
    });
  }

  const token = authHeader.slice(7); // strip "Bearer "

  // ── Service-account bypass for backwards compatibility during migration ────
  const serviceToken = process.env.SERVICE_TOKEN;
  if (serviceToken && token === `svc-${serviceToken}`) {
    req.user = { sub: 'service-account', scope: 'openid roles' };
    return next();
  }

  // ── JWKS-based RS256 verification ─────────────────────────────────────────
  try {
    const payload = await verifyToken(token);
    req.user = payload;
    return next();
  } catch (err) {
    if (err.code === 'ERR_JWT_EXPIRED') {
      return res.status(401).json({ error: 'token_expired' });
    }
    return res.status(403).json({ error: 'invalid_token', error_description: err.message });
  }
}

module.exports = authMiddleware;
