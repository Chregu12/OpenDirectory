'use strict';

const jwt = require('jsonwebtoken');

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
 *  2. Signed JWT  — verified with process.env.JWT_SECRET.  Decoded payload
 *     is attached to req.user.
 *
 * Public paths (/health, /api/quick/health, /api/quick/status) are always
 * allowed through without a token.
 *
 * Responses:
 *  401  — Authorization header missing or malformed
 *  403  — Token present but invalid / expired / wrong secret
 */
function authMiddleware(req, res, next) {
  // Let public paths through unconditionally
  if (PUBLIC_PATHS.has(req.path)) {
    return next();
  }

  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Authorization header missing or malformed. Expected: Bearer <token>',
    });
  }

  const token = authHeader.slice(7); // strip "Bearer "

  // ── Service-account bypass ────────────────────────────────────────────────
  const serviceToken = process.env.SERVICE_TOKEN;
  if (serviceToken && token === `svc-${serviceToken}`) {
    req.user = { sub: 'service-account', role: 'service' };
    return next();
  }

  // ── JWT verification ──────────────────────────────────────────────────────
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('[auth] JWT_SECRET env var is not set — cannot verify tokens');
    return res.status(500).json({
      success: false,
      error: 'Server misconfiguration: authentication unavailable',
    });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    return next();
  } catch (err) {
    const message =
      err.name === 'TokenExpiredError'
        ? 'Token has expired'
        : 'Invalid or tampered token';

    return res.status(403).json({ success: false, error: message });
  }
}

module.exports = authMiddleware;
