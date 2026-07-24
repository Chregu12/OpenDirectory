'use strict';
const jwt = require('jsonwebtoken');
const config = require('../utils/config');

/**
 * requireBearerAuth
 *
 * Real JWT verification (same secret/signing scheme as the rest of the
 * service — see utils/tokenService.js) without the additional DB user
 * lookup + Zero-Trust re-evaluation that the passport 'jwt' strategy (see
 * index.js requireAuth()) performs on every request. Used for the PIM,
 * service-account, and directory (OUs / domain config) routes, where the
 * authenticated principal's identity claims (sub, username, roles) carried
 * in the token itself are sufficient and neither route needs the extra DB
 * round-trip.
 *
 * This replaces the pre-god-file-split `requireBearer` middleware, which
 * only checked for the *presence* of an Authorization header and never
 * verified anything about the token — meaning any caller could forge an
 * arbitrary Bearer value and reach these endpoints. This middleware verifies
 * the token's signature and expiry; a missing, malformed, expired, or
 * tampered token is rejected with 401 before the route handler runs, so no
 * anonymous directory mutation is possible.
 */
function requireBearerAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const match = /^Bearer\s+(.+)$/i.exec(authHeader);
  if (!match) {
    return res.status(401).json({ error: 'Authorization: Bearer token required' });
  }

  try {
    const decoded = jwt.verify(match[1], config.jwt.secret);
    req.user = {
      id: decoded.sub,
      username: decoded.username,
      roles: decoded.roles || [],
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireBearerAuth };
