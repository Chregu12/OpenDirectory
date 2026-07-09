const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// Plain prefix matcher — same semantics as the previous skipPaths check
// (exact match or the request path starts with the listed path).
function matchesPrefix(list, path) {
  return list.some(p => path === p || path.startsWith(p));
}

/**
 * Matches enrollmentPaths entries against a request path.
 *
 * Two entry forms are supported:
 *   - '/foo/bar'  → prefix match (path === '/foo/bar' or starts with it).
 *     Used for fixed routes such as '/api/devices/report-hardware'.
 *   - '*suffix'   → suffix match (path ends with 'suffix').
 *     Used for routes with a variable id segment, e.g. '*\/driver-recommendations'
 *     matches '/api/devices/:id/driver-recommendations' without also matching
 *     the generic '/api/devices' or '/api/devices/:id' CRUD routes.
 */
function matchesEnrollmentPath(list, path) {
  return list.some(p => {
    if (p.startsWith('*')) return path.endsWith(p.slice(1));
    // startsWith(p + '/') — never a bare startsWith(p) — so an entry like
    // '/api/devices/report-hardware' cannot also match the generic CRUD
    // route '/api/devices/report-hardwareXYZ' and hand it the enrollment
    // bypass. The trailing slash enforces a path-segment boundary.
    return path === p || path.startsWith(p + '/');
  });
}

/**
 * Constant-time comparison of the caller-supplied enrollment token against
 * DEVICE_ENROLLMENT_TOKEN. Always returns false (never throws) when the env
 * var is unset/empty or the header is missing — an unconfigured deployment
 * must not silently accept the bypass, and mismatched-length inputs must
 * not short-circuit before reaching a constant-time comparison.
 */
function isValidEnrollmentToken(headerValue) {
  const expected = process.env.DEVICE_ENROLLMENT_TOKEN;
  if (!expected || !headerValue || typeof headerValue !== 'string') return false;

  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(headerValue);
  if (expectedBuf.length !== providedBuf.length) return false;

  try {
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
  } catch {
    return false;
  }
}

/**
 * OIDC bearer-token auth middleware for the device-service.
 *
 * options.skipPaths       - paths that bypass auth entirely (health probes).
 * options.enrollmentPaths - paths that, in addition to a normal OIDC JWT,
 *                           accept the shared DEVICE_ENROLLMENT_TOKEN via the
 *                           `x-enrollment-token` header (see
 *                           services/core/samba-ad-dc/src/middleware/oidcAuth.js
 *                           for the same ENROLLMENT-CONTRACT). This exists for
 *                           device agents / join scripts that report hardware
 *                           and request driver recommendations before they
 *                           have any user/OIDC identity. Only routes
 *                           explicitly listed here get this bypass — every
 *                           other route (including the generic device and
 *                           driver CRUD APIs) is strictly JWT-only.
 */
function oidcAuth({ skipPaths = [], enrollmentPaths = [] } = {}) {
  return async (req, res, next) => {
    if (matchesPrefix(skipPaths, req.path)) return next();

    const auth = req.headers.authorization;

    // Enrollment bypass: only for explicitly whitelisted paths, and only
    // when the caller did not present a Bearer token (a Bearer token, if
    // present, is always verified as a normal OIDC JWT below).
    if (matchesEnrollmentPath(enrollmentPaths, req.path) && !auth?.startsWith('Bearer ')) {
      if (isValidEnrollmentToken(req.headers['x-enrollment-token'])) {
        req.enrolledViaToken = true;
        return next();
      }
      return res.status(401).json({ error: 'unauthorized' });
    }

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

module.exports = { oidcAuth, isValidEnrollmentToken, matchesEnrollmentPath };
