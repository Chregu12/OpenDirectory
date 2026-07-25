'use strict';

// ---------------------------------------------------------------------------
// P0 fix: antivirus-protection previously had ZERO HTTP authentication — only
// helmet()/cors() were mounted. Any unauthenticated caller could release
// already-quarantined malware back onto a device (POST
// /api/antivirus/quarantine/:fileId/restore), permanently destroy quarantine
// evidence (DELETE /api/antivirus/quarantine/:fileId), dispatch an arbitrary
// run_av_scan MDM command fleet-wide (POST /api/antivirus/scan), or trigger a
// signature update job (POST /api/antivirus/signatures/update). This module
// ports the JWKS-based OIDC bearer-token pattern already used across the
// fleet (see e.g. services/core/identity-service/src/middleware/oidcAuth.js
// for oidcAuth+requireAdmin, and services/core/device-service/src/middleware/
// oidcAuth.js for the enrollmentPaths bypass and its wildcard-suffix
// matcher), so antivirus-protection verifies against the same identity
// provider (oauth-provider) as the rest of the fleet.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// startsWith(p + '/') — never a bare startsWith(p) — so a skip/enrollment
// path can't be smuggled as a prefix of a route that should actually require
// auth (e.g. '/health' must not also cover '/healthXYZ').
function matchesPrefix(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * Matches enrollmentPaths entries against a request path. Mirrors
 * device-service's matchesEnrollmentPath: two entry forms are supported.
 *
 *   - '/foo/bar'  -> prefix match (path === '/foo/bar' or starts with it).
 *   - '*suffix'   -> suffix match (path ends with 'suffix'). Used for routes
 *     with a variable device-id segment, e.g. '*\/report' matches
 *     '/api/antivirus/devices/:deviceId/report' without also matching the
 *     generic device CRUD routes ('/api/antivirus/devices',
 *     '/api/antivirus/devices/:deviceId').
 */
function matchesEnrollmentPath(list, path) {
  return list.some(p => {
    if (p.startsWith('*')) return path.endsWith(p.slice(1));
    return path === p || path.startsWith(p + '/');
  });
}

/**
 * Constant-time comparison of the caller-supplied enrollment token against
 * DEVICE_ENROLLMENT_TOKEN — the same shared fleet-agent token used by
 * device-service and samba-ad-dc. Always returns false (never throws) when
 * the env var is unset/empty or the header is missing — an unconfigured
 * deployment must not silently accept the bypass, and mismatched-length
 * inputs must not short-circuit before reaching a constant-time comparison.
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
 * OIDC bearer-token auth middleware for antivirus-protection.
 *
 * options.skipPaths       - paths that bypass auth entirely (health probes).
 * options.enrollmentPaths - paths that, in addition to a normal OIDC JWT,
 *                           accept the shared DEVICE_ENROLLMENT_TOKEN via the
 *                           `x-enrollment-token` header. This exists for the
 *                           ClamAV device agent, which reports scan results
 *                           (POST .../devices/:deviceId/report) and AV status
 *                           (POST .../devices/:deviceId/status) server-to-
 *                           server with no end-user JWT in hand. Only routes
 *                           explicitly listed here get this bypass — every
 *                           other route (scan/quarantine/signature/schedule
 *                           management, the generic device/threat CRUD APIs)
 *                           is strictly JWT-only.
 */
function oidcAuth({ skipPaths = [], enrollmentPaths = [] } = {}) {
  return async (req, res, next) => {
    if (matchesPrefix(skipPaths, req.path)) return next();

    const auth = req.headers.authorization;

    // Enrollment bypass: only for explicitly whitelisted paths, and only
    // when the caller did not present a Bearer token (a Bearer token, if
    // present, is always verified as a normal OIDC JWT below — a raw device
    // token never silently substitutes for a rejected JWT).
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

// -----------------------------------------------------------------------
// Role/scope authorization for antivirus-protection's most sensitive
// endpoints: quarantine restore/delete (un-quarantining or destroying
// malware evidence), fleet scan dispatch / scheduling (an MDM command sent
// to every managed device), and signature-update triggers. A verified JWT
// only proves *who* is asking; these routes additionally require the
// caller to hold an admin role or an antivirus.admin scope.
// -----------------------------------------------------------------------

const AV_ADMIN_ROLES = ['admin'];
const AV_ADMIN_SCOPES = ['antivirus.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform admin operations on antivirus-protection.
 *
 * Defensive by design: any shape mismatch (missing claims, wrong types)
 * resolves to false rather than throwing, since callers must fail closed on
 * anything they can't positively verify.
 */
function hasAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => AV_ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => AV_ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => AV_ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on routes that must be
 * admin-only. Requires req.user (set by oidcAuth from a verified JWT) to
 * carry an admin role or an antivirus.admin scope. Fails closed: a token
 * with no roles/scopes, or a request with no req.user at all (e.g. one that
 * came through the enrollment-token bypass, which never sets req.user), is
 * rejected.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = {
  oidcAuth,
  requireAdmin,
  hasAdminAccess,
  isValidEnrollmentToken,
  matchesEnrollmentPath,
};
