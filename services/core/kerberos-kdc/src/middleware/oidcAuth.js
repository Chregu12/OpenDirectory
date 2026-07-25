'use strict';

const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');

// ---------------------------------------------------------------------------
// P0 fix: kerberos-kdc previously had ZERO HTTP authentication (see
// src/index.js history — only helmet()/cors() were mounted, and requireDb()
// is a database-availability gate, not an auth check). Any unauthenticated
// caller could set the password of ANY principal (including
// admin/krbtgt-adjacent service accounts), mint keytabs, and configure
// Kerberos delegation (S4U2Proxy/RBCD/unconstrained) — a full, silent realm
// takeover. This module ports the JWKS-based OIDC bearer-token pattern
// already used by services/core/samba-ad-dc and services/core/device-service
// (same middleware shape, same JWKS_URI/OIDC_ISSUER contract) so kerberos-kdc
// verifies against the same identity provider (oauth-provider) as the rest
// of the fleet.
// ---------------------------------------------------------------------------

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// startsWith(p + '/') — never a bare startsWith(p): a bare prefix match would
// let '/api/kerberos/sync-userPWNED' (or similar) piggy-back on a shorter
// whitelisted path. The trailing slash enforces a path-segment boundary,
// mirroring samba-ad-dc's/device-service's matchesPath().
function matchesPath(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * Constant-time comparison of the caller-supplied internal-service token
 * against KDC_INTERNAL_TOKEN. Always returns false (never throws) when the
 * env var is unset/empty or the header is missing — an unconfigured
 * deployment must not silently accept the bypass, and mismatched-length
 * inputs must not short-circuit before reaching a constant-time comparison.
 */
function isValidInternalToken(headerValue) {
  const expected = process.env.KDC_INTERNAL_TOKEN;
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
 * OIDC bearer-token auth middleware for kerberos-kdc.
 *
 * options.skipPaths           - paths that bypass auth entirely (health probes).
 * options.internalServicePaths - paths that, in addition to a normal OIDC JWT,
 *                           accept the shared KDC_INTERNAL_TOKEN via the
 *                           `x-kdc-internal-token` header. This exists for
 *                           authentication-service's registration and
 *                           password-change flows (services/core/
 *                           authentication-service/src/routes/users.js),
 *                           which call POST /api/kerberos/sync-user
 *                           server-to-server with no end-user JWT in hand.
 *                           Only the route explicitly listed here gets this
 *                           bypass — every other route (principal
 *                           create/delete/password, keytabs, delegation,
 *                           protected-users) is strictly JWT-only.
 *                           A caller that used the internal-token bypass is
 *                           marked via req.internalService = true; that flag
 *                           does NOT grant admin rights on its own — see
 *                           requireKdcAdminOrInternal below.
 */
function oidcAuth({ skipPaths = [], internalServicePaths = [] } = {}) {
  return async (req, res, next) => {
    if (matchesPath(skipPaths, req.path)) return next();

    const auth = req.headers.authorization;

    // Internal-service bypass: only for explicitly whitelisted paths, and
    // only when the caller did not present a Bearer token (a Bearer token,
    // if present, is always verified as a normal OIDC JWT below — a raw
    // service token never silently substitutes for a rejected JWT).
    if (matchesPath(internalServicePaths, req.path) && !auth?.startsWith('Bearer ')) {
      if (isValidInternalToken(req.headers['x-kdc-internal-token'])) {
        req.internalService = true;
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
// Role/scope authorization for the highly-sensitive kerberos-kdc endpoints:
// principal create/delete/password-set, keytab issuance, delegation
// configuration (constrained/RBCD/unconstrained), ticket-policy changes, and
// Protected Users membership. A verified JWT only proves *who* is asking;
// these routes additionally require the caller to hold an admin role or a
// kdc.admin scope. Deliberately NOT extended to a broader "helpdesk" role
// (unlike samba-ad-dc's LAPS/BitLocker gate) — these operations amount to
// realm-wide credential and trust-path control, not day-to-day device
// support.
// -----------------------------------------------------------------------

const KDC_ADMIN_ROLES = ['admin'];
const KDC_ADMIN_SCOPES = ['kdc.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform realm-admin operations on kerberos-kdc.
 *
 * Defensive by design: any shape mismatch (missing claims, wrong types)
 * resolves to false rather than throwing, since callers must fail closed on
 * anything they can't positively verify.
 */
function hasKdcAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => KDC_ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => KDC_ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => KDC_ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on routes that must be
 * admin-only. Requires req.user (set by oidcAuth from a verified JWT) to
 * carry an admin role or a kdc.admin scope. Fails closed: a token with no
 * roles/scopes, or a request with no req.user at all, is rejected.
 */
function requireKdcAdmin(req, res, next) {
  if (!hasKdcAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

/**
 * Route middleware for POST /api/kerberos/sync-user only: passes requests
 * that came through the internal-service-token bypass (req.internalService,
 * set by oidcAuth's internalServicePaths) straight through — that shared
 * secret is itself the trust boundary for authentication-service's
 * registration/password-change flows. Any request that instead presented a
 * user JWT (no internal token used) must still carry admin rights, since
 * sync-user can set an arbitrary principal's password just like the
 * password-set endpoint.
 */
function requireKdcAdminOrInternal(req, res, next) {
  if (req.internalService === true) return next();
  return requireKdcAdmin(req, res, next);
}

module.exports = {
  oidcAuth,
  requireKdcAdmin,
  requireKdcAdminOrInternal,
  hasKdcAdminAccess,
  isValidInternalToken,
};
