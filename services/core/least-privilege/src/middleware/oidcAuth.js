'use strict';

// OIDC bearer-token auth for the least-privilege service, following the same
// pattern used across the other core services (see e.g.
// services/core/samba-ad-dc/src/middleware/oidcAuth.js and
// services/core/policy-service/src/middleware/oidcAuth.js): verify a Bearer
// JWT against the platform JWKS, then a separate role-gate (requireAdmin)
// for endpoints that mutate privilege — permission assignment and PIM
// elevation approve/deny. A verified JWT only proves *who* is asking; those
// endpoints additionally require an admin role.

const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// startsWith(p + '/') — never a bare startsWith(p) — so a skip path can't be
// smuggled as a prefix of a route that should actually require auth.
function matchesPath(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * options.skipPaths - paths that bypass auth entirely (health/metrics probes).
 */
function oidcAuth({ skipPaths = [] } = {}) {
  return async (req, res, next) => {
    if (matchesPath(skipPaths, req.path)) return next();

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

// Role claim (req.user.roles, and the Keycloak-style req.user.realm_access.roles
// fallback) that grants admin access to this service's mutating endpoints.
const ADMIN_ROLES = ['admin'];
// Scope claim (space-delimited req.user.scope string, or an array under
// req.user.scopes) that grants the same access.
const ADMIN_SCOPES = ['least-privilege.admin'];

/**
 * True if the verified-JWT payload carries a role or scope authorized to
 * assign permissions or approve/deny PIM elevation requests. Defensive by
 * design: any shape mismatch (missing claims, wrong types) resolves to
 * false rather than throwing — the caller (requireAdmin) must fail closed.
 */
function hasAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on the specific routes that
 * assign permissions or approve/deny PIM elevation requests. Requires
 * req.user (set by oidcAuth from a verified JWT) to carry an admin role or
 * a least-privilege.admin scope. Fails closed on a missing/malformed user.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { oidcAuth, requireAdmin, hasAdminAccess };
