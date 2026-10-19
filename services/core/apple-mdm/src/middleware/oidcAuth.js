'use strict';

// ---------------------------------------------------------------------------
// P0 fix: apple-mdm previously had ZERO HTTP authentication on its admin API
// (see src/index.js history — only helmet()/cors()/prometheus metrics were
// mounted). Any unauthenticated caller on the network could:
//   - POST /api/mdm/devices/:udid/wipe   -> queue Apple's EraseDevice command
//     (full remote destruction of any enrolled device's data)
//   - POST /api/mdm/devices/:udid/lock   -> queue DeviceLock
//   - plus ~13 further mutating endpoints (command enqueue, blueprint apply,
//     profile install/remove, DEP assignment, MDM push-cert config).
//
// This module ports the same JWKS-based OIDC bearer-token pattern already
// used across the fleet (see e.g. services/core/kerberos-kdc/src/middleware/
// oidcAuth.js, services/core/certificate-authority/src/middleware/oidcAuth.js,
// services/core/identity-service/src/middleware/oidcAuth.js) — same
// JWKS_URI/OIDC_ISSUER env contract, same requireAdmin role/scope gate — so
// apple-mdm verifies against the same identity provider (oauth-provider) as
// the rest of the platform.
//
// IMPORTANT — this middleware is intentionally NOT applied to the MDM
// protocol endpoints under /mdm/* (enrollment profile download, device
// check-in, command polling/result-reporting). Real Apple devices speak
// Apple's MDM protocol to those routes and authenticate via their
// enrollment identity certificate (mTLS) / the Apple-defined check-in
// handshake — they have no OIDC/OAuth user identity and cannot be made to
// send a Bearer JWT (Apple, not this codebase, controls that HTTP client).
// Gating /mdm/* behind oidcAuth would not add security (nothing in this
// codebase implements the actual client-certificate verification that is
// the real trust boundary for that protocol) and WOULD break every enrolled
// device's check-in/command flow. See src/index.js for the skipPaths list
// and per-route rationale.
// ---------------------------------------------------------------------------

const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// startsWith(p + '/') — never a bare startsWith(p): a bare prefix match
// would let e.g. '/mdmPWNED' or '/api/mdmadmin' piggy-back on a shorter
// whitelisted path. The trailing slash enforces a path-segment boundary,
// mirroring the matchesPath() helper used by the other services' oidcAuth
// middleware.
function matchesPath(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * options.skipPaths - paths that bypass auth entirely: health/metrics probes
 * and the Apple MDM protocol endpoints under /mdm/* (see file header).
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
// fallback) that grants admin access to apple-mdm's mutating admin-console
// endpoints (device lock/wipe/push/install/remove-profile, blueprint apply,
// DEP assignment, profile CRUD, APNs/MDM push-cert config).
const MDM_ADMIN_ROLES = ['admin'];
// Scope claim (space-delimited req.user.scope string, or an array under
// req.user.scopes) that grants the same access.
const MDM_ADMIN_SCOPES = ['mdm.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform MDM admin-console mutations. Defensive by design: any shape
 * mismatch (missing claims, wrong types) resolves to false rather than
 * throwing — callers must fail closed on anything they can't positively
 * verify.
 */
function hasAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => MDM_ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => MDM_ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => MDM_ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on the specific /api/mdm/*
 * routes that mutate device/fleet state (lock, wipe, push, install/remove
 * profile, blueprint apply, DEP assign, profile create/delete, MDM config).
 * Requires req.user (set by oidcAuth from a verified JWT) to carry an admin
 * role or an mdm.admin scope. Fails closed on a missing/malformed user.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { oidcAuth, requireAdmin, hasAdminAccess };
