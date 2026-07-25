'use strict';

// ---------------------------------------------------------------------------
// P0 fix: policy-simulator previously had ZERO HTTP authentication — only
// helmet()/cors() were mounted. Any unauthenticated caller could run
// what-if policy simulations (POST /api/simulator/simulate), read compliance
// drift/timeline/impact data for arbitrary devices, and — most notably —
// generate detailed rollback plans for production policies (POST
// /api/simulator/rollback-plan), which expose fleet-wide affected-device
// counts, estimated rollback timing, and service-interruption assessments.
// This module ports the JWKS-based OIDC bearer-token pattern already used
// across the fleet (see e.g.
// services/core/identity-service/src/middleware/oidcAuth.js and
// services/enterprise/antivirus-protection/src/middleware/oidcAuth.js), so
// policy-simulator verifies against the same identity provider
// (oauth-provider) as the rest of the platform.
//
// Server-to-server callers: the only in-repo caller is api-gateway
// (services/core/api-gateway/src/index.js, setupServiceProxy('simulator',
// ...) / ('drift', ...) / ('timeline', ...)), which proxies via
// http-proxy-middleware with changeOrigin:true and no onProxyReq header
// rewriting — the end user's Authorization header is forwarded through
// unmodified. There is no separate service-to-service credential to
// support here, so this middleware is JWT-only (no internal-token bypass).
// ---------------------------------------------------------------------------

const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// startsWith(p + '/') — never a bare startsWith(p) — so a skip path can't be
// smuggled as a prefix of a route that should actually require auth (e.g.
// '/health' must not also cover '/healthXYZ').
function matchesPath(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * OIDC bearer-token auth middleware for policy-simulator.
 *
 * options.skipPaths - paths that bypass auth entirely (health probes).
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

// -----------------------------------------------------------------------
// Role/scope authorization for policy-simulator's most operationally
// sensitive endpoint: POST /api/simulator/rollback-plan. A verified JWT
// only proves *who* is asking. Note that createRollbackPlan() (see
// src/services/simulationEngine.js) never applies anything to production —
// there is no separate "apply rollback" endpoint in this service, it only
// *plans* one — but the plan itself surfaces fleet-wide affected-device
// counts, rollback timing, and service-interruption risk for a real
// production policy, which is treated as an admin-only operational action
// consistent with how deployment/rollback tooling is gated elsewhere in the
// fleet. POST /api/simulator/simulate, by contrast, is a pure "what-if"
// exploration against the in-memory simulation model with no operational
// rollback intelligence attached, so it stays self-service (any
// authenticated caller) — see requireAdmin usage in src/index.js.
// -----------------------------------------------------------------------

const SIMULATOR_ADMIN_ROLES = ['admin'];
const SIMULATOR_ADMIN_SCOPES = ['simulator.admin'];

/**
 * True if the verified-JWT payload carries a role or scope authorized to
 * generate a policy rollback plan. Defensive by design: any shape mismatch
 * (missing claims, wrong types) resolves to false rather than throwing —
 * the caller (requireAdmin) must fail closed.
 */
function hasAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => SIMULATOR_ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => SIMULATOR_ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => SIMULATOR_ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on routes that must be
 * admin-only (currently just POST /api/simulator/rollback-plan). Requires
 * req.user (set by oidcAuth from a verified JWT) to carry an admin role or
 * a simulator.admin scope. Fails closed on a missing/malformed user.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { oidcAuth, requireAdmin, hasAdminAccess };
