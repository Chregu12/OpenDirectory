'use strict';

// OIDC bearer-token auth for device-lifecycle.
//
// P0 fix: this service previously had ZERO HTTP authentication — helmet(),
// cors(), compression() and a rate limiter were mounted, but nothing verified
// who was calling. Every route under /api/lifecycle/* was reachable by any
// unauthenticated caller, including the two mutation endpoints:
//   POST /api/lifecycle/devices/:id/transition   (single-device state change)
//   POST /api/lifecycle/bulk-transition           (bulk state change)
// Both can drive a device (or an arbitrary batch of devices) straight to
// 'Retired'/'Retiring', i.e. unauthenticated mass device decommissioning.
//
// This module ports the same JWKS-based OIDC bearer-token pattern already
// used across the rest of the fleet (see e.g.
// services/core/identity-service/src/middleware/oidcAuth.js,
// services/core/network-infrastructure/src/middleware/oidcAuth.js): verify a
// Bearer JWT against the platform JWKS, then a separate role-gate
// (requireAdmin) for the two mutation routes above — a verified JWT only
// proves *who* is asking, not that they're allowed to retire/decommission
// devices.
//
// Internal-service bypass: NOT implemented here, deliberately. A repo-wide
// grep for server-to-server HTTP callers of device-lifecycle (docker-compose
// service name / :3020 / '/api/lifecycle') turned up exactly one caller:
// api-gateway's generic setupServiceProxy('lifecycle'/'device-lifecycle', ...)
// (services/core/api-gateway/src/index.js), which proxies requests with
// changeOrigin only — it does not add or replace headers, so the end user's
// own Authorization header (their real OIDC Bearer JWT) reaches this service
// unchanged. There is no shared-secret / service-token caller to accommodate.
// The only other producers of lifecycle transitions are the 'device.enrolled'
// / 'device.retired' events consumed off the internal gRPC event bus (see
// src/index.js connectBus()/_bus.subscribe) — that is not an HTTP path and
// carries no bearer token at all, so it is outside this middleware's scope
// entirely. If a future service needs direct server-to-server HTTP access
// (bypassing a human's JWT), add an internalServicePaths option here
// mirroring services/core/kerberos-kdc/src/middleware/oidcAuth.js's pattern
// rather than loosening this middleware.

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
// '/health-check-bypass' piggy-backing on a bare '/health' prefix match).
function matchesPath(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
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

// Role claim (req.user.roles, and the Keycloak-style req.user.realm_access.roles
// fallback) that grants admin access to this service's lifecycle-mutation
// endpoints (single and bulk state transitions, including retire/decommission).
const ADMIN_ROLES = ['admin'];
// Scope claim (space-delimited req.user.scope string, or an array under
// req.user.scopes) that grants the same access.
const ADMIN_SCOPES = ['lifecycle.admin'];

/**
 * True if the verified-JWT payload carries a role or scope authorized to
 * mutate device lifecycle state (transition / bulk-transition, including
 * retire/decommission). Defensive by design: any shape mismatch (missing
 * claims, wrong types) resolves to false rather than throwing — the caller
 * (requireAdmin) must fail closed.
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
 * mutate device lifecycle state (POST .../transition, POST
 * /bulk-transition). Requires req.user (set by oidcAuth from a verified JWT)
 * to carry an admin role or a lifecycle.admin scope. Fails closed on a
 * missing/malformed user.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { oidcAuth, requireAdmin, hasAdminAccess };
