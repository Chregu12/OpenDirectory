'use strict';

// OIDC bearer-token auth for network-infrastructure.
//
// P0 fix: this service previously had ZERO HTTP authentication — helmet(),
// compression(), cors() and a rate limiter were mounted, but nothing verified
// who was calling. The only "auth" in the file was a WebSocket-level
// mock-token check (see the `authenticate` WS message handler /
// validateAuthToken() in src/index.js), which never applied to the ~60
// Express HTTP routes under /api/network/*. Any unauthenticated caller could
// create/update/delete DNS records, hand out or release DHCP leases, create
// or delete VLANs, and add/modify/delete firewall rules — a full,
// unauthenticated takeover of the network control plane.
//
// This module ports the same JWKS-based OIDC bearer-token pattern already
// used across the rest of the fleet (see e.g.
// services/core/kerberos-kdc/src/middleware/oidcAuth.js,
// services/core/certificate-authority/src/middleware/oidcAuth.js,
// services/core/identity-service/src/middleware/oidcAuth.js): verify a
// Bearer JWT against the platform JWKS, then a separate role-gate
// (requireAdmin) for the network-critical routes — firewall rules, VLANs,
// and DNS zone creation — since a verified JWT only proves *who* is asking,
// not that they're allowed to reconfigure network segmentation or perimeter
// rules.
//
// Internal-service bypass: NOT implemented here, deliberately. A repo-wide
// grep for server-to-server callers of network-infrastructure's HTTP API
// (docker-compose service name / NETWORK_INFRA_URL / :3007) turned up
// exactly one cross-service caller — integration-service's
// NetworkInfrastructureService.getServiceStatus(), which only calls
// GET /health (see src/index.js skipPaths below) for the services dashboard.
// The frontend's /api/network/* traffic goes through the Next.js rewrite
// (frontend/web-app/next.config.js) with the end user's own Bearer JWT
// attached (frontend/web-app/src/lib/api.ts), so it authenticates like any
// other user request — no shared-secret bypass is needed. If a future
// service needs server-to-server access (e.g. an enrollment flow creating
// DNS/DHCP records without a user in the loop), add an
// internalServicePaths option here mirroring kerberos-kdc's pattern rather
// than loosening this middleware.

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
 * options.skipPaths - paths that bypass auth entirely (health probes and, if
 * ever added, purely public read-only discovery endpoints).
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
// fallback) that grants admin access to network-critical mutation endpoints
// (firewall rules, VLANs, DNS zone creation).
const ADMIN_ROLES = ['admin'];
// Scope claim (space-delimited req.user.scope string, or an array under
// req.user.scopes) that grants the same access.
const ADMIN_SCOPES = ['network.admin'];

/**
 * True if the verified-JWT payload carries a role or scope authorized to
 * mutate network-critical configuration (firewall, VLANs, DNS zones).
 * Defensive by design: any shape mismatch (missing claims, wrong types)
 * resolves to false rather than throwing — the caller (requireAdmin) must
 * fail closed.
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
 * create/update/delete firewall rules, VLANs, or DNS zones. Requires
 * req.user (set by oidcAuth from a verified JWT) to carry an admin role or a
 * network.admin scope. Fails closed on a missing/malformed user.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { oidcAuth, requireAdmin, hasAdminAccess };
