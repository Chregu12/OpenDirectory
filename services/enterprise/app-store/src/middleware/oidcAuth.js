'use strict';

// ---------------------------------------------------------------------------
// P0 fix: app-store previously had ZERO HTTP authentication (see src/index.js
// history — only helmet()/cors() were mounted). Any unauthenticated caller
// could publish arbitrary "apps" into the catalog, upload arbitrary installer
// binaries, and push a "deploy" to any set of target devices — i.e. push
// malware onto the entire device fleet with a single unauthenticated POST
// (a full supply-chain compromise). This module ports the JWKS-based OIDC
// bearer-token pattern already used across the platform (see e.g.
// services/core/identity-service/src/middleware/oidcAuth.js,
// services/core/kerberos-kdc/src/middleware/oidcAuth.js,
// services/core/certificate-authority/src/middleware/oidcAuth.js) so
// app-store verifies against the same identity provider (oauth-provider) as
// the rest of the fleet.
//
// app-store additionally has a small number of genuine device/agent-facing
// endpoints that cannot carry an end-user OIDC JWT:
//   - PUT  /api/store/install/:installId/status  — a device agent reports
//     install progress/result back to app-store (see the route's own
//     "called by device agents" comment).
//   - GET  /api/appstore/packages/:packageId/download — device-service hands
//     this exact URL to the device agent (services/core/device-service/src/
//     index.js, installApp()) as the download source for a "store_install"
//     command; the agent fetches it directly over plain HTTP with no OIDC
//     identity of its own.
// Both are handled via `agentTokenPaths` below: a shared-secret
// APPSTORE_AGENT_TOKEN, accepted via the `x-appstore-agent-token` header
// (for callers that can set headers) OR the `agent_token` query parameter
// (for the bare download URL handed to the agent, which cannot attach custom
// headers). Exactly like the enrollment-token bypass in device-service /
// kerberos-kdc, this ONLY applies to the explicitly whitelisted paths, and
// ONLY when the caller did not present a Bearer token — a Bearer token, if
// present, is always verified as a normal OIDC JWT. Every other route
// (catalog CRUD, package upload/delete, deploy, assignments) is strictly
// JWT-only, with requireAdmin layered on top for the state-changing ones.
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

// startsWith(p + '/') — never a bare startsWith(p): a bare prefix match would
// let e.g. '/health-probe-that-mutates-things' piggy-back on the '/health'
// skip entry. The trailing slash enforces a path-segment boundary.
function matchesPath(list, path) {
  return list.some(p => path === p || path.startsWith(p + '/'));
}

/**
 * Matches agentTokenPaths entries against a request path.
 *
 * Two entry forms are supported (mirrors device-service's
 * matchesEnrollmentPath):
 *   - '/foo/bar' → prefix match (path === '/foo/bar' or starts with it,
 *     on a path-segment boundary).
 *   - '*suffix'  → suffix match (path ends with 'suffix'). Used here because
 *     both device-callback routes have a variable id segment ahead of a
 *     fixed tail ('/status', '/download'), and a prefix match would be far
 *     too broad (e.g. a prefix of '/api/appstore/packages' would also cover
 *     the admin-only DELETE /api/appstore/packages/:packageId route).
 */
function matchesAgentPath(list, path) {
  return list.some(p => {
    if (p.startsWith('*')) return path.endsWith(p.slice(1));
    return path === p || path.startsWith(p + '/');
  });
}

/**
 * Constant-time comparison of the caller-supplied agent token against
 * APPSTORE_AGENT_TOKEN. Always returns false (never throws) when the env var
 * is unset/empty or no candidate value was supplied — an unconfigured
 * deployment must not silently accept the bypass, and mismatched-length
 * inputs must not short-circuit before reaching a constant-time comparison.
 */
function isValidAgentToken(candidate) {
  const expected = process.env.APPSTORE_AGENT_TOKEN;
  if (!expected || !candidate || typeof candidate !== 'string') return false;

  const expectedBuf = Buffer.from(expected);
  const candidateBuf = Buffer.from(candidate);
  if (expectedBuf.length !== candidateBuf.length) return false;

  try {
    return crypto.timingSafeEqual(expectedBuf, candidateBuf);
  } catch {
    return false;
  }
}

/**
 * OIDC bearer-token auth middleware for app-store.
 *
 * options.skipPaths       - paths that bypass auth entirely (health/metrics
 *                            probes).
 * options.agentTokenPaths - paths that, in addition to a normal OIDC JWT,
 *                           accept the shared APPSTORE_AGENT_TOKEN via the
 *                           `x-appstore-agent-token` header or the
 *                           `agent_token` query parameter. Only routes
 *                           explicitly listed here get this bypass; a caller
 *                           that used it is marked via req.agentAuthenticated
 *                           = true (informational — it does NOT grant admin
 *                           rights, see requireAdmin below).
 */
function oidcAuth({ skipPaths = [], agentTokenPaths = [] } = {}) {
  return async (req, res, next) => {
    if (matchesPath(skipPaths, req.path)) return next();

    const auth = req.headers.authorization;

    // Agent-token bypass: only for explicitly whitelisted device/agent
    // routes, and only when the caller did not present a Bearer token (a
    // Bearer token, if present, is always verified as a normal OIDC JWT
    // below — the agent token never silently substitutes for a rejected JWT).
    if (matchesAgentPath(agentTokenPaths, req.path) && !auth?.startsWith('Bearer ')) {
      const candidate = req.headers['x-appstore-agent-token'] || req.query?.agent_token;
      if (isValidAgentToken(candidate)) {
        req.agentAuthenticated = true;
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
// Role/scope authorization for app-store's state-changing / deploy
// endpoints: catalog create/update/delete/seed, assignment create/delete,
// installer package upload/delete, and app deploy/cancel-deploy. A verified
// JWT only proves *who* is asking; pushing software onto the fleet
// additionally requires the caller to hold an admin role or an
// appstore.admin scope — this is the exact "unauth software deployment =
// supply-chain attack" gap the audit flagged.
// -----------------------------------------------------------------------

const APPSTORE_ADMIN_ROLES = ['admin'];
const APPSTORE_ADMIN_SCOPES = ['appstore.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform admin operations on app-store. Defensive by design: any shape
 * mismatch (missing claims, wrong types) resolves to false rather than
 * throwing, since callers must fail closed on anything they can't positively
 * verify.
 */
function hasAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => APPSTORE_ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => APPSTORE_ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => APPSTORE_ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on the specific routes that
 * create/update/delete catalog apps, upload/delete installer packages,
 * manage assignments, or trigger/cancel a deploy. Requires req.user (set by
 * oidcAuth from a verified JWT) to carry an admin role or an appstore.admin
 * scope. Fails closed: a token with no roles/scopes, or a request that came
 * in via the agent-token bypass (req.user is never set in that case), is
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
  isValidAgentToken,
};
