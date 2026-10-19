'use strict';

// ---------------------------------------------------------------------------
// P0 fix: security-scanner previously had ZERO HTTP authentication — only
// helmet()/cors()/rate-limiting were mounted. Any unauthenticated caller
// could trigger a full AD/GPO/Intune exposure scan (POST /api/scanner/scan)
// or install a recurring cron-scheduled scan (POST /api/scanner/schedule),
// and read every finding, risk score, and trend the scanner has ever
// produced — a reconnaissance and resource-exhaustion gap against the
// service whose entire job is reporting the fleet's security exposure. This
// module ports the JWKS-based OIDC bearer-token pattern already used across
// the fleet (see e.g. services/core/identity-service/src/middleware/
// oidcAuth.js and services/enterprise/antivirus-protection/src/middleware/
// oidcAuth.js), so security-scanner verifies against the same identity
// provider (oauth-provider) as the rest of the fleet.
//
// No internal-service/enrollment-token bypass is wired up here: unlike
// kerberos-kdc (authentication-service's sync-user calls) or
// antivirus-protection (the ClamAV device agent's status/report calls),
// nothing in this repo calls security-scanner's HTTP API server-to-server
// today — compliance-engine does not call it, and the only caller found is
// the api-gateway proxy (services/core/api-gateway/src/index.js, forwarding
// '/api/scanner' -> http://security-scanner), which simply forwards whatever
// Authorization header the end-user request carried. The service's own
// cron-based rescan logic (services/services/exposureScanner.js) also never
// calls back into its own HTTP API — it runs in-process. If a real scheduler/
// compliance service is later wired up to trigger scans server-to-server,
// follow the kerberos-kdc internalServicePaths pattern rather than
// special-casing it here speculatively.
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
// Role/scope authorization for security-scanner's mutating endpoints:
// starting a scan (POST /api/scanner/scan) and installing a recurring
// scan schedule (POST /api/scanner/schedule). Scans enumerate GPO/AD/device
// exposure fleet-wide and a schedule persists indefinitely, so these are
// treated as admin/security-team operations rather than self-service — the
// frontend never exposes scan-triggering to a non-admin surface (see
// frontend/web-app/src/lib/api.ts's startSecurityScan, which is unused
// outside admin-only security tooling). A verified JWT only proves *who* is
// asking; these routes additionally require the caller to hold an admin
// role or a scanner.admin scope.
// -----------------------------------------------------------------------

const SCANNER_ADMIN_ROLES = ['admin'];
const SCANNER_ADMIN_SCOPES = ['scanner.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform admin operations on security-scanner.
 *
 * Defensive by design: any shape mismatch (missing claims, wrong types)
 * resolves to false rather than throwing, since callers must fail closed on
 * anything they can't positively verify.
 */
function hasAdminAccess(user) {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? user.roles : [];
  const realmRoles = Array.isArray(user.realm_access?.roles) ? user.realm_access.roles : [];
  if (roles.some(r => SCANNER_ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some(r => SCANNER_ADMIN_ROLES.includes(r))) return true;

  const scopeList = typeof user.scope === 'string'
    ? user.scope.split(/\s+/).filter(Boolean)
    : Array.isArray(user.scopes) ? user.scopes : [];
  if (scopeList.some(s => SCANNER_ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on routes that must be
 * admin-only (scan start, scan schedule). Requires req.user (set by
 * oidcAuth from a verified JWT) to carry an admin role or a scanner.admin
 * scope. Fails closed: a token with no roles/scopes, or a request with no
 * req.user at all, is rejected.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { oidcAuth, requireAdmin, hasAdminAccess };
