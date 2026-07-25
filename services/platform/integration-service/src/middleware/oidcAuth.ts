// ---------------------------------------------------------------------------
// P0 fix: integration-service previously had ZERO HTTP authentication (see
// src/index.ts history — only helmet()/cors()/rateLimit() were mounted; the
// only "Bearer" usage anywhere in the service was outbound, e.g. LLDAPService
// attaching its own admin token when calling LLDAP). Any unauthenticated
// caller reachable on the network could read or write EVERY secret, mint or
// revoke Vault tokens, and rewrite Vault policies (src/routes/vault.ts), and
// could create/update/delete LLDAP directory users and groups
// (src/routes/lldap.ts) — a full, silent takeover of both the secrets store
// and the directory. This module ports the JWKS-based OIDC bearer-token
// pattern already used across the fleet (see e.g.
// services/core/identity-service/src/middleware/oidcAuth.js,
// services/core/kerberos-kdc/src/middleware/oidcAuth.js) to TypeScript, with
// the same JWKS_URI/OIDC_ISSUER contract, so integration-service verifies
// against the same identity provider (oauth-provider) as the rest of the
// fleet.
//
// Server-to-server callers: a repo-wide audit (grepping for calls to this
// service's port/hostname and to INTEGRATION_SERVICE_URL) found no backend
// service calling integration-service's mounted routes (/api/lldap,
// /api/grafana, /api/prometheus, /api/vault, /api/config, /api/services)
// without a JWT. The only two access paths are: (1) the frontend's Next.js
// rewrite (frontend/web-app/next.config.js), which is a transparent proxy
// that forwards the end user's own Authorization header, and (2) plain
// GET /health probes (docker healthcheck, and other services' own dashboards
// polling this service's health), which carry no credentials by design and
// are handled via skipPaths below — mirroring network-infrastructure's and
// identity-service's precedent. No internal-service-token bypass (the
// KDC_INTERNAL_TOKEN pattern in services/core/kerberos-kdc) is wired up here
// because nothing needs it.
// ---------------------------------------------------------------------------

import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Verified JWT claims, set by oidcAuth() once the bearer token checks out. */
      user?: JWTPayload;
    }
  }
}

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS: JWTVerifyGetKey | null = null;

function getJWKS(): JWTVerifyGetKey {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

// startsWith(p + '/') — never a bare startsWith(p) — so a skip path can't be
// smuggled as a prefix of a route that should actually require auth (e.g.
// '/health-mutate-everything' must not piggy-back on a whitelisted '/health').
function matchesPath(list: string[], path: string): boolean {
  return list.some((p) => path === p || path.startsWith(p + '/'));
}

export interface OidcAuthOptions {
  /** Paths that bypass auth entirely (health probes). */
  skipPaths?: string[];
}

/**
 * OIDC bearer-token auth middleware for integration-service. Mount globally,
 * before the route table, with skipPaths covering only the liveness/health
 * surface — every other route (Vault, LLDAP, Grafana, Prometheus, config,
 * services) requires a verified platform JWT. Route-specific admin gating
 * (requireAdmin below) is layered on top per-route.
 */
export function oidcAuth({ skipPaths = [] }: OidcAuthOptions = {}): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (matchesPath(skipPaths, req.path)) return next();

    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }

    try {
      const { payload } = await jwtVerify(auth.slice(7), getJWKS(), { issuer: ISSUER });
      req.user = payload;
      next();
    } catch (err: any) {
      const status = err?.code === 'ERR_JWT_EXPIRED' ? 401 : 403;
      res.status(status).json({ error: 'invalid_token', message: err?.message });
    }
  };
}

// -----------------------------------------------------------------------
// Role/scope authorization for the highly-sensitive integration-service
// endpoints: Vault secret/token/policy read+write (full access to every
// secret in the platform), and LLDAP user/group CRUD (real directory
// mutation). A verified JWT only proves *who* is asking; these routes
// additionally require the caller to hold an admin role or an
// integration.admin scope.
// -----------------------------------------------------------------------

const ADMIN_ROLES = ['admin'];
const ADMIN_SCOPES = ['integration.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform admin-critical operations on integration-service (Vault,
 * directory mutation). Defensive by design: any shape mismatch (missing
 * claims, wrong types) resolves to false rather than throwing — callers must
 * fail closed on anything they can't positively verify.
 */
export function hasAdminAccess(user: JWTPayload | undefined): boolean {
  if (!user || typeof user !== 'object') return false;

  const roles = Array.isArray(user.roles) ? (user.roles as string[]) : [];
  const realmAccess = user.realm_access as { roles?: unknown } | undefined;
  const realmRoles = Array.isArray(realmAccess?.roles) ? (realmAccess!.roles as string[]) : [];
  if (roles.some((r) => ADMIN_ROLES.includes(r))) return true;
  if (realmRoles.some((r) => ADMIN_ROLES.includes(r))) return true;

  const scope = user.scope as unknown;
  const scopeList =
    typeof scope === 'string'
      ? scope.split(/\s+/).filter(Boolean)
      : Array.isArray(user.scopes)
        ? (user.scopes as string[])
        : [];
  if (scopeList.some((s) => ADMIN_SCOPES.includes(s))) return true;

  return false;
}

/**
 * Route middleware: mount AFTER oidcAuth() on routes (or whole routers) that
 * must be admin-only — the entire /api/vault surface, and LLDAP user/group
 * CRUD. Requires req.user (set by oidcAuth from a verified JWT) to carry an
 * admin role or an integration.admin scope. Fails closed: a token with no
 * roles/scopes, or a request with no req.user at all, is rejected.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!hasAdminAccess(req.user)) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  next();
}
