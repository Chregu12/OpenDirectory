'use strict';

// ---------------------------------------------------------------------------
// P0 fix: oauth-provider previously had ZERO authentication on its ~50
// admin/management routes (client registry incl. plaintext client secrets,
// SCIM user/group directory, MDM command issuance including remote wipe/
// lock, enrollment-token listing, update rings, SCIM connections). The only
// two bearer-token checks in the whole file were /oauth/userinfo and
// /oauth/introspect — both hand-rolled inline, not reusable.
//
// This module ports the same JWKS-based OIDC bearer-token + role-gate
// pattern used across the fleet (see e.g. services/core/identity-service and
// services/core/kerberos-kdc's src/middleware/oidcAuth.js — same exported
// shape: oidcAuth()/requireAdmin()/hasAdminAccess()), with one deliberate
// structural difference explained below.
//
// ─── Why this module does NOT use createRemoteJWKSet + a global app.use() ──
//
// Every other service in the fleet is a *relying party*: it verifies tokens
// minted by oauth-provider over HTTP against oauth-provider's JWKS endpoint,
// and its entire route surface (bar a couple of skipPaths) sits behind a
// single global oidcAuth() mount.
//
// oauth-provider is different on both counts:
//   1. It IS the issuer. The RSA keypair used to sign every token already
//      lives in this process (see index.js's buildJwk()/publicKey) — making
//      an HTTP round-trip to its own /.well-known/jwks.json to verify its
//      own tokens would be both wasteful and a bootstrapping hazard (the
//      server would need to be able to reach itself over the network before
//      it can authenticate anything). configureJwks() below wires the local
//      JWK in directly via jose's createLocalJWKSet — same verification
//      guarantees (signature + issuer + expiry), zero network hop.
//   2. Most of its ~70 routes are the OAuth/OIDC/SAML/SCIM-push *protocol*
//      surface (/oauth/authorize, /oauth/token, /oauth/device/*, /saml/*,
//      /.well-known/*, the device-join scripts, /health, /downloads) and
//      must stay completely open — they either implement their own
//      client/enrollment-token authentication (e.g. /oauth/token validates
//      client_secret; /api/enrollment/register validates the enrollment
//      token in the body) or ARE the mechanism other services authenticate
//      against. A global skip-list covering that many routes, some of which
//      are method-sensitive (e.g. GET /api/packages is a public read-only
//      catalog but POST /api/packages is an admin write), is exactly the
//      kind of thing that's easy to get wrong in one direction (leaving a
//      route open) or the other (breaking the token issuer itself).
//
// Given that, oidcAuth() here is mounted explicitly per admin/management
// route in index.js (grep for `adminAuth` / `requireAdmin` there) rather
// than globally — every admin route's auth requirement is visible right at
// its definition, and the OAuth/OIDC protocol endpoints are never touched by
// this module at all.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { createLocalJWKSet, jwtVerify } = require('jose');

const ISSUER = process.env.OAUTH_ISSUER ?? 'https://opendirectory.local';

let localJWKS = null;

/**
 * Wire in the JWKS this process signs its own tokens with. Must be called
 * once at boot (see index.js, right after buildJwk() is defined) before any
 * request reaches oidcAuth() — see the "auth_not_ready" fail-closed branch
 * below for what happens if a request arrives first.
 */
function configureJwks(jwks) {
  localJWKS = createLocalJWKSet(jwks);
}

/**
 * Constant-time comparison of the caller-supplied internal-service token
 * against OAUTH_PROVIDER_INTERNAL_TOKEN. Always returns false (never throws)
 * when the env var is unset/empty or the header is missing — an
 * unconfigured deployment must not silently accept the bypass, and
 * mismatched-length inputs must not short-circuit before reaching a
 * constant-time comparison.
 */
function isValidInternalToken(headerValue) {
  const expected = process.env.OAUTH_PROVIDER_INTERNAL_TOKEN;
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
 * OIDC bearer-token auth middleware for oauth-provider's own admin/
 * management surface.
 *
 * options.isTokenRevoked  - optional async (tokenHash) => boolean, wired to
 *                           index.js's Redis-backed revocation check so a
 *                           revoked admin token is rejected here exactly
 *                           like it already is at /oauth/userinfo.
 * options.allowInternalToken - when true, a request with NO Authorization
 *                           header on a route this middleware is mounted on
 *                           may instead present the shared
 *                           OAUTH_PROVIDER_INTERNAL_TOKEN via the
 *                           `x-oauth-internal-token` header. This exists for
 *                           server-to-server callers that have no end-user/
 *                           admin JWT in hand — concretely, POST
 *                           /api/devices/:deviceId/commands and GET
 *                           /api/devices/registry, called unauthenticated
 *                           today by services/enterprise/antivirus-protection
 *                           (AV scan dispatch) and services/core/
 *                           policy-service (GPO/blueprint push, device
 *                           inventory for targeting). A caller that used the
 *                           internal-token bypass is marked via
 *                           req.internalService = true; that flag does NOT
 *                           grant admin rights on its own — see
 *                           requireAdminOrInternal below. Deliberately a
 *                           per-instance boolean (mount a *separate*
 *                           oidcAuth({allowInternalToken:true}) only on
 *                           those specific routes) rather than a path list —
 *                           see the file-header comment for why oauth-
 *                           provider doesn't use the fleet's usual global-
 *                           mount-plus-skip/allow-list shape. A Bearer
 *                           token, if present, is always verified as a
 *                           normal JWT below — the internal-token bypass
 *                           only applies when no Authorization header was
 *                           sent at all.
 */
function oidcAuth({ isTokenRevoked, allowInternalToken = false } = {}) {
  return async (req, res, next) => {
    const auth = req.headers.authorization;

    if (allowInternalToken && !auth?.startsWith('Bearer ')) {
      if (isValidInternalToken(req.headers['x-oauth-internal-token'])) {
        req.internalService = true;
        return next();
      }
      return res.status(401).json({ error: 'unauthorized' });
    }

    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    if (!localJWKS) {
      // configureJwks() was never called — fail closed rather than accept
      // an unverifiable token.
      return res.status(503).json({ error: 'auth_not_ready' });
    }

    const token = auth.slice(7);
    try {
      const { payload } = await jwtVerify(token, localJWKS, { issuer: ISSUER });

      if (isTokenRevoked) {
        const hash = crypto.createHash('sha256').update(token).digest('hex');
        if (await isTokenRevoked(hash)) {
          return res.status(401).json({ error: 'token_revoked' });
        }
      }

      req.user = payload;
      next();
    } catch (err) {
      const status = err.code === 'ERR_JWT_EXPIRED' ? 401 : 403;
      res.status(status).json({ error: 'invalid_token', message: err.message });
    }
  };
}

// Role claim (req.user.roles, and the Keycloak-style req.user.realm_access.roles
// fallback) that grants admin access to oauth-provider's management
// endpoints (client registry, SCIM directory, MDM command issuance,
// enrollment tokens, update rings, SCIM connections).
const ADMIN_ROLES = ['admin'];
// Scope claim (space-delimited req.user.scope string, or an array under
// req.user.scopes) that grants the same access. A client_credentials or
// authorization_code token that requested the `oauth.admin` scope carries
// this the same way every other service's `<service>.admin` scope works.
const ADMIN_SCOPES = ['oauth.admin'];

/**
 * True if the given verified-JWT payload carries a role or scope authorized
 * to perform admin operations on oauth-provider. Defensive by design: any
 * shape mismatch (missing claims, wrong types) resolves to false rather than
 * throwing, since callers must fail closed on anything they can't
 * positively verify.
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
 * Route middleware: mount AFTER oidcAuth() on routes that must be
 * admin-only. Requires req.user (set by oidcAuth from a verified JWT) to
 * carry an admin role or an oauth.admin scope. Fails closed: a token with no
 * roles/scopes, or a request with no req.user at all, is rejected.
 */
function requireAdmin(req, res, next) {
  if (!hasAdminAccess(req.user)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

/**
 * Route middleware for the internal-service-bypass routes only (see
 * allowInternalToken above): passes requests that came through the
 * internal-service-token bypass (req.internalService, set by oidcAuth's
 * allowInternalToken) straight through — that shared secret is itself the
 * trust boundary for the server-to-server callers it exists for. Any
 * request that instead presented a user/admin JWT must still carry admin
 * rights.
 */
function requireAdminOrInternal(req, res, next) {
  if (req.internalService === true) return next();
  return requireAdmin(req, res, next);
}

module.exports = {
  oidcAuth,
  configureJwks,
  requireAdmin,
  requireAdminOrInternal,
  hasAdminAccess,
  isValidInternalToken,
};
