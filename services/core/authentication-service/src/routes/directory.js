'use strict';
const { Router } = require('express');
const jwt = require('jsonwebtoken');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const db = require('../db');
const logger = require('../utils/logger');
const { requireBearerAuth, requireAdminBearerAuth } = require('../middleware/bearerAuth');

const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';
const AUDIENCE = process.env.OIDC_AUDIENCE || 'opendirectory-api';
const JWKS_URI = process.env.JWKS_URI || 'http://oauth-provider:3010/.well-known/jwks.json';
const accessState = createAccessStateClient();
let jwks;

function getJwks() {
  if (!jwks) jwks = createRemoteJWKSet(new URL(JWKS_URI), { timeoutDuration: 2500, cooldownDuration: 1000, cacheMaxAge: 3600000 });
  return jwks;
}

function bearerAuth({ adminOnly = false } = {}) {
  const legacyAuth = adminOnly ? requireAdminBearerAuth : requireBearerAuth;
  return async (req, res, next) => {
    const match = /^Bearer\s+([A-Za-z0-9._~-]{1,16384})$/i.exec(req.headers.authorization || '');
    const decoded = match && jwt.decode(match[1], { complete: true });
    if (decoded?.header?.alg === 'HS256') return legacyAuth(req, res, next);
    if (decoded?.header?.alg !== 'RS256') return res.status(401).json({ error: 'Invalid or expired token' });

    try {
      const { payload, protectedHeader } = await jwtVerify(match[1], getJwks(), {
        issuer: ISSUER, audience: AUDIENCE, algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti'],
      });
      const roles = Array.isArray(payload.roles) ? payload.roles.filter(role => typeof role === 'string') : [];
      if ((protectedHeader.typ !== undefined && protectedHeader.typ !== 'JWT') || payload.token_use !== 'access' || payload.actor_type !== 'user'
        || typeof payload.sub !== 'string' || !payload.sub.trim()) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
      await accessState(req.headers.authorization, payload);
      if (adminOnly && !roles.includes('admin')) return res.status(403).json({ error: 'Admin access required' });
      req.user = { id: payload.sub, username: payload.preferred_username || payload.name || payload.sub, roles };
      return next();
    } catch (error) {
      const unavailable = error.status === 503 || ['ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code)
        || error instanceof TypeError;
      return res.status(unavailable ? 503 : 401).json({ error: unavailable ? 'Token verification source unavailable' : 'Invalid or expired token' });
    }
  };
}

/**
 * Directory routes: domain configuration.
 *
 * Restored from the pre-god-file-split implementation (see
 * `git show 1617f2c^:services/core/authentication-service/src/index.js`,
 * domain config ~line 1642) with verified bearer authentication. Legacy
 * HS256 tokens use bearerAuth.js; current browser sessions use RS256 OIDC
 * tokens verified with the OAuth provider's JWKS and active-session check.
 * Writes require the admin role in either token type. Missing, invalid,
 * expired, or revoked tokens are rejected before a handler runs.
 *
 * Domain config: DB-first (singleton `domain_config` table — see
 * migrations/008_domain_config.sql), with global.__od_domain_config used as
 * the in-memory fallback/mirror whenever the DB is unavailable or has no row.
 * The routes accept existing HS256 API tokens and current RS256 OIDC access
 * tokens; OIDC tokens are checked against JWKS and the OAuth session state.
 *
 * Authorization: writing domain config is admin-only —
 * `requireAdminBearerAuth` (src/middleware/bearerAuth.js), which
 * additionally requires 'admin' in the token's roles claim. Reads
 * (GET /api/config/domain) stay on plain `requireBearerAuth`.
 *
 * NOTE — OUs (Organizational Units) used to live here too (GET/POST/PUT/
 * DELETE /api/ous, DB-first against this service's own `auth` database —
 * migrations/003_groups_ous.sql `organizational_units` table). They were
 * removed as part of resolving a namespace collision: identity-service
 * (services/core/identity-service/src/index.js) independently grew its own
 * DB-first /api/ous implementation against a *different* `ous` table in the
 * separate "identity" database, and having two services own the same
 * domain entity in two different databases is a split-brain hazard (same
 * class of problem as the PIM route collision resolved via namespacing).
 * identity-service was chosen as the canonical /api/ous owner: it is the
 * platform's identity/directory store by design (see its migrations/
 * 001_identity_schema.sql header), it already owns the related
 * users/groups/roles entities, and api-gateway already proxies
 * /api/groups, /api/users, and /api/roles to it (see
 * services/core/api-gateway/src/middleware/routing.js) — /api/ous belongs
 * next to those, not next to this service's auth/token/MFA concerns. See
 * identity-service's directory-routes section for the merged
 * implementation (it now also returns the parent/child `tree` shape this
 * service used to build, so no capability was lost).
 *
 * The now-orphaned `organizational_units` table definition was left in
 * migrations/003_groups_ous.sql (not dropped) — see the comment there.
 */
function createDirectoryRoutes(services) { // eslint-disable-line no-unused-vars -- services kept for signature parity with sibling route modules
  const router = Router();
  const auth = bearerAuth();
  const admin = bearerAuth({ adminOnly: true });

  // ── Domain configuration ────────────────────────────────────────────────

  async function getDomainConfigFromDb() {
    if (!db.isAvailable()) return null;
    try {
      const r = await db.query('SELECT domain, issuer, configured_at FROM domain_config WHERE id = 1');
      if (r.rows.length === 0) return null;
      return {
        domain: r.rows[0].domain,
        issuer: r.rows[0].issuer,
        configuredAt: r.rows[0].configured_at,
      };
    } catch (err) {
      logger.warn('Directory: getDomainConfigFromDb failed, falling back to in-memory', { error: err.message });
      return null;
    }
  }

  // POST /api/config/domain (admin only)
  router.post('/api/config/domain', admin, async (req, res) => {
    const { domain, issuer } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    const configuredAt = new Date().toISOString();

    if (db.isAvailable()) {
      try {
        await db.query(
          `INSERT INTO domain_config(id, domain, issuer, configured_at) VALUES(1, $1, $2, $3)
           ON CONFLICT (id) DO UPDATE SET domain=$1, issuer=$2, configured_at=$3`,
          [domain, issuer ?? null, configuredAt]
        );
      } catch (err) {
        logger.error('Directory: domain config DB upsert failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    global.__od_domain_config = { domain, issuer, configuredAt };
    res.json({ success: true, domain, issuer });
  });

  // GET /api/config/domain
  router.get('/api/config/domain', auth, async (req, res) => {
    const dbConfig = await getDomainConfigFromDb();
    res.json(dbConfig ?? global.__od_domain_config ?? { domain: null, issuer: null });
  });

  return router;
}

module.exports = { createDirectoryRoutes };
