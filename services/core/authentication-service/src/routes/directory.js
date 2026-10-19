'use strict';
const { Router } = require('express');
const db = require('../db');
const logger = require('../utils/logger');
const { requireBearerAuth, requireAdminBearerAuth } = require('../middleware/bearerAuth');

/**
 * Directory routes: domain configuration.
 *
 * Restored from the pre-god-file-split implementation (see
 * `git show 1617f2c^:services/core/authentication-service/src/index.js`,
 * domain config ~line 1642) with the same security fix applied throughout
 * this restoration pass: the old inline header-presence check only verified
 * that *some* Authorization header was sent — never that it was a valid
 * token. The route group now sits behind `requireBearerAuth`
 * (src/middleware/bearerAuth.js) — real JWT signature/expiry verification
 * using the same secret as the rest of the service (deliberately not the
 * full passport 'jwt' `requireAuth()` used by the user/session/MFA routes —
 * that strategy additionally round-trips through
 * `userService.getUserById()`, which these routes don't need). An invalid,
 * expired, or missing token is rejected with 401 before any handler runs.
 *
 * Domain config: DB-first (singleton `domain_config` table — see
 * migrations/008_domain_config.sql), with global.__od_domain_config used as
 * the in-memory fallback/mirror whenever the DB is unavailable, has no row
 * yet, or (as in tests, where `pg` is mocked and every query resolves
 * `{ rows: [] }`) a write never actually lands — matching the pre-split
 * in-memory-only behavior for that case exactly.
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
  const auth = requireBearerAuth;
  const admin = requireAdminBearerAuth;

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
