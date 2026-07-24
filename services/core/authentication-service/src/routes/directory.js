'use strict';
const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const logger = require('../utils/logger');
const { requireBearerAuth, requireAdminBearerAuth } = require('../middleware/bearerAuth');

/**
 * Directory routes: Organizational Units + domain configuration.
 *
 * Restored from the pre-god-file-split implementation (see
 * `git show 1617f2c^:services/core/authentication-service/src/index.js`,
 * OUs ~line 1419, domain config ~line 1642) with the same security fix
 * applied throughout this restoration pass: the old `requireBearer` (OUs)
 * and inline header-presence check (domain config) only verified that *some*
 * Authorization header was sent — never that it was a valid token. Both
 * route groups now sit behind `requireBearerAuth`
 * (src/middleware/bearerAuth.js) — real JWT signature/expiry verification
 * using the same secret as the rest of the service (deliberately not the
 * full passport 'jwt' `requireAuth()` used by the user/session/MFA routes —
 * that strategy additionally round-trips through
 * `userService.getUserById()`, which these routes don't need). An invalid,
 * expired, or missing token is rejected with 401 before any handler runs.
 *
 * OUs: DB-first, using the pre-existing (but previously unused by this
 * service) `organizational_units` table — see migrations/003_groups_ous.sql.
 * An in-memory Map mirrors every write so reads stay consistent when the DB
 * is unavailable, or in tests where `pg` is mocked and never actually
 * persists what it "inserts".
 *
 * Domain config: DB-first (singleton `domain_config` table — see
 * migrations/008_domain_config.sql), with global.__od_domain_config used as
 * the in-memory fallback/mirror whenever the DB is unavailable, has no row
 * yet, or (as in tests, where `pg` is mocked and every query resolves
 * `{ rows: [] }`) a write never actually lands — matching the pre-split
 * in-memory-only behavior for that case exactly.
 *
 * Authorization: OU create/update/delete and writing domain config are
 * admin-only — `requireAdminBearerAuth` (src/middleware/bearerAuth.js),
 * which additionally requires 'admin' in the token's roles claim. Reads
 * (GET /api/ous, GET /api/config/domain) stay on plain `requireBearerAuth`.
 */
function createDirectoryRoutes(services) { // eslint-disable-line no-unused-vars -- services kept for signature parity with sibling route modules
  const router = Router();
  const auth = requireBearerAuth;
  const admin = requireAdminBearerAuth;

  // ── OUs ──────────────────────────────────────────────────────────────────

  const ous = new Map();

  function buildTree(list, parentId = null) {
    return list
      .filter((o) => !o.deleted && (o.parentId ?? null) === parentId)
      .map((o) => ({ ...o, children: buildTree(list, o.id) }));
  }

  async function getOusFromDb() {
    if (!db.isAvailable()) return null;
    try {
      const r = await db.query('SELECT id, name, description, parent_id, created_at FROM organizational_units ORDER BY created_at');
      return r.rows.map((row) => ({
        id: row.id,
        name: row.name,
        description: row.description,
        parentId: row.parent_id,
        deleted: false,
        createdAt: row.created_at,
      }));
    } catch (err) {
      logger.warn('Directory: getOusFromDb failed, falling back to in-memory', { error: err.message });
      return null;
    }
  }

  // GET /api/ous
  router.get('/api/ous', auth, async (req, res) => {
    const dbRows = await getOusFromDb();
    const list = dbRows ?? [...ous.values()];
    res.json(buildTree(list));
  });

  // POST /api/ous (admin only)
  router.post('/api/ous', admin, async (req, res) => {
    const { name, parentId, description } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const id = uuidv4();
    const ouData = {
      id,
      name,
      parentId: parentId ?? null,
      description: description ?? '',
      deleted: false,
      createdAt: new Date().toISOString(),
    };

    if (db.isAvailable()) {
      try {
        await db.query(
          'INSERT INTO organizational_units(id, name, description, parent_id) VALUES($1,$2,$3,$4)',
          [id, name, ouData.description, ouData.parentId]
        );
      } catch (err) {
        logger.error('Directory: create OU DB insert failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    ous.set(id, ouData);
    res.status(201).json(ouData);
  });

  // PUT /api/ous/:id (admin only)
  router.put('/api/ous/:id', admin, async (req, res) => {
    const { id } = req.params;
    const { name, parentId, description } = req.body;
    const updates = {
      ...(name && { name }),
      ...(parentId !== undefined && { parentId }),
      ...(description !== undefined && { description }),
    };

    if (db.isAvailable()) {
      try {
        const fields = [];
        const vals = [];
        let idx = 1;
        if (updates.name !== undefined) { fields.push(`name=$${idx++}`); vals.push(updates.name); }
        if (updates.parentId !== undefined) { fields.push(`parent_id=$${idx++}`); vals.push(updates.parentId); }
        if (updates.description !== undefined) { fields.push(`description=$${idx++}`); vals.push(updates.description); }
        if (fields.length > 0) {
          vals.push(id);
          await db.query(`UPDATE organizational_units SET ${fields.join(',')} WHERE id=$${idx}`, vals);
        }
      } catch (err) {
        logger.error('Directory: update OU DB update failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }

    const ou = ous.get(id);
    if (!ou || ou.deleted) return res.status(404).json({ error: 'OU not found' });
    Object.assign(ou, updates);
    res.json(ou);
  });

  // DELETE /api/ous/:id (admin only)
  router.delete('/api/ous/:id', admin, async (req, res) => {
    const { id } = req.params;
    const ou = ous.get(id);
    if (!ou) return res.status(404).json({ error: 'OU not found' });

    if (db.isAvailable()) {
      try {
        await db.query('DELETE FROM organizational_units WHERE id=$1', [id]);
      } catch (err) {
        logger.error('Directory: delete OU DB delete failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    ou.deleted = true;
    res.status(204).send();
  });

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
