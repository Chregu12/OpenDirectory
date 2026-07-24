'use strict';
const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const logger = require('../utils/logger');
const { requireBearerAuth } = require('../middleware/bearerAuth');

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
 * Domain config: in-memory only (global.__od_domain_config), matching the
 * pre-split behavior exactly — there was no DB-backed config store for this
 * before either.
 */
function createDirectoryRoutes(services) { // eslint-disable-line no-unused-vars -- services kept for signature parity with sibling route modules
  const router = Router();
  const auth = requireBearerAuth;

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

  // POST /api/ous
  router.post('/api/ous', auth, async (req, res) => {
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

  // PUT /api/ous/:id
  router.put('/api/ous/:id', auth, async (req, res) => {
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

  // DELETE /api/ous/:id
  router.delete('/api/ous/:id', auth, async (req, res) => {
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

  // POST /api/config/domain
  router.post('/api/config/domain', auth, (req, res) => {
    const { domain, issuer } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    global.__od_domain_config = { domain, issuer, configuredAt: new Date().toISOString() };
    res.json({ success: true, domain, issuer });
  });

  // GET /api/config/domain
  router.get('/api/config/domain', auth, (req, res) => {
    res.json(global.__od_domain_config || { domain: null, issuer: null });
  });

  return router;
}

module.exports = { createDirectoryRoutes };
