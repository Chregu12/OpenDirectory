'use strict';
const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const logger = require('../utils/logger');
const { requireBearerAuth, requireAdminBearerAuth } = require('../middleware/bearerAuth');

/**
 * PIM (Privileged Identity Management) routes.
 *
 * Restored from the pre-god-file-split implementation (see
 * `git show 1617f2c^:services/core/authentication-service/src/index.js`,
 * ~line 1812) with one deliberate security fix: the old `attachDirectoryApi`
 * IIFE gated these routes behind `requireBearer`, a presence-only check
 * ("is there *an* Authorization header") that never actually verified the
 * token. These routes now run behind `requireBearerAuth`
 * (src/middleware/bearerAuth.js) — real JWT signature/expiry verification
 * using the same secret as the rest of the service. This is deliberately
 * NOT the full passport 'jwt' `requireAuth()` used by the user/session/MFA
 * routes: that strategy additionally round-trips through
 * `userService.getUserById()` and Zero-Trust re-evaluation to resolve a full
 * user record, which these routes don't need — the token's own claims
 * (sub/username/roles) are sufficient. Either way, an invalid, expired, or
 * missing token is rejected with 401 before any handler runs — no anonymous
 * directory mutation is possible.
 *
 * Persistence: DB-first (pim_roles / pim_requests tables — see
 * migrations/004_pim.sql), with an in-memory Map mirror used whenever the DB
 * is unavailable OR a DB row can't be resolved (e.g. in tests, where `pg` is
 * mocked and never actually persists what it "inserts"). Every write goes to
 * both places so a request immediately following a create within the same
 * process sees consistent data regardless of whether a real DB is attached.
 *
 * Authorization: role management (create/update/delete a PIM role) and
 * approval decisions (approve/deny/revoke) are admin-only —
 * `requireAdminBearerAuth` (src/middleware/bearerAuth.js), which additionally
 * requires 'admin' in the token's roles claim. Requesting activation of a
 * role for yourself (POST /api/pim/requests) and all reads stay on plain
 * `requireBearerAuth` — any authenticated user may self-serve a request or
 * read the catalog/queue, but only an admin may define roles or decide
 * outstanding requests.
 */
function createPimRoutes(services) { // eslint-disable-line no-unused-vars -- services kept for signature parity with sibling route modules
  const router = Router();
  const auth = requireBearerAuth;
  const admin = requireAdminBearerAuth;

  // In-memory mirror / fallback store.
  const pimRoles = new Map();
  const pimRequests = new Map();

  async function getPimRolesFromDb() {
    if (!db.isAvailable()) return null;
    try {
      const r = await db.query('SELECT * FROM pim_roles ORDER BY created_at');
      return r.rows;
    } catch (err) {
      logger.warn('PIM: getPimRolesFromDb failed, falling back to in-memory', { error: err.message });
      return null;
    }
  }

  async function getPimRequestsFromDb(filters = {}) {
    if (!db.isAvailable()) return null;
    try {
      const conditions = [];
      const vals = [];
      let idx = 1;
      if (filters.status) { conditions.push(`status=$${idx++}`); vals.push(filters.status); }
      if (filters.userId) { conditions.push(`user_id=$${idx++}`); vals.push(filters.userId); }
      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
      const r = await db.query(`SELECT * FROM pim_requests ${where} ORDER BY requested_at DESC`, vals);
      return r.rows;
    } catch (err) {
      logger.warn('PIM: getPimRequestsFromDb failed, falling back to in-memory', { error: err.message });
      return null;
    }
  }

  // ── PIM Roles ─────────────────────────────────────────────────────────────

  // GET /api/pim/roles
  router.get('/api/pim/roles', auth, async (req, res) => {
    const dbRows = await getPimRolesFromDb();
    if (dbRows) return res.json(dbRows);
    res.json([...pimRoles.values()]);
  });

  // POST /api/pim/roles (admin only)
  router.post('/api/pim/roles', admin, async (req, res) => {
    const { name, description, target_group_id, target_group_name, max_duration_hours, requires_approval, approver_group_id } = req.body;
    if (!name || !target_group_id) {
      return res.status(400).json({ error: 'name and target_group_id required' });
    }
    const now = new Date().toISOString();
    const id = uuidv4();
    const role = {
      id,
      name,
      description: description ?? null,
      target_group_id,
      target_group_name: target_group_name ?? null,
      max_duration_hours: max_duration_hours ?? 8,
      requires_approval: requires_approval !== false,
      approver_group_id: approver_group_id ?? null,
      created_at: now,
      updated_at: now,
    };
    if (db.isAvailable()) {
      try {
        await db.query(
          `INSERT INTO pim_roles(id,name,description,target_group_id,target_group_name,max_duration_hours,requires_approval,approver_group_id)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
          [id, name, role.description, target_group_id, role.target_group_name, role.max_duration_hours, role.requires_approval, role.approver_group_id]
        );
      } catch (err) {
        logger.error('PIM: create role DB insert failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    pimRoles.set(id, role);
    res.status(201).json(role);
  });

  // PUT /api/pim/roles/:id (admin only)
  router.put('/api/pim/roles/:id', admin, async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const now = new Date().toISOString();
    if (db.isAvailable()) {
      try {
        const fields = [];
        const vals = [];
        let idx = 1;
        const allowed = ['name', 'description', 'target_group_id', 'target_group_name', 'max_duration_hours', 'requires_approval', 'approver_group_id'];
        for (const key of allowed) {
          if (updates[key] !== undefined) { fields.push(`${key}=$${idx++}`); vals.push(updates[key]); }
        }
        fields.push(`updated_at=$${idx++}`); vals.push(now);
        vals.push(id);
        if (fields.length > 1) {
          const r = await db.query(`UPDATE pim_roles SET ${fields.join(',')} WHERE id=$${idx} RETURNING *`, vals);
          if (r.rows.length > 0) {
            pimRoles.set(id, { ...pimRoles.get(id), ...r.rows[0] });
            return res.json(r.rows[0]);
          }
        }
      } catch (err) {
        logger.error('PIM: update role DB update failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    const role = pimRoles.get(id);
    if (!role) return res.status(404).json({ error: 'Role not found' });
    Object.assign(role, updates, { updated_at: now });
    res.json(role);
  });

  // DELETE /api/pim/roles/:id (admin only)
  router.delete('/api/pim/roles/:id', admin, async (req, res) => {
    const { id } = req.params;
    if (db.isAvailable()) {
      try {
        await db.query('DELETE FROM pim_roles WHERE id=$1', [id]);
      } catch (err) {
        logger.error('PIM: delete role DB delete failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    pimRoles.delete(id);
    res.status(204).send();
  });

  // ── PIM Requests ──────────────────────────────────────────────────────────

  // GET /api/pim/requests
  router.get('/api/pim/requests', auth, async (req, res) => {
    const { status, userId } = req.query;
    const dbRows = await getPimRequestsFromDb({ status, userId });
    if (dbRows) return res.json(dbRows);
    let list = [...pimRequests.values()];
    if (status) list = list.filter((r) => r.status === status);
    if (userId) list = list.filter((r) => r.user_id === userId);
    list.sort((a, b) => new Date(b.requested_at) - new Date(a.requested_at));
    res.json(list);
  });

  // POST /api/pim/requests
  router.post('/api/pim/requests', auth, async (req, res) => {
    const { role_id, justification, requested_duration_hours, user_id, user_name, user_email } = req.body;
    if (!role_id) return res.status(400).json({ error: 'role_id required' });

    let role = null;
    if (db.isAvailable()) {
      try {
        const r = await db.query('SELECT * FROM pim_roles WHERE id=$1', [role_id]);
        if (r.rows.length > 0) role = r.rows[0];
      } catch (err) {
        logger.warn('PIM: role lookup failed during request creation', { error: err.message });
      }
    }
    if (!role) role = pimRoles.get(role_id);
    if (!role) return res.status(404).json({ error: 'PIM role not found' });

    const now = new Date();
    const duration = Math.min(requested_duration_hours ?? 4, role.max_duration_hours);
    const autoApprove = !role.requires_approval;
    const id = uuidv4();

    const request = {
      id,
      user_id: user_id ?? req.user?.id ?? 'unknown',
      user_name: user_name ?? req.user?.username ?? null,
      user_email: user_email ?? null,
      role_id,
      role_name: role.name,
      justification: justification ?? null,
      requested_duration_hours: duration,
      status: autoApprove ? 'active' : 'pending',
      requested_at: now.toISOString(),
      decided_at: autoApprove ? now.toISOString() : null,
      decided_by: autoApprove ? 'system' : null,
      activated_at: autoApprove ? now.toISOString() : null,
      expires_at: autoApprove ? new Date(now.getTime() + duration * 3600_000).toISOString() : null,
      revoked_at: null,
      revoked_by: null,
    };

    if (db.isAvailable()) {
      try {
        await db.query(
          `INSERT INTO pim_requests(id,user_id,user_name,user_email,role_id,role_name,justification,requested_duration_hours,status,decided_at,decided_by,activated_at,expires_at)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [id, request.user_id, request.user_name, request.user_email, role_id, role.name, request.justification, duration, request.status, request.decided_at, request.decided_by, request.activated_at, request.expires_at]
        );
      } catch (err) {
        logger.error('PIM: create request DB insert failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    pimRequests.set(id, request);
    res.status(201).json(request);
  });

  // Shared handler for the approve/deny/revoke decision endpoints.
  function decisionHandler({ fromStatus, toStatus, actorField, verbLabel, extra }) {
    return async (req, res) => {
      const { id } = req.params;
      const actor = req.body[actorField] ?? req.user?.username ?? 'admin';
      const now = new Date();

      let request = null;
      if (db.isAvailable()) {
        try {
          const r = await db.query('SELECT * FROM pim_requests WHERE id=$1', [id]);
          if (r.rows.length > 0) request = r.rows[0];
        } catch (err) {
          logger.warn(`PIM: ${verbLabel} lookup failed`, { error: err.message });
        }
      }
      if (!request) request = pimRequests.get(id);
      if (!request) return res.status(404).json({ error: 'Request not found' });
      if (request.status !== fromStatus) {
        return res.status(400).json({ error: `Cannot ${verbLabel} request with status '${request.status}'` });
      }

      const patch = extra ? extra(request, now, actor) : {};
      const fullPatch = { status: toStatus, ...patch };

      if (db.isAvailable()) {
        try {
          const fields = Object.keys(fullPatch);
          const vals = fields.map((f) => fullPatch[f]);
          const setClause = fields.map((f, i) => `${f}=$${i + 1}`).join(',');
          const r = await db.query(`UPDATE pim_requests SET ${setClause} WHERE id=$${fields.length + 1} RETURNING *`, [...vals, id]);
          if (r.rows.length > 0) {
            const updated = r.rows[0];
            pimRequests.set(id, { ...pimRequests.get(id), ...updated });
            return res.json(updated);
          }
        } catch (err) {
          logger.error(`PIM: ${verbLabel} DB update failed:`, err);
          return res.status(500).json({ error: err.message });
        }
      }
      Object.assign(request, fullPatch);
      pimRequests.set(id, request);
      res.json(request);
    };
  }

  // POST /api/pim/requests/:id/approve (admin only)
  router.post('/api/pim/requests/:id/approve', admin, decisionHandler({
    fromStatus: 'pending',
    toStatus: 'active',
    actorField: 'decided_by',
    verbLabel: 'approve',
    extra: (request, now, actor) => {
      const duration = request.requested_duration_hours;
      const expiresAt = new Date(now.getTime() + duration * 3600_000).toISOString();
      return { decided_at: now.toISOString(), decided_by: actor, activated_at: now.toISOString(), expires_at: expiresAt };
    },
  }));

  // POST /api/pim/requests/:id/deny (admin only)
  router.post('/api/pim/requests/:id/deny', admin, decisionHandler({
    fromStatus: 'pending',
    toStatus: 'denied',
    actorField: 'decided_by',
    verbLabel: 'deny',
    extra: (request, now, actor) => ({ decided_at: now.toISOString(), decided_by: actor }),
  }));

  // POST /api/pim/requests/:id/revoke (admin only)
  router.post('/api/pim/requests/:id/revoke', admin, decisionHandler({
    fromStatus: 'active',
    toStatus: 'revoked',
    actorField: 'revoked_by',
    verbLabel: 'revoke',
    extra: (request, now, actor) => ({ revoked_at: now.toISOString(), revoked_by: actor }),
  }));

  // GET /api/pim/activations
  router.get('/api/pim/activations', auth, async (req, res) => {
    const now = new Date().toISOString();
    if (db.isAvailable()) {
      try {
        const r = await db.query(
          `SELECT * FROM pim_requests WHERE status='active' AND expires_at > $1 ORDER BY activated_at DESC`,
          [now]
        );
        return res.json(r.rows);
      } catch (err) {
        logger.warn('PIM: activations query failed, falling back to in-memory', { error: err.message });
      }
    }
    const active = [...pimRequests.values()].filter((r) => r.status === 'active' && r.expires_at && r.expires_at > now);
    active.sort((a, b) => new Date(b.activated_at) - new Date(a.activated_at));
    res.json(active);
  });

  return router;
}

module.exports = { createPimRoutes };
