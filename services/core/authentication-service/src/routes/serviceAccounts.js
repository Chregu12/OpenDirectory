'use strict';
const { Router } = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db');
const logger = require('../utils/logger');
const config = require('../utils/config');
const { requireBearerAuth, requireAdminBearerAuth } = require('../middleware/bearerAuth');

/**
 * Service account routes.
 *
 * Restored from the pre-god-file-split implementation (see
 * `git show 1617f2c^:services/core/authentication-service/src/index.js`,
 * ~line 1527) with the same security fix as the other routes restored
 * alongside this one: the old `requireBearer` gate only checked that *some*
 * Authorization header was present — it never verified the token. These
 * routes now sit behind `requireBearerAuth` (src/middleware/bearerAuth.js),
 * which really verifies the JWT's signature and expiry against the same
 * secret the rest of the service uses (deliberately not the full passport
 * 'jwt' `requireAuth()` used by the user/session/MFA routes — that strategy
 * additionally round-trips through `userService.getUserById()`, which these
 * routes don't need). An invalid, expired, or missing token is rejected
 * with 401 before any handler runs. No anonymous directory mutation is
 * possible.
 *
 * Persistence: DB-first (service_accounts table — see
 * migrations/007_service_accounts.sql), with an in-memory Map mirror used
 * whenever the DB is unavailable OR a DB row can't be resolved (e.g. in
 * tests, where `pg` is mocked and every query resolves `{ rows: [] }`
 * regardless of what was "inserted"). Every write goes to both places so a
 * request immediately following a create within the same process sees
 * consistent data regardless of whether a real DB is attached, and every
 * read/lookup tries the DB first and falls back to the in-memory mirror
 * when the DB has no matching row (same pattern as pim.js's request
 * lookups). Secrets (`token`) are never persisted to the DB row — only
 * re-derivable metadata (id/name/scopes/etc.) is stored; the JWT itself is
 * always re-signed on read/rotation from that metadata, matching pre-split
 * in-memory behavior exactly.
 *
 * Authorization: creating and deleting a service account are admin-only —
 * `requireAdminBearerAuth` (src/middleware/bearerAuth.js), which additionally
 * requires 'admin' in the token's roles claim. Reads (list/get/token-mint)
 * and secret rotation stay on plain `requireBearerAuth`.
 *
 * Body shape: the consumer of record — the quick-actions
 * servicePrincipalOrchestrator (services/platform/quick-actions/src/
 * orchestrators/servicePrincipalOrchestrator.js) — posts
 * { name, clientId, clientSecret, description, createdBy }. This service's
 * own contract (mirrored from the pre-split code and pinned by
 * src/__tests__/api.e2e.test.js) is { name, scopes } -> { id, name, ...,
 * token }. Both are accepted here: `clientId` (if supplied) is used as the
 * record id instead of a generated one, and `description`/`createdBy` are
 * stored passthrough — but the response shape and the freshly-minted JWT
 * `token` field follow this service's own contract, since that's what the
 * pinned test suite verifies end-to-end.
 */
function createServiceAccountRoutes(services) { // eslint-disable-line no-unused-vars -- services kept for signature parity with sibling route modules
  const router = Router();
  const auth = requireBearerAuth;
  const admin = requireAdminBearerAuth;

  const JWT_SECRET = config.jwt.secret;
  const serviceAccounts = new Map();

  function signServiceAccountToken(sa, expiresIn) {
    return jwt.sign(
      {
        sub: sa.id,
        type: 'service_account',
        name: sa.name,
        permissions: sa.scopes || [],
        iss: 'opendirectory',
        aud: 'opendirectory-services',
      },
      JWT_SECRET,
      { expiresIn, algorithm: 'HS256' }
    );
  }

  function rowToSa(row) {
    return {
      id: row.id,
      name: row.name,
      description: row.description ?? '',
      scopes: row.scopes ?? [],
      createdBy: row.created_by ?? null,
      createdAt: row.created_at,
      ...(row.rotated_at ? { rotatedAt: row.rotated_at } : {}),
    };
  }

  async function getServiceAccountsFromDb() {
    if (!db.isAvailable()) return null;
    try {
      const r = await db.query('SELECT * FROM service_accounts ORDER BY created_at');
      return r.rows;
    } catch (err) {
      logger.warn('ServiceAccounts: list DB query failed, falling back to in-memory', { error: err.message });
      return null;
    }
  }

  // DB-first lookup with in-memory fallback — mirrors the pim.js request
  // lookup pattern: try the DB, and if it comes back empty (unavailable, a
  // real miss, or — in tests — because `pg` is mocked and never actually
  // persisted the row) fall back to the in-memory mirror, which every write
  // below always updates regardless of DB availability.
  async function resolveServiceAccount(id) {
    if (db.isAvailable()) {
      try {
        const r = await db.query('SELECT * FROM service_accounts WHERE id=$1', [id]);
        if (r.rows.length > 0) {
          const sa = rowToSa(r.rows[0]);
          sa.token = signServiceAccountToken(sa, '90d');
          return sa;
        }
      } catch (err) {
        logger.warn('ServiceAccounts: lookup DB query failed, falling back to in-memory', { error: err.message });
      }
    }
    return serviceAccounts.get(id) ?? null;
  }

  // Seed demo service account (matches pre-split behavior). Mirrored into
  // the DB (best-effort) so it also survives a restart when Postgres is
  // actually attached; the in-memory Map remains the source of truth in
  // tests and whenever the DB is unavailable.
  const seedAccount = {
    id: 'sa-ci-runner',
    name: 'ci-runner',
    description: 'CI/CD pipeline service account',
    scopes: ['devices:read', 'policies:read'],
    createdAt: new Date().toISOString(),
  };
  seedAccount.token = signServiceAccountToken(seedAccount, '90d');
  serviceAccounts.set(seedAccount.id, seedAccount);
  if (db.isAvailable()) {
    db.query(
      `INSERT INTO service_accounts(id, name, description, scopes, created_at)
       VALUES($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`,
      [seedAccount.id, seedAccount.name, seedAccount.description, JSON.stringify(seedAccount.scopes), seedAccount.createdAt]
    ).catch((err) => logger.warn('ServiceAccounts: seed DB insert failed', { error: err.message }));
  }

  // GET /api/service-accounts
  router.get('/api/service-accounts', auth, async (req, res) => {
    const dbRows = await getServiceAccountsFromDb();
    const list = dbRows && dbRows.length > 0 ? dbRows.map(rowToSa) : [...serviceAccounts.values()];
    res.json(list.map(({ token: _token, ...s }) => s));
  });

  // GET /api/service-accounts/:id
  router.get('/api/service-accounts/:id', auth, async (req, res) => {
    const sa = await resolveServiceAccount(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    const { token: _token, ...safe } = sa;
    res.json(safe);
  });

  // POST /api/service-accounts (admin only)
  router.post('/api/service-accounts', admin, async (req, res) => {
    const { name, scopes, description, clientId, createdBy } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const id = clientId || `sa-${Date.now()}`;
    const sa = {
      id,
      name,
      description: description ?? '',
      scopes: scopes ?? [],
      createdBy: createdBy ?? req.user?.id ?? null,
      createdAt: new Date().toISOString(),
    };

    if (db.isAvailable()) {
      try {
        await db.query(
          `INSERT INTO service_accounts(id, name, description, scopes, created_by, created_at)
           VALUES($1,$2,$3,$4,$5,$6)
           ON CONFLICT (id) DO UPDATE SET name=$2, description=$3, scopes=$4, created_by=$5`,
          [id, name, sa.description, JSON.stringify(sa.scopes), sa.createdBy, sa.createdAt]
        );
      } catch (err) {
        logger.error('ServiceAccounts: create DB insert failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    sa.token = signServiceAccountToken(sa, '90d');
    serviceAccounts.set(id, sa);
    res.status(201).json(sa); // Include token on creation only
  });

  // PATCH /api/service-accounts/:id — secret/token rotation
  router.patch('/api/service-accounts/:id', auth, async (req, res) => {
    const sa = await resolveServiceAccount(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    sa.rotatedAt = req.body.rotatedAt ?? new Date().toISOString();

    if (db.isAvailable()) {
      try {
        await db.query('UPDATE service_accounts SET rotated_at=$1 WHERE id=$2', [sa.rotatedAt, sa.id]);
      } catch (err) {
        logger.error('ServiceAccounts: rotate DB update failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    sa.token = signServiceAccountToken(sa, '90d');
    serviceAccounts.set(sa.id, sa);
    const { token: _token, ...safe } = sa;
    res.json(safe);
  });

  // DELETE /api/service-accounts/:id (admin only)
  router.delete('/api/service-accounts/:id', admin, async (req, res) => {
    const existing = await resolveServiceAccount(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Service account not found' });
    }
    if (db.isAvailable()) {
      try {
        await db.query('DELETE FROM service_accounts WHERE id=$1', [req.params.id]);
      } catch (err) {
        logger.error('ServiceAccounts: delete DB delete failed:', err);
        return res.status(500).json({ error: err.message });
      }
    }
    serviceAccounts.delete(req.params.id);
    res.status(204).send();
  });

  // GET /api/service-accounts/:id/token — issue a fresh short-lived token
  router.get('/api/service-accounts/:id/token', auth, async (req, res) => {
    const sa = await resolveServiceAccount(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    const freshToken = signServiceAccountToken(sa, '24h');
    res.json({ token: freshToken, expiresIn: '24h' });
  });

  return router;
}

module.exports = { createServiceAccountRoutes };
