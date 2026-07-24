'use strict';
const { Router } = require('express');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger'); // eslint-disable-line no-unused-vars -- kept for consistency/parity, available for future error logging
const config = require('../utils/config');
const { requireBearerAuth } = require('../middleware/bearerAuth');

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
 * Persistence: in-memory only (Map), matching the pre-split behavior.
 * There is no `service_accounts` table/migration in this service yet — a
 * restart loses everything but the seeded 'sa-ci-runner' account. Wiring
 * this to Postgres is a real follow-up (new migration + table), tracked
 * separately; the security fix (real auth) is not blocked on it.
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

  // Seed demo service account (matches pre-split behavior).
  const seedAccount = {
    id: 'sa-ci-runner',
    name: 'ci-runner',
    description: 'CI/CD pipeline service account',
    scopes: ['devices:read', 'policies:read'],
    createdAt: new Date().toISOString(),
  };
  seedAccount.token = signServiceAccountToken(seedAccount, '90d');
  serviceAccounts.set(seedAccount.id, seedAccount);

  // GET /api/service-accounts
  router.get('/api/service-accounts', auth, (req, res) => {
    const list = [...serviceAccounts.values()].map(({ token: _token, ...s }) => s);
    res.json(list);
  });

  // GET /api/service-accounts/:id
  router.get('/api/service-accounts/:id', auth, (req, res) => {
    const sa = serviceAccounts.get(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    const { token: _token, ...safe } = sa;
    res.json(safe);
  });

  // POST /api/service-accounts
  router.post('/api/service-accounts', auth, (req, res) => {
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
    sa.token = signServiceAccountToken(sa, '90d');
    serviceAccounts.set(id, sa);
    res.status(201).json(sa); // Include token on creation only
  });

  // PATCH /api/service-accounts/:id — secret/token rotation
  router.patch('/api/service-accounts/:id', auth, (req, res) => {
    const sa = serviceAccounts.get(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    sa.rotatedAt = req.body.rotatedAt ?? new Date().toISOString();
    sa.token = signServiceAccountToken(sa, '90d');
    const { token: _token, ...safe } = sa;
    res.json(safe);
  });

  // DELETE /api/service-accounts/:id
  router.delete('/api/service-accounts/:id', auth, (req, res) => {
    if (!serviceAccounts.has(req.params.id)) {
      return res.status(404).json({ error: 'Service account not found' });
    }
    serviceAccounts.delete(req.params.id);
    res.status(204).send();
  });

  // GET /api/service-accounts/:id/token — issue a fresh short-lived token
  router.get('/api/service-accounts/:id/token', auth, (req, res) => {
    const sa = serviceAccounts.get(req.params.id);
    if (!sa) return res.status(404).json({ error: 'Service account not found' });
    const freshToken = signServiceAccountToken(sa, '24h');
    res.json({ token: freshToken, expiresIn: '24h' });
  });

  return router;
}

module.exports = { createServiceAccountRoutes };
