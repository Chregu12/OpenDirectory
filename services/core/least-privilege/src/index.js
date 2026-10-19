'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');
const { oidcAuth, requireAdmin } = require('./middleware/oidcAuth');

const promClient = require('prom-client');
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// HTTP request counter
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
});

// HTTP request duration
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [register],
});

const pimRequestsGauge = new promClient.Gauge({ name: 'pim_pending_requests', help: 'Pending PIM elevation requests', registers: [register] });
const escalationAlertsGauge = new promClient.Gauge({ name: 'privilege_escalation_alerts', help: 'Active escalation alerts', registers: [register] });

setInterval(() => {
  pimRequestsGauge.set([...pimRequests.values()].filter(r => r.status === 'pending').length);
  escalationAlertsGauge.set(escalationAlerts.size);
}, 30000);

const PORT = process.env.LEAST_PRIVILEGE_PORT ?? 3011;

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 300 }));

// ─── Prometheus metrics middleware ────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const route = req.route?.path ?? req.path ?? 'unknown';
    const duration = (Date.now() - start) / 1000;
    httpRequestsTotal.inc({ method: req.method, route, status: res.statusCode });
    httpRequestDuration.observe({ method: req.method, route }, duration);
  });
  next();
});

app.get('/metrics', async (req, res) => {
  res.setHeader('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// ─── Auth ─────────────────────────────────────────────────────────────────────
//
// Every route below (other than /health and /metrics) manages or reveals
// privilege state — the permission matrix, permission assignment, and PIM
// elevation — so all of it requires a verified bearer token. Assigning a
// permission and approving/denying a PIM elevation request additionally
// require an admin role (see requireAdmin on those specific routes below);
// oidcAuth alone only proves *who* is asking.
app.use(oidcAuth({ skipPaths: ['/health', '/metrics'] }));

// ─── Permission Model ─────────────────────────────────────────────────────────

const RESOURCES = ['devices', 'users', 'policies', 'apps', 'secrets', 'printers', 'reports'];
const LEVELS    = ['none', 'read', 'write', 'admin'];

// Default role → resource → level mapping
const ROLE_DEFAULTS = {
  admin: Object.fromEntries(RESOURCES.map(r => [r, 'admin'])),
  user:  { devices: 'read', users: 'none', policies: 'read', apps: 'read', secrets: 'none', printers: 'read', reports: 'none' },
  'read-only': Object.fromEntries(RESOURCES.map(r => [r, 'read'])),
  'service-account': { devices: 'read', users: 'none', policies: 'read', apps: 'none', secrets: 'none', printers: 'none', reports: 'read' },
};

// ─── In-Memory Stores ─────────────────────────────────────────────────────────

// userId → { role, overrides: { resource: level } }
const userPermissions = new Map();

// PIM requests
const pimRequests = new Map();

// Active elevations
const activeElevations = new Map();

// Escalation alerts: userId → { userId, adminCount, detectedAt }
const escalationAlerts = new Map();

// Unused permissions (mocked — same list as GET /api/permissions/unused)
const unusedPermissions = [
  { userId: 'user-bob', userName: 'Bob Developer', resource: 'reports', level: 'write', lastUsed: new Date(Date.now() - 95 * 86400_000).toISOString(), daysIdle: 95 },
  { userId: 'user-carol', userName: 'Carol ReadOnly', resource: 'printers', level: 'read', lastUsed: new Date(Date.now() - 120 * 86400_000).toISOString(), daysIdle: 120 },
  { userId: 'user-dave', userName: 'Dave Engineer', resource: 'apps', level: 'write', lastUsed: new Date(Date.now() - 180 * 86400_000).toISOString(), daysIdle: 180 },
];

// ─── Seed Demo Data ───────────────────────────────────────────────────────────

const demoUsers = [
  { id: 'user-alice',   name: 'Alice Admin',     role: 'admin' },
  { id: 'user-bob',     name: 'Bob Developer',   role: 'user' },
  { id: 'user-carol',   name: 'Carol ReadOnly',  role: 'read-only' },
  { id: 'user-dave',    name: 'Dave Engineer',   role: 'user' },
  { id: 'user-eve',     name: 'Eve DevOps',      role: 'user' },
  { id: 'sa-ci-runner', name: 'CI Runner',       role: 'service-account' },
];

demoUsers.forEach(u => {
  userPermissions.set(u.id, { ...u, overrides: {} });
});

// Seed a pending PIM request
const pendingPim = { id: uuidv4(), userId: 'user-bob', userName: 'Bob Developer', resource: 'secrets', duration_hours: 2, reason: 'Need to rotate API keys for Q4 release', status: 'pending', createdAt: new Date(Date.now() - 10 * 60_000).toISOString(), expiresAt: null };
pimRequests.set(pendingPim.id, pendingPim);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getEffectivePermissions(userId) {
  const rec = userPermissions.get(userId);
  if (!rec) return null;
  const defaults = ROLE_DEFAULTS[rec.role] ?? ROLE_DEFAULTS['read-only'];
  const effective = { ...defaults };
  for (const [res, level] of Object.entries(rec.overrides ?? {})) {
    effective[res] = level;
  }
  // Apply active elevations
  for (const elev of activeElevations.values()) {
    if (elev.userId === userId && elev.expiresAt > Date.now()) {
      effective[elev.resource] = 'write';
    }
  }
  return effective;
}

function calcRiskScore(userId) {
  const perms = getEffectivePermissions(userId);
  if (!perms) return 0;
  const scores = { none: 0, read: 10, write: 25, admin: 40 };
  const total = RESOURCES.reduce((sum, r) => sum + (scores[perms[r]] ?? 0), 0);
  const max = RESOURCES.length * 40;
  return Math.round((total / max) * 100);
}

// ─── Permission Matrix ────────────────────────────────────────────────────────

app.get('/api/permissions/matrix', async (req, res) => {
  try {
    if (db.isAvailable()) {
      const rows = await db.getPermissionMatrix();
      // Group by userId
      const byUser = {};
      for (const row of rows) {
        if (!byUser[row.user_id]) byUser[row.user_id] = { userId: row.user_id, name: row.user_id, role: 'user', permissions: {} };
        byUser[row.user_id].permissions[row.resource] = row.override || row.level;
      }
      // Also include in-memory users not yet in DB
      for (const [userId, rec] of userPermissions.entries()) {
        if (!byUser[userId]) {
          byUser[userId] = { userId, name: rec.name, role: rec.role, permissions: getEffectivePermissions(userId) || {} };
        }
      }
      return res.json({ resources: RESOURCES, levels: LEVELS, matrix: Object.values(byUser) });
    }
  } catch (err) {
    console.error('[perm-matrix]', err.message);
  }
  // fallback to in-memory
  const matrix = [];
  for (const [userId, rec] of userPermissions.entries()) {
    const perms = getEffectivePermissions(userId);
    matrix.push({ userId, name: rec.name, role: rec.role, permissions: perms });
  }
  res.json({ resources: RESOURCES, levels: LEVELS, matrix });
});

app.get('/api/permissions/users/:userId', (req, res) => {
  const perms = getEffectivePermissions(req.params.userId);
  if (!perms) return res.status(404).json({ error: 'User not found' });
  const rec = userPermissions.get(req.params.userId);
  res.json({ userId: req.params.userId, name: rec.name, role: rec.role, permissions: perms, riskScore: calcRiskScore(req.params.userId) });
});

app.post('/api/permissions/users/:userId/assign', requireAdmin, (req, res) => {
  const { resource, level } = req.body;
  if (!RESOURCES.includes(resource)) return res.status(400).json({ error: 'invalid resource' });
  if (!LEVELS.includes(level)) return res.status(400).json({ error: 'invalid level' });
  let rec = userPermissions.get(req.params.userId);
  if (!rec) {
    rec = { id: req.params.userId, name: req.params.userId, role: 'user', overrides: {} };
    userPermissions.set(req.params.userId, rec);
  }
  rec.overrides[resource] = level;

  // Persist to DB if available
  if (db.isAvailable()) {
    db.upsertPermission(req.params.userId, resource, level).catch(err =>
      console.error('[perm-assign-db]', err.message)
    );
  }

  // ─── Privilege Escalation Detection ───────────────────────────────────────────
  const effectivePerms = getEffectivePermissions(req.params.userId);
  const adminCount = effectivePerms ? RESOURCES.filter(r => effectivePerms[r] === 'admin').length : 0;
  if (adminCount > 3) {
    escalationAlerts.set(req.params.userId, {
      userId: req.params.userId,
      userName: rec.name,
      adminCount,
      detectedAt: new Date().toISOString(),
    });
    console.warn(`[escalation-alert] User ${req.params.userId} has admin on ${adminCount} resources`);
    if (db.isAvailable()) {
      db.insertEscalationAlert(req.params.userId, adminCount, RESOURCES.filter(r => effectivePerms[r] === 'admin'))
        .catch(err => console.error('[escalation-db]', err.message));
    }
  }

  res.json({ userId: req.params.userId, resource, level });
});

// ─── Unused Permissions ───────────────────────────────────────────────────────

app.get('/api/permissions/unused', (req, res) => {
  res.json(unusedPermissions);
});

app.post('/api/permissions/revoke-unused', (req, res) => {
  // Mock revocation: reset write/admin on non-core resources for users with idle permissions
  const revoked = [];
  for (const [userId, rec] of userPermissions.entries()) {
    if (rec.role !== 'admin') {
      for (const resource of ['reports', 'printers']) {
        if ((rec.overrides[resource] === 'write') || (rec.overrides[resource] === 'read')) {
          rec.overrides[resource] = 'none';
          revoked.push({ userId, resource });
        }
      }
    }
  }
  res.json({ revokedCount: revoked.length, revoked });
});

// ─── Risk Scores ─────────────────────────────────────────────────────────────────

app.get('/api/permissions/risk-scores', (req, res) => {
  const scores = [];
  for (const [userId, rec] of userPermissions.entries()) {
    scores.push({ userId, name: rec.name, role: rec.role, riskScore: calcRiskScore(userId) });
  }
  scores.sort((a, b) => b.riskScore - a.riskScore);
  res.json(scores);
});

// ─── PIM Requests ─────────────────────────────────────────────────────────────────
//
// NOTE ON THE PATH PREFIX: this is deliberately namespaced under
// /api/pim/elevation/*, NOT bare /api/pim/*. authentication-service (see
// services/core/authentication-service/src/routes/pim.js) already owns
// /api/pim/* for a *different* capability — role-based PIM (admin-defined
// "pim_roles" tied to an AD/Entra group; users request activation of a
// named role; decisions via POST .../approve|deny|revoke; GET
// /api/pim/activations). This service's PIM is resource/level-based
// just-in-time elevation (request write/admin on one of RESOURCES for N
// hours; decisions via PUT .../approve|deny; GET /api/pim/active) — it
// operates on this service's own permission matrix (userPermissions /
// ROLE_DEFAULTS above), not on directory groups, and has an incompatible
// request shape (resource+duration_hours vs role_id). These are two
// different features that happened to collide on the same prefix, not the
// same feature implemented twice. Both api-gateway
// (services/core/api-gateway/src/index.js) and the frontend's Next.js
// rewrite layer (frontend/web-app/next.config.js — see apiRewrites.test.js,
// which documents that these rewrites ARE the effective gateway for the
// browser) route bare /api/pim/* to authentication-service, which would
// silently shadow these routes if they stayed on that prefix.
// PermissionsView.tsx (frontend/web-app/src/components/views/PermissionsView.tsx)
// is the sole consumer and has been updated to match this prefix.

// ─── PIM Persistence Helpers ───────────────────────────────────────────────
//
// create/approve/deny/get all branch on db.isAvailable() the *same* way, so
// a request created while the DB is up is the exact row approve/deny later
// mutate (and vice versa for the in-memory fallback). Previously the POST
// handler unconditionally wrote to the in-memory Map regardless of
// db.isAvailable(), while approve() unconditionally consulted Postgres when
// available — so with a real DB configured, db.createPimRequest was never
// called, pim_requests stayed empty, and every approval 404'd against a
// request that only ever existed in memory. denyPimRequest had the same
// problem (never called at all). Fixed by giving create/approve/deny an
// identical db.isAvailable() branch, each backed by the same store.

const DEFAULT_ELEVATION_LEVEL = 'write'; // matches the level active elevations grant — see getEffectivePermissions

function lookupUserName(userId) {
  return userPermissions.get(userId)?.name ?? userId;
}

function toIso(value) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : value;
}

// Normalizes a raw Postgres pim_requests row (snake_case, no user_name
// column) into the same shape the in-memory fallback already produces.
// Also tolerates db.approvePimRequest's return value, which merges the
// pre-update row with a camelCase `expiresAt` override.
function toApiPimRequest(row) {
  return {
    id: row.id,
    userId: row.user_id,
    userName: lookupUserName(row.user_id),
    resource: row.resource,
    duration_hours: row.duration_hours,
    reason: row.justification ?? '',
    status: row.status,
    createdAt: toIso(row.requested_at),
    expiresAt: toIso(row.expiresAt ?? row.expires_at),
  };
}

// The identity performing the request, from the verified JWT (see
// src/middleware/oidcAuth.js). Used below to block a requester from
// approving their own PIM elevation request, even if they also hold an
// admin role — a verified JWT + an admin role only proves *who* is asking
// and *that* they're an admin, not that this specific approval is
// independent of the request.
function callerIdentity(req) {
  return req.user?.sub ?? req.user?.preferred_username ?? req.user?.userId ?? null;
}

app.get('/api/pim/elevation/requests', async (req, res) => {
  if (db.isAvailable()) {
    try {
      const rows = await db.getPimRequests(req.query.status);
      return res.json(rows.map(toApiPimRequest));
    } catch (err) { console.error('[pim-get-db]', err.message); }
  }
  res.json([...pimRequests.values()]);
});

app.post('/api/pim/elevation/request', async (req, res) => {
  const { userId, resource, duration_hours, reason, level } = req.body;
  if (!userId || !resource || !duration_hours) return res.status(400).json({ error: 'userId, resource, duration_hours required' });
  const id = uuidv4();
  const elevationLevel = level ?? DEFAULT_ELEVATION_LEVEL;

  if (db.isAvailable()) {
    try {
      const row = await db.createPimRequest(id, userId, lookupUserName(userId), resource, elevationLevel, reason ?? '', duration_hours);
      return res.status(201).json(toApiPimRequest(row));
    } catch (err) {
      console.error('[pim-create-db]', err.message);
    }
  }
  // In-memory fallback
  const request = { id, userId, userName: lookupUserName(userId), resource, duration_hours, reason: reason ?? '', status: 'pending', createdAt: new Date().toISOString(), expiresAt: null };
  pimRequests.set(id, request);
  res.status(201).json(request);
});

app.put('/api/pim/elevation/requests/:id/approve', requireAdmin, async (req, res) => {
  const caller = callerIdentity(req);

  if (db.isAvailable()) {
    try {
      const target = await db.getPimRequestById(req.params.id);
      if (!target) return res.status(404).json({ error: 'Request not found' });
      if (caller && caller === target.user_id) {
        return res.status(403).json({ error: 'forbidden', message: 'cannot approve your own elevation request' });
      }
      if (target.status !== 'pending') return res.status(400).json({ error: 'Request already processed' });
      const result = await db.approvePimRequest(req.params.id, caller || req.body.approvedBy || 'admin');
      if (!result) return res.status(404).json({ error: 'Request not found' });
      return res.json(toApiPimRequest(result));
    } catch (err) {
      console.error('[pim-approve-db]', err.message);
    }
  }
  // In-memory fallback
  const request = pimRequests.get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (caller && caller === request.userId) {
    return res.status(403).json({ error: 'forbidden', message: 'cannot approve your own elevation request' });
  }
  if (request.status !== 'pending') return res.status(400).json({ error: 'Request already processed' });
  request.status = 'approved';
  const expiresAt = Date.now() + request.duration_hours * 3600_000;
  request.expiresAt = new Date(expiresAt).toISOString();
  const elevId = uuidv4();
  activeElevations.set(elevId, { id: elevId, userId: request.userId, userName: request.userName, resource: request.resource, expiresAt, requestId: request.id });
  res.json(request);
});

app.put('/api/pim/elevation/requests/:id/deny', requireAdmin, async (req, res) => {
  if (db.isAvailable()) {
    try {
      const result = await db.denyPimRequest(req.params.id);
      if (!result) return res.status(404).json({ error: 'Request not found' });
      return res.json(toApiPimRequest(result));
    } catch (err) {
      console.error('[pim-deny-db]', err.message);
    }
  }
  // In-memory fallback
  const request = pimRequests.get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  request.status = 'denied';
  res.json(request);
});

app.get('/api/pim/elevation/active', async (req, res) => {
  if (db.isAvailable()) {
    try {
      const rows = await db.getActiveElevations();
      const now = Date.now();
      return res.json(rows.map(e => ({
        ...e,
        timeRemainingMs: new Date(e.expires_at).getTime() - now,
        timeRemainingMinutes: Math.ceil((new Date(e.expires_at).getTime() - now) / 60_000)
      })));
    } catch (err) { console.error('[pim-active-db]', err.message); }
  }
  const now = Date.now();
  const active = [...activeElevations.values()].filter(e => e.expiresAt > now).map(e => ({ ...e, timeRemainingMs: e.expiresAt - now, timeRemainingMinutes: Math.ceil((e.expiresAt - now) / 60_000) }));
  res.json(active);
});

// ─── Escalation Alerts ───────────────────────────────────────────────────────────

app.get('/api/permissions/escalation-alerts', async (req, res) => {
  if (db.isAvailable()) {
    try {
      const rows = await db.getEscalationAlerts();
      return res.json(rows);
    } catch (err) { console.error('[escalation-get-db]', err.message); }
  }
  res.json([...escalationAlerts.values()]);
});

// ─── Group Membership Permission Propagation ──────────────────────────────────────

app.post('/api/permissions/groups/:groupId/propagate', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  // Use ROLE_DEFAULTS['user'] as the group template
  const template = ROLE_DEFAULTS['user'];

  let rec = userPermissions.get(userId);
  if (!rec) {
    rec = { id: userId, name: userId, role: 'user', overrides: {} };
    userPermissions.set(userId, rec);
  }

  // Propagate all group template permissions to the user (only if higher than current)
  const levelIndex = l => LEVELS.indexOf(l);
  for (const [resource, level] of Object.entries(template)) {
    const currentLevel = rec.overrides[resource] ?? (ROLE_DEFAULTS[rec.role] ?? ROLE_DEFAULTS['read-only'])[resource] ?? 'none';
    if (levelIndex(level) > levelIndex(currentLevel)) {
      rec.overrides[resource] = level;
    }
  }

  const effective = getEffectivePermissions(userId);
  res.json({ userId, groupId: req.params.groupId, propagated: template, effectivePermissions: effective });
});

// ─── Auto-Revoke Cron (runs every 60s — represents a daily job) ──────────────────

setInterval(() => {
  const GRACE_DAYS = 97; // 90 days idle + 7 day grace
  let count = 0;
  for (const entry of unusedPermissions) {
    if (entry.daysIdle > GRACE_DAYS) {
      const rec = userPermissions.get(entry.userId);
      if (rec) {
        rec.overrides[entry.resource] = 'none';
        count++;
      }
    }
  }
  // Remove revoked entries from the array
  const before = unusedPermissions.length;
  for (let i = unusedPermissions.length - 1; i >= 0; i--) {
    if (unusedPermissions[i].daysIdle > GRACE_DAYS) unusedPermissions.splice(i, 1);
  }
  if (count > 0) {
    console.log(`[auto-revoke] Revoked ${count} unused permissions`);
  }
}, 60_000);

// ─── Health ───────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'least-privilege', users: userPermissions.size, pendingPimRequests: [...pimRequests.values()].filter(r => r.status === 'pending').length });
});

// ─── Start ────────────────────────────────────────────────────────────────────────

db.initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[oauth-provider] listening on :${PORT}`);
  });
}).catch(err => {
  console.error('[oauth-provider] startup error:', err.message);
  process.exit(1);
});

module.exports = app;
