const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const db = require('./db');
const { oidcAuth, requireAdmin } = require('./middleware/oidcAuth');

// ─── Event Bus ───────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'identity-service' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));

// ─── Auth ─────────────────────────────────────────────────────────────────────
//
// identity-service is the platform's identity store: every route below
// (other than /health) reads or writes users, groups, or OUs, so all of it
// requires a verified bearer token. Creating/updating/deleting users,
// groups (incl. membership), and OUs additionally requires an admin role
// (see requireAdmin on those specific routes below) — oidcAuth alone only
// proves *who* is asking, not that they're allowed to mutate the directory.
app.use(oidcAuth({ skipPaths: ['/health'] }));

// In-memory store — DB-first (see db.js), this mirrors every successful
// write so reads stay consistent when PostgreSQL is unavailable (initDb()
// failed to connect — see server bootstrap below) or in tests where `pg` is
// mocked and doesn't actually persist what it "inserts". See db.isAvailable()
// call sites below for the DB-first / in-memory-fallback split on each route.
const users = new Map();
const groups = new Map();
const ous = new Map();

// Converts a pg TIMESTAMPTZ value (a Date, via node-postgres's default
// parser) — or a plain ISO string, as produced by a mocked pg client in
// tests — into the ISO string shape the pre-existing in-memory
// implementation always returned. Returns undefined (not null) for an
// absent value so JSON.stringify drops the key entirely, matching the
// original stub's behavior of never emitting e.g. `"updatedAt": null` for a
// user that has never been updated.
function iso(value) {
  if (!value) return undefined;
  return value instanceof Date ? value.toISOString() : value;
}

function rowToUser(row) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    displayName: row.display_name ?? undefined,
    department: row.department ?? undefined,
    title: row.title ?? undefined,
    enabled: row.enabled,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function rowToGroup(row, members) {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    members: members ?? [],
    createdAt: iso(row.created_at),
  };
}

function rowToOu(row) {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    parentId: row.parent_id ?? undefined,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

// ==================
// Users: DB-first reads
// ==================
async function getAllUsers() {
  if (db.isAvailable()) {
    try {
      const r = await db.query(
        'SELECT id, username, email, display_name, department, title, enabled, created_at, updated_at FROM users ORDER BY created_at'
      );
      return r.rows.map(rowToUser);
    } catch (err) {
      logger.warn('identity-db: list users failed, falling back to in-memory', { error: err.message });
    }
  }
  return [...users.values()];
}

async function getUserById(id) {
  if (db.isAvailable()) {
    try {
      const r = await db.query(
        'SELECT id, username, email, display_name, department, title, enabled, created_at, updated_at FROM users WHERE id=$1',
        [id]
      );
      return r.rows.length ? rowToUser(r.rows[0]) : null;
    } catch (err) {
      logger.warn('identity-db: get user failed, falling back to in-memory', { error: err.message });
    }
  }
  return users.get(id) ?? null;
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'identity-service', timestamp: new Date().toISOString() });
});

// ==================
// Users API
// ==================
app.get('/api/users', async (req, res) => {
  const { page = 1, limit = 50, search } = req.query;
  let result = await getAllUsers();
  if (search) {
    const q = search.toLowerCase();
    result = result.filter(u => u.displayName?.toLowerCase().includes(q) || u.email?.toLowerCase().includes(q));
  }
  const start = (page - 1) * limit;
  res.json({ users: result.slice(start, start + Number(limit)), total: result.length, page: Number(page) });
});

app.get('/api/users/:id', async (req, res) => {
  const user = await getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, email, displayName, department, title } = req.body;
  if (!username || !email) return res.status(400).json({ error: 'username and email are required' });
  const id = crypto.randomUUID();
  const user = { id, username, email, displayName, department, title, enabled: true, createdAt: new Date().toISOString() };
  if (db.isAvailable()) {
    try {
      await db.query(
        'INSERT INTO users(id, username, email, display_name, department, title, enabled) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [id, username, email, displayName ?? null, department ?? null, title ?? null, true]
      );
    } catch (err) {
      logger.error('identity-db: create user failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  users.set(id, user);
  logger.info(`User created: ${username}`);
  publish('identity.user.created', { userId: id, username, email });
  res.status(201).json(user);
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const existing = await getUserById(req.params.id);
  if (!existing) return res.status(404).json({ error: 'User not found' });
  const updated = { ...existing, ...req.body, updatedAt: new Date().toISOString() };
  if (db.isAvailable()) {
    try {
      await db.query(
        'UPDATE users SET username=$1, email=$2, display_name=$3, department=$4, title=$5, enabled=$6, updated_at=$7 WHERE id=$8',
        [updated.username, updated.email, updated.displayName ?? null, updated.department ?? null, updated.title ?? null, updated.enabled, updated.updatedAt, req.params.id]
      );
    } catch (err) {
      logger.error('identity-db: update user failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  users.set(req.params.id, updated);
  res.json(updated);
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  const existing = await getUserById(req.params.id);
  if (!existing) return res.status(404).json({ error: 'User not found' });
  const userId = req.params.id;
  if (db.isAvailable()) {
    try {
      await db.query('DELETE FROM users WHERE id=$1', [userId]);
    } catch (err) {
      logger.error('identity-db: delete user failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  users.delete(userId);
  publish('identity.user.deleted', { userId });
  res.status(204).send();
});

// ==================
// Groups: DB-first reads
// ==================
async function getAllGroups() {
  if (db.isAvailable()) {
    try {
      const g = await db.query('SELECT id, name, description, created_at FROM groups ORDER BY created_at');
      const m = await db.query('SELECT group_id, user_id FROM group_members');
      const membersByGroup = new Map();
      for (const row of m.rows) {
        if (!membersByGroup.has(row.group_id)) membersByGroup.set(row.group_id, []);
        membersByGroup.get(row.group_id).push(row.user_id);
      }
      return g.rows.map(row => rowToGroup(row, membersByGroup.get(row.id)));
    } catch (err) {
      logger.warn('identity-db: list groups failed, falling back to in-memory', { error: err.message });
    }
  }
  return [...groups.values()];
}

async function getGroupById(id) {
  if (db.isAvailable()) {
    try {
      const g = await db.query('SELECT id, name, description, created_at FROM groups WHERE id=$1', [id]);
      if (!g.rows.length) return null;
      const m = await db.query('SELECT user_id FROM group_members WHERE group_id=$1', [id]);
      return rowToGroup(g.rows[0], m.rows.map(r => r.user_id));
    } catch (err) {
      logger.warn('identity-db: get group failed, falling back to in-memory', { error: err.message });
    }
  }
  return groups.get(id) ?? null;
}

// ==================
// Groups API
// ==================
app.get('/api/groups', async (req, res) => {
  const list = await getAllGroups();
  res.json({ groups: list, total: list.length });
});

app.get('/api/groups/:id', async (req, res) => {
  const group = await getGroupById(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  res.json(group);
});

app.post('/api/groups', requireAdmin, async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  const id = crypto.randomUUID();
  const group = { id, name, description, members: [], createdAt: new Date().toISOString() };
  if (db.isAvailable()) {
    try {
      await db.query('INSERT INTO groups(id, name, description) VALUES($1,$2,$3)', [id, name, description ?? null]);
    } catch (err) {
      logger.error('identity-db: create group failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  groups.set(id, group);
  logger.info(`Group created: ${name}`);
  publish('identity.group.created', { groupId: id, name });
  res.status(201).json(group);
});

app.post('/api/groups/:id/members', requireAdmin, async (req, res) => {
  const group = await getGroupById(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const { userId } = req.body;
  if (!group.members.includes(userId)) group.members.push(userId);
  if (db.isAvailable() && userId !== undefined && userId !== null) {
    try {
      await db.query(
        'INSERT INTO group_members(group_id, user_id) VALUES($1,$2) ON CONFLICT (group_id, user_id) DO NOTHING',
        [req.params.id, userId]
      );
    } catch (err) {
      logger.error('identity-db: add group member failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  groups.set(req.params.id, group);
  res.json(group);
});

app.delete('/api/groups/:id', requireAdmin, async (req, res) => {
  const existing = await getGroupById(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Group not found' });
  if (db.isAvailable()) {
    try {
      await db.query('DELETE FROM groups WHERE id=$1', [req.params.id]); // ON DELETE CASCADE clears group_members
    } catch (err) {
      logger.error('identity-db: delete group failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  groups.delete(req.params.id);
  res.status(204).send();
});

// ==================
// OUs: DB-first reads
//
// The pre-existing stub declared an `ous` in-memory Map but wired up no
// routes for it at all — dead code. These routes are new (see task audit),
// modeled on the users/groups CRUD conventions already established in this
// file, and are DB-backed + auth-gated from the start.
// ==================
async function getAllOus() {
  if (db.isAvailable()) {
    try {
      const r = await db.query('SELECT id, name, description, parent_id, created_at, updated_at FROM ous ORDER BY created_at');
      return r.rows.map(rowToOu);
    } catch (err) {
      logger.warn('identity-db: list OUs failed, falling back to in-memory', { error: err.message });
    }
  }
  return [...ous.values()];
}

async function getOuById(id) {
  if (db.isAvailable()) {
    try {
      const r = await db.query('SELECT id, name, description, parent_id, created_at, updated_at FROM ous WHERE id=$1', [id]);
      return r.rows.length ? rowToOu(r.rows[0]) : null;
    } catch (err) {
      logger.warn('identity-db: get OU failed, falling back to in-memory', { error: err.message });
    }
  }
  return ous.get(id) ?? null;
}

// ==================
// OUs API
// ==================
app.get('/api/ous', async (req, res) => {
  const list = await getAllOus();
  res.json({ ous: list, total: list.length });
});

app.get('/api/ous/:id', async (req, res) => {
  const ou = await getOuById(req.params.id);
  if (!ou) return res.status(404).json({ error: 'OU not found' });
  res.json(ou);
});

app.post('/api/ous', requireAdmin, async (req, res) => {
  const { name, description, parentId } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  const id = crypto.randomUUID();
  const ou = { id, name, description, parentId, createdAt: new Date().toISOString() };
  if (db.isAvailable()) {
    try {
      await db.query(
        'INSERT INTO ous(id, name, description, parent_id) VALUES($1,$2,$3,$4)',
        [id, name, description ?? null, parentId ?? null]
      );
    } catch (err) {
      logger.error('identity-db: create OU failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  ous.set(id, ou);
  logger.info(`OU created: ${name}`);
  publish('identity.ou.created', { ouId: id, name });
  res.status(201).json(ou);
});

app.put('/api/ous/:id', requireAdmin, async (req, res) => {
  const existing = await getOuById(req.params.id);
  if (!existing) return res.status(404).json({ error: 'OU not found' });
  const updated = { ...existing, ...req.body, updatedAt: new Date().toISOString() };
  if (db.isAvailable()) {
    try {
      await db.query(
        'UPDATE ous SET name=$1, description=$2, parent_id=$3, updated_at=$4 WHERE id=$5',
        [updated.name, updated.description ?? null, updated.parentId ?? null, updated.updatedAt, req.params.id]
      );
    } catch (err) {
      logger.error('identity-db: update OU failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  ous.set(req.params.id, updated);
  res.json(updated);
});

app.delete('/api/ous/:id', requireAdmin, async (req, res) => {
  const existing = await getOuById(req.params.id);
  if (!existing) return res.status(404).json({ error: 'OU not found' });
  if (db.isAvailable()) {
    try {
      await db.query('DELETE FROM ous WHERE id=$1', [req.params.id]);
    } catch (err) {
      logger.error('identity-db: delete OU failed', { error: err.message });
      return res.status(500).json({ error: err.message });
    }
  }
  ous.delete(req.params.id);
  res.status(204).send();
});

// ==================
// Identity (LDAP-compatible) endpoint
// ==================
app.get('/api/identity/search', async (req, res) => {
  const { filter, base, scope } = req.query; // eslint-disable-line no-unused-vars -- kept for API-shape parity; not yet used for filtering
  const allUsers = await getAllUsers();
  const allGroups = await getAllGroups();
  res.json({ entries: [...allUsers, ...allGroups], total: allUsers.length + allGroups.length });
});

// Start server
db.initDb().catch(err => logger.warn('identity-db: initDb failed', { error: err.message }));
connectBus();
const server = app.listen(PORT, () => {
  logger.info(`Identity Service running on port ${PORT}`);
});

function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully`);
  server.close(() => { logger.info('Identity service stopped'); process.exit(0); });
  setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

module.exports = app;
