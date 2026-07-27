const express = require('express');
const cors = require('cors');
const { NodeSSH } = require('node-ssh');
const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt    = require('jsonwebtoken');
const { callDeviceService } = require('./utils/serviceClient');
const db = require('./db');

// ── Auth helpers ─────────────────────────────────────────────────────────────
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET environment variable is required in production');
}
const JWT_SECRET    = process.env.JWT_SECRET || 'dev-jwt-secret-not-for-production';
const BCRYPT_ROUNDS = 10;

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function comparePassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function parseCookies(cookieHeader = '') {
  return Object.fromEntries(
    cookieHeader.split(';').map(c => c.trim().split('=').map(decodeURIComponent))
  );
}

function authMiddleware(req, res, next) {
  const cookies = parseCookies(req.headers.cookie || '');
  const cookieToken = cookies['auth_token'];
  const authHeader = req.headers['authorization'];
  const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const token = cookieToken || headerToken;

  if (!token) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  req.user = payload;
  next();
}
// ────────────────────────────────────────────────────────────────────────────

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) {
      if (process.env.NODE_ENV === 'production') {
        return callback(new Error('Origin header is required'), false);
      }
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`Origin ${origin} not allowed by CORS policy`), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// SSH connection for Ubuntu container
const ssh = new NodeSSH();
const CT2001_HOST = process.env.CT2001_HOST || '192.168.1.51';

// In-memory device store — populated via enrollment. This is the
// in-memory MIRROR: DB-first reads/writes go through the helpers below
// (getAllLocalDevices / getLocalDeviceById / saveLocalDevice), which keep
// this object in sync on every successful write so the fallback stays
// consistent whether or not PostgreSQL is reachable — see db.js.
const deviceStore = {};

// ── Local device persistence (DB-first, in-memory fallback) ────────────────
// The legacy in-memory deviceStore predates device-service delegation (see
// callDeviceService above) and is still the source of truth for devices
// enrolled directly against api-backend (POST /api/devices/enroll) and for
// the GET /api/devices(/:id) fallback path used when device-service is
// unreachable. Its entries are mutated ad hoc by several handlers (refresh,
// apps/install, apps/:appId delete — each adding/changing fields like
// installedApps, installedAppsCount, status, lastSeen) rather than
// conforming to one fixed shape, so instead of modeling a relational schema
// per field (risking silently dropping a field none of the golden-master
// tests happen to exercise), each device is persisted as a single JSONB
// blob keyed by id — see migrations/001_api_backend_schema.sql.
//
// DB write failures are logged and swallowed rather than surfaced as a new
// 500: the pre-existing in-memory implementation could never fail these
// operations, and changing a status code on DB hiccups would violate the
// golden-master contract this work must preserve. The in-memory mirror is
// always updated regardless, so the request still succeeds exactly as it
// did before this persistence layer existed.
function deviceRowToObject(row) {
  return { id: row.id, ...row.data };
}

async function dbListDevices() {
  if (!db.isAvailable()) return null;
  try {
    const r = await db.query('SELECT id, data FROM devices ORDER BY updated_at');
    return r.rows.map(deviceRowToObject);
  } catch (err) {
    console.warn('[api-backend-db] list devices failed, falling back to in-memory:', err.message);
    return null;
  }
}

async function dbGetDevice(id) {
  if (!db.isAvailable()) return undefined;
  try {
    const r = await db.query('SELECT id, data FROM devices WHERE id=$1', [id]);
    return r.rows.length ? deviceRowToObject(r.rows[0]) : null;
  } catch (err) {
    console.warn('[api-backend-db] get device failed, falling back to in-memory:', err.message);
    return undefined;
  }
}

async function dbUpsertDevice(device) {
  if (!db.isAvailable()) return;
  const { id, ...data } = device;
  try {
    await db.query(
      'INSERT INTO devices(id, data, updated_at) VALUES($1,$2,NOW()) ON CONFLICT (id) DO UPDATE SET data=$2, updated_at=NOW()',
      [id, JSON.stringify(data)]
    );
  } catch (err) {
    console.warn('[api-backend-db] upsert device failed:', err.message);
  }
}

// DB-first: returns every device, falling back to the in-memory mirror
// whenever the DB is unavailable or errors. Used by GET /api/devices'
// fallback path, the WebSocket initial snapshot, and /api/health's count.
async function getAllLocalDevices() {
  const fromDb = await dbListDevices();
  return fromDb !== null ? fromDb : Object.values(deviceStore);
}

// DB-first: null means "DB says this id doesn't exist" (a real answer —
// do NOT fall back to memory), undefined-from-dbGetDevice means "DB
// unavailable/errored", which IS when we fall back to the in-memory
// mirror. Mirrors the identity-service db.js call-site convention.
async function getLocalDeviceById(id) {
  const fromDb = await dbGetDevice(id);
  if (fromDb !== undefined) return fromDb;
  return deviceStore[id] || null;
}

// Persists a device (insert or update) to the DB (best-effort — see note
// above) and always mirrors it into deviceStore.
async function saveLocalDevice(device) {
  await dbUpsertDevice(device);
  deviceStore[device.id] = device;
}

// ── device-service delegation ─────────────────────────────────────────────────
// GET /api/devices and GET /api/devices/:id delegate to device-service (the
// domain owner) via a Client Credentials service token. If device-service is
// unreachable, rejects the token, or errors out, we fall back to the legacy
// in-memory deviceStore so the API keeps working during rollout / outages.

// Throttle the fallback warning to at most once per minute so a persistent
// outage doesn't spam the logs on every request.
const DELEGATION_WARN_THROTTLE_MS = 60 * 1000;
let _lastDelegationWarnAt = 0;
function warnDelegationFallback(routeLabel, err) {
  const now = Date.now();
  if (now - _lastDelegationWarnAt < DELEGATION_WARN_THROTTLE_MS) return;
  _lastDelegationWarnAt = now;
  console.warn(`[device-delegation] ${routeLabel} — falling back to local deviceStore: ${err.message}`);
}

// Fields that are new/nullable on newer device-service builds. If a field is
// missing from the response (older device-service), it is omitted from the
// adapted device rather than forced to null, so the shape matches what the
// frontend already gets from the legacy in-memory store today.
const DEVICE_NULLABLE_FIELDS = ['complianceScore', 'os', 'osVersion', 'ipAddress', 'kernel', 'packageManager'];

/**
 * Adapts a device-service device (toJSON shape) to the shape api-backend has
 * historically returned: `hostname` -> `name`, core fields passed through,
 * and the newer compliance/inventory fields passed through only when present.
 */
function adaptDevice(raw) {
  if (!raw || typeof raw !== 'object') return raw;

  const device = {
    id: raw.id,
    name: raw.hostname,
    platform: raw.platform,
    status: raw.status,
    enrolledAt: raw.enrolledAt,
    lastSeen: raw.lastSeen,
  };

  if (raw.isCompliant !== undefined) device.isCompliant = raw.isCompliant;
  if (raw.complianceViolations !== undefined) device.complianceViolations = raw.complianceViolations;

  for (const field of DEVICE_NULLABLE_FIELDS) {
    if (raw[field] !== undefined && raw[field] !== null) {
      device[field] = raw[field];
    }
  }

  return device;
}

const userStore = [
  {
    id: 'admin',
    name: 'Administrator',
    username: 'admin',
    email: 'admin@opendirectory.local',
    role: 'System Administrator',
    active: true,
    groups: ['admin'],
    passwordHash: null, // set below after BCRYPT_ROUNDS is defined
    lastLogin: new Date(),
    created: new Date('2024-01-01')
  }
];
const initialAdminPassword = process.env.ADMIN_PASSWORD;
if (!initialAdminPassword && process.env.NODE_ENV === 'production') {
  throw new Error('ADMIN_PASSWORD environment variable is required in production');
}
userStore[0].passwordHash = bcrypt.hashSync(initialAdminPassword || 'admin!', BCRYPT_ROUNDS);

// ── Local user persistence (DB-first, in-memory fallback) ──────────────────
// Mirrors the deviceStore pattern above and the established
// identity-service/src/db.js convention: DB-first reads that fall back to
// the in-memory userStore array on unavailability/error, and best-effort
// (log-and-continue, never a new 500) DB writes that always also mirror
// into userStore so behavior — including status codes — matches the
// pre-existing pure in-memory implementation exactly.
function userRowToObject(row) {
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    email: row.email,
    role: row.role,
    active: row.active,
    groups: row.groups || [],
    passwordHash: row.password_hash,
    lastLogin: row.last_login,
    created: row.created,
  };
}

const USER_COLUMNS = 'id, name, username, email, role, active, groups, password_hash, last_login, created';

async function dbListUsers() {
  if (!db.isAvailable()) return null;
  try {
    const r = await db.query(`SELECT ${USER_COLUMNS} FROM users ORDER BY created`);
    return r.rows.map(userRowToObject);
  } catch (err) {
    console.warn('[api-backend-db] list users failed, falling back to in-memory:', err.message);
    return null;
  }
}

async function dbGetUserById(id) {
  if (!db.isAvailable()) return undefined;
  try {
    const r = await db.query(`SELECT ${USER_COLUMNS} FROM users WHERE id=$1`, [id]);
    return r.rows.length ? userRowToObject(r.rows[0]) : null;
  } catch (err) {
    console.warn('[api-backend-db] get user failed, falling back to in-memory:', err.message);
    return undefined;
  }
}

async function dbFindActiveUserByIdentifier(identifier) {
  if (!db.isAvailable()) return undefined;
  try {
    const r = await db.query(
      `SELECT ${USER_COLUMNS} FROM users WHERE (username=$1 OR email=$1) AND active=true LIMIT 1`,
      [identifier]
    );
    return r.rows.length ? userRowToObject(r.rows[0]) : null;
  } catch (err) {
    console.warn('[api-backend-db] find user failed, falling back to in-memory:', err.message);
    return undefined;
  }
}

async function dbUsernameExists(username) {
  if (!db.isAvailable()) return undefined;
  try {
    const r = await db.query('SELECT 1 FROM users WHERE username=$1 LIMIT 1', [username]);
    return r.rows.length > 0;
  } catch (err) {
    console.warn('[api-backend-db] username lookup failed, falling back to in-memory:', err.message);
    return undefined;
  }
}

async function dbInsertUser(user) {
  if (!db.isAvailable()) return;
  try {
    await db.query(
      `INSERT INTO users(${USER_COLUMNS}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [user.id, user.name, user.username, user.email, user.role, user.active, user.groups, user.passwordHash, user.lastLogin, user.created]
    );
  } catch (err) {
    console.warn('[api-backend-db] insert user failed:', err.message);
  }
}

async function dbUpdateUser(id, fields) {
  if (!db.isAvailable()) return;
  const entries = Object.entries(fields);
  if (!entries.length) return;
  const sets = entries.map(([col], i) => `${col}=$${i + 1}`);
  const params = entries.map(([, val]) => val);
  params.push(id);
  try {
    await db.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${params.length}`, params);
  } catch (err) {
    console.warn('[api-backend-db] update user failed:', err.message);
  }
}

async function dbDeleteUser(id) {
  if (!db.isAvailable()) return;
  try {
    await db.query('DELETE FROM users WHERE id=$1', [id]);
  } catch (err) {
    console.warn('[api-backend-db] delete user failed:', err.message);
  }
}

// DB-first accessors — see the "null means DB found nothing, undefined
// means DB unavailable/errored (fall back)" convention documented on the
// device helpers above.
async function getAllUsersFull() {
  const fromDb = await dbListUsers();
  return fromDb !== null ? fromDb : userStore;
}

async function getUserByIdFull(id) {
  const fromDb = await dbGetUserById(id);
  if (fromDb !== undefined) return fromDb;
  return userStore.find(u => u.id === id) || null;
}

async function findActiveUserByIdentifier(identifier) {
  const fromDb = await dbFindActiveUserByIdentifier(identifier);
  if (fromDb !== undefined) return fromDb;
  return userStore.find(u => (u.username === identifier || u.email === identifier) && u.active) || null;
}

async function usernameExists(username) {
  const fromDb = await dbUsernameExists(username);
  if (fromDb !== undefined) return fromDb;
  return !!userStore.find(u => u.username === username);
}

// Upserts a user into the in-memory mirror by id. Used after every write so
// userStore stays consistent regardless of whether the preceding read came
// from the DB (a fresh object, not a userStore reference) or from memory.
function mirrorUserInStore(user) {
  const idx = userStore.findIndex(u => u.id === user.id);
  if (idx === -1) userStore.push(user);
  else userStore[idx] = user;
}

// Seed the default admin user into the DB once it's available (idempotent
// via ON CONFLICT DO NOTHING, so a password changed via
// POST /api/auth/change-password on a prior boot is never clobbered). This
// runs after migrations complete — see db.initDb() call near the bottom of
// this file — and is required for correctness: once db.isAvailable() is
// true, DB-first reads no longer consult userStore, so without this seed a
// fresh database would have no 'admin' row and the documented default
// login would stop working.
async function seedAdminUser() {
  if (!db.isAvailable()) return;
  const admin = userStore[0];
  try {
    await db.query(
      `INSERT INTO users(${USER_COLUMNS}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (id) DO NOTHING`,
      [admin.id, admin.name, admin.username, admin.email, admin.role, admin.active, admin.groups, admin.passwordHash, admin.lastLogin, admin.created]
    );
  } catch (err) {
    console.warn('[api-backend-db] admin seed failed:', err.message);
  }
}

// WebSocket connections — validate token on connect
const clients = new Set();

wss.on('connection', async (ws, req) => {
  // Extract token from query param or cookie
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const queryToken = url.searchParams.get('token');
  const cookies = parseCookies(req.headers.cookie || '');
  const token = queryToken || cookies['auth_token'];

  if (!token || !verifyToken(token)) {
    ws.close(4401, 'Unauthorized');
    return;
  }

  clients.add(ws);

  ws.on('close', () => {
    clients.delete(ws);
  });

  ws.send(JSON.stringify({
    type: 'device_status',
    data: await getAllLocalDevices()
  }));
});

function broadcast(message) {
  const data = JSON.stringify(message);
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  });
}

// ── Input validation helpers ─────────────────────────────────────────────────
function isNonEmptyString(v, maxLen = 255) {
  return typeof v === 'string' && v.trim().length > 0 && v.length <= maxLen;
}

function isValidEmail(v) {
  return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
}

function validateLoginBody(body) {
  const { username, password } = body || {};
  if (!isNonEmptyString(username, 254)) return 'username is required';
  if (!isNonEmptyString(password, 128)) return 'password is required';
  return null;
}

function validateUserBody(body) {
  const { username, password } = body || {};
  if (!isNonEmptyString(username, 64)) return 'username is required (max 64 chars)';
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return 'username may only contain letters, numbers, underscores and hyphens';
  if (!isNonEmptyString(password, 128) || password.length < 8) return 'password is required (min 8 chars)';
  if (body.email && !isValidEmail(body.email)) return 'invalid email address';
  return null;
}
// ────────────────────────────────────────────────────────────────────────────

// ── Per-username rate limiter for login ──────────────────────────────────────
const loginAttempts = new Map();
const LOGIN_WINDOW_MS  = 15 * 60 * 1000;
const LOGIN_MAX        = 5;

function loginRateLimit(req, res, next) {
  const username = (req.body?.username || '').toLowerCase().trim();
  const key = username || req.ip;
  const now = Date.now();

  const record = loginAttempts.get(key) || { count: 0, resetAt: now + LOGIN_WINDOW_MS };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + LOGIN_WINDOW_MS; }
  record.count += 1;
  loginAttempts.set(key, record);

  if (record.count > LOGIN_MAX) {
    return res.status(429).json({ success: false, error: 'Too many login attempts, please try again later.' });
  }
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [key, record] of loginAttempts) {
    if (now > record.resetAt) loginAttempts.delete(key);
  }
}, LOGIN_WINDOW_MS);

// ── Per-IP rate limiter for write operations (enrollment, user creation) ─────
const writeAttempts = new Map();
const WRITE_WINDOW_MS = 60 * 1000; // 1 minute
const WRITE_MAX       = 20;

function writeRateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const record = writeAttempts.get(key) || { count: 0, resetAt: now + WRITE_WINDOW_MS };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + WRITE_WINDOW_MS; }
  record.count += 1;
  writeAttempts.set(key, record);
  if (record.count > WRITE_MAX) {
    return res.status(429).json({ success: false, error: 'Too many requests, please try again later.' });
  }
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [key, record] of writeAttempts) {
    if (now > record.resetAt) writeAttempts.delete(key);
  }
}, WRITE_WINDOW_MS);
// ────────────────────────────────────────────────────────────────────────────

// ── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const validationError = validateLoginBody(req.body);
  if (validationError)
    return res.status(400).json({ success: false, error: validationError });

  const { username, password } = req.body;

  const user = await findActiveUserByIdentifier(username);
  if (!user || !(await comparePassword(password, user.passwordHash)))
    return res.status(401).json({ success: false, error: 'Invalid username or password' });

  user.lastLogin = new Date();
  await dbUpdateUser(user.id, { last_login: user.lastLogin });
  mirrorUserInStore(user);
  const token = signToken({ id: user.id, username: user.username, name: user.name, role: user.role, groups: user.groups });
  const { passwordHash, ...safeUser } = user;

  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/',
  });

  res.json({ success: true, data: { token, user: safeUser } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token', { path: '/' });
  res.json({ success: true, message: 'Logged out' });
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  const user = await getUserByIdFull(req.user.id);
  if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const user = await getUserByIdFull(req.user.id);
  if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { name, email } = req.body;
  const fields = {};
  if (name && isNonEmptyString(name, 128))  { user.name  = name;  fields.name  = name; }
  if (email && isValidEmail(email))         { user.email = email; fields.email = email; }
  if (Object.keys(fields).length) await dbUpdateUser(user.id, fields);
  mirrorUserInStore(user);
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const user = await getUserByIdFull(req.user.id);
  if (!user) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { currentPassword, newPassword } = req.body || {};
  if (!isNonEmptyString(currentPassword, 128) || !isNonEmptyString(newPassword, 128) || newPassword.length < 8)
    return res.status(400).json({ success: false, error: 'newPassword must be at least 8 characters' });
  if (!(await comparePassword(currentPassword, user.passwordHash)))
    return res.status(400).json({ success: false, error: 'Current password is incorrect' });
  user.passwordHash = await hashPassword(newPassword);
  await dbUpdateUser(user.id, { password_hash: user.passwordHash });
  mirrorUserInStore(user);
  res.json({ success: true, message: 'Password changed' });
});
// ────────────────────────────────────────────────────────────────────────────

// Users API — requires authentication for all operations
app.get('/api/users', authMiddleware, async (req, res) => {
  const users = await getAllUsersFull();
  res.json({ success: true, data: users.map(({ passwordHash, ...u }) => u) });
});

app.post('/api/users', authMiddleware, writeRateLimit, async (req, res) => {
  const validationError = validateUserBody(req.body);
  if (validationError)
    return res.status(400).json({ success: false, error: validationError });

  const { username, name, email, password, role, groups } = req.body;
  if (await usernameExists(username))
    return res.status(409).json({ success: false, error: 'Username already exists' });
  const user = {
    id: 'user_' + Date.now(),
    username, name: name || username,
    email: email || `${username}@opendirectory.local`,
    role: role || 'User',
    active: true,
    groups: groups || ['user'],
    passwordHash: await hashPassword(password),
    lastLogin: null,
    created: new Date(),
  };
  await dbInsertUser(user);
  userStore.push(user);
  const { passwordHash, ...safeUser } = user;
  res.status(201).json({ success: true, data: safeUser });
});

app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const user = await getUserByIdFull(req.params.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  const { name, email, role, groups, active, password } = req.body || {};
  const fields = {};
  if (name   !== undefined) { user.name   = name;   fields.name   = name; }
  if (email  !== undefined) { user.email  = email;  fields.email  = email; }
  if (role   !== undefined) { user.role   = role;   fields.role   = role; }
  if (groups !== undefined) { user.groups = groups; fields.groups = groups; }
  if (active !== undefined) { user.active = active; fields.active = active; }
  if (password) { user.passwordHash = await hashPassword(password); fields.password_hash = user.passwordHash; }
  if (Object.keys(fields).length) await dbUpdateUser(user.id, fields);
  mirrorUserInStore(user);
  const { passwordHash, ...safeUser } = user;
  res.json({ success: true, data: safeUser });
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  const user = await getUserByIdFull(req.params.id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  if (user.id === 'admin')
    return res.status(400).json({ success: false, error: 'Cannot delete the default admin user' });
  await dbDeleteUser(user.id);
  const idx = userStore.findIndex(u => u.id === user.id);
  if (idx !== -1) userStore.splice(idx, 1);
  res.json({ success: true, message: 'User deleted' });
});

// Device Management APIs
// Delegates to device-service (domain owner) with a bounded timeout;
// falls back to the legacy in-memory deviceStore on any failure
// (timeout, ECONNREFUSED, 401/403 token rejection, 5xx, ...).
app.get('/api/devices', authMiddleware, async (req, res) => {
  try {
    const remote = await callDeviceService('GET', '/api/devices');
    const list = Array.isArray(remote) ? remote : (Array.isArray(remote?.data) ? remote.data : null);
    if (!list) throw new Error('device-service returned an unexpected response shape');
    return res.json({ success: true, data: list.map(adaptDevice) });
  } catch (err) {
    warnDelegationFallback('GET /api/devices', err);
    return res.json({
      success: true,
      data: await getAllLocalDevices()
    });
  }
});

app.get('/api/devices/:id', authMiddleware, async (req, res) => {
  try {
    const remote = await callDeviceService('GET', `/api/devices/${encodeURIComponent(req.params.id)}`);
    const raw = remote?.data !== undefined ? remote.data : remote;
    if (!raw || !raw.id) throw new Error('device-service returned an unexpected response shape');
    return res.json({ success: true, data: adaptDevice(raw) });
  } catch (err) {
    warnDelegationFallback(`GET /api/devices/${req.params.id}`, err);
    const device = await getLocalDeviceById(req.params.id);
    if (!device) {
      return res.status(404).json({ success: false, error: 'Device not found' });
    }
    return res.json({ success: true, data: device });
  }
});

// TODO(device-service delegation): this write path still operates on the
// legacy in-memory deviceStore only. Once device-service exposes an
// equivalent write endpoint, delegate here too (mirroring the GET routes
// above) so refreshed state is persisted in the device-service domain.
app.post('/api/devices/:id/refresh', authMiddleware, async (req, res) => {
  const deviceId = req.params.id;
  const device = await getLocalDeviceById(deviceId);

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: process.env.CT2001_USERNAME || 'root',
        password: process.env.SSH_PASSWORD || '',
        port: parseInt(process.env.CT2001_PORT) || 22
      });

      const uptime = await ssh.execCommand('uptime');
      const apps = await ssh.execCommand('dpkg --get-selections | grep -v deinstall | wc -l');

      device.lastSeen = new Date();
      device.status = uptime.stdout ? 'online' : 'offline';
      device.installedAppsCount = parseInt(apps.stdout) || 0;

      ssh.dispose();
    }

    await saveLocalDevice(device);

    broadcast({
      type: 'device_updated',
      data: device
    });

    res.json({ success: true, data: device });
  } catch (error) {
    console.error('Device refresh error:', error);
    res.status(500).json({ success: false, error: 'Failed to refresh device' });
  }
});

// Whitelist of allowed app IDs to prevent command injection
const ALLOWED_APP_IDS = new Set(['docker', 'vscode', 'firefox', 'chrome']);

// TODO(device-service delegation): app install/uninstall still operate on
// the legacy in-memory deviceStore only — not yet delegated to device-service.
app.post('/api/devices/:id/apps/install', authMiddleware, async (req, res) => {
  const { appId, appName, version } = req.body;
  const deviceId = req.params.id;
  const device = await getLocalDeviceById(deviceId);

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  if (!ALLOWED_APP_IDS.has(appId)) {
    return res.status(400).json({ success: false, error: `Unknown application. Allowed: ${[...ALLOWED_APP_IDS].join(', ')}` });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: process.env.CT2001_USERNAME || 'root',
        password: process.env.SSH_PASSWORD || '',
        port: parseInt(process.env.CT2001_PORT) || 22
      });

      let installCommand = '';
      switch (appId) {
        case 'docker':
          installCommand = 'apt-get update && apt-get install -y docker.io';
          break;
        case 'vscode':
          installCommand = 'wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg && install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/ && echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list && apt-get update && apt-get install -y code';
          break;
        case 'firefox':
          installCommand = 'apt-get update && apt-get install -y firefox';
          break;
        case 'chrome':
          installCommand = 'wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && apt-get update && apt-get install -y google-chrome-stable';
          break;
      }

      const result = await ssh.execCommand(installCommand);
      ssh.dispose();

      if (result.code === 0) {
        if (!device.installedApps) device.installedApps = [];
        device.installedApps.push({
          app: appId,
          name: appName,
          version: version,
          status: 'installed',
          installedAt: new Date()
        });
        await saveLocalDevice(device);

        broadcast({
          type: 'app_installed',
          data: { deviceId, app: { appId, appName, version } }
        });

        res.json({
          success: true,
          message: `${appName} installed successfully on ${device.name}`,
          data: device
        });
      } else {
        res.status(500).json({
          success: false,
          error: 'Installation failed'
        });
      }
    } else {
      res.status(400).json({ success: false, error: 'Remote installation not supported for this device' });
    }
  } catch (error) {
    console.error('App installation error:', error);
    res.status(500).json({ success: false, error: 'Installation failed' });
  }
});

// TODO(device-service delegation): not yet delegated — see install route above.
app.delete('/api/devices/:id/apps/:appId', authMiddleware, async (req, res) => {
  const { appId } = req.params;
  const deviceId = req.params.id;
  const device = await getLocalDeviceById(deviceId);

  if (!device) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }

  if (!ALLOWED_APP_IDS.has(appId)) {
    return res.status(400).json({ success: false, error: `Unknown application. Allowed: ${[...ALLOWED_APP_IDS].join(', ')}` });
  }

  try {
    if (deviceId === 'CT2001') {
      await ssh.connect({
        host: CT2001_HOST,
        username: process.env.CT2001_USERNAME || 'root',
        password: process.env.SSH_PASSWORD || '',
        port: parseInt(process.env.CT2001_PORT) || 22
      });

      let uninstallCommand = '';
      switch (appId) {
        case 'docker':
          uninstallCommand = 'apt-get remove -y docker.io && apt-get autoremove -y';
          break;
        case 'chrome':
          uninstallCommand = 'apt-get remove -y google-chrome-stable && apt-get autoremove -y';
          break;
        default:
          uninstallCommand = `apt-get remove -y ${appId} && apt-get autoremove -y`;
      }

      const result = await ssh.execCommand(uninstallCommand);
      ssh.dispose();

      if (result.code === 0) {
        if (device.installedApps) {
          device.installedApps = device.installedApps.filter(app => app.app !== appId);
        }
        await saveLocalDevice(device);

        broadcast({
          type: 'app_uninstalled',
          data: { deviceId, appId }
        });

        res.json({
          success: true,
          message: `Application ${appId} uninstalled successfully`,
          data: device
        });
      } else {
        res.status(500).json({
          success: false,
          error: 'Uninstallation failed'
        });
      }
    } else {
      res.status(400).json({ success: false, error: 'Remote uninstallation not supported for this device' });
    }
  } catch (error) {
    console.error('App uninstallation error:', error);
    res.status(500).json({ success: false, error: 'Uninstallation failed' });
  }
});

app.post('/api/users/sync', authMiddleware, async (req, res) => {
  try {
    // Placeholder: in production, sync with LLDAP
    broadcast({
      type: 'users_synced',
      data: { count: 0, newUsers: [] }
    });

    const users = await getAllUsersFull();
    res.json({
      success: true,
      message: 'Users synced successfully',
      data: { syncedCount: 0, totalUsers: users.length }
    });
  } catch (error) {
    console.error('User sync error:', error);
    res.status(500).json({ success: false, error: 'User sync failed' });
  }
});

// System Health API (public — used by Docker healthchecks)
app.get('/api/health', async (req, res) => {
  const [devices, users] = await Promise.all([getAllLocalDevices(), getAllUsersFull()]);
  res.json({
    success: true,
    data: {
      status: 'healthy',
      timestamp: new Date(),
      services: {
        database: 'connected',
        ldap: 'connected',
        monitoring: 'active'
      },
      stats: {
        devices: devices.length,
        users: users.length,
        uptime: process.uptime()
      }
    }
  });
});

// System Resources API
const os = require('os');

app.get('/api/system/resources', authMiddleware, (req, res) => {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;

  res.json({
    success: true,
    data: {
      ram: {
        totalMB: Math.round(totalMem / 1024 / 1024),
        usedMB: Math.round(usedMem / 1024 / 1024),
        freeMB: Math.round(freeMem / 1024 / 1024),
        usagePercent: Math.round((usedMem / totalMem) * 100),
      },
      cpu: {
        cores: os.cpus().length,
        model: os.cpus()[0]?.model || 'Unknown',
      },
      uptime: os.uptime(),
      platform: os.platform(),
      hostname: os.hostname(),
    }
  });
});

// Setup Wizard APIs
let setupConfig = null;

// ── Local setup-config persistence (DB-first, in-memory fallback) ──────────
// setupConfig is a singleton, not a collection — mirrors the in-memory `let`
// with a single-row (id=1) table. See migrations/001_api_backend_schema.sql.
async function dbGetSetupConfig() {
  if (!db.isAvailable()) return undefined;
  try {
    const r = await db.query('SELECT data FROM setup_config WHERE id = 1');
    return r.rows.length ? r.rows[0].data : null;
  } catch (err) {
    console.warn('[api-backend-db] get setup_config failed, falling back to in-memory:', err.message);
    return undefined;
  }
}

async function dbSaveSetupConfig(config) {
  if (!db.isAvailable()) return;
  try {
    await db.query(
      'INSERT INTO setup_config(id, data) VALUES(1, $1) ON CONFLICT (id) DO UPDATE SET data = $1',
      [JSON.stringify(config)]
    );
  } catch (err) {
    console.warn('[api-backend-db] save setup_config failed:', err.message);
  }
}

async function getSetupConfig() {
  const fromDb = await dbGetSetupConfig();
  return fromDb !== undefined ? fromDb : setupConfig;
}

app.get('/api/config/setup-status', async (req, res) => {
  const config = await getSetupConfig();
  res.json({
    success: true,
    data: {
      isFirstRun: config === null,
      config,
    }
  });
});

app.get('/api/config/wizard/available-modules', (req, res) => {
  res.json({
    success: true,
    data: [
      { id: 'network', name: 'Netzwerk', ram: '192 MB', profile: 'network' },
      { id: 'printers', name: 'Drucker', ram: '192 MB', profile: 'printers' },
      { id: 'monitoring', name: 'Monitoring', ram: '448 MB', profile: 'monitoring' },
      { id: 'security', name: 'Security', ram: '320 MB', profile: 'security' },
      { id: 'lifecycle', name: 'Lifecycle', ram: '448 MB', profile: 'lifecycle' },
    ]
  });
});

app.post('/api/config/wizard/setup', async (req, res) => {
  const { orgName, modules, devices, completedAt } = req.body;
  setupConfig = { orgName, modules, devices, completedAt };
  await dbSaveSetupConfig(setupConfig);
  res.json({
    success: true,
    message: 'Setup completed',
    data: setupConfig,
  });
});

// Policy Management APIs
app.get('/api/policies', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: [
      {
        id: 'version_mgmt',
        name: 'Version Management Policy',
        description: 'Automatic application updates with version control',
        active: true,
        platforms: ['linux'],
        rules: { autoUpdate: true, updateWindow: 'maintenance', rollback: true }
      },
      {
        id: 'security_updates',
        name: 'Security Update Policy',
        description: 'Immediate deployment of security patches',
        active: true,
        platforms: ['windows', 'macos', 'linux'],
        rules: { immediate: true, critical: true, notification: true }
      }
    ]
  });
});

// ── Device Enrollment APIs ──────────────────────────────────────────
const enrollmentTokens = {};

// ── Enrollment token persistence (DB-first, in-memory fallback) ────────────
// Same DB-first / best-effort-write / always-mirror convention as the
// users and devices helpers above.
async function dbGetToken(token) {
  if (!db.isAvailable()) return undefined;
  try {
    const r = await db.query(
      'SELECT token, created_at, expires_at, used, created_by FROM enrollment_tokens WHERE token=$1',
      [token]
    );
    if (!r.rows.length) return null;
    const row = r.rows[0];
    return { token: row.token, createdAt: row.created_at, expiresAt: row.expires_at, used: row.used, createdBy: row.created_by };
  } catch (err) {
    console.warn('[api-backend-db] get enrollment token failed, falling back to in-memory:', err.message);
    return undefined;
  }
}

async function dbInsertToken(t) {
  if (!db.isAvailable()) return;
  try {
    await db.query(
      'INSERT INTO enrollment_tokens(token, created_at, expires_at, used, created_by) VALUES($1,$2,$3,$4,$5)',
      [t.token, t.createdAt, t.expiresAt, t.used, t.createdBy]
    );
  } catch (err) {
    console.warn('[api-backend-db] insert enrollment token failed:', err.message);
  }
}

async function dbMarkTokenUsed(token) {
  if (!db.isAvailable()) return;
  try {
    await db.query('UPDATE enrollment_tokens SET used = true WHERE token=$1', [token]);
  } catch (err) {
    console.warn('[api-backend-db] mark enrollment token used failed:', err.message);
  }
}

async function getTokenRecord(token) {
  const fromDb = await dbGetToken(token);
  if (fromDb !== undefined) return fromDb;
  return enrollmentTokens[token] || null;
}

// Token generation requires authentication (admin creates tokens for devices)
app.post('/api/devices/enroll/token', authMiddleware, writeRateLimit, async (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const record = {
    token,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    used: false,
    createdBy: req.user.id,
  };
  await dbInsertToken(record);
  enrollmentTokens[token] = record;
  res.json({
    success: true,
    data: { token, expiresAt: expiresAt.toISOString() },
  });
});

// Device enrollment uses token (no user auth, but token is required)
// TODO(device-service delegation): enrollment still writes to the legacy
// in-memory deviceStore only, so devices enrolled here won't be visible via
// device-service until this is delegated too (see GET routes above for the
// read-side delegation + fallback pattern to follow).
app.post('/api/devices/enroll', writeRateLimit, async (req, res) => {
  const { token, hostname, platform, os: deviceOs, osVersion } = req.body;

  const tokenData = token ? await getTokenRecord(token) : null;
  if (!token || !tokenData) {
    return res.status(401).json({ success: false, error: 'Invalid enrollment token' });
  }
  if (tokenData.used || new Date(tokenData.expiresAt) < new Date()) {
    return res.status(401).json({ success: false, error: 'Token expired or already used' });
  }

  if (!isNonEmptyString(hostname, 253)) {
    return res.status(400).json({ success: false, error: 'hostname is required' });
  }

  tokenData.used = true;
  await dbMarkTokenUsed(token);
  enrollmentTokens[token] = tokenData;

  const deviceId = `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const newDevice = {
    id: deviceId,
    name: hostname,
    platform: isNonEmptyString(platform, 32) ? platform : 'unknown',
    os: isNonEmptyString(deviceOs, 64) ? deviceOs : 'Unknown',
    osVersion: isNonEmptyString(osVersion, 32) ? osVersion : '',
    status: 'online',
    enrolledAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  };

  await saveLocalDevice(newDevice);

  res.json({
    success: true,
    data: { deviceId, message: 'Device enrolled successfully', device: newDevice },
  });
});

// Printer discovery (mock data — replace with real discovery in production)
app.get('/api/printers/discover', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: [
      { name: 'HP LaserJet Pro M404n', ip: process.env.PRINTER1_IP || '192.168.1.200', protocol: 'ipp', status: 'online' },
      { name: 'Brother HL-L2350DW', ip: process.env.PRINTER2_IP || '192.168.1.201', protocol: 'lpd', status: 'online' },
    ],
  });
});

app.post('/api/printers', authMiddleware, (req, res) => {
  const { name, ip, protocol } = req.body;
  if (!name || !ip) {
    return res.status(400).json({ success: false, error: 'Name and IP are required' });
  }
  const printerId = `PRT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  res.json({
    success: true,
    data: { id: printerId, name, ip, protocol: protocol || 'ipp', status: 'online' },
  });
});

// Initialize DB persistence (users/devices/enrollment tokens/setup config —
// see db.js and migrations/001_api_backend_schema.sql). Runs unconditionally
// (not gated on require.main, matching identity-service/src/index.js) so
// that both `node server.js` and the Jest test suite exercise the same
// DB-availability detection: when no PostgreSQL is reachable (the CI/test
// environment), db.isAvailable() resolves to false quickly (~15ms —
// ECONNREFUSED, not a multi-second timeout) and every route above falls
// back to its pre-existing in-memory store, so this does not slow down or
// change the outcome of the 22 pre-existing tests.
db.initDb()
  .then(() => seedAdminUser())
  .catch(err => console.warn('[api-backend-db] initDb failed:', err.message));

// Export app for testing
module.exports = { app, server, userStore, hashPassword };

if (require.main === module) {
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`OpenDirectory API Backend running on port ${PORT}`);
  console.log(`WebSocket server ready — token authentication required`);
  // Network services are provided by the network-infrastructure module (port 3007)
});

// Periodic device health check
setInterval(async () => {
  const devices = await getAllLocalDevices();
  for (const device of devices) {
    const deviceId = device.id;
    if (deviceId === 'CT2001') {
      try {
        await ssh.connect({
          host: CT2001_HOST,
          username: process.env.CT2001_USERNAME || 'root',
          password: process.env.SSH_PASSWORD || '',
          port: parseInt(process.env.CT2001_PORT) || 22,
          readyTimeout: 5000
        });

        device.status = 'online';
        device.lastSeen = new Date();
        ssh.dispose();
      } catch (error) {
        device.status = 'offline';
      }

      await saveLocalDevice(device);

      broadcast({
        type: 'device_heartbeat',
        data: { deviceId, status: device.status, lastSeen: device.lastSeen }
      });
    }
  }
}, 30000);

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down gracefully...`);
  clients.forEach(ws => ws.terminate());
  try { ssh.dispose(); } catch (_) {}
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
} // end if (require.main === module)
