'use strict';
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { execSync } = require('child_process');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const DelegationManager = require('./delegation/delegationManager');
const ProtectedUsersPolicy = require('./security/protectedUsersPolicy');
const { oidcAuth, requireKdcAdmin, requireKdcAdminOrInternal } = require('./middleware/oidcAuth');

const app = express();
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// P0: kerberos-kdc previously had NO HTTP auth at all — any unauthenticated
// caller could reset any principal's password (realm takeover), mint
// keytabs, and configure delegation. Every route below requires a verified
// OIDC JWT (see middleware/oidcAuth.js), except:
//   - /health: liveness/readiness probe (docker-compose healthcheck, no
//     credentials available to it).
//   - POST /api/kerberos/sync-user: called server-to-server by
//     authentication-service on registration/password-change, with no
//     end-user JWT in hand. Accepts the shared KDC_INTERNAL_TOKEN instead
//     (see oidcAuth.js internalServicePaths); a JWT presented on this route
//     is still verified normally and, absent the internal token, must carry
//     admin rights (requireKdcAdminOrInternal).
app.use(oidcAuth({
  skipPaths: ['/health'],
  internalServicePaths: ['/api/kerberos/sync-user'],
}));

const PORT = parseInt(process.env.KDC_API_PORT || '3013');
const REALM = process.env.KRB5_REALM || 'OPENDIRECTORY.LOCAL';

// ─── Kadmin helpers ───────────────────────────────────────────────────────────

function kadminLocal(command) {
  return execSync(`kadmin.local -q "${command.replace(/"/g, '\\"')}" 2>&1`).toString().trim();
}

// ─── PostgreSQL pool ──────────────────────────────────────────────────────────

const db = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || process.env.POSTGRES_DB || 'kerberos',
  user: process.env.DB_USER || process.env.POSTGRES_USER || 'postgres',
  password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || '',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

let dbAvailable = false;

async function runMigrations() {
  const migrationsDir = path.join(__dirname, 'db', 'migrations');
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  for (const file of files) {
    try {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await db.query(sql);
      console.log(`[kdc-db] Applied migration: ${file}`);
    } catch (err) {
      console.error(`[kdc-db] Migration ${file} error:`, err.message);
    }
  }
}

async function initDb() {
  try {
    await db.query('SELECT 1');
    dbAvailable = true;
    await runMigrations();
    console.log('[kdc-db] PostgreSQL connected');
  } catch (err) {
    console.warn('[kdc-db] PostgreSQL not available — delegation/policy features disabled:', err.message);
  }
}

// ─── Service instances (set after DB init) ────────────────────────────────────

let delegationManager;
let protectedUsersPolicy;

// Ticket policy defaults
const DEFAULT_TICKET_POLICY = {
  maxTicketLife: 10 * 60 * 60,    // 10 hours (seconds)
  maxRenewLife: 7 * 24 * 60 * 60, // 7 days (seconds)
  forwardable: true,
  proxiable: false,
  renewable: true,
  noAddress: true,
};

// ─── Middleware: require DB ───────────────────────────────────────────────────

function requireDb(req, res, next) {
  if (!dbAvailable) {
    return res.status(503).json({ error: 'Database not available — feature requires PostgreSQL' });
  }
  next();
}

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  try {
    kadminLocal('listprincs');
    res.json({ status: 'ok', realm: REALM, db: dbAvailable ? 'connected' : 'unavailable' });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// ─── Kerberos Principal Management ───────────────────────────────────────────

// List all principals (read-only; any authenticated caller — see oidcAuth above)
app.get('/api/kerberos/principals', (req, res) => {
  try {
    const output = kadminLocal('listprincs');
    const principals = output.split('\n')
      .filter(p => p.trim() && !p.includes('Authenticating'))
      .map(p => p.trim());
    res.json({ realm: REALM, principals, count: principals.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get principal details (read-only; any authenticated caller)
app.get('/api/kerberos/principals/:name', (req, res) => {
  try {
    const output = kadminLocal(`getprinc ${req.params.name}@${REALM}`);
    const lines = output.split('\n').filter(l => l.trim());
    const details = {};
    for (const line of lines) {
      const [key, ...val] = line.split(':');
      if (key && val.length) details[key.trim()] = val.join(':').trim();
    }
    res.json({ principal: `${req.params.name}@${REALM}`, details });
  } catch (err) {
    res.status(404).json({ error: 'Principal not found' });
  }
});

// Create principal — admin-only: minting a new Kerberos identity
app.post('/api/kerberos/principals', requireKdcAdmin, (req, res) => {
  const { name, password, noexpiry = true } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    if (password) {
      kadminLocal(`addprinc -pw ${password}${noexpiry ? ' -pwexpiry never' : ''} ${name}@${REALM}`);
    } else {
      kadminLocal(`addprinc -randkey ${name}@${REALM}`);
    }
    res.status(201).json({ principal: `${name}@${REALM}`, realm: REALM });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Change principal password — admin-only. This is the realm-takeover
// endpoint: without gating, any caller could set the password of ANY
// principal (including admin/krbtgt-adjacent service accounts).
app.put('/api/kerberos/principals/:name/password', requireKdcAdmin, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });
  try {
    kadminLocal(`cpw -pw ${password} ${req.params.name}@${REALM}`);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete principal — admin-only: destructive, can remove any account incl.
// service principals.
app.delete('/api/kerberos/principals/:name', requireKdcAdmin, (req, res) => {
  try {
    kadminLocal(`delprinc -force ${req.params.name}@${REALM}`);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Generate keytab for a service principal — admin-only: a keytab is a
// long-lived, offline-usable credential for that principal.
app.post('/api/kerberos/keytabs/:name', requireKdcAdmin, (req, res) => {
  const keytabPath = `/tmp/keytab-${req.params.name.replace(/[^a-zA-Z0-9]/g, '_')}.keytab`;
  try {
    kadminLocal(`ktadd -k ${keytabPath} ${req.params.name}@${REALM}`);
    const keytabData = fs.readFileSync(keytabPath);
    fs.unlinkSync(keytabPath);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.name}.keytab"`);
    res.send(keytabData);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Sync user from OpenDirectory (create Kerberos principal for LLDAP user).
// Called server-to-server by authentication-service (register / change-
// password) using the shared KDC_INTERNAL_TOKEN — see oidcAuth.js. Just as
// sensitive as the password-set endpoint (it can set an arbitrary
// principal's password too), so any caller that did NOT use the internal
// token must present an admin JWT.
app.post('/api/kerberos/sync-user', requireKdcAdminOrInternal, (req, res) => {
  const { username, password } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  try {
    const exists = (() => {
      try { kadminLocal(`getprinc ${username}@${REALM}`); return true; } catch { return false; }
    })();
    if (exists) {
      if (password) kadminLocal(`cpw -pw ${password} ${username}@${REALM}`);
      return res.json({ action: 'updated', principal: `${username}@${REALM}` });
    }
    if (password) {
      kadminLocal(`addprinc -pw ${password} -pwexpiry never ${username}@${REALM}`);
    } else {
      kadminLocal(`addprinc -randkey ${username}@${REALM}`);
    }
    res.status(201).json({ action: 'created', principal: `${username}@${REALM}` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── Ticket Policy endpoints ──────────────────────────────────────────────────

// GET /api/ticket-policy — get realm-wide ticket policy (read-only; any authenticated caller)
app.get('/api/ticket-policy', requireDb, async (req, res) => {
  try {
    const { rows } = await db.query(
      "SELECT * FROM ticket_policies WHERE principal = 'REALM_DEFAULT'"
    );
    const row = rows[0];
    if (!row) return res.json({ principal: 'REALM_DEFAULT', ...DEFAULT_TICKET_POLICY });
    res.json({
      principal: row.principal,
      maxTicketLife: row.max_ticket_life,
      maxRenewLife: row.max_renew_life,
      forwardable: row.forwardable,
      proxiable: row.proxiable,
      renewable: row.renewable,
      noAddress: row.no_address,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/ticket-policy — update realm-wide ticket policy — admin-only
app.put('/api/ticket-policy', requireDb, requireKdcAdmin, async (req, res) => {
  const { maxTicketLife, maxRenewLife, forwardable, proxiable, renewable, noAddress } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO ticket_policies (principal, max_ticket_life, max_renew_life, forwardable, proxiable, renewable, no_address, updated_at)
       VALUES ('REALM_DEFAULT', $1, $2, $3, $4, $5, $6, NOW())
       ON CONFLICT (principal) DO UPDATE SET
         max_ticket_life  = COALESCE($1, ticket_policies.max_ticket_life),
         max_renew_life   = COALESCE($2, ticket_policies.max_renew_life),
         forwardable      = COALESCE($3, ticket_policies.forwardable),
         proxiable        = COALESCE($4, ticket_policies.proxiable),
         renewable        = COALESCE($5, ticket_policies.renewable),
         no_address       = COALESCE($6, ticket_policies.no_address),
         updated_at       = NOW()
       RETURNING *`,
      [maxTicketLife ?? null, maxRenewLife ?? null, forwardable ?? null, proxiable ?? null, renewable ?? null, noAddress ?? null]
    );
    const row = rows[0];
    res.json({
      principal: row.principal,
      maxTicketLife: row.max_ticket_life,
      maxRenewLife: row.max_renew_life,
      forwardable: row.forwardable,
      proxiable: row.proxiable,
      renewable: row.renewable,
      noAddress: row.no_address,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/principals/:name/ticket-policy — per-principal policy override (read-only; any authenticated caller)
app.get('/api/principals/:name/ticket-policy', requireDb, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT * FROM ticket_policies WHERE principal = $1',
      [req.params.name]
    );
    if (!rows.length) {
      return res.status(404).json({ error: 'No per-principal override found', principal: req.params.name });
    }
    const row = rows[0];
    res.json({
      principal: row.principal,
      maxTicketLife: row.max_ticket_life,
      maxRenewLife: row.max_renew_life,
      forwardable: row.forwardable,
      proxiable: row.proxiable,
      renewable: row.renewable,
      noAddress: row.no_address,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/principals/:name/ticket-policy — set per-principal override — admin-only
app.put('/api/principals/:name/ticket-policy', requireDb, requireKdcAdmin, async (req, res) => {
  const { maxTicketLife, maxRenewLife, forwardable, proxiable, renewable, noAddress } = req.body;
  const principal = req.params.name;
  if (principal === 'REALM_DEFAULT') {
    return res.status(400).json({ error: 'Use PUT /api/ticket-policy to modify the realm default' });
  }
  try {
    const { rows } = await db.query(
      `INSERT INTO ticket_policies (principal, max_ticket_life, max_renew_life, forwardable, proxiable, renewable, no_address, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (principal) DO UPDATE SET
         max_ticket_life  = COALESCE($2, ticket_policies.max_ticket_life),
         max_renew_life   = COALESCE($3, ticket_policies.max_renew_life),
         forwardable      = COALESCE($4, ticket_policies.forwardable),
         proxiable        = COALESCE($5, ticket_policies.proxiable),
         renewable        = COALESCE($6, ticket_policies.renewable),
         no_address       = COALESCE($7, ticket_policies.no_address),
         updated_at       = NOW()
       RETURNING *`,
      [principal, maxTicketLife ?? null, maxRenewLife ?? null, forwardable ?? null, proxiable ?? null, renewable ?? null, noAddress ?? null]
    );
    const row = rows[0];
    res.json({
      principal: row.principal,
      maxTicketLife: row.max_ticket_life,
      maxRenewLife: row.max_renew_life,
      forwardable: row.forwardable,
      proxiable: row.proxiable,
      renewable: row.renewable,
      noAddress: row.no_address,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/principals/:name/ticket-policy — remove per-principal override — admin-only
app.delete('/api/principals/:name/ticket-policy', requireDb, requireKdcAdmin, async (req, res) => {
  const principal = req.params.name;
  if (principal === 'REALM_DEFAULT') {
    return res.status(400).json({ error: 'Cannot delete the realm default policy' });
  }
  try {
    const { rowCount } = await db.query(
      'DELETE FROM ticket_policies WHERE principal = $1',
      [principal]
    );
    if (!rowCount) return res.status(404).json({ error: 'No per-principal override found' });
    res.json({ removed: true, principal });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Delegation endpoints ─────────────────────────────────────────────────────
// All admin-only: delegation configuration (constrained/RBCD/unconstrained)
// controls Kerberos trust paths and impersonation rights — misconfiguration
// or disclosure is a direct privilege-escalation/lateral-movement vector. No
// other service calls these routes (verified against the codebase), so
// there is no internal-token bypass need here, unlike sync-user.

// GET /api/delegation — list all delegation configurations
app.get('/api/delegation', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const result = await delegationManager.listDelegations({ type: 'all' });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/delegation/constrained/:principal — get constrained delegation
app.get('/api/delegation/constrained/:principal', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const config = await delegationManager.getConstrainedDelegation(req.params.principal);
    if (!config) return res.status(404).json({ error: 'No constrained delegation configured for this principal' });
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/delegation/constrained — set constrained delegation
app.post('/api/delegation/constrained', requireDb, requireKdcAdmin, async (req, res) => {
  const { servicePrincipal, allowedTargets, protocol } = req.body;
  if (!servicePrincipal) return res.status(400).json({ error: 'servicePrincipal required' });
  try {
    const result = await delegationManager.setConstrainedDelegation(servicePrincipal, {
      allowedTargets: allowedTargets || [],
      protocol: protocol || 'kerberos-only',
    });
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/delegation/constrained/:principal — remove constrained delegation
app.delete('/api/delegation/constrained/:principal', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const result = await delegationManager.removeConstrainedDelegation(req.params.principal);
    if (!result.removed) return res.status(404).json({ error: 'No constrained delegation found' });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/delegation/rbcd — set RBCD on a resource
app.post('/api/delegation/rbcd', requireDb, requireKdcAdmin, async (req, res) => {
  const { resourcePrincipal, allowedDelegators } = req.body;
  if (!resourcePrincipal) return res.status(400).json({ error: 'resourcePrincipal required' });
  try {
    const result = await delegationManager.setRBCD(resourcePrincipal, {
      allowedDelegators: allowedDelegators || [],
    });
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/delegation/rbcd/:resource — get RBCD config for a resource
app.get('/api/delegation/rbcd/:resource', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const config = await delegationManager.getRBCD(req.params.resource);
    if (!config) return res.status(404).json({ error: 'No RBCD configuration found for this resource' });
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/delegation/rbcd/:resource — remove RBCD config
app.delete('/api/delegation/rbcd/:resource', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const result = await delegationManager.removeRBCD(req.params.resource);
    if (!result.removed) return res.status(404).json({ error: 'No RBCD configuration found' });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/delegation/unconstrained — security audit: list unconstrained delegation
app.get('/api/delegation/unconstrained', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const list = await delegationManager.listUnconstrainedDelegations();
    res.json({
      warning: 'Unconstrained delegation is a significant security risk. Review these entries carefully.',
      count: list.length,
      entries: list,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/delegation/unconstrained — set/unset unconstrained delegation
app.post('/api/delegation/unconstrained', requireDb, requireKdcAdmin, async (req, res) => {
  const { principal, enabled } = req.body;
  if (!principal) return res.status(400).json({ error: 'principal required' });
  try {
    const result = await delegationManager.setUnconstrainedDelegation(principal, !!enabled);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/delegation/simulate/s4u2self — simulate S4U2Self
app.post('/api/delegation/simulate/s4u2self', requireDb, requireKdcAdmin, async (req, res) => {
  const { servicePrincipal, userPrincipal } = req.body;
  if (!servicePrincipal || !userPrincipal) {
    return res.status(400).json({ error: 'servicePrincipal and userPrincipal required' });
  }
  try {
    const result = await delegationManager.simulateS4U2Self(servicePrincipal, userPrincipal);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/delegation/simulate/s4u2proxy — validate S4U2Proxy
app.post('/api/delegation/simulate/s4u2proxy', requireDb, requireKdcAdmin, async (req, res) => {
  const { servicePrincipal, targetServiceSPN, evidenceTicket } = req.body;
  if (!servicePrincipal || !targetServiceSPN) {
    return res.status(400).json({ error: 'servicePrincipal and targetServiceSPN required' });
  }
  try {
    const result = await delegationManager.validateS4U2Proxy(
      servicePrincipal,
      targetServiceSPN,
      evidenceTicket || {}
    );
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/delegation/audit — query delegation audit log
app.get('/api/delegation/audit', requireDb, requireKdcAdmin, async (req, res) => {
  const { from, to, servicePrincipal, limit } = req.query;
  try {
    const entries = await delegationManager.getDelegationAuditLog({
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
      servicePrincipal: servicePrincipal || undefined,
      limit: limit ? parseInt(limit) : 100,
    });
    res.json({ count: entries.length, entries });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Protected Users endpoints ────────────────────────────────────────────────

// GET /api/protected-users — list members
app.get('/api/protected-users', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const members = await protectedUsersPolicy.listMembers();
    res.json({ count: members.length, members });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/protected-users — add a member
app.post('/api/protected-users', requireDb, requireKdcAdmin, async (req, res) => {
  const { userPrincipal, addedBy } = req.body;
  if (!userPrincipal) return res.status(400).json({ error: 'userPrincipal required' });
  try {
    const result = await protectedUsersPolicy.addMember(userPrincipal, addedBy || null);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/protected-users/:principal — remove a member
app.delete('/api/protected-users/:principal', requireDb, requireKdcAdmin, async (req, res) => {
  const { removedBy } = req.body || {};
  try {
    const result = await protectedUsersPolicy.removeMember(req.params.principal, removedBy || null);
    if (!result.removed) return res.status(404).json({ error: 'Principal not found in Protected Users' });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/protected-users/report — protection report
app.get('/api/protected-users/report', requireDb, requireKdcAdmin, async (req, res) => {
  try {
    const report = await protectedUsersPolicy.getProtectionReport();
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/protected-users/:principal/check — check if an operation is allowed
app.post('/api/protected-users/:principal/check', requireDb, requireKdcAdmin, async (req, res) => {
  const { operation } = req.body;
  if (!operation) return res.status(400).json({ error: 'operation required' });
  try {
    const result = await protectedUsersPolicy.enforceRestrictions(req.params.principal, operation);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

async function start() {
  await initDb();

  if (dbAvailable) {
    delegationManager = new DelegationManager(db);
    protectedUsersPolicy = new ProtectedUsersPolicy(db);
    console.log('[kdc] DelegationManager and ProtectedUsersPolicy initialised');
  }

  return new Promise(resolve => {
    const server = app.listen(PORT, () => {
      console.log(`[kerberos-admin-api] REST API on :${PORT}, Realm: ${REALM}`);
      resolve(server);
    });
  });
}

// Only auto-start when run directly (docker entrypoint: `node src/index.js`).
// When required as a module — e.g. by the e2e test suite, which needs to
// mock pg/child_process/JWKS *before* start() runs and needs the returned
// server handle to close it after tests — the caller drives start() itself.
if (require.main === module) {
  start().catch(err => {
    console.error('[kdc] Startup error:', err);
    process.exit(1);
  });
}

module.exports = { app, start };
