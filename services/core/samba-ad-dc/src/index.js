'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const http = require('http');
const https = require('https');
const { oidcAuth, requireDeviceAdmin } = require('./middleware/oidcAuth');

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

// ---------------------------------------------------------------------------
// Notify device-service of domain join (fire-and-forget)
// ---------------------------------------------------------------------------
const DEVICE_SERVICE_URL = (process.env.DEVICE_SERVICE_URL || 'http://device-service:3003').replace(/\/$/, '');

function notifyDeviceService(payload) {
  // This is meant to be fire-and-forget: a domain join must not fail (or
  // report an error to the caller) just because the notification could not
  // be sent. new URL() throws synchronously on a malformed
  // DEVICE_SERVICE_URL, which — uncaught — would bubble up into the
  // /api/computers/join route's try/catch and turn an already-successful
  // join into a reported failure. Guard the whole thing.
  try {
    const body = JSON.stringify(payload);
    const url = new URL(`${DEVICE_SERVICE_URL}/api/devices/report-hardware`);
    const proto = url.protocol === 'https:' ? https : http;
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
    // device-service's report-hardware endpoint requires either an OIDC JWT
    // or the shared enrollment token (see its oidcAuth enrollmentPaths
    // contract) — this call runs machine-to-machine with no user token, so
    // it must present the enrollment token to get through.
    if (process.env.DEVICE_ENROLLMENT_TOKEN) {
      headers['X-Enrollment-Token'] = process.env.DEVICE_ENROLLMENT_TOKEN;
    }
    const req = proto.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers,
    }, res => {
      res.resume(); // drain
      logger.info('Device-service notified of domain join', { status: res.statusCode, hostname: payload.hostname });
    });
    req.on('error', err => logger.warn('Could not notify device-service', { message: err.message }));
    req.setTimeout(5000, () => req.destroy());
    req.write(body);
    req.end();
  } catch (err) {
    logger.warn('Could not notify device-service', { message: err.message });
  }
}

// ---------------------------------------------------------------------------
// PostgreSQL pool + migration runner (optional — service degrades
// gracefully without it). See src/db/index.js: this now actually applies
// migrations/*.sql (domain_trusts, laps_passwords, bitlocker_keys, ...)
// instead of just handing managers a raw, unmigrated Pool. initDb() is
// fire-and-forget here (matches identity-service/least-privilege): the
// server starts serving immediately, and db.isAvailable() flips true once
// connectivity + migrations are confirmed. Managers below receive the `db`
// module itself (not a raw Pool) so their `this.db.query(...)` calls are
// gated by isAvailable() rather than by "does a Pool object exist".
// ---------------------------------------------------------------------------
const db = require('./db');
db.initDb().catch(err => logger.warn('db.initDb() failed unexpectedly', { error: err.message }));

// ---------------------------------------------------------------------------
// Service modules
// ---------------------------------------------------------------------------
const sambaLdap = require('./ldap/sambaLdap');

const TrustManager       = require('./trust/trustManager');
const ComputerManager    = require('./computer/computerManager');
const ReplicationManager = require('./replication/replicationManager');

const trustManager       = new TrustManager(sambaLdap, db);
const computerManager    = new ComputerManager(sambaLdap, db);
const replicationManager = new ReplicationManager(sambaLdap, db);

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3010;

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '1mb' }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 200 });
app.use(limiter);

// ---------------------------------------------------------------------------
// Authentication
//
// Every route below (including everything under /api/samba/* and
// /api/computers/*, which the frontend reaches via the /api/samba/computers/*
// rewrite) requires a valid OIDC bearer token. The sole exception is
// /api/computers/join: domain-join scripts run on a machine before it has
// any user/OIDC identity, so that single path additionally accepts the
// shared DEVICE_ENROLLMENT_TOKEN via the x-enrollment-token header. The
// highly sensitive computer endpoints (LAPS passwords, BitLocker recovery
// keys, machine-password reset, unjoin) are deliberately NOT in
// enrollmentPaths — they stay strictly JWT-only, and additionally require
// requireDeviceAdmin (an admin/helpdesk role or device.admin scope on the
// verified token) at the individual route level, since a valid JWT alone
// only proves identity, not authorization for device secrets.
// ---------------------------------------------------------------------------
app.use(oidcAuth({
  skipPaths: ['/health'],
  enrollmentPaths: ['/api/computers/join'],
}));

// ---------------------------------------------------------------------------
// Existing routes (domain, DNS, Kerberos, sync, users, groups, OUs, computers)
// ---------------------------------------------------------------------------
app.use('/api/samba', require('./api/routes'));
app.use('/api/samba', require('./api/domainRoutes'));
app.use('/api/samba', require('./api/gpoRoutes'));

// ---------------------------------------------------------------------------
// Health / readiness
// ---------------------------------------------------------------------------
app.get('/health', async (req, res) => {
  const ldapStatus = await sambaLdap.testConnection();
  res.json({
    status: ldapStatus.connected ? 'ok' : 'degraded',
    ldap: ldapStatus,
    database: db.isAvailable() ? 'connected' : (process.env.DATABASE_URL ? 'configured-not-ready' : 'disabled'),
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ---------------------------------------------------------------------------
// Trust endpoints
// ---------------------------------------------------------------------------

/**
 * GET /api/trusts
 * List all domain/forest trusts.
 */
app.get('/api/trusts', async (req, res) => {
  try {
    const trusts = await trustManager.listTrusts();
    res.json({ trusts, total: trusts.length, retrievedAt: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/trusts
 * Create a new trust relationship.
 * Body: { trustedDomain, trustType, trustDirection, trustPassword, transitivity }
 */
app.post('/api/trusts', async (req, res) => {
  try {
    const { trustedDomain, trustType, trustDirection, trustPassword, transitivity } = req.body;

    if (!trustedDomain || !trustType || !trustDirection || !trustPassword) {
      return res.status(400).json({
        error: 'trustedDomain, trustType, trustDirection, and trustPassword are required'
      });
    }

    const result = await trustManager.createTrust({ trustedDomain, trustType, trustDirection, trustPassword, transitivity });
    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('Invalid') ? 400 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * GET /api/trusts/transitive-closure
 * Return the full transitive trust graph.
 * Must be registered before /:domain to avoid route shadowing.
 */
app.get('/api/trusts/transitive-closure', async (req, res) => {
  try {
    const graph = await trustManager.getTrustTransitiveClosure();
    res.json({ graph, retrievedAt: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/trusts/:domain/verify
 * Verify a trust is healthy.
 */
app.get('/api/trusts/:domain/verify', async (req, res) => {
  try {
    const { domain } = req.params;
    const result = await trustManager.verifyTrust(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/trusts/:domain/forest-info
 * Get forest trust UPN suffixes and SID namespaces.
 */
app.get('/api/trusts/:domain/forest-info', async (req, res) => {
  try {
    const { domain } = req.params;
    const result = await trustManager.getForestTrustInfo(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/trusts/:domain/rotate-password
 * Rotate the trust credential.
 */
app.post('/api/trusts/:domain/rotate-password', async (req, res) => {
  try {
    const { domain } = req.params;
    const result = await trustManager.rotateTrustPassword(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/trusts/:domain
 * Remove a trust relationship.
 */
app.delete('/api/trusts/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const result = await trustManager.removeTrust(domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Computer / LAPS / BitLocker endpoints
// ---------------------------------------------------------------------------

/**
 * POST /api/computers/join
 * Domain join: create a computer account.
 * Body: { computerName, ouDn, requestingUser, operatingSystem, osVersion, ipAddress }
 *
 * Enrollment contract: this is the one route where oidcAuth (see mount
 * above) also accepts the shared DEVICE_ENROLLMENT_TOKEN header
 * (x-enrollment-token) in place of an OIDC JWT, since join scripts run on a
 * machine before it has any user identity.
 */
app.post('/api/computers/join', async (req, res) => {
  try {
    const { computerName, ouDn, requestingUser, operatingSystem, osVersion, ipAddress,
            manufacturer, model } = req.body;

    if (!computerName) {
      return res.status(400).json({ error: 'computerName is required' });
    }

    const result = await computerManager.joinDomain({
      computerName, ouDn, requestingUser, operatingSystem, osVersion, ipAddress
    });

    // Fire-and-forget: notify device-service so driver matching can start
    notifyDeviceService({
      hostname: computerName,
      manufacturer: manufacturer || null,
      model: model || null,
      os: operatingSystem || null,
      osVersion: osVersion || null,
    });

    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('required') || err.message.includes('NetBIOS') ? 400 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * GET /api/computers
 * List computer accounts.
 * Query: ouDn, operatingSystem, enabled (bool), limit, offset
 */
app.get('/api/computers', async (req, res) => {
  try {
    const { ouDn, operatingSystem, enabled, limit, offset } = req.query;
    const result = await computerManager.listComputers({
      ouDn,
      operatingSystem,
      enabled: enabled === undefined ? undefined : enabled === 'true',
      limit: limit ? parseInt(limit, 10) : 100,
      offset: offset ? parseInt(offset, 10) : 0
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/computers/:name
 * Get a single computer's full attributes.
 */
app.get('/api/computers/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const computer = await computerManager.getComputer(name);
    if (!computer) {
      return res.status(404).json({ error: `Computer ${name} not found` });
    }
    res.json(computer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/computers/:name
 * Update computer inventory attributes.
 * Body: { osVersion, lastLogon, ipAddress, macAddress }
 */
app.put('/api/computers/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const { osVersion, lastLogon, ipAddress, macAddress } = req.body;
    const result = await computerManager.updateComputerAttributes(name, { osVersion, lastLogon, ipAddress, macAddress });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/computers/:name/join
 * Domain unjoin (delete or disable computer account).
 * Body: { disableOnly }
 *
 * Role-gated (see requireDeviceAdmin): unjoining a computer is destructive
 * and must not be reachable by any authenticated-but-unprivileged caller.
 */
app.delete('/api/computers/:name/join', requireDeviceAdmin, async (req, res) => {
  try {
    const { name } = req.params;
    const { disableOnly } = req.body || {};
    const result = await computerManager.unjoinDomain(name, { disableOnly: !!disableOnly });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/computers/:name/reset-machine-password
 * Reset the machine account password.
 *
 * Strictly JWT-only (no enrollment-token bypass — see oidcAuth mount above)
 * and role-gated (see requireDeviceAdmin) — resetting the machine account
 * password breaks the computer's domain trust relationship until it rejoins.
 */
app.post('/api/computers/:name/reset-machine-password', requireDeviceAdmin, async (req, res) => {
  try {
    const { name } = req.params;
    const result = await computerManager.resetMachinePassword(name);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/computers/:name/laps-password
 * Retrieve the LAPS local administrator password.
 *
 * Strictly JWT-only (no enrollment-token bypass — see oidcAuth mount above).
 * requestingUserId is derived from the verified token subject, never from
 * the (client-controlled, unverified) query parameter, so the audit trail
 * in computerManager.getLAPSPassword can't be spoofed by whoever is calling.
 * Role-gated via requireDeviceAdmin: oidcAuth alone only proves *who* is
 * asking, not that they're *allowed* to read this computer's cleartext LAPS
 * password, so the route additionally requires an admin/helpdesk role (or
 * device.admin scope) — see middleware/oidcAuth.js for the claim shapes
 * checked.
 */
app.get('/api/computers/:name/laps-password', requireDeviceAdmin, async (req, res) => {
  try {
    const { name } = req.params;
    const requestingUserId = req.user.sub;

    const result = await computerManager.getLAPSPassword(name, requestingUserId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/computers/:name/laps-rotate
 * Rotate the LAPS password.
 *
 * Role-gated (see requireDeviceAdmin).
 */
app.post('/api/computers/:name/laps-rotate', requireDeviceAdmin, async (req, res) => {
  try {
    const { name } = req.params;
    const result = await computerManager.rotateLAPSPassword(name);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/computers/:name/bitlocker-keys
 * Escrow a BitLocker recovery key.
 * Body: { volumeType, recoveryKeyId, recoveryKey, tpmThumbprint }
 *
 * Role-gated (see requireDeviceAdmin).
 */
app.post('/api/computers/:name/bitlocker-keys', requireDeviceAdmin, async (req, res) => {
  try {
    const { name } = req.params;
    const { volumeType, recoveryKeyId, recoveryKey, tpmThumbprint } = req.body;

    if (!volumeType || !recoveryKeyId || !recoveryKey) {
      return res.status(400).json({ error: 'volumeType, recoveryKeyId, and recoveryKey are required' });
    }

    const result = await computerManager.escrowBitLockerKey(name, { volumeType, recoveryKeyId, recoveryKey, tpmThumbprint });
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/computers/:name/bitlocker-keys
 * List BitLocker keys for a computer (metadata only, no key material).
 *
 * Role-gated (see requireDeviceAdmin) — even metadata (which recovery keys
 * exist, when they were escrowed) is sensitive enough to restrict.
 */
app.get('/api/computers/:name/bitlocker-keys', requireDeviceAdmin, async (req, res) => {
  try {
    const { name } = req.params;
    const keys = await computerManager.listBitLockerKeys(name);
    res.json({ computerName: name.toUpperCase(), keys, total: keys.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/computers/:name/bitlocker-keys/:keyId
 * Retrieve a BitLocker recovery key (sensitive — logs access).
 *
 * Strictly JWT-only (no enrollment-token bypass — see oidcAuth mount above).
 * requestingUserId is derived from the verified token subject, never from
 * the (client-controlled, unverified) query parameter, so the audit trail
 * in computerManager.getBitLockerKey can't be spoofed by whoever is calling.
 * Role-gated via requireDeviceAdmin: oidcAuth alone only proves *who* is
 * asking, not that they're *allowed* to read this computer's BitLocker
 * recovery key, so the route additionally requires an admin/helpdesk role
 * (or device.admin scope) — see middleware/oidcAuth.js for the claim shapes
 * checked.
 */
app.get('/api/computers/:name/bitlocker-keys/:keyId', requireDeviceAdmin, async (req, res) => {
  try {
    const { name, keyId } = req.params;
    const requestingUserId = req.user.sub;

    const result = await computerManager.getBitLockerKey(name, keyId, requestingUserId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Replication endpoints
// ---------------------------------------------------------------------------

/**
 * GET /api/replication/status
 * Full replication status across all DC partners.
 */
app.get('/api/replication/status', async (req, res) => {
  try {
    const status = await replicationManager.getReplicationStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/replication/health
 * Health summary per naming context.
 */
app.get('/api/replication/health', async (req, res) => {
  try {
    const health = await replicationManager.getReplicationHealth();
    res.json(health);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/replication/usn
 * Current highest committed USN for this DC.
 */
app.get('/api/replication/usn', async (req, res) => {
  try {
    const usn = await replicationManager.getCurrentUSN();
    res.json(usn);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/replication/force-sync
 * Trigger replication sync.
 * Body: { sourceDC, namingContext, fullSync }
 */
app.post('/api/replication/force-sync', async (req, res) => {
  try {
    const { sourceDC, namingContext, fullSync } = req.body;

    if (!sourceDC || !namingContext) {
      return res.status(400).json({ error: 'sourceDC and namingContext are required' });
    }

    const result = await replicationManager.forceSync({ sourceDC, namingContext, fullSync });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/replication/schedule
 * Get the replication schedule.
 */
app.get('/api/replication/schedule', async (req, res) => {
  try {
    const schedule = await replicationManager.getReplicationSchedule();
    res.json(schedule);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/replication/schedule
 * Update the replication schedule.
 * Body: { intervalMinutes, startTime, endTime, daysOfWeek, enabled }
 */
app.put('/api/replication/schedule', async (req, res) => {
  try {
    const result = await replicationManager.setReplicationSchedule(req.body);
    res.json(result);
  } catch (err) {
    const status = err.message.includes('required') ? 400 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * GET /api/replication/lingering-objects/:partnerDC
 * Detect lingering objects relative to a partner DC.
 */
app.get('/api/replication/lingering-objects/:partnerDC', async (req, res) => {
  try {
    const { partnerDC } = req.params;
    const result = await replicationManager.detectLingeringObjects(partnerDC);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/replication/usn-rollback/:dcName
 * Detect if a DC's USN has rolled back.
 */
app.get('/api/replication/usn-rollback/:dcName', async (req, res) => {
  try {
    const { dcName } = req.params;
    const result = await replicationManager.detectUSNRollback(dcName);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/replication/object-metadata
 * Get replication metadata for an LDAP object.
 * Query: dn (required)
 */
app.get('/api/replication/object-metadata', async (req, res) => {
  try {
    const { dn } = req.query;
    if (!dn) {
      return res.status(400).json({ error: 'dn query parameter is required' });
    }
    const result = await replicationManager.getObjectMetadata(dn);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// 404 catch-all
// ---------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  logger.info('Samba AD DC service started', { port: PORT });
});

module.exports = app;
