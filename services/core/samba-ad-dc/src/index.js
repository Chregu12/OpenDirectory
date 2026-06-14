'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

// ---------------------------------------------------------------------------
// PostgreSQL pool (optional — service degrades gracefully without it)
// ---------------------------------------------------------------------------
let db = null;
if (process.env.DATABASE_URL) {
  try {
    const { Pool } = require('pg');
    db = new Pool({ connectionString: process.env.DATABASE_URL });
    db.on('error', (err) => logger.warn('PG pool error', { error: err.message }));
    logger.info('PostgreSQL pool initialised');
  } catch (err) {
    logger.warn('pg module not available — DB features disabled', { error: err.message });
  }
}

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
    database: db ? 'configured' : 'disabled',
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
 */
app.post('/api/computers/join', async (req, res) => {
  try {
    const { computerName, ouDn, requestingUser, operatingSystem, osVersion, ipAddress } = req.body;

    if (!computerName) {
      return res.status(400).json({ error: 'computerName is required' });
    }

    const result = await computerManager.joinDomain({
      computerName, ouDn, requestingUser, operatingSystem, osVersion, ipAddress
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
 */
app.delete('/api/computers/:name/join', async (req, res) => {
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
 */
app.post('/api/computers/:name/reset-machine-password', async (req, res) => {
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
 * Query: requestingUserId (required)
 */
app.get('/api/computers/:name/laps-password', async (req, res) => {
  try {
    const { name } = req.params;
    const { requestingUserId } = req.query;

    if (!requestingUserId) {
      return res.status(400).json({ error: 'requestingUserId query parameter is required' });
    }

    const result = await computerManager.getLAPSPassword(name, requestingUserId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/computers/:name/laps-rotate
 * Rotate the LAPS password.
 */
app.post('/api/computers/:name/laps-rotate', async (req, res) => {
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
 */
app.post('/api/computers/:name/bitlocker-keys', async (req, res) => {
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
 */
app.get('/api/computers/:name/bitlocker-keys', async (req, res) => {
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
 * Query: requestingUserId (required)
 */
app.get('/api/computers/:name/bitlocker-keys/:keyId', async (req, res) => {
  try {
    const { name, keyId } = req.params;
    const { requestingUserId } = req.query;

    if (!requestingUserId) {
      return res.status(400).json({ error: 'requestingUserId query parameter is required' });
    }

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
