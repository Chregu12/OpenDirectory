'use strict';

const express = require('express');
const router = express.Router();
const provisioner = require('../samba/provisioner');
const domainController = require('../samba/domainController');
const dnsBackend = require('../samba/dnsBackend');
const kerberosManager = require('../samba/kerberosManager');
const syncEngine = require('../ldap/syncEngine');

// ==========================================
// Domain Provisioning & Status
// ==========================================

/**
 * POST /api/samba/domain/provision
 * Provision a new Samba AD DC domain.
 */
router.post('/domain/provision', async (req, res) => {
  try {
    const { realm, domain, adminPassword, dnsBackend: dnsBack } = req.body;

    if (!realm || !domain || !adminPassword) {
      return res.status(400).json({
        error: 'realm, domain, and adminPassword are required'
      });
    }

    const result = await provisioner.provisionDomain(realm, domain, adminPassword, dnsBack);
    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('already provisioned') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * GET /api/samba/domain/status
 * Get domain provisioning status.
 */
router.get('/domain/status', async (req, res) => {
  try {
    const status = await provisioner.getDomainStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/domain/info
 * Get forest and domain info including functional levels.
 */
router.get('/domain/info', async (req, res) => {
  try {
    const info = await provisioner.getForestInfo();
    res.json(info);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// Domain Controller Status
// ==========================================

/**
 * GET /api/samba/dc/status
 * Get DC health status.
 */
router.get('/dc/status', async (req, res) => {
  try {
    const status = await domainController.getDCStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/dc/fsmo
 * Get FSMO role holders.
 */
router.get('/dc/fsmo', async (req, res) => {
  try {
    const roles = await domainController.getFSMORoles();
    res.json(roles);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/dc/fsmo/transfer
 * Transfer an FSMO role.
 */
router.post('/dc/fsmo/transfer', async (req, res) => {
  try {
    const { role, targetDC } = req.body;
    if (!role || !targetDC) {
      return res.status(400).json({ error: 'role and targetDC are required' });
    }
    const result = await domainController.transferFSMORole(role, targetDC);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/dc/replication
 * Get replication status.
 */
router.get('/dc/replication', async (req, res) => {
  try {
    const status = await domainController.getReplicationStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/dc/level
 * Get domain/forest functional levels.
 */
router.get('/dc/level', async (req, res) => {
  try {
    const level = await domainController.getDomainLevel();
    res.json(level);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// DNS Management
// ==========================================

/**
 * GET /api/samba/dns/zones
 * List DNS zones.
 */
router.get('/dns/zones', async (req, res) => {
  try {
    const zones = await dnsBackend.getZones();
    res.json(zones);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/dns/records
 * List DNS records for a zone.
 */
router.get('/dns/records', async (req, res) => {
  try {
    const { zone } = req.query;
    if (!zone) {
      return res.status(400).json({ error: 'zone query parameter is required' });
    }
    const records = await dnsBackend.getRecords(zone);
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/dns/records
 * Add a DNS record.
 */
router.post('/dns/records', async (req, res) => {
  try {
    const { zone, name, type, data, ttl } = req.body;
    if (!zone || !name || !type || !data) {
      return res.status(400).json({ error: 'zone, name, type, and data are required' });
    }
    const result = await dnsBackend.addRecord(zone, name, type, data, ttl);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/dns/records/:id
 * Delete a DNS record.
 */
router.delete('/dns/records/:id', async (req, res) => {
  try {
    const { zone, name, type, data } = req.query;
    if (!zone || !name || !type || !data) {
      return res.status(400).json({ error: 'zone, name, type, and data query parameters are required' });
    }
    const result = await dnsBackend.deleteRecord(zone, name, type, data);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/dns/forwarders
 * Get DNS forwarders.
 */
router.get('/dns/forwarders', async (req, res) => {
  try {
    const forwarders = await dnsBackend.getForwarders();
    res.json(forwarders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/samba/dns/forwarders
 * Set DNS forwarders.
 */
router.put('/dns/forwarders', async (req, res) => {
  try {
    const { forwarders } = req.body;
    if (!forwarders) {
      return res.status(400).json({ error: 'forwarders array is required' });
    }
    const result = await dnsBackend.setForwarders(forwarders);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// Kerberos Management
// ==========================================

/**
 * GET /api/samba/kerberos/config
 * Get Kerberos configuration.
 */
router.get('/kerberos/config', async (req, res) => {
  try {
    const config = await kerberosManager.getKerberosConfig();
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/kerberos/principals
 * List Kerberos principals.
 */
router.get('/kerberos/principals', async (req, res) => {
  try {
    const principals = await kerberosManager.listPrincipals();
    res.json(principals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/kerberos/spn
 * Create a Service Principal Name.
 */
router.post('/kerberos/spn', async (req, res) => {
  try {
    const { service, hostname } = req.body;
    if (!service || !hostname) {
      return res.status(400).json({ error: 'service and hostname are required' });
    }
    const result = await kerberosManager.createServicePrincipal(service, hostname);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/kerberos/keytab
 * Export a keytab file.
 */
router.post('/kerberos/keytab', async (req, res) => {
  try {
    const { principal, path } = req.body;
    if (!principal || !path) {
      return res.status(400).json({ error: 'principal and path are required' });
    }
    const result = await kerberosManager.exportKeytab(principal, path);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/kerberos/test
 * Test Kerberos authentication.
 */
router.post('/kerberos/test', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }
    const result = await kerberosManager.testAuthentication(username, password);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// Sync Engine
// ==========================================

/**
 * GET /api/samba/sync/status
 * Get sync engine status.
 */
router.get('/sync/status', (req, res) => {
  const status = syncEngine.getSyncStatus();
  res.json(status);
});

/**
 * POST /api/samba/sync/lldap-to-samba
 * Trigger sync from lldap to Samba AD.
 */
router.post('/sync/lldap-to-samba', async (req, res) => {
  try {
    const result = await syncEngine.syncFromLldapToSamba();
    res.json(result);
  } catch (err) {
    const status = err.message.includes('already in progress') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * POST /api/samba/sync/samba-to-lldap
 * Trigger sync from Samba AD to lldap.
 */
router.post('/sync/samba-to-lldap', async (req, res) => {
  try {
    const result = await syncEngine.syncFromSambaToLldap();
    res.json(result);
  } catch (err) {
    const status = err.message.includes('already in progress') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * POST /api/samba/sync/continuous/start
 * Start continuous sync.
 */
router.post('/sync/continuous/start', (req, res) => {
  try {
    const { intervalMs } = req.body;
    const result = syncEngine.startContinuousSync(intervalMs);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/sync/continuous/stop
 * Stop continuous sync.
 */
router.post('/sync/continuous/stop', (req, res) => {
  const result = syncEngine.stopContinuousSync();
  res.json(result);
});

module.exports = router;
