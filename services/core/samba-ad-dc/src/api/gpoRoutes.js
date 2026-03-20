'use strict';

const express = require('express');
const router = express.Router();
const sysvolManager = require('../gpo/sysvolManager');
const gpoLinker = require('../gpo/gpoLinker');

// ==========================================
// GPO Management
// ==========================================

/**
 * GET /api/samba/gpo
 * List all GPOs.
 */
router.get('/', async (req, res) => {
  try {
    const result = await sysvolManager.listGPOs();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/samba/gpo
 * Create a new GPO.
 */
router.post('/', async (req, res) => {
  try {
    const { name, settings } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'GPO name is required' });
    }

    const result = await sysvolManager.createGPO(name, settings);
    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('already exists') ? 409 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * GET /api/samba/gpo/:id
 * Get GPO details and settings.
 */
router.get('/:id', async (req, res) => {
  try {
    const result = await sysvolManager.getGPOSettings(req.params.id);
    res.json(result);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * PUT /api/samba/gpo/:id
 * Update GPO settings.
 */
router.put('/:id', async (req, res) => {
  try {
    const settings = req.body;

    if (!settings || Object.keys(settings).length === 0) {
      return res.status(400).json({ error: 'Settings object is required' });
    }

    const result = await sysvolManager.updateGPOSettings(req.params.id, settings);
    res.json(result);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/gpo/:id
 * Delete a GPO.
 */
router.delete('/:id', async (req, res) => {
  try {
    const result = await sysvolManager.deleteGPO(req.params.id);
    res.json(result);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// ==========================================
// GPO Linking
// ==========================================

/**
 * POST /api/samba/gpo/:id/link
 * Link a GPO to an OU, Domain, or Site.
 */
router.post('/:id/link', async (req, res) => {
  try {
    const { targetDn, enforced, disabled } = req.body;

    if (!targetDn) {
      return res.status(400).json({ error: 'targetDn is required' });
    }

    const result = await gpoLinker.linkGPO(
      req.params.id,
      targetDn,
      enforced === true,
      disabled === true
    );
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/samba/gpo/:id/link
 * Unlink a GPO from a target.
 */
router.delete('/:id/link', async (req, res) => {
  try {
    const { targetDn } = req.body;

    if (!targetDn) {
      return res.status(400).json({ error: 'targetDn is required' });
    }

    const result = await gpoLinker.unlinkGPO(req.params.id, targetDn);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/gpo/:id/links
 * Get where a GPO is linked.
 */
router.get('/:id/links', async (req, res) => {
  try {
    const { targetDn } = req.query;

    if (!targetDn) {
      return res.status(400).json({ error: 'targetDn query parameter is required' });
    }

    const result = await gpoLinker.getLinkedGPOs(targetDn);
    // Filter to only show links for the specified GPO
    const filtered = result.linkedGPOs.filter(l => l.gpoId === req.params.id);
    res.json({ ...result, linkedGPOs: filtered });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/samba/gpo/:id/link/enforce
 * Set the enforced flag on a GPO link.
 */
router.put('/:id/link/enforce', async (req, res) => {
  try {
    const { targetDn, enforced } = req.body;

    if (!targetDn || typeof enforced !== 'boolean') {
      return res.status(400).json({ error: 'targetDn and enforced (boolean) are required' });
    }

    const result = await gpoLinker.setEnforced(req.params.id, targetDn, enforced);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/samba/gpo/link-order
 * Set GPO processing order for a target.
 */
router.put('/link-order', async (req, res) => {
  try {
    const { targetDn, gpoIds } = req.body;

    if (!targetDn || !gpoIds) {
      return res.status(400).json({ error: 'targetDn and gpoIds array are required' });
    }

    const result = await gpoLinker.setLinkOrder(targetDn, gpoIds);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/samba/gpo/:id/report
 * Generate a GPO settings report.
 */
router.get('/:id/report', async (req, res) => {
  try {
    const settings = await sysvolManager.getGPOSettings(req.params.id);

    const report = {
      id: settings.id,
      name: settings.name || settings.displayName,
      version: settings.version,
      machineVersion: settings.machineVersion,
      userVersion: settings.userVersion,
      createdAt: settings.createdAt,
      modifiedAt: settings.modifiedAt,
      machineSettings: settings.machineSettings || {},
      userSettings: settings.userSettings || {},
      scripts: settings.scripts || {},
      flags: settings.flags,
      enabled: (settings.flags & 3) === 0,
      machineEnabled: (settings.flags & 2) === 0,
      userEnabled: (settings.flags & 1) === 0,
      generatedAt: new Date().toISOString()
    };

    res.json(report);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * POST /api/samba/gpo/:id/backup
 * Backup a GPO.
 */
router.post('/:id/backup', async (req, res) => {
  try {
    const { backupDir } = req.body;
    const result = await sysvolManager.backupGPO(req.params.id, backupDir);
    res.status(201).json(result);
  } catch (err) {
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

/**
 * POST /api/samba/gpo/restore
 * Restore a GPO from backup.
 */
router.post('/restore', async (req, res) => {
  try {
    const { backupPath } = req.body;

    if (!backupPath) {
      return res.status(400).json({ error: 'backupPath is required' });
    }

    const result = await sysvolManager.restoreGPO(backupPath);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
