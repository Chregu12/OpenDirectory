'use strict';

const express = require('express');
const multer = require('multer');
const path = require('path');
const winston = require('winston');

const manager = require('../services/deviceDriverManager');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const router = express.Router();

// Store uploads in memory so we can compute sha256 before writing to disk
const upload = multer({ storage: multer.memoryStorage() });

// GET /drivers — list with optional filters
router.get('/', async (req, res) => {
  try {
    const { os, deviceType, vendor } = req.query;
    const drivers = await manager.listDrivers({ os, deviceType, vendor });
    res.json({ success: true, data: drivers });
  } catch (err) {
    logger.error('listDrivers error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /drivers/:id — single driver with deployments
router.get('/:id', async (req, res) => {
  try {
    const driver = await manager.getDriver(req.params.id);
    if (!driver) return res.status(404).json({ error: 'Treiber nicht gefunden' });
    res.json({ success: true, data: driver });
  } catch (err) {
    logger.error('getDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/upload — multipart upload
// Note: this route must be declared before /:id to avoid being shadowed
router.post('/upload', upload.single('driver'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Keine Treiberdatei hochgeladen (Feld: driver)' });
    }

    const { name, version, vendor, os, deviceType, format, architecture, description, tags } = req.body;

    // Basic required-field validation
    const missing = ['name', 'version', 'vendor', 'os', 'deviceType', 'format', 'architecture']
      .filter(f => !req.body[f]);
    if (missing.length) {
      return res.status(400).json({ error: `Pflichtfelder fehlen: ${missing.join(', ')}` });
    }

    const driver = await manager.addDriver({
      fileBuffer: req.file.buffer,
      filename: req.file.originalname || `driver.${format}`,
      name,
      version,
      vendor,
      os,
      deviceType,
      format,
      architecture,
      description,
      tags,
    });

    res.status(201).json({ success: true, data: driver });
  } catch (err) {
    logger.error('uploadDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /drivers/:id
router.delete('/:id', async (req, res) => {
  try {
    const deleted = await manager.deleteDriver(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Treiber nicht gefunden' });
    res.json({ success: true });
  } catch (err) {
    logger.error('deleteDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/:id/deploy — body: { deviceIds: string[] }
router.post('/:id/deploy', async (req, res) => {
  try {
    const { deviceIds } = req.body;
    if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'deviceIds muss ein nicht-leeres Array sein' });
    }
    const deployments = await manager.deployDriver(req.params.id, deviceIds);
    res.status(201).json({ success: true, data: deployments });
  } catch (err) {
    logger.error('deployDriver error:', err);
    const status = err.message.includes('nicht gefunden') || err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// GET /drivers/:id/deployments
router.get('/:id/deployments', async (req, res) => {
  try {
    const deployments = await manager.getDeployments(req.params.id);
    res.json({ success: true, data: deployments });
  } catch (err) {
    logger.error('getDeployments error:', err);
    const status = err.message.includes('not found') ? 404 : 500;
    res.status(status).json({ error: err.message });
  }
});

// PATCH /drivers/:id/deployments/:deploymentId — body: { status, error? }
router.patch('/:id/deployments/:deploymentId', async (req, res) => {
  try {
    const { status, error } = req.body;
    if (!status) return res.status(400).json({ error: 'status ist erforderlich' });

    const deployment = await manager.updateDeploymentStatus(req.params.deploymentId, status, error);
    if (!deployment) return res.status(404).json({ error: 'Deployment nicht gefunden' });
    res.json({ success: true, data: deployment });
  } catch (err) {
    logger.error('updateDeploymentStatus error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
