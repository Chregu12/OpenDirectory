'use strict';

const express = require('express');
const multer = require('multer');
const winston = require('winston');

const DriverApplicationService = require('../application/DriverApplicationService');
const FileDriverRepository = require('../infrastructure/repositories/FileDriverRepository');
const FileHardwareReportRepository = require('../infrastructure/repositories/FileHardwareReportRepository');
const { matchDrivers } = require('../services/driverMatchingService');

const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB — mirrors the import-url download limit

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

// Module singleton — file-backed repositories + the (already clean) driver
// matching wrapper. deviceDetectionRoutes.js builds its own instance backed
// by the same repository classes so both routers share behaviour, not state
// (each repository re-reads process.env.DEVICE_DRIVERS_DIR / DEVICE_HARDWARE_DIR
// at construction time, same as the transaction-script version did).
const driverAppService = new DriverApplicationService({
  driverRepo: new FileDriverRepository(),
  reportRepo: new FileHardwareReportRepository(),
  matchDrivers,
});

const router = express.Router();

// Store uploads in memory so we can compute sha256 before writing to disk.
// Cap file size to match the import-url download limit so a huge upload
// can't exhaust process memory.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_DOWNLOAD_BYTES } });

// GET /drivers — list with optional filters
router.get('/', async (req, res) => {
  try {
    const { os, deviceType, vendor } = req.query;
    const drivers = await driverAppService.listDrivers({ os, deviceType, vendor });
    res.json({ success: true, data: drivers.map(d => d.toJSON()) });
  } catch (err) {
    logger.error('listDrivers error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /drivers/:id — single driver with deployments
// Note: this route must be declared after /upload and /import-url to avoid shadowing them.
router.get('/:id', async (req, res) => {
  try {
    const driver = await driverAppService.getDriver(req.params.id);
    if (!driver) return res.status(404).json({ error: 'Treiber nicht gefunden' });
    res.json({ success: true, data: driver.toJSON() });
  } catch (err) {
    logger.error('getDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/upload — multipart upload (file field: "driver" or "file").
// Metadata fields are optional; sensible defaults are derived from the filename.
// Note: this route must be declared before /:id to avoid being shadowed
router.post('/upload', upload.fields([{ name: 'driver', maxCount: 1 }, { name: 'file', maxCount: 1 }]), async (req, res) => {
  try {
    const file = req.files?.driver?.[0] || req.files?.file?.[0];
    if (!file) {
      return res.status(400).json({ error: 'Keine Treiberdatei hochgeladen (Feld: driver oder file)' });
    }

    const { name, version, vendor, os, deviceType, format, architecture, description, tags } = req.body;
    const driver = await driverAppService.uploadDriver(file.buffer, file.originalname, {
      name, version, vendor, os, deviceType, format, architecture, description, tags,
    });

    res.status(201).json({ success: true, data: driver.toJSON() });
  } catch (err) {
    logger.error('uploadDriver error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /drivers/import-url — download a driver from a URL and register it.
// Body: { url, name?, version?, vendor?, os?, deviceType?, format?, architecture?, description?, tags? }
// Used by the frontend to import recommended drivers (Dell catalog, vendor catalogs).
router.post('/import-url', async (req, res) => {
  try {
    const { url, name, version, vendor, os, deviceType, format, architecture, description, tags } = req.body;
    if (!url) return res.status(400).json({ error: 'url ist erforderlich' });

    const driver = await driverAppService.importFromUrl(url, {
      name, version, vendor, os, deviceType, format, architecture, description, tags,
    });

    res.status(201).json({ success: true, data: driver.toJSON() });
  } catch (err) {
    logger.error('importDriverFromUrl error:', err);
    const status = err.message === 'url ist erforderlich' ? 400 : 500;
    res.status(status).json({ error: err.message });
  }
});

// DELETE /drivers/:id
router.delete('/:id', async (req, res) => {
  try {
    const deleted = await driverAppService.deleteDriver(req.params.id);
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
    const deployments = await driverAppService.deployDriver(req.params.id, deviceIds);
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
    const deployments = await driverAppService.getDeployments(req.params.id);
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

    const deployment = await driverAppService.updateDeploymentStatus(req.params.deploymentId, status, error);
    if (!deployment) return res.status(404).json({ error: 'Deployment nicht gefunden' });
    res.json({ success: true, data: deployment });
  } catch (err) {
    logger.error('updateDeploymentStatus error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
