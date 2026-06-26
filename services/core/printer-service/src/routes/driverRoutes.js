'use strict';

// NOTE: This router requires multer for multipart uploads.
//       If not already installed: npm install multer
const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs').promises;
const winston = require('winston');

const driverManager = require('../services/printerDriverManager');

const router = express.Router();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'printer-service.log' })
  ]
});

// ── Multer storage: write directly to the driver files directory ──────────────
// We use a temporary name during upload and rename after addDriver() returns
// the final filename.
const upload = multer({
  storage: multer.diskStorage({
    destination: async (_req, _file, cb) => {
      try {
        await driverManager.ensureStorage();
        cb(null, driverManager.FILES_DIR);
      } catch (err) {
        cb(err);
      }
    },
    filename: (_req, file, cb) => {
      // Temporary name; printerDriverManager.addDriver() will compute the real one
      const tmp = `upload-${Date.now().toString(36)}-${path.basename(file.originalname)}`;
      cb(null, tmp);
    },
  }),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB cap
});

// ── Helper ────────────────────────────────────────────────────────────────────

function ok(res, data) {
  res.json({ success: true, data });
}

function fail(res, status, message) {
  res.status(status).json({ error: message });
}

// ── GET /drivers ──────────────────────────────────────────────────────────────
// Query params: ?os=linux|windows|macos|universal  ?format=ppd|inf|cab|pkg|zip
router.get('/drivers', async (req, res) => {
  try {
    const { os, format } = req.query;
    const drivers = await driverManager.listDrivers({ os, format });
    ok(res, drivers);
  } catch (err) {
    logger.error('List drivers error:', err);
    fail(res, 500, err.message);
  }
});

// ── GET /drivers/:id ──────────────────────────────────────────────────────────
router.get('/drivers/:id', async (req, res) => {
  try {
    const driver = await driverManager.getDriver(req.params.id);
    if (!driver) return fail(res, 404, 'Driver not found');
    ok(res, driver);
  } catch (err) {
    logger.error('Get driver error:', err);
    fail(res, 500, err.message);
  }
});

// ── POST /drivers/upload ──────────────────────────────────────────────────────
// multipart/form-data fields: name, version, vendor, os, format, models (comma-sep)
// file field: driver
router.post('/drivers/upload', upload.single('driver'), async (req, res) => {
  const tmpPath = req.file?.path;

  try {
    if (!req.file) return fail(res, 400, 'No driver file uploaded (field name: driver)');

    const { name, version, vendor, os, format, models } = req.body;
    if (!name)    return fail(res, 400, 'name is required');
    if (!version) return fail(res, 400, 'version is required');
    if (!vendor)  return fail(res, 400, 'vendor is required');
    if (!os)      return fail(res, 400, 'os is required');
    if (!format)  return fail(res, 400, 'format is required');

    const modelList = models
      ? models.split(',').map(m => m.trim()).filter(Boolean)
      : [];

    // Register the driver — returns the canonical filename/filePath
    const driver = await driverManager.addDriver({
      name,
      version,
      vendor,
      os,
      format,
      models: modelList,
      filename: req.file.originalname,
      fileSize: req.file.size,
    });

    // Rename temp upload to the canonical path computed by addDriver
    await fs.rename(tmpPath, driver.filePath);

    logger.info(`Driver uploaded: ${name} v${version} (id=${driver.id})`);
    ok(res, driver);
  } catch (err) {
    logger.error('Upload driver error:', err);
    // Clean up tmp file on error
    if (tmpPath) fs.unlink(tmpPath).catch(() => {});
    fail(res, 500, err.message);
  }
});

// ── DELETE /drivers/:id ───────────────────────────────────────────────────────
router.delete('/drivers/:id', async (req, res) => {
  try {
    const deleted = await driverManager.deleteDriver(req.params.id);
    if (!deleted) return fail(res, 404, 'Driver not found');
    ok(res, { id: req.params.id });
  } catch (err) {
    logger.error('Delete driver error:', err);
    fail(res, 500, err.message);
  }
});

// ── POST /drivers/:id/assign ──────────────────────────────────────────────────
// body: { printerId: string }
router.post('/drivers/:id/assign', async (req, res) => {
  try {
    const { printerId } = req.body;
    if (!printerId) return fail(res, 400, 'printerId is required');

    const driver = await driverManager.assignDriverToPrinter(req.params.id, printerId);
    ok(res, driver);
  } catch (err) {
    logger.error('Assign driver error:', err);
    const status = err.message.startsWith('Driver not found') ? 404 : 500;
    fail(res, status, err.message);
  }
});

// ── DELETE /drivers/:id/assign/:printerId ─────────────────────────────────────
router.delete('/drivers/:id/assign/:printerId', async (req, res) => {
  try {
    const driver = await driverManager.unassignDriverFromPrinter(
      req.params.id,
      req.params.printerId
    );
    ok(res, driver);
  } catch (err) {
    logger.error('Unassign driver error:', err);
    const status = err.message.startsWith('Driver not found') ? 404 : 500;
    fail(res, status, err.message);
  }
});

// ── GET /printers/:printerId/drivers ─────────────────────────────────────────
router.get('/printers/:printerId/drivers', async (req, res) => {
  try {
    const drivers = await driverManager.getDriversForPrinter(req.params.printerId);
    ok(res, drivers);
  } catch (err) {
    logger.error('Get printer drivers error:', err);
    fail(res, 500, err.message);
  }
});

module.exports = router;
