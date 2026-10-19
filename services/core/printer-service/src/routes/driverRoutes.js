'use strict';

// NOTE: This router requires multer for multipart uploads.
//       If not already installed: npm install multer
const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs').promises;
const crypto  = require('crypto');
const winston = require('winston');

const appService = require('../application/DriverCatalogApplicationService');

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
// We use a temporary name during upload and rename after appService.uploadDriver()
// resolves the final filename.
const upload = multer({
  storage: multer.diskStorage({
    destination: async (_req, _file, cb) => {
      try {
        await appService.ensureStorage();
        cb(null, appService.FILES_DIR);
      } catch (err) {
        cb(err);
      }
    },
    filename: (_req, file, cb) => {
      // Temporary name; appService.uploadDriver() will compute the real one.
      // Random component avoids two concurrent uploads of the same filename
      // colliding when Date.now() lands in the same millisecond.
      const rand = crypto.randomBytes(4).toString('hex');
      const tmp = `upload-${Date.now().toString(36)}-${rand}-${path.basename(file.originalname)}`;
      cb(null, tmp);
    },
  }),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB cap
});

// ── One-time startup cleanup: sweep orphaned temp uploads ─────────────────────
// If the process crashes between multer writing "upload-*-..." and
// appService.uploadDriver() renaming it to its final path, the temp file is
// left behind forever. Sweep once at module load for anything older than
// 24h; best-effort/fire-and-forget.
(async () => {
  try {
    await appService.ensureStorage();
    const entries = await fs.readdir(appService.FILES_DIR);
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    await Promise.all(
      entries
        .filter((name) => name.startsWith('upload-'))
        .map(async (name) => {
          const filePath = path.join(appService.FILES_DIR, name);
          try {
            const stat = await fs.stat(filePath);
            if (stat.mtimeMs < cutoff) await fs.unlink(filePath);
          } catch (_) {
            // Ignore — file may have been renamed/removed concurrently.
          }
        })
    );
  } catch (_) {
    // Storage not ready/readable yet — nothing to clean up.
  }
})();

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
    const drivers = await appService.listDrivers({ os, format });
    ok(res, drivers);
  } catch (err) {
    logger.error('List drivers error:', err);
    fail(res, 500, err.message);
  }
});

// ── GET /drivers/:id ──────────────────────────────────────────────────────────
router.get('/drivers/:id', async (req, res) => {
  try {
    const driver = await appService.getDriver(req.params.id);
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
  try {
    if (!req.file) return fail(res, 400, 'No driver file uploaded (field name: driver)');

    const driver = await appService.uploadDriver(
      req.file.path,
      { originalname: req.file.originalname, size: req.file.size },
      req.body
    );

    logger.info(`Driver uploaded: ${req.body.name} v${req.body.version} (id=${driver.id})`);
    res.status(201).json({ success: true, data: driver });
  } catch (err) {
    logger.error('Upload driver error:', err);
    fail(res, 500, err.message);
  }
});

// ── DELETE /drivers/:id ───────────────────────────────────────────────────────
router.delete('/drivers/:id', async (req, res) => {
  try {
    const deleted = await appService.deleteDriver(req.params.id);
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

    const driver = await appService.assignDriverToPrinter(req.params.id, printerId);
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
    const driver = await appService.unassignDriverFromPrinter(
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
    const drivers = await appService.getDriversForPrinter(req.params.printerId);
    ok(res, drivers);
  } catch (err) {
    logger.error('Get printer drivers error:', err);
    fail(res, 500, err.message);
  }
});

module.exports = router;
