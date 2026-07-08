'use strict';

const fs = require('fs').promises;
const path = require('path');
const express = require('express');
const DriverCatalogManager = require('../services/driverCatalogManager');
const dellCatalog = require('../services/dellCatalogService');
const printerDriverManager = require('../services/printerDriverManager');

const router = express.Router();
const catalog = new DriverCatalogManager();

// Coerce a query param that may be a single value, an array (e.g. ?q=a&q=b,
// which Express turns into req.query.q === ['a', 'b']), or undefined into a
// plain string so downstream .toLowerCase()/comparisons never crash.
function qs(value, fallback = '') {
  return String([].concat(value ?? fallback)[0] ?? fallback);
}

// printerDriverManager only stores a single OS value (linux|windows|macos|
// universal) and listDrivers()/getDriver() filter on it with strict
// equality. Catalog/import records may carry an array of supported OSes
// (e.g. ['linux', 'macos']); collapse that to a single value that still
// makes sense for that filtering.
function normalizeOs(os) {
  if (Array.isArray(os)) {
    return os.length === 1 ? os[0] : 'universal';
  }
  return os || 'universal';
}

// Register a downloaded catalog/URL import record with printerDriverManager
// (drivers.json) and move the already-downloaded file into place. Without
// this, importFromCatalog()/importFromUrl() only return an in-memory object
// and the driver never shows up in GET /api/printer/drivers.
async function persistImportedDriver(record) {
  let driver;
  try {
    driver = await printerDriverManager.addDriver({
      name: record.name,
      version: record.version || '0.0.0',
      vendor: record.vendor || 'Unbekannt',
      os: normalizeOs(record.os),
      format: record.format || 'bin',
      models: record.models || [],
      filename: path.basename(record.localPath),
      fileSize: record.fileSize,
    });

    try {
      await fs.rename(record.localPath, driver.filePath);
    } catch (err) {
      if (err.code === 'EXDEV') {
        await fs.copyFile(record.localPath, driver.filePath);
        await fs.unlink(record.localPath);
      } else {
        throw err;
      }
    }

    return driver;
  } catch (err) {
    if (record.localPath) await fs.unlink(record.localPath).catch(() => {});
    if (driver) await printerDriverManager.deleteDriver(driver.id).catch(() => {});
    throw err;
  }
}

// ─── GET /catalog/search ──────────────────────────────────────────────────────
// Query params: q, vendor, os, deviceType, source, includeOpenPrinting
router.get('/search', async (req, res) => {
  try {
    const q = qs(req.query.q);
    const vendor = qs(req.query.vendor);
    const os = qs(req.query.os);
    const deviceType = qs(req.query.deviceType);
    const { source, includeOpenPrinting } = req.query;

    const filters = {};
    if (vendor)   filters.vendor   = vendor;
    if (os)       filters.os       = os;
    if (deviceType) filters.deviceType = deviceType;
    if (source)   filters.source   = source;
    if (includeOpenPrinting === 'true' || includeOpenPrinting === '1') {
      filters.includeOpenPrinting = true;
    }

    const results = await catalog.searchCatalog(q, filters);
    res.json({ success: true, count: results.length, results });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/vendors ─────────────────────────────────────────────────────
// Returns all known vendors with entry counts
router.get('/vendors', async (req, res) => {
  try {
    const vendors = await catalog.getVendors();
    const list = Object.entries(vendors).map(([id, count]) => ({
      id,
      name: id.charAt(0).toUpperCase() + id.slice(1),
      count,
    }));
    res.json({ success: true, vendors: list });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/openprinting ────────────────────────────────────────────────
// Query params: q (required)
router.get('/openprinting', async (req, res) => {
  try {
    const q = qs(req.query.q);
    if (!q) return res.status(400).json({ success: false, error: 'q (query) parameter is required' });

    const results = await catalog.searchOpenPrinting(q);
    res.json({ success: true, source: 'openprinting', count: results.length, results });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── POST /catalog/import ─────────────────────────────────────────────────────
// Body: { entry }  — entry is a CatalogEntry object (e.g. from /search)
router.post('/import', async (req, res) => {
  try {
    const { entry } = req.body;
    if (!entry) return res.status(400).json({ success: false, error: 'entry is required in request body' });
    if (!entry.downloadUrl) {
      return res.status(400).json({ success: false, error: 'entry.downloadUrl is required to import' });
    }

    const record = await catalog.importFromCatalog(entry);
    const driver = await persistImportedDriver(record);
    res.json({ success: true, driver });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── POST /catalog/import-url ─────────────────────────────────────────────────
// Body: { url, name, version, vendor, os, deviceType, format }
router.post('/import-url', async (req, res) => {
  try {
    const { url, ...metadata } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'url is required' });

    const record = await catalog.importFromUrl(url, metadata);
    const driver = await persistImportedDriver(record);
    res.json({ success: true, driver });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/dell ───────────────────────────────────────────────────────
// Live Dell catalog search.  Query params: q, systemModel, os, deviceType,
// limit (default 100, max 1000) — the full catalog has tens of thousands of
// entries, so unbounded responses are never returned.
router.get('/dell', async (req, res) => {
  try {
    const q = qs(req.query.q);
    const systemModel = qs(req.query.systemModel);
    const os = qs(req.query.os);
    const deviceType = qs(req.query.deviceType);
    const limit = Math.min(Math.max(parseInt(qs(req.query.limit), 10) || 100, 1), 1000);
    const filters = {};
    if (systemModel) filters.systemModel = systemModel;
    if (os)          filters.os          = os;
    if (deviceType)  filters.deviceType  = deviceType;

    const results = await dellCatalog.search(q, filters);
    res.json({
      success: true,
      source: 'dell',
      count: results.length,
      results: results.slice(0, limit),
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/dell/stats ─────────────────────────────────────────────────
router.get('/dell/stats', async (req, res) => {
  try {
    const stats = await dellCatalog.getStats();
    res.json({ success: true, ...stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── POST /catalog/dell/refresh ──────────────────────────────────────────────
// Force re-download and re-parse of the Dell CatalogPC.cab
router.post('/dell/refresh', async (req, res) => {
  try {
    const result = await dellCatalog.refresh();
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
