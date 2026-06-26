'use strict';

const express = require('express');
const DriverCatalogManager = require('../services/driverCatalogManager');
const dellCatalog = require('../services/dellCatalogService');

const router = express.Router();
const catalog = new DriverCatalogManager();

// ─── GET /catalog/search ──────────────────────────────────────────────────────
// Query params: q, vendor, os, deviceType, source, includeOpenPrinting
router.get('/search', async (req, res) => {
  try {
    const { q = '', vendor, os, deviceType, source, includeOpenPrinting } = req.query;

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
    const { q } = req.query;
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
    res.json({ success: true, driver: record });
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
    res.json({ success: true, driver: record });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/dell ───────────────────────────────────────────────────────
// Live Dell catalog search.  Query params: q, systemModel, os, deviceType
router.get('/dell', async (req, res) => {
  try {
    const { q = '', systemModel, os, deviceType } = req.query;
    const filters = {};
    if (systemModel) filters.systemModel = systemModel;
    if (os)          filters.os          = os;
    if (deviceType)  filters.deviceType  = deviceType;

    const results = await dellCatalog.search(q, filters);
    res.json({ success: true, source: 'dell', count: results.length, results });
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
