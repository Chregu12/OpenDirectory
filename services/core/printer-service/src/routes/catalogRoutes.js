'use strict';

const express = require('express');
const appService = require('../application/DriverCatalogApplicationService');

const router = express.Router();

// Coerce a query param that may be a single value, an array (e.g. ?q=a&q=b,
// which Express turns into req.query.q === ['a', 'b']), or undefined into a
// plain string so downstream .toLowerCase()/comparisons never crash.
function qs(value, fallback = '') {
  return String([].concat(value ?? fallback)[0] ?? fallback);
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

    const results = await appService.searchCatalog(q, filters);
    res.json({ success: true, count: results.length, results });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/vendors ─────────────────────────────────────────────────────
// Returns all known vendors with entry counts
router.get('/vendors', async (req, res) => {
  try {
    const vendors = await appService.getVendors();
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

    const results = await appService.searchOpenPrinting(q);
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

    const driver = await appService.importCatalogEntry(entry);
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

    const driver = await appService.importFromUrl(url, metadata);
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

    const { count, results } = await appService.searchDell(q, filters, limit);
    res.json({ success: true, source: 'dell', count, results });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── GET /catalog/dell/stats ─────────────────────────────────────────────────
router.get('/dell/stats', async (req, res) => {
  try {
    const stats = await appService.getDellStats();
    res.json({ success: true, ...stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─── POST /catalog/dell/refresh ──────────────────────────────────────────────
// Force re-download and re-parse of the Dell CatalogPC.cab
router.post('/dell/refresh', async (req, res) => {
  try {
    const result = await appService.refreshDell();
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
