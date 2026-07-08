'use strict';

const express = require('express');
const fsp = require('fs').promises;
const path = require('path');
const { matchDrivers } = require('../services/driverMatchingService');

const router = express.Router();

// In-memory store for hardware reports (keyed by hostname/deviceId)
// In production this would go into the database
const hardwareReports = new Map();
const driverRecommendations = new Map();

// Cap in-memory caches so a stream of distinct hostnames/deviceIds can't
// grow these maps without bound; evict the oldest entry (FIFO) once full.
const MAX_CACHE_ENTRIES = 500;
function cacheSet(map, key, value) {
  if (!map.has(key) && map.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
  map.set(key, value);
}

const REPORT_DIR = process.env.DEVICE_HARDWARE_DIR || '/var/lib/opendirectory/device-hardware';

async function persistReport(key, data) {
  try {
    await fsp.mkdir(REPORT_DIR, { recursive: true });
    await fsp.writeFile(path.join(REPORT_DIR, `${key}.json`), JSON.stringify(data, null, 2));
  } catch (_) {}
}

async function loadReport(key) {
  try {
    const raw = await fsp.readFile(path.join(REPORT_DIR, `${key}.json`), 'utf-8');
    return JSON.parse(raw);
  } catch (_) { return null; }
}

// POST /api/devices/report-hardware
// Called by Windows agent / Join script after domain join
// Body: { hostname, deviceId?, manufacturer, model, os, osVersion, hardwareIds? }
router.post('/report-hardware', async (req, res) => {
  try {
    const { hostname, deviceId, manufacturer, model, os, osVersion, hardwareIds = [] } = req.body || {};
    if (!hostname && !deviceId) {
      return res.status(400).json({ success: false, error: 'hostname or deviceId required' });
    }

    const key = String(deviceId || hostname).toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    if (!key) {
      return res.status(400).json({ success: false, error: 'hostname or deviceId required' });
    }
    const report = { hostname, deviceId, manufacturer, model, os, osVersion, hardwareIds, reportedAt: new Date().toISOString() };

    cacheSet(hardwareReports, key, report);
    await persistReport(key, report);

    // Run driver matching
    const recommendations = await matchDrivers({ manufacturer, model, os, hardwareIds });
    cacheSet(driverRecommendations, key, { recommendations, matchedAt: new Date().toISOString() });

    res.json({
      success: true,
      key,
      report,
      recommendations: recommendations.slice(0, 20),
      count: recommendations.length,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/devices/:id/driver-recommendations
// Returns driver recommendations for a device (by hostname or deviceId)
router.get('/:id/driver-recommendations', async (req, res) => {
  try {
    const key = req.params.id.toLowerCase().replace(/[^a-z0-9_-]/g, '_');

    let cached = driverRecommendations.get(key);
    if (!cached) {
      // Try to load hardware report from disk and re-run matching
      const report = await loadReport(key);
      if (!report) {
        return res.status(404).json({ success: false, error: 'No hardware report found for this device. Run report-hardware first.' });
      }
      const recommendations = await matchDrivers(report);
      cached = { recommendations, matchedAt: new Date().toISOString() };
      cacheSet(driverRecommendations, key, cached);
    }

    res.json({ success: true, ...cached, count: cached.recommendations.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /api/devices/:id/detect-drivers
// Re-run driver detection for a device (optionally with new hw info in body)
router.post('/:id/detect-drivers', async (req, res) => {
  try {
    const key = req.params.id.toLowerCase().replace(/[^a-z0-9_-]/g, '_');

    let hwInfo = req.body || {};
    if (!hwInfo.manufacturer) {
      const stored = hardwareReports.get(key) || await loadReport(key);
      if (!stored) {
        return res.status(404).json({ success: false, error: 'No hardware info available. POST to /report-hardware first.' });
      }
      hwInfo = { ...stored, ...hwInfo };
    }

    const recommendations = await matchDrivers(hwInfo);
    cacheSet(driverRecommendations, key, { recommendations, matchedAt: new Date().toISOString() });

    res.json({ success: true, count: recommendations.length, recommendations: recommendations.slice(0, 20) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/devices/report-hardware/:id  (retrieve stored report)
router.get('/report-hardware/:id', async (req, res) => {
  try {
    const key = req.params.id.toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    const report = hardwareReports.get(key) || await loadReport(key);
    if (!report) return res.status(404).json({ success: false, error: 'No report found' });
    res.json({ success: true, report });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
