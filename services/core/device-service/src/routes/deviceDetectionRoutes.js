'use strict';

const express = require('express');

const DriverApplicationService = require('../application/DriverApplicationService');
const FileDriverRepository = require('../infrastructure/repositories/FileDriverRepository');
const FileHardwareReportRepository = require('../infrastructure/repositories/FileHardwareReportRepository');
const { HardwareProfile, sanitizeKey } = require('../domain/value-objects/HardwareProfile');
const { matchDrivers } = require('../services/driverMatchingService');

const router = express.Router();

// Module singleton — see driverRoutes.js for why each router builds its own
// application-service instance backed by the file repositories.
const driverAppService = new DriverApplicationService({
  driverRepo: new FileDriverRepository(),
  reportRepo: new FileHardwareReportRepository(),
  matchDrivers,
});

// POST /api/devices/report-hardware
// Called by Windows agent / Join script after domain join
// Body: { hostname, deviceId?, manufacturer, model, os, osVersion, hardwareIds? }
router.post('/report-hardware', async (req, res) => {
  try {
    const { hostname, deviceId, manufacturer, model, os, osVersion, hardwareIds = [] } = req.body || {};
    if (!hostname && !deviceId) {
      return res.status(400).json({ success: false, error: 'hostname or deviceId required' });
    }

    let profile;
    try {
      profile = new HardwareProfile({ hostname, deviceId, manufacturer, model, os, osVersion, hardwareIds });
    } catch (_) {
      return res.status(400).json({ success: false, error: 'hostname or deviceId required' });
    }

    const { key, report, recommendations } = await driverAppService.reportHardware(profile);

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
    const key = sanitizeKey(req.params.id);
    const cached = await driverAppService.getRecommendations(key);
    if (!cached) {
      return res.status(404).json({ success: false, error: 'No hardware report found for this device. Run report-hardware first.' });
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
    const key = sanitizeKey(req.params.id);
    const result = await driverAppService.detectDrivers(key, req.body || {});
    if (!result) {
      return res.status(404).json({ success: false, error: 'No hardware info available. POST to /report-hardware first.' });
    }
    res.json({ success: true, count: result.count, recommendations: result.recommendations.slice(0, 20) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/devices/report-hardware/:id  (retrieve stored report)
router.get('/report-hardware/:id', async (req, res) => {
  try {
    const key = sanitizeKey(req.params.id);
    const report = await driverAppService.getHardwareReport(key);
    if (!report) return res.status(404).json({ success: false, error: 'No report found' });
    res.json({ success: true, report });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
