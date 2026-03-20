'use strict';

const express = require('express');
const logger = require('../utils/logger');

/**
 * Create compliance API routes.
 * @param {object} deps - Injected dependencies
 * @returns {express.Router}
 */
function createComplianceRoutes(deps) {
  const router = express.Router();
  const { evaluator, baselineManager, waiverManager, scoreCalculator, trendAnalyzer, reportGenerator } = deps;

  // ─── Baselines ────────────────────────────────────────────────────

  // GET /api/compliance/baselines - List baselines
  router.get('/baselines', async (req, res) => {
    try {
      const filters = {
        framework: req.query.framework,
        platform: req.query.platform,
        enabled: req.query.enabled !== undefined ? req.query.enabled === 'true' : undefined,
        search: req.query.search,
        limit: req.query.limit ? parseInt(req.query.limit, 10) : undefined,
        offset: req.query.offset ? parseInt(req.query.offset, 10) : undefined,
      };

      const baselines = await baselineManager.listBaselines(filters);
      res.json({ success: true, data: baselines, count: baselines.length });
    } catch (error) {
      logger.error(`Failed to list baselines: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to list baselines' });
    }
  });

  // GET /api/compliance/baselines/:id - Get baseline detail
  router.get('/baselines/:id', async (req, res) => {
    try {
      const baseline = await baselineManager.getBaseline(req.params.id);
      if (!baseline) {
        return res.status(404).json({ success: false, error: 'Baseline not found' });
      }
      res.json({ success: true, data: baseline });
    } catch (error) {
      logger.error(`Failed to get baseline: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to get baseline' });
    }
  });

  // POST /api/compliance/baselines - Create custom baseline
  router.post('/baselines', async (req, res) => {
    try {
      const { name, description, framework, platform, version, checks, enabled } = req.body;

      if (!name || !framework || !version) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: name, framework, version',
        });
      }

      const baseline = await baselineManager.createBaseline({
        name, description, framework, platform, version, checks, enabled,
      });

      res.status(201).json({ success: true, data: baseline });
    } catch (error) {
      logger.error(`Failed to create baseline: ${error.message}`, { error });
      const status = error.message.includes('Invalid') || error.message.includes('Missing') ? 400 : 500;
      res.status(status).json({ success: false, error: error.message });
    }
  });

  // PUT /api/compliance/baselines/:id - Update baseline
  router.put('/baselines/:id', async (req, res) => {
    try {
      const baseline = await baselineManager.updateBaseline(req.params.id, req.body);
      res.json({ success: true, data: baseline });
    } catch (error) {
      logger.error(`Failed to update baseline: ${error.message}`, { error });
      const status = error.message.includes('not found') ? 404 :
                     error.message.includes('No valid') ? 400 : 500;
      res.status(status).json({ success: false, error: error.message });
    }
  });

  // ─── Results & Evaluation ─────────────────────────────────────────

  // GET /api/compliance/results/:deviceId - Get device compliance results
  router.get('/results/:deviceId', async (req, res) => {
    try {
      const { deviceId } = req.params;
      const { baselineId, framework, limit } = req.query;

      let query = `
        SELECT cr.*, cb.name AS baseline_name, cb.framework, cb.platform
        FROM compliance_results cr
        JOIN compliance_baselines cb ON cr.baseline_id = cb.id
        WHERE cr.device_id = $1
      `;
      const params = [deviceId];

      if (baselineId) {
        params.push(baselineId);
        query += ` AND cr.baseline_id = $${params.length}`;
      }

      if (framework) {
        params.push(framework);
        query += ` AND cb.framework = $${params.length}`;
      }

      query += ` ORDER BY cr.scanned_at DESC`;

      if (limit) {
        params.push(parseInt(limit, 10));
        query += ` LIMIT $${params.length}`;
      } else {
        query += ` LIMIT 50`;
      }

      const { rows } = await deps.db.query(query, params);

      res.json({ success: true, data: rows, count: rows.length });
    } catch (error) {
      logger.error(`Failed to get results for device: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to get compliance results' });
    }
  });

  // POST /api/compliance/evaluate/:deviceId - Trigger evaluation for device
  router.post('/evaluate/:deviceId', async (req, res) => {
    try {
      const { deviceId } = req.params;
      const inventoryData = req.body;

      if (!inventoryData || Object.keys(inventoryData).length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Request body must contain device inventory data',
        });
      }

      const result = await evaluator.evaluateDevice(deviceId, inventoryData);

      // Broadcast via WebSocket if available
      if (deps.broadcast) {
        deps.broadcast({
          type: 'compliance.evaluation.completed',
          deviceId,
          overallScore: result.overallScore,
          timestamp: result.evaluatedAt,
        });
      }

      res.json({ success: true, data: result });
    } catch (error) {
      logger.error(`Failed to evaluate device ${req.params.deviceId}: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Compliance evaluation failed' });
    }
  });

  // ─── Scores ───────────────────────────────────────────────────────

  // GET /api/compliance/score/:deviceId - Get device compliance score
  router.get('/score/:deviceId', async (req, res) => {
    try {
      const score = await evaluator.getDeviceScore(req.params.deviceId);
      res.json({ success: true, data: score });
    } catch (error) {
      logger.error(`Failed to get device score: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to get device score' });
    }
  });

  // GET /api/compliance/score/fleet - Get fleet-wide score
  router.get('/score/fleet', async (req, res) => {
    try {
      const filters = {
        framework: req.query.framework,
        platform: req.query.platform,
        baselineId: req.query.baselineId,
      };
      const score = await evaluator.getFleetScore(filters);
      res.json({ success: true, data: score });
    } catch (error) {
      logger.error(`Failed to get fleet score: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to get fleet score' });
    }
  });

  // GET /api/compliance/score/ou/:ouId - Get OU score
  router.get('/score/ou/:ouId', async (req, res) => {
    try {
      const score = await scoreCalculator.getOUScore(req.params.ouId);
      res.json({ success: true, data: score });
    } catch (error) {
      logger.error(`Failed to get OU score: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to get OU score' });
    }
  });

  // ─── Trends ───────────────────────────────────────────────────────

  // GET /api/compliance/trend/:deviceId - Get compliance trend
  router.get('/trend/:deviceId', async (req, res) => {
    try {
      const days = parseInt(req.query.days, 10) || 30;
      const trend = await scoreCalculator.getTrend(req.params.deviceId, days);
      res.json({ success: true, data: trend });
    } catch (error) {
      logger.error(`Failed to get compliance trend: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to get compliance trend' });
    }
  });

  // ─── Waivers ──────────────────────────────────────────────────────

  // GET /api/compliance/waivers - List waivers
  router.get('/waivers', async (req, res) => {
    try {
      const filters = {
        status: req.query.status,
        deviceId: req.query.deviceId,
        deviceGroup: req.query.deviceGroup,
        baselineId: req.query.baselineId,
        checkId: req.query.checkId,
        limit: req.query.limit ? parseInt(req.query.limit, 10) : undefined,
        offset: req.query.offset ? parseInt(req.query.offset, 10) : undefined,
      };

      const waivers = await waiverManager.listWaivers(filters);
      res.json({ success: true, data: waivers, count: waivers.length });
    } catch (error) {
      logger.error(`Failed to list waivers: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to list waivers' });
    }
  });

  // POST /api/compliance/waivers - Create waiver
  router.post('/waivers', async (req, res) => {
    try {
      const { deviceId, deviceGroup, baselineId, checkId, reason, approvedBy, expiresAt } = req.body;

      if (!checkId || !reason || !approvedBy || !expiresAt) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: checkId, reason, approvedBy, expiresAt',
        });
      }

      const waiver = await waiverManager.createWaiver({
        deviceId, deviceGroup, baselineId, checkId, reason, approvedBy, expiresAt,
      });

      res.status(201).json({ success: true, data: waiver });
    } catch (error) {
      logger.error(`Failed to create waiver: ${error.message}`, { error });
      const status = error.message.includes('required') || error.message.includes('Invalid') ||
                     error.message.includes('must be') || error.message.includes('cannot exceed') ||
                     error.message.includes('already exists') ? 400 : 500;
      res.status(status).json({ success: false, error: error.message });
    }
  });

  // DELETE /api/compliance/waivers/:id - Revoke waiver
  router.delete('/waivers/:id', async (req, res) => {
    try {
      const waiver = await waiverManager.revokeWaiver(req.params.id);
      res.json({ success: true, data: waiver });
    } catch (error) {
      logger.error(`Failed to revoke waiver: ${error.message}`, { error });
      const status = error.message.includes('not found') ? 404 : 500;
      res.status(status).json({ success: false, error: error.message });
    }
  });

  // ─── Dashboard ────────────────────────────────────────────────────

  // GET /api/compliance/dashboard - Dashboard aggregation
  router.get('/dashboard', async (req, res) => {
    try {
      const [fleetScore, domainScore, waiverStats, trendData] = await Promise.all([
        evaluator.getFleetScore({}),
        scoreCalculator.getDomainScore(),
        waiverManager.getStats(),
        trendAnalyzer.analyzeTrends({ days: 30 }),
      ]);

      res.json({
        success: true,
        data: {
          fleet: fleetScore,
          domain: domainScore,
          waivers: waiverStats,
          trends: trendData,
          generatedAt: new Date().toISOString(),
        },
      });
    } catch (error) {
      logger.error(`Failed to build dashboard: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to build dashboard data' });
    }
  });

  // ─── Reports ──────────────────────────────────────────────────────

  // POST /api/compliance/reports/generate - Generate compliance report
  router.post('/reports/generate', async (req, res) => {
    try {
      const {
        deviceId, baselineId, framework, platform,
        includeDeviceBreakdown, includeRemediations, includeHistory, title,
      } = req.body;

      const pdfBuffer = await reportGenerator.generateReport({
        deviceId, baselineId, framework, platform,
        includeDeviceBreakdown, includeRemediations, includeHistory, title,
      });

      const filename = deviceId
        ? `compliance-report-${deviceId}-${Date.now()}.pdf`
        : `compliance-report-fleet-${Date.now()}.pdf`;

      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': pdfBuffer.length,
      });

      res.send(pdfBuffer);
    } catch (error) {
      logger.error(`Failed to generate report: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to generate compliance report' });
    }
  });

  // ─── Frameworks ───────────────────────────────────────────────────

  // GET /api/compliance/frameworks - List supported frameworks
  router.get('/frameworks', async (req, res) => {
    try {
      const { rows } = await deps.db.query(
        `SELECT framework, COUNT(*) AS baseline_count,
                array_agg(DISTINCT platform) AS platforms
         FROM compliance_baselines
         WHERE enabled = true
         GROUP BY framework
         ORDER BY framework`
      );

      const frameworks = [
        { id: 'cis', name: 'CIS Benchmarks', description: 'Center for Internet Security configuration benchmarks' },
        { id: 'nist', name: 'NIST 800-171', description: 'NIST Special Publication 800-171 controls' },
        { id: 'bsi', name: 'BSI IT-Grundschutz', description: 'German Federal Office for Information Security baseline' },
        { id: 'iso27001', name: 'ISO 27001', description: 'International information security management standard' },
        { id: 'dsgvo', name: 'DSGVO/GDPR', description: 'EU General Data Protection Regulation technical measures' },
        { id: 'stig', name: 'DISA STIG', description: 'Defense Information Systems Agency Security Technical Implementation Guides' },
        { id: 'custom', name: 'Custom', description: 'Organization-specific custom baselines' },
      ];

      // Merge with actual baseline data
      for (const fw of frameworks) {
        const dbRow = rows.find(r => r.framework === fw.id);
        fw.baselineCount = dbRow ? parseInt(dbRow.baseline_count, 10) : 0;
        fw.platforms = dbRow ? dbRow.platforms.filter(Boolean) : [];
      }

      res.json({ success: true, data: frameworks });
    } catch (error) {
      logger.error(`Failed to list frameworks: ${error.message}`, { error });
      res.status(500).json({ success: false, error: 'Failed to list frameworks' });
    }
  });

  return router;
}

module.exports = createComplianceRoutes;
