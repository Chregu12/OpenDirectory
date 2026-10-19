'use strict';

// Printer CRUD, deployment and print-job-queue (read/cancel) routes.
// Extracted verbatim (same paths, same request/response shapes, same status
// codes — including pre-existing quirks such as missing-by-id returning 500
// rather than 404 on several endpoints) from src/index.js so the printer
// slice can sit behind PrinterApplicationService instead of talking to the
// managers directly.
//
// Unlike routes/driverRoutes.js (which imports a module-level singleton
// application service), this router is a factory: index.js still owns the
// single printerManager/discovery/deployment/printQueue instances (they are
// also used by routes that were intentionally NOT moved here — permissions,
// quota, scanner, print-pool, agent routes) and injects one
// PrinterApplicationService built from them.
//
//   const printerRoutes = require('./routes/printerRoutes')(printerAppService);
//   app.use(printerRoutes);

const express = require('express');
const winston = require('winston');

const { ValidationError, NotFoundError } = require('../application/PrinterApplicationService');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'printer-service.log' }),
  ],
});

module.exports = function createPrinterRoutes(appService) {
  const router = express.Router();

  // ── Printer discovery and management ─────────────────────────────────────

  router.post('/api/printers/discover', async (req, res) => {
    try {
      const { method = 'all', subnet, timeout = 30000 } = req.body;
      const printers = await appService.discoverPrinters(method, subnet, timeout);
      res.json({ success: true, printers });
    } catch (error) {
      logger.error('Discovery error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.post('/api/printers/add', async (req, res) => {
    try {
      const printer = await appService.addPrinter(req.body);
      res.json({ success: true, printer });
    } catch (error) {
      logger.error('Add printer error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.get('/api/printers', async (req, res) => {
    try {
      const printers = await appService.listPrinters();
      res.json({ success: true, printers });
    } catch (error) {
      logger.error('List printers error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ── Probe a specific IP for printer info ─────────────────────────────────

  router.post('/api/printer/probe', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip is required' });

    const result = await appService.probePrinter(ip);
    if (!result) return res.status(404).json({ error: 'No printer found at that address' });

    res.json(result);
  });

  // Alias: /api/printer/discover → run a quick IPP scan (returns [] on macOS; use /probe for targeted checks)
  router.post('/api/printer/discover', async (req, res) => {
    const printers = await appService.discoverPrintersQuick(req.body?.subnet);
    res.json({ success: true, printers });
  });

  // ── Frontend-compatible routes (called via /api/printer/* gateway prefix) ──

  router.get('/api/printer/printers', async (req, res) => {
    try {
      const printers = await appService.listPrintersFrontend();
      res.json(printers);
    } catch (error) {
      logger.error('List printers (frontend) error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.post('/api/printer/printers', async (req, res) => {
    try {
      const printer = await appService.addPrinterFrontend(req.body);
      res.json(printer);
    } catch (error) {
      if (error instanceof ValidationError) return res.status(400).json({ error: error.message });
      logger.error('Add printer (frontend) error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.delete('/api/printer/printers/:id', async (req, res) => {
    try {
      await appService.removePrinterFrontend(req.params.id);
      res.json({ success: true });
    } catch (error) {
      logger.error('Delete printer (frontend) error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Submit a print job / test page via IPP directly to the printer
  router.post('/api/printer/jobs', async (req, res) => {
    try {
      const result = await appService.submitTestPrintJob(req.body);
      res.json({ success: true, message: result.message });
    } catch (error) {
      if (error instanceof ValidationError) return res.status(400).json({ error: error.message });
      if (error instanceof NotFoundError)   return res.status(404).json({ error: error.message });
      logger.error('Print job error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // GET /api/printer/jobs — return job log for the frontend
  router.get('/api/printer/jobs', (req, res) => {
    const { printer } = req.query;
    res.json({ data: appService.getJobLog(printer) });
  });

  router.get('/api/printers/:id', async (req, res) => {
    try {
      const printer = await appService.getPrinter(req.params.id);
      res.json({ success: true, printer });
    } catch (error) {
      logger.error('Get printer error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.put('/api/printers/:id', async (req, res) => {
    try {
      const printer = await appService.updatePrinter(req.params.id, req.body);
      res.json({ success: true, printer });
    } catch (error) {
      logger.error('Update printer error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.delete('/api/printers/:id', async (req, res) => {
    try {
      await appService.removePrinter(req.params.id);
      res.json({ success: true });
    } catch (error) {
      logger.error('Remove printer error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ── Deployment endpoints ───────────────────────────────────────────────────

  router.post('/api/deployment/generate', async (req, res) => {
    try {
      const { platform, printers, settings } = req.body;
      const config = await appService.generateDeploymentConfig(platform, printers, settings);
      res.json({ success: true, config });
    } catch (error) {
      logger.error('Generate config error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.post('/api/deployment/deploy', async (req, res) => {
    try {
      const { targetDevices, printers, platform } = req.body;
      const result = await appService.deployPrintersConfig(targetDevices, printers, platform);
      res.json({ success: true, result });
    } catch (error) {
      logger.error('Deploy error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ── Print job queue: read/cancel ────────────────────────────────────────────
  // (submitting new jobs — POST /api/print — stays in index.js: it is
  // cross-cut with the permissions/quota slices, out of scope here)

  router.get('/api/jobs', async (req, res) => {
    try {
      const { userId, printerId, status } = req.query;
      const jobs = await appService.listJobs({ userId, printerId, status });
      res.json({ success: true, jobs });
    } catch (error) {
      logger.error('List jobs error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.get('/api/jobs/:id', async (req, res) => {
    try {
      const job = await appService.getJob(req.params.id);
      res.json({ success: true, job });
    } catch (error) {
      logger.error('Get job error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  router.delete('/api/jobs/:id', async (req, res) => {
    try {
      await appService.cancelJob(req.params.id);
      res.json({ success: true });
    } catch (error) {
      logger.error('Cancel job error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  return router;
};
