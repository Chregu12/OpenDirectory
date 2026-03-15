'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');

const ExposureScanner = require('./services/exposureScanner');

/**
 * Security Exposure Scanner Service
 *
 * Express server with REST API and WebSocket support for real-time scan progress.
 * Scans AD/Intune/device configurations for security vulnerabilities and
 * compliance gaps against CIS, NIST, and DISA STIG benchmarks.
 */
class SecurityScannerService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({
      server: this.server,
      path: '/ws/scanner',
    });

    this.port = process.env.SECURITY_SCANNER_PORT || 3040;
    this.activeConnections = new Map();

    // Initialize logger
    this.logger = this._createLogger();

    // Initialize scanner
    this.scanner = new ExposureScanner({ logger: this.logger });

    this._initializeMiddleware();
    this._initializeWebSocket();
    this._initializeRoutes();
    this._initializeScannerEvents();
  }

  // --- Middleware ---

  _initializeMiddleware() {
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
        },
      },
    }));

    this.app.use(cors({
      origin: process.env.CORS_ORIGIN || '*',
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    }));

    this.app.use(compression());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Too many requests, please try again later.' },
    });
    this.app.use('/api/', limiter);

    // Scan endpoint has stricter rate limiting
    const scanLimiter = rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10,
      message: { error: 'Scan rate limit exceeded. Maximum 10 scans per hour.' },
    });
    this.app.use('/api/scanner/scan', scanLimiter);

    // Request ID and logging middleware
    this.app.use((req, res, next) => {
      req.requestId = req.headers['x-request-id'] || uuidv4();
      res.setHeader('X-Request-ID', req.requestId);

      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        this.logger.info(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`, {
          requestId: req.requestId,
          method: req.method,
          url: req.originalUrl,
          status: res.statusCode,
          duration,
        });
      });

      next();
    });
  }

  // --- WebSocket ---

  _initializeWebSocket() {
    this.wss.on('connection', (ws, req) => {
      const connectionId = uuidv4();
      this.activeConnections.set(connectionId, ws);

      this.logger.info(`WebSocket client connected: ${connectionId}`);

      ws.send(JSON.stringify({
        type: 'connected',
        connectionId,
        message: 'Connected to Security Exposure Scanner',
        timestamp: new Date().toISOString(),
      }));

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          this._handleWebSocketMessage(connectionId, ws, message);
        } catch (err) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format. Expected JSON.',
          }));
        }
      });

      ws.on('close', () => {
        this.activeConnections.delete(connectionId);
        this.logger.info(`WebSocket client disconnected: ${connectionId}`);
      });

      ws.on('error', (err) => {
        this.logger.error(`WebSocket error for ${connectionId}:`, err.message);
        this.activeConnections.delete(connectionId);
      });

      // Heartbeat
      ws.isAlive = true;
      ws.on('pong', () => { ws.isAlive = true; });
    });

    // Heartbeat interval
    this.heartbeatInterval = setInterval(() => {
      this.wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);

    this.wss.on('close', () => {
      clearInterval(this.heartbeatInterval);
    });
  }

  _handleWebSocketMessage(connectionId, ws, message) {
    switch (message.type) {
      case 'subscribe':
        // Client subscribes to scan progress updates
        ws.subscribedScans = ws.subscribedScans || new Set();
        if (message.scanId) {
          ws.subscribedScans.add(message.scanId);
          ws.send(JSON.stringify({
            type: 'subscribed',
            scanId: message.scanId,
          }));
        }
        break;

      case 'unsubscribe':
        if (ws.subscribedScans) {
          ws.subscribedScans.delete(message.scanId);
        }
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
        break;

      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: `Unknown message type: ${message.type}`,
        }));
    }
  }

  _broadcastScanEvent(eventType, data) {
    const message = JSON.stringify({
      type: eventType,
      ...data,
      timestamp: new Date().toISOString(),
    });

    this.wss.clients.forEach((ws) => {
      if (ws.readyState !== WebSocket.OPEN) return;

      // Send to all clients if no scan filtering, or to subscribed clients
      if (!data.scanId || !ws.subscribedScans || ws.subscribedScans.size === 0 || ws.subscribedScans.has(data.scanId)) {
        ws.send(message);
      }
    });
  }

  // --- Scanner events ---

  _initializeScannerEvents() {
    this.scanner.on('scanStarted', (data) => {
      this._broadcastScanEvent('scanStarted', data);
    });

    this.scanner.on('scanProgress', (data) => {
      this._broadcastScanEvent('scanProgress', data);
    });

    this.scanner.on('scanCompleted', (data) => {
      this._broadcastScanEvent('scanCompleted', data);
    });

    this.scanner.on('scanFailed', (data) => {
      this._broadcastScanEvent('scanFailed', data);
    });

    this.scanner.on('scanScheduled', (data) => {
      this._broadcastScanEvent('scanScheduled', data);
    });
  }

  // --- Routes ---

  _initializeRoutes() {
    const router = express.Router();

    // POST /api/scanner/scan - Start a new scan
    router.post('/scan', async (req, res) => {
      try {
        const schema = Joi.object({
          scope: Joi.array().items(
            Joi.string().valid('gpo', 'privilege', 'device')
          ).default(['gpo', 'privilege', 'device']),
          targets: Joi.object({
            gpoData: Joi.object().optional(),
            adData: Joi.object().optional(),
            devices: Joi.array().items(Joi.object()).optional(),
          }).default({}),
          benchmarks: Joi.array().items(
            Joi.string().valid('CIS', 'NIST', 'DISA_STIG')
          ).default(['CIS']),
        });

        const { error, value } = schema.validate(req.body);
        if (error) {
          return res.status(400).json({
            error: 'Validation Error',
            details: error.details.map((d) => d.message),
          });
        }

        const result = await this.scanner.startScan(value);

        res.status(202).json({
          success: true,
          message: 'Scan started successfully',
          data: result,
          links: {
            status: `/api/scanner/scan/${result.scanId}`,
            findings: `/api/scanner/findings?scanId=${result.scanId}`,
            ws: `ws://localhost:${this.port}/ws/scanner`,
          },
        });
      } catch (err) {
        this.logger.error('Error starting scan:', err);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to start scan',
        });
      }
    });

    // GET /api/scanner/scan/:scanId - Get scan status/results
    router.get('/scan/:scanId', (req, res) => {
      try {
        const scan = this.scanner.getScan(req.params.scanId);
        if (!scan) {
          return res.status(404).json({
            error: 'Not Found',
            message: `Scan ${req.params.scanId} not found`,
          });
        }

        res.json({
          success: true,
          data: scan,
          links: {
            findings: `/api/scanner/findings?scanId=${req.params.scanId}`,
            riskScore: '/api/scanner/risk-score',
          },
        });
      } catch (err) {
        this.logger.error('Error getting scan:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/findings - List all findings with filtering
    router.get('/findings', (req, res) => {
      try {
        const filters = {
          scanId: req.query.scanId,
          severity: req.query.severity ? req.query.severity.split(',') : undefined,
          category: req.query.category,
          subcategory: req.query.subcategory,
          benchmark: req.query.benchmark,
          status: req.query.status,
          deviceId: req.query.deviceId,
          search: req.query.search,
          sortBy: req.query.sortBy,
          sortOrder: req.query.sortOrder,
          page: req.query.page ? parseInt(req.query.page, 10) : 1,
          pageSize: req.query.pageSize ? Math.min(parseInt(req.query.pageSize, 10), 100) : 50,
        };

        const result = this.scanner.getFindings(filters);

        res.json({
          success: true,
          data: result.findings,
          pagination: result.pagination,
        });
      } catch (err) {
        this.logger.error('Error getting findings:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/findings/:findingId - Get specific finding with remediation
    router.get('/findings/:findingId', (req, res) => {
      try {
        const finding = this.scanner.getFinding(req.params.findingId);
        if (!finding) {
          return res.status(404).json({
            error: 'Not Found',
            message: `Finding ${req.params.findingId} not found`,
          });
        }

        res.json({
          success: true,
          data: finding,
        });
      } catch (err) {
        this.logger.error('Error getting finding:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/risk-score - Overall risk score
    router.get('/risk-score', (req, res) => {
      try {
        const riskScore = this.scanner.getOverallRiskScore();

        res.json({
          success: true,
          data: riskScore,
        });
      } catch (err) {
        this.logger.error('Error getting risk score:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/risk-score/:entityType/:entityId - Risk score for entity
    router.get('/risk-score/:entityType/:entityId', (req, res) => {
      try {
        const validTypes = ['device', 'user', 'group', 'gpo'];
        if (!validTypes.includes(req.params.entityType)) {
          return res.status(400).json({
            error: 'Validation Error',
            message: `Invalid entity type. Must be one of: ${validTypes.join(', ')}`,
          });
        }

        const riskScore = this.scanner.getEntityRiskScore(
          req.params.entityType,
          req.params.entityId
        );

        res.json({
          success: true,
          data: riskScore,
        });
      } catch (err) {
        this.logger.error('Error getting entity risk score:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/benchmarks - Available compliance benchmarks
    router.get('/benchmarks', (req, res) => {
      try {
        const benchmarks = this.scanner.getBenchmarks();

        res.json({
          success: true,
          data: benchmarks,
        });
      } catch (err) {
        this.logger.error('Error getting benchmarks:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/trends - Risk trends over time
    router.get('/trends', (req, res) => {
      try {
        const days = req.query.days ? parseInt(req.query.days, 10) : 30;

        if (days < 1 || days > 365) {
          return res.status(400).json({
            error: 'Validation Error',
            message: 'Days parameter must be between 1 and 365.',
          });
        }

        const trends = this.scanner.getTrends({ days });

        res.json({
          success: true,
          data: trends,
        });
      } catch (err) {
        this.logger.error('Error getting trends:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // POST /api/scanner/schedule - Schedule recurring scan
    router.post('/schedule', (req, res) => {
      try {
        const schema = Joi.object({
          name: Joi.string().max(255).optional(),
          cronExpression: Joi.string().required(),
          scope: Joi.array().items(
            Joi.string().valid('gpo', 'privilege', 'device')
          ).default(['gpo', 'privilege', 'device']),
          benchmarks: Joi.array().items(
            Joi.string().valid('CIS', 'NIST', 'DISA_STIG')
          ).default(['CIS']),
          enabled: Joi.boolean().default(true),
        });

        const { error, value } = schema.validate(req.body);
        if (error) {
          return res.status(400).json({
            error: 'Validation Error',
            details: error.details.map((d) => d.message),
          });
        }

        const schedule = this.scanner.scheduleScan(value);

        res.status(201).json({
          success: true,
          message: 'Scan scheduled successfully',
          data: schedule,
        });
      } catch (err) {
        if (err.message.includes('Invalid cron expression')) {
          return res.status(400).json({
            error: 'Validation Error',
            message: err.message,
          });
        }
        this.logger.error('Error scheduling scan:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // GET /api/scanner/schedules - List all schedules
    router.get('/schedules', (req, res) => {
      try {
        const schedules = this.scanner.getSchedules();

        res.json({
          success: true,
          data: schedules,
        });
      } catch (err) {
        this.logger.error('Error getting schedules:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // DELETE /api/scanner/schedules/:scheduleId - Delete a schedule
    router.delete('/schedules/:scheduleId', (req, res) => {
      try {
        const deleted = this.scanner.deleteSchedule(req.params.scheduleId);
        if (!deleted) {
          return res.status(404).json({
            error: 'Not Found',
            message: `Schedule ${req.params.scheduleId} not found`,
          });
        }

        res.json({
          success: true,
          message: 'Schedule deleted successfully',
        });
      } catch (err) {
        this.logger.error('Error deleting schedule:', err);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // Mount router
    this.app.use('/api/scanner', router);

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      const uptime = process.uptime();
      const memUsage = process.memoryUsage();

      res.json({
        status: 'healthy',
        service: 'security-exposure-scanner',
        version: '1.0.0',
        uptime: {
          seconds: Math.floor(uptime),
          formatted: this._formatUptime(uptime),
        },
        memory: {
          rss: this._formatBytes(memUsage.rss),
          heapUsed: this._formatBytes(memUsage.heapUsed),
          heapTotal: this._formatBytes(memUsage.heapTotal),
        },
        connections: {
          websocket: this.activeConnections.size,
        },
        scans: {
          active: Array.from(this.scanner.scans.values()).filter((s) => s.status === 'running').length,
          completed: Array.from(this.scanner.scans.values()).filter((s) => s.status === 'completed').length,
          scheduled: this.scanner.getSchedules().length,
        },
        findings: {
          total: this.scanner.findings.size,
        },
        timestamp: new Date().toISOString(),
      });
    });

    // 404 handler
    this.app.use((req, res) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.method} ${req.originalUrl} not found`,
        availableEndpoints: [
          'POST   /api/scanner/scan',
          'GET    /api/scanner/scan/:scanId',
          'GET    /api/scanner/findings',
          'GET    /api/scanner/findings/:findingId',
          'GET    /api/scanner/risk-score',
          'GET    /api/scanner/risk-score/:entityType/:entityId',
          'GET    /api/scanner/benchmarks',
          'GET    /api/scanner/trends',
          'POST   /api/scanner/schedule',
          'GET    /api/scanner/schedules',
          'DELETE /api/scanner/schedules/:scheduleId',
          'GET    /health',
          'WS     /ws/scanner',
        ],
      });
    });

    // Error handler
    this.app.use((err, req, res, _next) => {
      this.logger.error('Unhandled error:', err);
      res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
        requestId: req.requestId,
      });
    });
  }

  // --- Logger ---

  _createLogger() {
    const levels = { error: 0, warn: 1, info: 2, debug: 3 };
    const currentLevel = levels[process.env.LOG_LEVEL || 'info'] || 2;

    const log = (level, message, meta = {}) => {
      if (levels[level] > currentLevel) return;
      const timestamp = new Date().toISOString();
      const metaStr = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
      const output = `[${timestamp}] [${level.toUpperCase()}] [security-scanner] ${message}${metaStr}`;

      if (level === 'error') {
        process.stderr.write(output + '\n');
      } else {
        process.stdout.write(output + '\n');
      }
    };

    return {
      error: (msg, ...args) => log('error', msg, args[0]),
      warn: (msg, ...args) => log('warn', msg, args[0]),
      info: (msg, ...args) => log('info', msg, args[0]),
      debug: (msg, ...args) => log('debug', msg, args[0]),
    };
  }

  // --- Utility ---

  _formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(' ');
  }

  _formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  }

  // --- Start / Stop ---

  start() {
    return new Promise((resolve) => {
      this.server.listen(this.port, () => {
        this.logger.info(`Security Exposure Scanner started on port ${this.port}`);
        this.logger.info(`REST API: http://localhost:${this.port}/api/scanner`);
        this.logger.info(`WebSocket: ws://localhost:${this.port}/ws/scanner`);
        this.logger.info(`Health:    http://localhost:${this.port}/health`);
        resolve(this.server);
      });
    });
  }

  async stop() {
    this.logger.info('Shutting down Security Exposure Scanner...');

    // Stop scheduled scans
    this.scanner.shutdown();

    // Close WebSocket connections
    this.wss.clients.forEach((ws) => {
      ws.send(JSON.stringify({ type: 'shutdown', message: 'Server shutting down' }));
      ws.close();
    });

    clearInterval(this.heartbeatInterval);

    return new Promise((resolve) => {
      this.server.close(() => {
        this.logger.info('Security Exposure Scanner stopped');
        resolve();
      });
    });
  }
}

// --- Entry point ---

const service = new SecurityScannerService();

service.start().catch((err) => {
  console.error('Failed to start Security Exposure Scanner:', err);
  process.exit(1);
});

// Graceful shutdown
const shutdown = async (signal) => {
  console.log(`\nReceived ${signal}. Graceful shutdown...`);
  await service.stop();
  process.exit(0);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

module.exports = SecurityScannerService;
