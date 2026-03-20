'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { EventEmitter } = require('events');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const WebSocket = require('ws');

// ====================================================================== //
//  Logger setup
// ====================================================================== //

const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ' ' + JSON.stringify(meta);
    }
    return msg;
  })
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'security-scanner', version: '1.0.0' },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 20 * 1024 * 1024,
      maxFiles: 14,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 20 * 1024 * 1024,
      maxFiles: 30,
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat,
    level: process.env.LOG_LEVEL || 'debug',
  }));
}

// ====================================================================== //
//  Import services
// ====================================================================== //

const GPOAnalyzer = require('./services/gpoAnalyzer');
const PrivilegeAuditor = require('./services/privilegeAuditor');
const DeviceSecurityAnalyzer = require('./services/deviceSecurityAnalyzer');

// ====================================================================== //
//  ExposureScanner - inline orchestrator that coordinates all analyzers
// ====================================================================== //

class ExposureScanner extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logger = options.logger || console;
    this.gpoAnalyzer = options.gpoAnalyzer;
    this.privilegeAuditor = options.privilegeAuditor;
    this.deviceSecurityAnalyzer = options.deviceSecurityAnalyzer;

    // In-memory stores
    this.scans = new Map();
    this.findings = new Map();
    this.schedules = new Map();
    this.trends = [];
  }

  /**
   * Start a new security scan.
   */
  async startScan(params) {
    const scanId = uuidv4();
    const scan = {
      id: scanId,
      status: 'running',
      type: params.type || 'full',
      targets: params.targets || [],
      benchmarks: params.benchmarks || ['CIS'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      progress: 0,
      message: 'Initializing scan...',
      results: null,
      error: null,
    };

    this.scans.set(scanId, scan);
    this.emit('scanStarted', { scanId });

    // Run asynchronously so the HTTP response returns immediately
    this._executeScan(scanId, params).catch((err) => {
      this.logger.error(`Scan ${scanId} failed: ${err.message}`);
      scan.status = 'failed';
      scan.error = err.message;
      scan.updatedAt = new Date().toISOString();
      this.emit('scanFailed', { scanId, error: err.message });
    });

    return { scanId, status: scan.status, createdAt: scan.createdAt };
  }

  async _executeScan(scanId, params) {
    const scan = this.scans.get(scanId);
    if (!scan) return;

    const allFindings = [];
    const phases = [];

    if (!params.type || params.type === 'full' || params.type === 'gpo') {
      phases.push({ name: 'GPO Analysis', weight: 30, run: () => this._runGPOAnalysis(params) });
    }
    if (!params.type || params.type === 'full' || params.type === 'privilege') {
      phases.push({ name: 'Privilege Audit', weight: 30, run: () => this._runPrivilegeAudit(params) });
    }
    if (!params.type || params.type === 'full' || params.type === 'device') {
      phases.push({ name: 'Device Security', weight: 40, run: () => this._runDeviceAnalysis(params) });
    }

    let completedWeight = 0;

    for (const phase of phases) {
      scan.message = `Running ${phase.name}...`;
      scan.updatedAt = new Date().toISOString();
      this.emit('scanProgress', { scanId, progress: completedWeight, message: scan.message });

      try {
        const phaseResult = await phase.run();
        if (phaseResult && phaseResult.findings) {
          allFindings.push(...phaseResult.findings);
        }
      } catch (err) {
        this.logger.error(`Phase ${phase.name} failed: ${err.message}`);
      }

      completedWeight += phase.weight;
      scan.progress = completedWeight;
    }

    // Store findings
    for (const finding of allFindings) {
      this.findings.set(finding.id, finding);
    }

    // Finalise scan
    scan.status = 'completed';
    scan.progress = 100;
    scan.message = 'Scan complete';
    scan.updatedAt = new Date().toISOString();
    scan.results = {
      totalFindings: allFindings.length,
      findingIds: allFindings.map((f) => f.id),
      bySeverity: this._countBySeverity(allFindings),
      riskScore: this._computeOverallRiskScore(allFindings),
    };

    // Record trend data-point
    this.trends.push({
      timestamp: new Date().toISOString(),
      scanId,
      riskScore: scan.results.riskScore,
      totalFindings: allFindings.length,
      bySeverity: { ...scan.results.bySeverity },
    });

    this.emit('scanCompleted', { scanId, results: scan.results });
  }

  async _runGPOAnalysis(params) {
    const gpoData = params.gpoData || params.data || {};
    return this.gpoAnalyzer.analyze(gpoData.gpos || [], params.benchmarks || ['CIS']);
  }

  async _runPrivilegeAudit(params) {
    const adData = params.adData || params.data || {};
    return this.privilegeAuditor.audit(adData);
  }

  async _runDeviceAnalysis(params) {
    const devices = params.devices || (params.data && params.data.devices) || [];
    if (devices.length === 0) return { findings: [] };
    return this.deviceSecurityAnalyzer.analyzeFleet(devices, params.benchmarks || ['CIS']);
  }

  getScan(scanId) {
    return this.scans.get(scanId) || null;
  }

  getFindings(filters = {}) {
    let results = Array.from(this.findings.values());

    if (filters.severity) {
      const sevArr = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
      results = results.filter((f) => sevArr.includes(f.severity));
    }
    if (filters.category) {
      results = results.filter((f) => f.category === filters.category);
    }
    if (filters.status) {
      results = results.filter((f) => f.status === filters.status);
    }
    if (filters.scanId) {
      const scan = this.scans.get(filters.scanId);
      if (scan && scan.results) {
        const ids = new Set(scan.results.findingIds);
        results = results.filter((f) => ids.has(f.id));
      }
    }

    // Sort by severity weight descending
    const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    results.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));

    const limit = filters.limit || 100;
    const offset = filters.offset || 0;
    return {
      total: results.length,
      offset,
      limit,
      findings: results.slice(offset, offset + limit),
    };
  }

  getFinding(findingId) {
    return this.findings.get(findingId) || null;
  }

  getOverallRiskScore() {
    const allFindings = Array.from(this.findings.values()).filter((f) => f.status === 'open');
    return {
      riskScore: this._computeOverallRiskScore(allFindings),
      totalOpenFindings: allFindings.length,
      bySeverity: this._countBySeverity(allFindings),
      timestamp: new Date().toISOString(),
    };
  }

  getEntityRiskScore(entityType, entityId) {
    const allFindings = Array.from(this.findings.values());
    const entityFindings = allFindings.filter((f) =>
      (f.affectedObjects || []).some((obj) => {
        const objType = (obj.type || '').toLowerCase();
        const objName = (obj.name || obj.id || '').toLowerCase();
        return objType === entityType.toLowerCase() && objName === entityId.toLowerCase();
      })
    );

    return {
      entityType,
      entityId,
      riskScore: this._computeOverallRiskScore(entityFindings),
      totalFindings: entityFindings.length,
      bySeverity: this._countBySeverity(entityFindings),
      findings: entityFindings.map((f) => ({ id: f.id, title: f.title, severity: f.severity })),
      timestamp: new Date().toISOString(),
    };
  }

  getBenchmarks() {
    return [
      { id: 'CIS', name: 'CIS Benchmarks', version: '3.0', description: 'Center for Internet Security best practices' },
      { id: 'NIST', name: 'NIST SP 800-53', version: 'Rev 5', description: 'NIST security and privacy controls' },
      { id: 'STIG', name: 'DISA STIG', version: '2024Q4', description: 'Security Technical Implementation Guides' },
    ];
  }

  getTrends(filters = {}) {
    let data = [...this.trends];

    if (filters.from) {
      const from = new Date(filters.from);
      data = data.filter((t) => new Date(t.timestamp) >= from);
    }
    if (filters.to) {
      const to = new Date(filters.to);
      data = data.filter((t) => new Date(t.timestamp) <= to);
    }
    if (filters.days) {
      const cutoff = new Date(Date.now() - filters.days * 24 * 60 * 60 * 1000);
      data = data.filter((t) => new Date(t.timestamp) >= cutoff);
    }

    return {
      dataPoints: data,
      total: data.length,
      timestamp: new Date().toISOString(),
    };
  }

  scheduleScan(params) {
    const scheduleId = uuidv4();
    const schedule = {
      id: scheduleId,
      name: params.name || `Schedule ${scheduleId.slice(0, 8)}`,
      cron: params.cron || params.cronExpression || '0 2 * * 0',
      type: params.type || 'full',
      benchmarks: params.benchmarks || ['CIS'],
      scope: params.scope || ['gpo', 'privilege', 'device'],
      targets: params.targets || [],
      enabled: params.enabled !== undefined ? params.enabled : true,
      createdAt: new Date().toISOString(),
      nextRun: params.nextRun || null,
    };

    this.schedules.set(scheduleId, schedule);
    this.logger.info(`Scan scheduled: ${scheduleId} with cron "${schedule.cron}"`);
    this.emit('scanScheduled', { scheduleId, schedule });

    return schedule;
  }

  getSchedules() {
    return Array.from(this.schedules.values());
  }

  deleteSchedule(scheduleId) {
    return this.schedules.delete(scheduleId);
  }

  shutdown() {
    this.schedules.clear();
  }

  _countBySeverity(findings) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    return counts;
  }

  _computeOverallRiskScore(findings) {
    if (findings.length === 0) return 0;
    const severityScores = { Critical: 10, High: 8, Medium: 5, Low: 2 };
    const total = findings.reduce((sum, f) => sum + (severityScores[f.severity] || 5), 0);
    const maxPossible = findings.length * 10;
    return Math.min(100, Math.round((total / maxPossible) * 100));
  }
}

// ====================================================================== //
//  Validation schemas
// ====================================================================== //

const schemas = {
  startScan: Joi.object({
    type: Joi.string().valid('full', 'gpo', 'privilege', 'device').optional(),
    targets: Joi.array().items(Joi.string()).optional(),
    benchmarks: Joi.array().items(Joi.string().valid('CIS', 'NIST', 'STIG')).optional(),
    data: Joi.object().optional(),
    gpoData: Joi.object().optional(),
    adData: Joi.object().optional(),
    devices: Joi.array().items(Joi.object()).optional(),
    scope: Joi.array().items(Joi.string().valid('gpo', 'privilege', 'device')).optional(),
  }),
  scheduleScan: Joi.object({
    name: Joi.string().max(255).optional(),
    cron: Joi.string().optional(),
    cronExpression: Joi.string().optional(),
    type: Joi.string().valid('full', 'gpo', 'privilege', 'device').optional(),
    benchmarks: Joi.array().items(Joi.string().valid('CIS', 'NIST', 'STIG')).optional(),
    scope: Joi.array().items(Joi.string().valid('gpo', 'privilege', 'device')).optional(),
    targets: Joi.array().items(Joi.string()).optional(),
    enabled: Joi.boolean().optional(),
    nextRun: Joi.string().isoDate().optional(),
  }),
};

// ====================================================================== //
//  SecurityScannerService
// ====================================================================== //

class SecurityScannerService extends EventEmitter {
  constructor() {
    super();
    this.app = express();
    this.server = null;
    this.wss = null;

    // Initialise analysers
    this.gpoAnalyzer = new GPOAnalyzer({ logger });
    this.privilegeAuditor = new PrivilegeAuditor({ logger });
    this.deviceSecurityAnalyzer = new DeviceSecurityAnalyzer({ logger });

    // Orchestrator
    this.scanner = new ExposureScanner({
      logger,
      gpoAnalyzer: this.gpoAnalyzer,
      privilegeAuditor: this.privilegeAuditor,
      deviceSecurityAnalyzer: this.deviceSecurityAnalyzer,
    });

    this._initializeMiddleware();
    this._initializeRoutes();
    this._initializeErrorHandling();
  }

  // ------------------------------------------------------------------ //
  //  Middleware
  // ------------------------------------------------------------------ //

  _initializeMiddleware() {
    logger.info('Setting up middleware...');

    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    }));

    this.app.use(cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        const allowed = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',');
        if (allowed.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID'],
    }));

    this.app.use(compression());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Rate limiting on API routes
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 1000,
      message: {
        error: 'Too many requests from this IP, please try again later',
        retryAfter: '15 minutes',
      },
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => req.path === '/health' || req.path === '/metrics',
    });
    this.app.use('/api', limiter);

    // Stricter rate limit for scan endpoint
    const scanLimiter = rateLimit({
      windowMs: 60 * 60 * 1000,
      max: 20,
      message: { error: 'Scan rate limit exceeded. Maximum 20 scans per hour.' },
    });
    this.app.use('/api/scanner/scan', scanLimiter);

    // Request logging
    this.app.use((req, res, next) => {
      req.requestId = req.headers['x-request-id'] || uuidv4();
      res.setHeader('X-Request-ID', req.requestId);

      const start = Date.now();
      res.on('finish', () => {
        logger.info(`${req.method} ${req.originalUrl}`, {
          statusCode: res.statusCode,
          durationMs: Date.now() - start,
          ip: req.ip,
          requestId: req.requestId,
        });
      });
      next();
    });

    logger.info('Middleware setup completed');
  }

  // ------------------------------------------------------------------ //
  //  Routes
  // ------------------------------------------------------------------ //

  _initializeRoutes() {
    logger.info('Setting up routes...');

    // ---- Health ----

    this.app.get('/health', (_req, res) => {
      const uptime = process.uptime();
      const memUsage = process.memoryUsage();

      res.json({
        status: 'healthy',
        service: 'security-exposure-scanner',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        services: {
          gpoAnalyzer: 'operational',
          privilegeAuditor: 'operational',
          deviceSecurityAnalyzer: 'operational',
          exposureScanner: 'operational',
        },
        uptime: {
          seconds: Math.floor(uptime),
          formatted: this._formatUptime(uptime),
        },
        memory: {
          rss: this._formatBytes(memUsage.rss),
          heapUsed: this._formatBytes(memUsage.heapUsed),
          heapTotal: this._formatBytes(memUsage.heapTotal),
        },
        scans: {
          active: Array.from(this.scanner.scans.values()).filter((s) => s.status === 'running').length,
          completed: Array.from(this.scanner.scans.values()).filter((s) => s.status === 'completed').length,
        },
        findings: {
          total: this.scanner.findings.size,
        },
      });
    });

    // ---- Scanner API ----

    const router = express.Router();

    // POST /api/scanner/scan - Start a new scan
    router.post('/scan', async (req, res, next) => {
      try {
        const { error, value } = schemas.startScan.validate(req.body);
        if (error) {
          return res.status(400).json({
            error: 'Validation error',
            details: error.details.map((d) => d.message),
            timestamp: new Date().toISOString(),
          });
        }

        const result = await this.scanner.startScan(value);

        res.status(202).json({
          message: 'Scan started',
          ...result,
          links: {
            status: `/api/scanner/scan/${result.scanId}`,
            findings: `/api/scanner/findings?scanId=${result.scanId}`,
            ws: `ws://localhost:${this.port}/ws`,
          },
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/scan/:scanId - Get scan status / results
    router.get('/scan/:scanId', (req, res, next) => {
      try {
        const scan = this.scanner.getScan(req.params.scanId);
        if (!scan) {
          return res.status(404).json({
            error: 'Scan not found',
            scanId: req.params.scanId,
            timestamp: new Date().toISOString(),
          });
        }
        res.json({ success: true, data: scan });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/findings - List findings
    router.get('/findings', (req, res, next) => {
      try {
        const filters = {
          severity: req.query.severity ? req.query.severity.split(',') : null,
          category: req.query.category || null,
          status: req.query.status || null,
          scanId: req.query.scanId || null,
          limit: req.query.limit ? parseInt(req.query.limit, 10) : 100,
          offset: req.query.offset ? parseInt(req.query.offset, 10) : 0,
        };
        const result = this.scanner.getFindings(filters);
        res.json({ success: true, ...result });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/findings/:findingId - Finding detail
    router.get('/findings/:findingId', (req, res, next) => {
      try {
        const finding = this.scanner.getFinding(req.params.findingId);
        if (!finding) {
          return res.status(404).json({
            error: 'Finding not found',
            findingId: req.params.findingId,
            timestamp: new Date().toISOString(),
          });
        }
        res.json({ success: true, data: finding });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/risk-score - Overall risk score
    router.get('/risk-score', (_req, res, next) => {
      try {
        const score = this.scanner.getOverallRiskScore();
        res.json({ success: true, data: score });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/risk-score/:entityType/:entityId - Entity risk score
    router.get('/risk-score/:entityType/:entityId', (req, res, next) => {
      try {
        const validTypes = ['device', 'user', 'group', 'gpo', 'service-account', 'principal'];
        if (!validTypes.includes(req.params.entityType)) {
          return res.status(400).json({
            error: 'Validation error',
            message: `Invalid entity type. Must be one of: ${validTypes.join(', ')}`,
            timestamp: new Date().toISOString(),
          });
        }

        const score = this.scanner.getEntityRiskScore(
          req.params.entityType,
          req.params.entityId
        );
        res.json({ success: true, data: score });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/benchmarks - Available benchmarks
    router.get('/benchmarks', (_req, res, next) => {
      try {
        const benchmarks = this.scanner.getBenchmarks();
        res.json({ success: true, data: benchmarks, timestamp: new Date().toISOString() });
      } catch (err) {
        next(err);
      }
    });

    // GET /api/scanner/trends - Risk trends over time
    router.get('/trends', (req, res, next) => {
      try {
        const filters = {
          from: req.query.from || null,
          to: req.query.to || null,
          days: req.query.days ? parseInt(req.query.days, 10) : null,
        };
        const trends = this.scanner.getTrends(filters);
        res.json({ success: true, data: trends });
      } catch (err) {
        next(err);
      }
    });

    // POST /api/scanner/schedule - Schedule a recurring scan
    router.post('/schedule', (req, res, next) => {
      try {
        const { error, value } = schemas.scheduleScan.validate(req.body);
        if (error) {
          return res.status(400).json({
            error: 'Validation error',
            details: error.details.map((d) => d.message),
            timestamp: new Date().toISOString(),
          });
        }

        const schedule = this.scanner.scheduleScan(value);

        res.status(201).json({
          message: 'Scan scheduled',
          success: true,
          data: schedule,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    });

    this.app.use('/api/scanner', router);

    logger.info('Routes setup completed');
  }

  // ------------------------------------------------------------------ //
  //  Error handling
  // ------------------------------------------------------------------ //

  _initializeErrorHandling() {
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Endpoint not found',
        message: `The requested endpoint ${req.method} ${req.originalUrl} was not found`,
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
          'GET    /health',
          'WS     /ws',
        ],
        timestamp: new Date().toISOString(),
      });
    });

    // Global error handler
    this.app.use((err, _req, res, _next) => {
      const statusCode = err.statusCode || 500;
      const isDev = process.env.NODE_ENV === 'development';

      if (statusCode >= 500) {
        logger.error('Unhandled error', { message: err.message, stack: err.stack });
      } else {
        logger.warn('Client error', { statusCode, message: err.message });
      }

      res.status(statusCode).json({
        error: statusCode >= 500 && !isDev ? 'Internal server error' : err.message,
        ...(isDev && { stack: err.stack }),
        timestamp: new Date().toISOString(),
      });
    });

    // Process-level handlers
    process.on('uncaughtException', (err) => {
      logger.error('Uncaught Exception', { message: err.message, stack: err.stack });
      process.exit(1);
    });

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled Rejection', { reason: String(reason) });
    });

    logger.info('Error handling setup completed');
  }

  // ------------------------------------------------------------------ //
  //  WebSocket for scan progress
  // ------------------------------------------------------------------ //

  _initializeWebSocket(server) {
    this.wss = new WebSocket.Server({ server, path: '/ws' });
    this.activeConnections = new Map();

    this.wss.on('connection', (ws) => {
      const connectionId = uuidv4();
      this.activeConnections.set(connectionId, ws);
      logger.info(`WebSocket client connected: ${connectionId}`);

      ws.send(JSON.stringify({
        type: 'connected',
        connectionId,
        message: 'Connected to Security Scanner WebSocket',
        timestamp: new Date().toISOString(),
      }));

      ws.isAlive = true;
      ws.subscribedScans = new Set();

      ws.on('pong', () => { ws.isAlive = true; });

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          this._handleWebSocketMessage(connectionId, ws, message);
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format. Expected JSON.' }));
        }
      });

      ws.on('close', () => {
        this.activeConnections.delete(connectionId);
        logger.info(`WebSocket client disconnected: ${connectionId}`);
      });

      ws.on('error', (err) => {
        logger.error(`WebSocket error for ${connectionId}: ${err.message}`);
        this.activeConnections.delete(connectionId);
      });
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

    // Wire scanner events to WebSocket broadcast
    const broadcast = (eventType, data) => {
      const message = JSON.stringify({ type: eventType, ...data, timestamp: new Date().toISOString() });
      this.wss.clients.forEach((client) => {
        if (client.readyState !== WebSocket.OPEN) return;
        // Send to all clients, or only subscribed clients if they have subscriptions
        if (!data.scanId || !client.subscribedScans || client.subscribedScans.size === 0 || client.subscribedScans.has(data.scanId)) {
          client.send(message);
        }
      });
    };

    this.scanner.on('scanStarted', (data) => broadcast('scanStarted', data));
    this.scanner.on('scanProgress', (data) => broadcast('scanProgress', data));
    this.scanner.on('scanCompleted', (data) => broadcast('scanCompleted', data));
    this.scanner.on('scanFailed', (data) => broadcast('scanFailed', data));
    this.scanner.on('scanScheduled', (data) => broadcast('scanScheduled', data));

    logger.info('WebSocket server initialized on /ws');
  }

  _handleWebSocketMessage(connectionId, ws, message) {
    switch (message.type) {
      case 'subscribe':
        if (message.scanId) {
          ws.subscribedScans.add(message.scanId);
          ws.send(JSON.stringify({ type: 'subscribed', scanId: message.scanId }));
        }
        break;

      case 'unsubscribe':
        if (message.scanId) {
          ws.subscribedScans.delete(message.scanId);
          ws.send(JSON.stringify({ type: 'unsubscribed', scanId: message.scanId }));
        }
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
        break;

      default:
        ws.send(JSON.stringify({ type: 'error', message: `Unknown message type: ${message.type}` }));
    }
  }

  // ------------------------------------------------------------------ //
  //  Utility
  // ------------------------------------------------------------------ //

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

  // ------------------------------------------------------------------ //
  //  Lifecycle
  // ------------------------------------------------------------------ //

  async start() {
    this.port = parseInt(process.env.PORT, 10) || 3902;
    const host = process.env.HOST || '0.0.0.0';

    return new Promise((resolve, reject) => {
      this.server = http.createServer(this.app);

      // Attach WebSocket server
      this._initializeWebSocket(this.server);

      this.server.listen(this.port, host, () => {
        logger.info(`OpenDirectory Security Scanner Service started on ${host}:${this.port}`);
        logger.info(`Health check: http://${host}:${this.port}/health`);
        logger.info(`API base:     http://${host}:${this.port}/api/scanner`);
        logger.info(`WebSocket:    ws://${host}:${this.port}/ws`);
        this.emit('started');
        resolve(this.server);
      });

      this.server.on('error', (err) => {
        logger.error('Server error', { message: err.message });
        this.emit('error', err);
        reject(err);
      });

      // Graceful shutdown
      const shutdown = (signal) => {
        logger.info(`Received ${signal}, shutting down...`);

        // Stop scheduled scans
        this.scanner.shutdown();

        // Close WebSocket connections
        if (this.wss) {
          this.wss.clients.forEach((client) => {
            client.send(JSON.stringify({ type: 'shutdown', message: 'Server shutting down' }));
            client.close(1001, 'Server shutting down');
          });
          clearInterval(this.heartbeatInterval);
          this.wss.close();
        }

        this.server.close(() => {
          logger.info('Graceful shutdown completed');
          process.exit(0);
        });

        // Force exit after 10 seconds
        setTimeout(() => {
          logger.error('Forced shutdown after timeout');
          process.exit(1);
        }, 10000);
      };

      process.on('SIGTERM', () => shutdown('SIGTERM'));
      process.on('SIGINT', () => shutdown('SIGINT'));
    });
  }

  async stop() {
    logger.info('Shutting down Security Scanner...');
    this.scanner.shutdown();

    if (this.wss) {
      this.wss.clients.forEach((client) => {
        client.send(JSON.stringify({ type: 'shutdown', message: 'Server shutting down' }));
        client.close();
      });
      clearInterval(this.heartbeatInterval);
    }

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Security Scanner stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

// ====================================================================== //
//  Export & auto-start
// ====================================================================== //

module.exports = SecurityScannerService;

if (require.main === module) {
  const service = new SecurityScannerService();
  service.start().catch((err) => {
    logger.error('Failed to start Security Scanner Service', { message: err.message });
    process.exit(1);
  });
}
