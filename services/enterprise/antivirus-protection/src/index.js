'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { EventEmitter } = require('events');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');
const Joi = require('joi');
const http = require('http');
const { WebSocketServer } = require('ws');

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
    defaultMeta: { service: 'antivirus-protection', version: '1.0.0' },
    transports: [
        new DailyRotateFile({
            filename: path.join(logsDir, 'error-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            maxSize: '20m',
            maxFiles: '14d',
            zippedArchive: true,
        }),
        new DailyRotateFile({
            filename: path.join(logsDir, 'combined-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            zippedArchive: true,
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

const ScanOrchestrator = require('./services/scanOrchestrator');
const SignatureManager = require('./services/signatureManager');
const QuarantineManager = require('./services/quarantineManager');
const ThreatIntelligence = require('./services/threatIntelligence');

// ====================================================================== //
//  Validation schemas
// ====================================================================== //

const schemas = {
    initiateScan: Joi.object({
        deviceIds: Joi.array().items(Joi.string()).optional(),
        scanType: Joi.string().valid('quick', 'full', 'custom', 'memory').default('quick'),
        paths: Joi.array().items(Joi.string()).when('scanType', {
            is: 'custom',
            then: Joi.required(),
            otherwise: Joi.optional(),
        }),
    }),
    schedule: Joi.object({
        name: Joi.string().min(3).max(200).required(),
        scanType: Joi.string().valid('quick', 'full', 'custom', 'memory').default('quick'),
        cronExpression: Joi.string().required(),
        deviceSelector: Joi.object({
            all: Joi.boolean(),
            deviceIds: Joi.array().items(Joi.string()),
            department: Joi.string(),
            platform: Joi.string(),
        }).optional(),
        paths: Joi.array().items(Joi.string()).optional(),
        enabled: Joi.boolean().default(true),
        createdBy: Joi.string().optional(),
    }),
    signatureUpdate: Joi.object({
        deviceIds: Joi.array().items(Joi.string()).optional(),
    }),
};

// ====================================================================== //
//  AntivirusProtectionService
// ====================================================================== //

class AntivirusProtectionService extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = null;
        this.wss = null;

        // Initialise core services
        this.scanOrchestrator = new ScanOrchestrator(logger);
        this.signatureManager = new SignatureManager(this.scanOrchestrator, logger);
        this.quarantineManager = new QuarantineManager(this.scanOrchestrator, logger);
        this.threatIntelligence = new ThreatIntelligence(this.scanOrchestrator, logger);

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

        // Request logging
        this.app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                logger.info(`${req.method} ${req.originalUrl}`, {
                    statusCode: res.statusCode,
                    durationMs: Date.now() - start,
                    ip: req.ip,
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

        // ---- Health & info ----

        this.app.get('/health', (_req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: '1.0.0',
                services: {
                    scanOrchestrator: 'operational',
                    signatureManager: 'operational',
                    quarantineManager: 'operational',
                    threatIntelligence: 'operational',
                },
                uptime: process.uptime(),
            });
        });

        this.app.get('/metrics', (_req, res) => {
            res.json({
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
            });
        });

        this.app.get('/', (_req, res) => {
            res.json({
                name: 'OpenDirectory Antivirus Protection Service',
                version: '1.0.0',
                description: 'ClamAV antivirus scanning orchestration across managed devices for the OpenDirectory UEM platform',
                features: [
                    'Fleet-wide ClamAV scan orchestration',
                    'Real-time scan progress via WebSocket',
                    'Signature/definition management and distribution',
                    'Quarantine management with file hash correlation',
                    'Threat intelligence aggregation and IoC tracking',
                    'Scheduled scans with cron expressions',
                    'Dashboard and statistics',
                ],
                api: {
                    baseUrl: '/api/antivirus',
                    documentation: '/api/antivirus/docs',
                },
                timestamp: new Date().toISOString(),
            });
        });

        // ---- Antivirus API ----

        const router = express.Router();

        // -- Scan endpoints --

        // POST /api/antivirus/scan - Initiate scan
        router.post('/scan', (req, res, next) => {
            try {
                const { error, value } = schemas.initiateScan.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const result = this.scanOrchestrator.initiateScan(
                    value.deviceIds,
                    value.scanType,
                    value.paths
                );

                res.status(201).json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/antivirus/scan/:scanId - Get scan status/results
        router.get('/scan/:scanId', (req, res, next) => {
            try {
                const scan = this.scanOrchestrator.getScan(req.params.scanId);
                res.json(scan);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/antivirus/scans - List all scans
        router.get('/scans', (req, res, next) => {
            try {
                const filters = {
                    status: req.query.status || null,
                    deviceId: req.query.deviceId || null,
                    scanType: req.query.scanType || null,
                    dateFrom: req.query.dateFrom || null,
                    dateTo: req.query.dateTo || null,
                    page: req.query.page || 1,
                    limit: req.query.limit || 50,
                };
                const result = this.scanOrchestrator.listScans(filters);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // -- Device endpoints --

        // GET /api/antivirus/devices - Device AV status overview
        router.get('/devices', (req, res, next) => {
            try {
                const filters = {
                    platform: req.query.platform || null,
                    department: req.query.department || null,
                    status: req.query.status || null,
                };
                const result = this.scanOrchestrator.getDevices(filters);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/antivirus/devices/:deviceId - Detailed AV status for device
        router.get('/devices/:deviceId', (req, res, next) => {
            try {
                const device = this.scanOrchestrator.getDevice(req.params.deviceId);
                res.json(device);
            } catch (err) {
                next(err);
            }
        });

        // -- Threat endpoints --

        // GET /api/antivirus/threats - List all detected threats
        router.get('/threats', (req, res, next) => {
            try {
                const filters = {
                    severity: req.query.severity || null,
                    deviceId: req.query.deviceId || null,
                    category: req.query.category || null,
                    action: req.query.action || null,
                    page: req.query.page || 1,
                    limit: req.query.limit || 50,
                };
                const result = this.scanOrchestrator.getThreats(filters);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/antivirus/threats/:threatId - Threat detail
        router.get('/threats/:threatId', (req, res, next) => {
            try {
                const threat = this.scanOrchestrator.getThreat(req.params.threatId);
                res.json(threat);
            } catch (err) {
                next(err);
            }
        });

        // -- Quarantine endpoints --

        // GET /api/antivirus/quarantine - List quarantined files
        router.get('/quarantine', (req, res, next) => {
            try {
                const filters = {
                    deviceId: req.query.deviceId || null,
                    severity: req.query.severity || null,
                    status: req.query.status || null,
                    category: req.query.category || null,
                    sha256: req.query.sha256 || null,
                    page: req.query.page || 1,
                    limit: req.query.limit || 50,
                };
                const result = this.quarantineManager.listQuarantinedFiles(filters);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // POST /api/antivirus/quarantine/:fileId/restore - Restore quarantined file
        router.post('/quarantine/:fileId/restore', (req, res, next) => {
            try {
                const result = this.quarantineManager.restoreFile(req.params.fileId);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // DELETE /api/antivirus/quarantine/:fileId - Delete quarantined file
        router.delete('/quarantine/:fileId', (req, res, next) => {
            try {
                const result = this.quarantineManager.deleteFile(req.params.fileId);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // -- Signature endpoints --

        // GET /api/antivirus/signatures - Signature database status
        router.get('/signatures', (_req, res, next) => {
            try {
                const status = this.signatureManager.getSignatureStatus();
                res.json(status);
            } catch (err) {
                next(err);
            }
        });

        // POST /api/antivirus/signatures/update - Trigger signature update
        router.post('/signatures/update', (req, res, next) => {
            try {
                const { error, value } = schemas.signatureUpdate.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const result = this.signatureManager.triggerUpdate(value.deviceIds);
                res.status(202).json(result);
            } catch (err) {
                next(err);
            }
        });

        // -- Statistics & Dashboard --

        // GET /api/antivirus/statistics - Fleet-wide AV statistics
        router.get('/statistics', (_req, res, next) => {
            try {
                const stats = this.scanOrchestrator.getStatistics();
                res.json(stats);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/antivirus/dashboard - Dashboard summary data
        router.get('/dashboard', (_req, res, next) => {
            try {
                const dashboard = this.scanOrchestrator.getDashboard();
                res.json(dashboard);
            } catch (err) {
                next(err);
            }
        });

        // -- Schedule endpoints --

        // POST /api/antivirus/schedule - Schedule recurring scan
        router.post('/schedule', (req, res, next) => {
            try {
                const { error, value } = schemas.schedule.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const result = this.scanOrchestrator.createSchedule(value);
                res.status(201).json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/antivirus/schedules - List scheduled scans
        router.get('/schedules', (_req, res, next) => {
            try {
                const schedules = this.scanOrchestrator.getSchedules();
                res.json(schedules);
            } catch (err) {
                next(err);
            }
        });

        // -- API documentation --

        router.get('/docs', (_req, res) => {
            res.json({
                openapi: '3.0.0',
                info: {
                    title: 'OpenDirectory Antivirus Protection API',
                    version: '1.0.0',
                    description: 'ClamAV antivirus scanning orchestration for managed devices',
                },
                servers: [{ url: '/api/antivirus', description: 'Antivirus Protection API' }],
                paths: {
                    '/scan': {
                        post: {
                            summary: 'Initiate a scan on device(s)',
                            requestBody: {
                                required: true,
                                content: {
                                    'application/json': {
                                        schema: {
                                            type: 'object',
                                            properties: {
                                                deviceIds: { type: 'array', items: { type: 'string' }, description: 'Device IDs to scan (omit for all devices)' },
                                                scanType: { type: 'string', enum: ['quick', 'full', 'custom', 'memory'], default: 'quick' },
                                                paths: { type: 'array', items: { type: 'string' }, description: 'Paths to scan (required for custom scan type)' },
                                            },
                                        },
                                    },
                                },
                            },
                            responses: { '201': { description: 'Scan initiated' } },
                        },
                    },
                    '/scan/{scanId}': {
                        get: {
                            summary: 'Get scan status and results',
                            parameters: [{ name: 'scanId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'Scan details' } },
                        },
                    },
                    '/scans': {
                        get: {
                            summary: 'List all scans with filtering',
                            parameters: [
                                { name: 'status', in: 'query', schema: { type: 'string' } },
                                { name: 'deviceId', in: 'query', schema: { type: 'string' } },
                                { name: 'scanType', in: 'query', schema: { type: 'string' } },
                                { name: 'dateFrom', in: 'query', schema: { type: 'string', format: 'date-time' } },
                                { name: 'dateTo', in: 'query', schema: { type: 'string', format: 'date-time' } },
                                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
                            ],
                            responses: { '200': { description: 'Paginated scan list' } },
                        },
                    },
                    '/devices': {
                        get: {
                            summary: 'Device antivirus status overview',
                            parameters: [
                                { name: 'platform', in: 'query', schema: { type: 'string' } },
                                { name: 'department', in: 'query', schema: { type: 'string' } },
                                { name: 'status', in: 'query', schema: { type: 'string' } },
                            ],
                            responses: { '200': { description: 'Device list with AV status' } },
                        },
                    },
                    '/devices/{deviceId}': {
                        get: {
                            summary: 'Detailed AV status for a specific device',
                            parameters: [{ name: 'deviceId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'Device AV details' } },
                        },
                    },
                    '/threats': {
                        get: {
                            summary: 'List all detected threats',
                            parameters: [
                                { name: 'severity', in: 'query', schema: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] } },
                                { name: 'deviceId', in: 'query', schema: { type: 'string' } },
                                { name: 'category', in: 'query', schema: { type: 'string' } },
                                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
                            ],
                            responses: { '200': { description: 'Paginated threat list' } },
                        },
                    },
                    '/threats/{threatId}': {
                        get: {
                            summary: 'Get threat details',
                            parameters: [{ name: 'threatId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'Threat details with related threats' } },
                        },
                    },
                    '/quarantine': {
                        get: {
                            summary: 'List quarantined files',
                            parameters: [
                                { name: 'deviceId', in: 'query', schema: { type: 'string' } },
                                { name: 'severity', in: 'query', schema: { type: 'string' } },
                                { name: 'status', in: 'query', schema: { type: 'string' } },
                                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
                            ],
                            responses: { '200': { description: 'Paginated quarantine list' } },
                        },
                    },
                    '/quarantine/{fileId}/restore': {
                        post: {
                            summary: 'Restore a quarantined file',
                            parameters: [{ name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'File restored' } },
                        },
                    },
                    '/quarantine/{fileId}': {
                        delete: {
                            summary: 'Permanently delete a quarantined file',
                            parameters: [{ name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'File deleted' } },
                        },
                    },
                    '/signatures': {
                        get: {
                            summary: 'Get signature database status',
                            responses: { '200': { description: 'Signature status' } },
                        },
                    },
                    '/signatures/update': {
                        post: {
                            summary: 'Trigger signature update on devices',
                            requestBody: {
                                content: {
                                    'application/json': {
                                        schema: {
                                            type: 'object',
                                            properties: {
                                                deviceIds: { type: 'array', items: { type: 'string' }, description: 'Device IDs to update (omit for all)' },
                                            },
                                        },
                                    },
                                },
                            },
                            responses: { '202': { description: 'Update initiated' } },
                        },
                    },
                    '/statistics': {
                        get: {
                            summary: 'Get fleet-wide AV statistics',
                            responses: { '200': { description: 'Fleet statistics' } },
                        },
                    },
                    '/dashboard': {
                        get: {
                            summary: 'Get dashboard summary data',
                            responses: { '200': { description: 'Dashboard data' } },
                        },
                    },
                    '/schedule': {
                        post: {
                            summary: 'Schedule a recurring scan',
                            requestBody: {
                                required: true,
                                content: {
                                    'application/json': {
                                        schema: {
                                            type: 'object',
                                            required: ['name', 'cronExpression'],
                                            properties: {
                                                name: { type: 'string' },
                                                scanType: { type: 'string', enum: ['quick', 'full', 'custom', 'memory'] },
                                                cronExpression: { type: 'string', example: '0 2 * * 0' },
                                                deviceSelector: { type: 'object' },
                                                paths: { type: 'array', items: { type: 'string' } },
                                                enabled: { type: 'boolean', default: true },
                                            },
                                        },
                                    },
                                },
                            },
                            responses: { '201': { description: 'Schedule created' } },
                        },
                    },
                    '/schedules': {
                        get: {
                            summary: 'List scheduled scans',
                            responses: { '200': { description: 'Schedule list' } },
                        },
                    },
                },
            });
        });

        this.app.use('/api/antivirus', router);

        logger.info('Routes setup completed');
    }

    // ------------------------------------------------------------------ //
    //  WebSocket setup
    // ------------------------------------------------------------------ //

    _initializeWebSocket(server) {
        this.wss = new WebSocketServer({ server, path: '/ws/scans' });

        this.wss.on('connection', (ws) => {
            logger.info('WebSocket client connected');

            const listener = (message) => {
                if (ws.readyState === ws.OPEN) {
                    ws.send(JSON.stringify(message));
                }
            };

            this.scanOrchestrator.addScanListener(listener);

            ws.on('message', (data) => {
                try {
                    const msg = JSON.parse(data);
                    if (msg.type === 'ping') {
                        ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
                    }
                } catch (err) {
                    logger.warn('Invalid WebSocket message received', { error: err.message });
                }
            });

            ws.on('close', () => {
                logger.info('WebSocket client disconnected');
                this.scanOrchestrator.removeScanListener(listener);
            });

            ws.on('error', (err) => {
                logger.error('WebSocket error', { error: err.message });
                this.scanOrchestrator.removeScanListener(listener);
            });

            // Send welcome message
            ws.send(JSON.stringify({
                type: 'connected',
                message: 'Connected to antivirus scan updates',
                timestamp: new Date().toISOString(),
            }));
        });

        logger.info('WebSocket server initialized on /ws/scans');
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
    //  Lifecycle
    // ------------------------------------------------------------------ //

    async start() {
        const port = parseInt(process.env.PORT, 10) || 3905;
        const host = process.env.HOST || '0.0.0.0';

        return new Promise((resolve, reject) => {
            this.server = http.createServer(this.app);

            // Initialize WebSocket on the same server
            this._initializeWebSocket(this.server);

            this.server.listen(port, host, () => {
                logger.info(`OpenDirectory Antivirus Protection Service started on ${host}:${port}`);
                logger.info(`Health check:   http://${host}:${port}/health`);
                logger.info(`API docs:       http://${host}:${port}/api/antivirus/docs`);
                logger.info(`WebSocket:      ws://${host}:${port}/ws/scans`);
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

                // Close WebSocket connections
                if (this.wss) {
                    this.wss.clients.forEach((client) => {
                        client.close(1001, 'Server shutting down');
                    });
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
}

// ====================================================================== //
//  Export & auto-start
// ====================================================================== //

module.exports = AntivirusProtectionService;

if (require.main === module) {
    const service = new AntivirusProtectionService();
    service.start().catch((err) => {
        logger.error('Failed to start Antivirus Protection Service', { message: err.message });
        process.exit(1);
    });
}
