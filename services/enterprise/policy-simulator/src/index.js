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
    defaultMeta: { service: 'policy-simulator', version: '1.0.0' },
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

const SimulationEngine = require('./services/simulationEngine');
const ImpactAnalyzer = require('./services/impactAnalyzer');
const DriftDetector = require('./services/driftDetector');
const ComplianceTimeline = require('./services/complianceTimeline');

// ====================================================================== //
//  Validation schemas
// ====================================================================== //

const schemas = {
    simulate: Joi.object({
        policyId: Joi.string().required(),
        changes: Joi.object().min(1).required(),
        scope: Joi.object({
            groups: Joi.array().items(Joi.string()),
            platforms: Joi.array().items(Joi.string()),
        }).optional(),
    }),
    rollbackPlan: Joi.object({
        policyId: Joi.string().required(),
        changes: Joi.object().min(1).required(),
    }),
};

// ====================================================================== //
//  PolicySimulatorService
// ====================================================================== //

class PolicySimulatorService extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = null;

        // Initialise core services
        this.simulationEngine = new SimulationEngine(logger);
        this.impactAnalyzer = new ImpactAnalyzer(this.simulationEngine, logger);
        this.driftDetector = new DriftDetector(this.simulationEngine, logger);
        this.complianceTimeline = new ComplianceTimeline(this.simulationEngine, logger);

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
                    simulationEngine: 'operational',
                    impactAnalyzer: 'operational',
                    driftDetector: 'operational',
                    complianceTimeline: 'operational',
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
                name: 'OpenDirectory Policy Simulator Service',
                version: '1.0.0',
                description: 'What-If analysis for policy changes in the OpenDirectory UEM platform',
                features: [
                    'Simulate policy changes before applying',
                    'Impact analysis (devices, users, compliance)',
                    'Configuration drift detection',
                    'Compliance timeline per device',
                    'Policy conflict detection',
                    'Rollback planning',
                ],
                api: {
                    baseUrl: '/api/simulator',
                    documentation: '/api/simulator/docs',
                },
                timestamp: new Date().toISOString(),
            });
        });

        // ---- Simulator API ----

        const router = express.Router();

        // POST /api/simulator/simulate
        router.post('/simulate', (req, res, next) => {
            try {
                const { error, value } = schemas.simulate.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const result = this.simulationEngine.simulate(
                    value.policyId,
                    value.changes,
                    value.scope || {}
                );

                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/simulator/impact/:policyId
        router.get('/impact/:policyId', (req, res, next) => {
            try {
                const report = this.impactAnalyzer.analyze(req.params.policyId);
                res.json(report);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/simulator/drift
        router.get('/drift', (req, res, next) => {
            try {
                const filters = {
                    platform: req.query.platform || null,
                    department: req.query.department || null,
                    severity: req.query.severity || null,
                };
                const report = this.driftDetector.detectAll(filters);
                res.json(report);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/simulator/drift/:deviceId
        router.get('/drift/:deviceId', (req, res, next) => {
            try {
                const report = this.driftDetector.detectForDevice(req.params.deviceId);
                res.json(report);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/simulator/timeline/:deviceId
        router.get('/timeline/:deviceId', (req, res, next) => {
            try {
                const options = {
                    from: req.query.from || null,
                    to: req.query.to || null,
                    eventTypes: req.query.eventTypes ? req.query.eventTypes.split(',') : null,
                    limit: req.query.limit ? parseInt(req.query.limit, 10) : 200,
                };
                const timeline = this.complianceTimeline.getTimeline(
                    req.params.deviceId,
                    options
                );
                res.json(timeline);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/simulator/conflicts
        router.get('/conflicts', (_req, res, next) => {
            try {
                const report = this.simulationEngine.detectAllConflicts();
                res.json(report);
            } catch (err) {
                next(err);
            }
        });

        // POST /api/simulator/rollback-plan
        router.post('/rollback-plan', (req, res, next) => {
            try {
                const { error, value } = schemas.rollbackPlan.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const plan = this.simulationEngine.createRollbackPlan(
                    value.policyId,
                    value.changes
                );

                res.json(plan);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/simulator/history
        router.get('/history', (req, res, next) => {
            try {
                const limit = req.query.limit ? parseInt(req.query.limit, 10) : 50;
                const offset = req.query.offset ? parseInt(req.query.offset, 10) : 0;
                const history = this.simulationEngine.getHistory(limit, offset);
                res.json(history);
            } catch (err) {
                next(err);
            }
        });

        // API documentation
        router.get('/docs', (_req, res) => {
            res.json({
                openapi: '3.0.0',
                info: {
                    title: 'OpenDirectory Policy Simulator API',
                    version: '1.0.0',
                    description: 'What-If analysis for enterprise policy changes',
                },
                servers: [{ url: '/api/simulator', description: 'Policy Simulator API' }],
                paths: {
                    '/simulate': {
                        post: {
                            summary: 'Simulate a policy change',
                            description: 'Runs a what-if simulation for the given policy changes and returns predicted impact.',
                            requestBody: {
                                required: true,
                                content: {
                                    'application/json': {
                                        schema: {
                                            type: 'object',
                                            required: ['policyId', 'changes'],
                                            properties: {
                                                policyId: { type: 'string', example: 'policy-security-baseline' },
                                                changes: { type: 'object', example: { passwordMinLength: 12 } },
                                                scope: {
                                                    type: 'object',
                                                    properties: {
                                                        groups: { type: 'array', items: { type: 'string' } },
                                                        platforms: { type: 'array', items: { type: 'string' } },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            responses: { '200': { description: 'Simulation result' } },
                        },
                    },
                    '/impact/{policyId}': {
                        get: {
                            summary: 'Get impact analysis for a policy',
                            parameters: [{ name: 'policyId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'Impact report' } },
                        },
                    },
                    '/drift': {
                        get: {
                            summary: 'Get all drift detections',
                            parameters: [
                                { name: 'platform', in: 'query', schema: { type: 'string' } },
                                { name: 'department', in: 'query', schema: { type: 'string' } },
                                { name: 'severity', in: 'query', schema: { type: 'string' } },
                            ],
                            responses: { '200': { description: 'Drift report' } },
                        },
                    },
                    '/drift/{deviceId}': {
                        get: {
                            summary: 'Get drift for a specific device',
                            parameters: [{ name: 'deviceId', in: 'path', required: true, schema: { type: 'string' } }],
                            responses: { '200': { description: 'Device drift report' } },
                        },
                    },
                    '/timeline/{deviceId}': {
                        get: {
                            summary: 'Get compliance timeline for a device',
                            parameters: [
                                { name: 'deviceId', in: 'path', required: true, schema: { type: 'string' } },
                                { name: 'from', in: 'query', schema: { type: 'string', format: 'date-time' } },
                                { name: 'to', in: 'query', schema: { type: 'string', format: 'date-time' } },
                                { name: 'eventTypes', in: 'query', schema: { type: 'string' } },
                                { name: 'limit', in: 'query', schema: { type: 'integer' } },
                            ],
                            responses: { '200': { description: 'Compliance timeline' } },
                        },
                    },
                    '/conflicts': {
                        get: {
                            summary: 'Detect policy conflicts',
                            responses: { '200': { description: 'Conflict report' } },
                        },
                    },
                    '/rollback-plan': {
                        post: {
                            summary: 'Create a rollback plan',
                            requestBody: {
                                required: true,
                                content: {
                                    'application/json': {
                                        schema: {
                                            type: 'object',
                                            required: ['policyId', 'changes'],
                                            properties: {
                                                policyId: { type: 'string' },
                                                changes: { type: 'object' },
                                            },
                                        },
                                    },
                                },
                            },
                            responses: { '200': { description: 'Rollback plan' } },
                        },
                    },
                    '/history': {
                        get: {
                            summary: 'Get simulation history',
                            parameters: [
                                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
                                { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
                            ],
                            responses: { '200': { description: 'Simulation history' } },
                        },
                    },
                },
            });
        });

        this.app.use('/api/simulator', router);

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
        const port = parseInt(process.env.PORT, 10) || 3020;
        const host = process.env.HOST || '0.0.0.0';

        return new Promise((resolve, reject) => {
            this.server = this.app.listen(port, host, () => {
                logger.info(`OpenDirectory Policy Simulator Service started on ${host}:${port}`);
                logger.info(`Health check: http://${host}:${port}/health`);
                logger.info(`API docs:     http://${host}:${port}/api/simulator/docs`);
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

module.exports = PolicySimulatorService;

if (require.main === module) {
    const service = new PolicySimulatorService();
    service.start().catch((err) => {
        logger.error('Failed to start Policy Simulator Service', { message: err.message });
        process.exit(1);
    });
}
