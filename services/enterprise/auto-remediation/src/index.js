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
    defaultMeta: { service: 'auto-remediation', version: '1.0.0' },
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

const RemediationEngine = require('./services/remediationEngine');
const ScriptGenerator = require('./services/scriptGenerator');
const PlaybookManager = require('./services/playbookManager');

// ====================================================================== //
//  Validation schemas
// ====================================================================== //

const schemas = {
    executeRemediation: Joi.object({
        executedBy: Joi.string().optional(),
        force: Joi.boolean().optional(),
    }),
    createPlaybook: Joi.object({
        name: Joi.string().required(),
        description: Joi.string().allow('').optional(),
        category: Joi.string().optional(),
        severity: Joi.string().valid('low', 'medium', 'high', 'critical').optional(),
        platforms: Joi.array().items(Joi.string()).optional(),
        steps: Joi.array().items(
            Joi.object({
                name: Joi.string().required(),
                issueType: Joi.string().required(),
                description: Joi.string().allow('').optional(),
                continueOnFailure: Joi.boolean().optional(),
            })
        ).min(1).required(),
        requiresApproval: Joi.boolean().optional(),
        estimatedDuration: Joi.string().optional(),
        createdBy: Joi.string().optional(),
    }),
    bulkExecute: Joi.object({
        issueIds: Joi.array().items(Joi.string()).min(1).required(),
        executedBy: Joi.string().optional(),
        force: Joi.boolean().optional(),
    }),
};

// ====================================================================== //
//  AutoRemediationService
// ====================================================================== //

class AutoRemediationService extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = null;

        // Initialise core services
        this.scriptGenerator = new ScriptGenerator();
        this.playbookManager = new PlaybookManager();
        this.remediationEngine = new RemediationEngine(this.scriptGenerator, this.playbookManager);

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
                    remediationEngine: 'operational',
                    scriptGenerator: 'operational',
                    playbookManager: 'operational',
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
                name: 'OpenDirectory Auto Remediation Engine',
                version: '1.0.0',
                description: 'Detects compliance issues and generates platform-specific remediation scripts',
                features: [
                    'Auto-detect compliance issues and generate remediation scripts',
                    'Platform-specific script generation (PowerShell/bash)',
                    'Remediation playbooks for common scenarios',
                    'Approval workflow (auto-remediate low-risk, require approval for high-risk)',
                    'Remediation history and success tracking',
                    'Bulk remediation operations',
                ],
                api: {
                    baseUrl: '/api/remediation',
                    endpoints: [
                        'GET  /api/remediation/issues',
                        'GET  /api/remediation/issues/:id',
                        'POST /api/remediation/execute/:issueId',
                        'GET  /api/remediation/scripts/:issueId',
                        'GET  /api/remediation/playbooks',
                        'POST /api/remediation/playbooks',
                        'GET  /api/remediation/history',
                        'GET  /api/remediation/statistics',
                        'POST /api/remediation/bulk-execute',
                        'GET  /health',
                    ],
                },
                timestamp: new Date().toISOString(),
            });
        });

        // ---- Remediation API ----

        const router = express.Router();

        // GET /api/remediation/issues - List detected issues
        router.get('/issues', (req, res, next) => {
            try {
                const filters = {
                    status: req.query.status,
                    severity: req.query.severity,
                    type: req.query.type,
                    deviceId: req.query.deviceId,
                    platform: req.query.platform,
                    page: req.query.page,
                    limit: req.query.limit,
                };
                const result = this.remediationEngine.getIssues(filters);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/remediation/issues/:id - Issue detail with generated fix
        router.get('/issues/:id', (req, res, next) => {
            try {
                const issue = this.remediationEngine.getIssueById(req.params.id);
                if (!issue) {
                    return res.status(404).json({
                        error: 'Issue not found',
                        message: `No issue found with ID ${req.params.id}`,
                        timestamp: new Date().toISOString(),
                    });
                }
                res.json(issue);
            } catch (err) {
                next(err);
            }
        });

        // POST /api/remediation/execute/:issueId - Execute remediation
        router.post('/execute/:issueId', (req, res, next) => {
            try {
                const { error, value } = schemas.executeRemediation.validate(req.body || {});
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const result = this.remediationEngine.executeRemediation(
                    req.params.issueId,
                    {
                        executedBy: value.executedBy || 'api-user',
                        force: value.force === true,
                    }
                );

                if (result.requiresApproval) {
                    return res.status(202).json(result);
                }

                res.json(result);
            } catch (err) {
                if (err.message.includes('not found')) {
                    return res.status(404).json({ error: 'Issue not found', message: err.message, timestamp: new Date().toISOString() });
                }
                if (err.message.includes('already been') || err.message.includes('currently being')) {
                    return res.status(409).json({ error: 'Conflict', message: err.message, timestamp: new Date().toISOString() });
                }
                next(err);
            }
        });

        // GET /api/remediation/scripts/:issueId - Get generated remediation script
        router.get('/scripts/:issueId', (req, res, next) => {
            try {
                const script = this.remediationEngine.getScript(req.params.issueId);
                if (!script) {
                    return res.status(404).json({
                        error: 'Issue not found',
                        message: `No issue found with ID ${req.params.issueId}`,
                        timestamp: new Date().toISOString(),
                    });
                }
                res.json(script);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/remediation/playbooks - List available playbooks
        router.get('/playbooks', (req, res, next) => {
            try {
                const filters = {
                    category: req.query.category,
                    severity: req.query.severity,
                    platform: req.query.platform,
                    search: req.query.search,
                };
                const playbooks = this.playbookManager.getAllPlaybooks(filters);
                res.json({ playbooks });
            } catch (err) {
                next(err);
            }
        });

        // POST /api/remediation/playbooks - Create custom playbook
        router.post('/playbooks', (req, res, next) => {
            try {
                const { error, value } = schemas.createPlaybook.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const playbook = this.playbookManager.createPlaybook({
                    name: value.name,
                    description: value.description,
                    category: value.category,
                    severity: value.severity,
                    platforms: value.platforms,
                    steps: value.steps,
                    requiresApproval: value.requiresApproval,
                    estimatedDuration: value.estimatedDuration,
                    createdBy: value.createdBy || 'api-user',
                });

                res.status(201).json(playbook);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/remediation/history - Remediation execution history
        router.get('/history', (req, res, next) => {
            try {
                const filters = {
                    status: req.query.status,
                    deviceId: req.query.deviceId,
                    issueType: req.query.issueType,
                    success: req.query.success,
                    page: req.query.page,
                    limit: req.query.limit,
                };
                const result = this.remediationEngine.getHistory(filters);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        // GET /api/remediation/statistics - Success/failure stats
        router.get('/statistics', (req, res, next) => {
            try {
                const stats = this.remediationEngine.getStatistics();
                res.json(stats);
            } catch (err) {
                next(err);
            }
        });

        // POST /api/remediation/bulk-execute - Bulk remediation
        router.post('/bulk-execute', (req, res, next) => {
            try {
                const { error, value } = schemas.bulkExecute.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        error: 'Validation error',
                        details: error.details.map(d => d.message),
                        timestamp: new Date().toISOString(),
                    });
                }

                const result = this.remediationEngine.bulkExecute(
                    value.issueIds,
                    {
                        executedBy: value.executedBy || 'api-user',
                        force: value.force === true,
                    }
                );

                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        this.app.use('/api/remediation', router);

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
        const port = parseInt(process.env.PORT, 10) || 3904;
        const host = process.env.HOST || '0.0.0.0';

        return new Promise((resolve, reject) => {
            this.server = this.app.listen(port, host, () => {
                logger.info(`OpenDirectory Auto Remediation Engine started on ${host}:${port}`);
                logger.info(`Health check: http://${host}:${port}/health`);
                logger.info(`API base:     http://${host}:${port}/api/remediation`);
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

module.exports = AutoRemediationService;

if (require.main === module) {
    const service = new AutoRemediationService();
    service.start().catch((err) => {
        logger.error('Failed to start Auto Remediation Engine', { message: err.message });
        process.exit(1);
    });
}
