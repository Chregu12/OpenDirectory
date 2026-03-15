const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { EventEmitter } = require('events');

const LifecycleManager = require('./services/lifecycleManager');
const RiskScorer = require('./services/riskScorer');

class DeviceLifecycleService extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = null;

        this.lifecycleManager = new LifecycleManager();
        this.riskScorer = new RiskScorer();

        this.initializeMiddleware();
        this.initializeRoutes();
        this.initializeErrorHandling();
    }

    /**
     * Initialize middleware
     */
    initializeMiddleware() {
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"]
                }
            },
            crossOriginEmbedderPolicy: false
        }));

        this.app.use(cors({
            origin: function (origin, callback) {
                if (!origin) return callback(null, true);
                const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',');
                if (allowedOrigins.indexOf(origin) !== -1) {
                    callback(null, true);
                } else {
                    callback(new Error('Not allowed by CORS'));
                }
            },
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID']
        }));

        this.app.use(compression());
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true }));

        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: parseInt(process.env.RATE_LIMIT_MAX) || 1000,
            message: {
                error: 'Too many requests from this IP, please try again later',
                retryAfter: '15 minutes'
            },
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => req.path === '/health' || req.path === '/metrics'
        });
        this.app.use('/api', limiter);

        // Request logging
        this.app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                const duration = Date.now() - start;
                if (req.path !== '/health' && req.path !== '/metrics') {
                    console.log(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
                }
            });
            next();
        });
    }

    /**
     * Initialize routes
     */
    initializeRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                service: 'device-lifecycle-manager',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                version: '1.0.0'
            });
        });

        // Metrics
        this.app.get('/metrics', (req, res) => {
            res.json({
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            });
        });

        // -------------------------------------------------------
        // Lifecycle API Routes
        // -------------------------------------------------------

        // GET /api/lifecycle/devices - List all devices with lifecycle state
        this.app.get('/api/lifecycle/devices', (req, res) => {
            try {
                const filters = {
                    state: req.query.state,
                    platform: req.query.platform,
                    owner: req.query.owner,
                    search: req.query.search,
                    page: req.query.page,
                    limit: req.query.limit
                };
                const result = this.lifecycleManager.getAllDevices(filters);
                res.json(result);
            } catch (error) {
                console.error('Error listing devices:', error);
                res.status(500).json({ error: 'Failed to list devices', message: error.message });
            }
        });

        // GET /api/lifecycle/devices/:id - Device detail with full lifecycle history
        this.app.get('/api/lifecycle/devices/:id', (req, res) => {
            try {
                const device = this.lifecycleManager.getDeviceById(req.params.id);
                if (!device) {
                    return res.status(404).json({
                        error: 'Device not found',
                        message: `No device found with ID ${req.params.id}`
                    });
                }
                res.json(device);
            } catch (error) {
                console.error('Error getting device:', error);
                res.status(500).json({ error: 'Failed to get device', message: error.message });
            }
        });

        // POST /api/lifecycle/devices/:id/transition - Transition device state
        this.app.post('/api/lifecycle/devices/:id/transition', (req, res) => {
            try {
                const { targetState, performedBy, reason } = req.body;

                if (!targetState) {
                    return res.status(400).json({
                        error: 'Validation error',
                        message: 'targetState is required'
                    });
                }

                const result = this.lifecycleManager.transitionDevice(
                    req.params.id,
                    targetState,
                    { performedBy: performedBy || 'api-user', reason: reason || '' }
                );

                res.json(result);
            } catch (error) {
                if (error.message.includes('not found')) {
                    return res.status(404).json({ error: 'Device not found', message: error.message });
                }
                if (error.message.includes('Invalid')) {
                    return res.status(400).json({ error: 'Invalid transition', message: error.message });
                }
                console.error('Error transitioning device:', error);
                res.status(500).json({ error: 'Failed to transition device', message: error.message });
            }
        });

        // GET /api/lifecycle/devices/:id/risk-score - Get device risk score with breakdown
        this.app.get('/api/lifecycle/devices/:id/risk-score', (req, res) => {
            try {
                const device = this.lifecycleManager.getDeviceById(req.params.id);
                if (!device) {
                    return res.status(404).json({
                        error: 'Device not found',
                        message: `No device found with ID ${req.params.id}`
                    });
                }

                const riskScore = this.riskScorer.calculateRiskScore(device);
                res.json(riskScore);
            } catch (error) {
                console.error('Error calculating risk score:', error);
                res.status(500).json({ error: 'Failed to calculate risk score', message: error.message });
            }
        });

        // GET /api/lifecycle/analytics - Lifecycle analytics
        this.app.get('/api/lifecycle/analytics', (req, res) => {
            try {
                const analytics = this.lifecycleManager.getAnalytics();
                res.json(analytics);
            } catch (error) {
                console.error('Error getting analytics:', error);
                res.status(500).json({ error: 'Failed to get analytics', message: error.message });
            }
        });

        // POST /api/lifecycle/bulk-transition - Bulk state transition
        this.app.post('/api/lifecycle/bulk-transition', (req, res) => {
            try {
                const { deviceIds, targetState, performedBy, reason } = req.body;

                if (!deviceIds || !Array.isArray(deviceIds) || deviceIds.length === 0) {
                    return res.status(400).json({
                        error: 'Validation error',
                        message: 'deviceIds must be a non-empty array'
                    });
                }
                if (!targetState) {
                    return res.status(400).json({
                        error: 'Validation error',
                        message: 'targetState is required'
                    });
                }

                const result = this.lifecycleManager.bulkTransition(
                    deviceIds,
                    targetState,
                    { performedBy: performedBy || 'api-user', reason: reason || '' }
                );

                res.json(result);
            } catch (error) {
                console.error('Error in bulk transition:', error);
                res.status(500).json({ error: 'Failed to perform bulk transition', message: error.message });
            }
        });

        // GET /api/lifecycle/devices/:id/timeline - Complete device timeline
        this.app.get('/api/lifecycle/devices/:id/timeline', (req, res) => {
            try {
                const timeline = this.lifecycleManager.getDeviceTimeline(req.params.id);
                if (!timeline) {
                    return res.status(404).json({
                        error: 'Device not found',
                        message: `No device found with ID ${req.params.id}`
                    });
                }
                res.json(timeline);
            } catch (error) {
                console.error('Error getting device timeline:', error);
                res.status(500).json({ error: 'Failed to get device timeline', message: error.message });
            }
        });

        // Root endpoint
        this.app.get('/', (req, res) => {
            res.json({
                name: 'OpenDirectory Device Lifecycle Manager',
                version: '1.0.0',
                description: 'Complete device lifecycle tracking, risk scoring, and analytics',
                features: [
                    'Device lifecycle state machine with audit trail',
                    'Device risk scoring (0-100) with detailed breakdown',
                    'Lifecycle analytics and compliance metrics',
                    'Bulk lifecycle operations',
                    'Complete device timeline history'
                ],
                api: {
                    baseUrl: '/api/lifecycle',
                    endpoints: [
                        'GET /api/lifecycle/devices',
                        'GET /api/lifecycle/devices/:id',
                        'POST /api/lifecycle/devices/:id/transition',
                        'GET /api/lifecycle/devices/:id/risk-score',
                        'GET /api/lifecycle/analytics',
                        'POST /api/lifecycle/bulk-transition',
                        'GET /api/lifecycle/devices/:id/timeline',
                        'GET /health'
                    ]
                },
                timestamp: new Date().toISOString()
            });
        });
    }

    /**
     * Initialize error handling
     */
    initializeErrorHandling() {
        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                message: `The requested endpoint ${req.method} ${req.originalUrl} was not found`,
                timestamp: new Date().toISOString()
            });
        });

        // Global error handler
        this.app.use((err, req, res, next) => {
            console.error('Unhandled error:', err);
            const isDevelopment = process.env.NODE_ENV === 'development';
            res.status(err.statusCode || 500).json({
                error: isDevelopment ? err.message : 'Internal server error',
                ...(isDevelopment && { stack: err.stack }),
                timestamp: new Date().toISOString()
            });
        });

        process.on('uncaughtException', (err) => {
            console.error('Uncaught Exception:', err);
            process.exit(1);
        });

        process.on('unhandledRejection', (reason, promise) => {
            console.error('Unhandled Rejection at:', promise, 'reason:', reason);
        });
    }

    /**
     * Start the service
     */
    async start() {
        try {
            const port = parseInt(process.env.PORT) || 3020;
            const host = process.env.HOST || '0.0.0.0';

            this.server = this.app.listen(port, host, () => {
                console.log(`OpenDirectory Device Lifecycle Manager started on ${host}:${port}`);
                console.log(`Health check: http://${host}:${port}/health`);
            });

            this.server.on('error', (err) => {
                console.error('Server error:', err);
                this.emit('error', err);
            });

            process.on('SIGTERM', () => this.shutdown('SIGTERM'));
            process.on('SIGINT', () => this.shutdown('SIGINT'));

            this.emit('started');
            return this.server;
        } catch (error) {
            console.error('Failed to start service:', error);
            throw error;
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(signal) {
        console.log(`Received ${signal}, starting graceful shutdown...`);
        if (this.server) {
            this.server.close((err) => {
                if (err) {
                    console.error('Error during server shutdown:', err);
                }
                console.log('Graceful shutdown completed');
                process.exit(0);
            });
        }
    }
}

module.exports = DeviceLifecycleService;

if (require.main === module) {
    const service = new DeviceLifecycleService();
    service.start().catch((error) => {
        console.error('Failed to start Device Lifecycle Manager:', error);
        process.exit(1);
    });
}
