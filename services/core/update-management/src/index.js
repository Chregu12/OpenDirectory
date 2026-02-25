const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { EventEmitter } = require('events');

// Import services
const WindowsUpdateService = require('./services/WindowsUpdateService');
const MacOSUpdateService = require('./services/MacOSUpdateService');
const LinuxUpdateService = require('./services/LinuxUpdateService');
const RemoteActionsService = require('./services/RemoteActionsService');
const UpdateRingsService = require('./services/UpdateRingsService');
const MAMService = require('./services/MAMService');
const TermsOfUseService = require('./services/TermsOfUseService');
const MultiTenantService = require('./services/MultiTenantService');

// Import utilities
const logger = require('./utils/logger');
const config = require('./config');
const AuditLogger = require('./audit/AuditLogger');

// Import controllers
const UpdateController = require('./controllers/UpdateController');
const RemoteActionsController = require('./controllers/RemoteActionsController');
const UpdateRingsController = require('./controllers/UpdateRingsController');
const MAMController = require('./controllers/MAMController');
const TermsOfUseController = require('./controllers/TermsOfUseController');
const MultiTenantController = require('./controllers/MultiTenantController');

// Import middleware
const authMiddleware = require('./middleware/auth');
const tenantMiddleware = require('./middleware/tenant');
const auditMiddleware = require('./middleware/audit');
const validationMiddleware = require('./middleware/validation');

class UpdateManagementService extends EventEmitter {
    constructor() {
        super();
        this.app = express();
        this.server = null;
        this.services = {};
        this.controllers = {};
        this.auditLogger = new AuditLogger();
        
        // Service initialization
        this.initializeServices();
        this.initializeMiddleware();
        this.initializeControllers();
        this.initializeRoutes();
        this.initializeErrorHandling();
    }

    /**
     * Initialize all services
     */
    initializeServices() {
        logger.info('Initializing Update Management services...');

        this.services = {
            windowsUpdate: new WindowsUpdateService(),
            macosUpdate: new MacOSUpdateService(),
            linuxUpdate: new LinuxUpdateService(),
            remoteActions: new RemoteActionsService(),
            updateRings: new UpdateRingsService(),
            mam: new MAMService(),
            termsOfUse: new TermsOfUseService(),
            multiTenant: new MultiTenantService()
        };

        // Set up service event listeners
        this.setupServiceEventListeners();

        logger.info('All services initialized successfully');
    }

    /**
     * Initialize middleware
     */
    initializeMiddleware() {
        logger.info('Setting up middleware...');

        // Security middleware
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
                    frameSrc: ["'none'"],
                }
            },
            crossOriginEmbedderPolicy: false
        }));

        // CORS configuration
        this.app.use(cors({
            origin: function (origin, callback) {
                // Allow requests with no origin (mobile apps, etc.)
                if (!origin) return callback(null, true);
                
                const allowedOrigins = config.cors?.allowedOrigins || ['http://localhost:3000'];
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

        // Compression and parsing
        this.app.use(compression());
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true }));

        // Rate limiting
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: config.rateLimiting?.maxRequests || 1000,
            message: {
                error: 'Too many requests from this IP, please try again later',
                retryAfter: '15 minutes'
            },
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => {
                // Skip rate limiting for health checks
                return req.path === '/health' || req.path === '/metrics';
            }
        });
        this.app.use('/api', limiter);

        // Custom middleware
        this.app.use(auditMiddleware(this.auditLogger));
        this.app.use(tenantMiddleware(this.services.multiTenant));
        
        // Request logging
        this.app.use((req, res, next) => {
            logger.info(`${req.method} ${req.path}`, {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                tenantId: req.tenantId,
                userId: req.user?.id
            });
            next();
        });

        logger.info('Middleware setup completed');
    }

    /**
     * Initialize controllers
     */
    initializeControllers() {
        logger.info('Initializing controllers...');

        this.controllers = {
            update: new UpdateController(this.services),
            remoteActions: new RemoteActionsController(this.services.remoteActions),
            updateRings: new UpdateRingsController(this.services.updateRings),
            mam: new MAMController(this.services.mam),
            termsOfUse: new TermsOfUseController(this.services.termsOfUse),
            multiTenant: new MultiTenantController(this.services.multiTenant)
        };

        logger.info('Controllers initialized successfully');
    }

    /**
     * Initialize routes
     */
    initializeRoutes() {
        logger.info('Setting up routes...');

        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: require('../../package.json').version || '1.0.0',
                services: {
                    windowsUpdate: 'operational',
                    macosUpdate: 'operational',
                    linuxUpdate: 'operational',
                    remoteActions: 'operational',
                    updateRings: 'operational',
                    mam: 'operational',
                    termsOfUse: 'operational',
                    multiTenant: 'operational'
                }
            });
        });

        // Metrics endpoint
        this.app.get('/metrics', (req, res) => {
            res.json({
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            });
        });

        // API routes with authentication
        const apiRouter = express.Router();
        
        // Apply authentication to all API routes
        apiRouter.use(authMiddleware);

        // Update management routes
        apiRouter.use('/updates', this.controllers.update.getRouter());
        
        // Remote actions routes
        apiRouter.use('/remote-actions', this.controllers.remoteActions.getRouter());
        
        // Update rings routes
        apiRouter.use('/update-rings', this.controllers.updateRings.getRouter());
        
        // MAM routes
        apiRouter.use('/mam', this.controllers.mam.getRouter());
        
        // Terms of Use routes
        apiRouter.use('/terms', this.controllers.termsOfUse.getRouter());
        
        // Multi-tenant management routes (admin only)
        apiRouter.use('/tenants', this.controllers.multiTenant.getRouter());

        // Mount API router
        this.app.use('/api/v1', apiRouter);

        // Root endpoint
        this.app.get('/', (req, res) => {
            res.json({
                name: 'OpenDirectory Update Management Service',
                version: require('../../package.json').version || '1.0.0',
                description: 'Comprehensive update management and remote device actions for OpenDirectory platform',
                features: [
                    'Cross-platform update management (Windows, macOS, Linux)',
                    'Remote device actions (Lock, Wipe, Restart, Locate)',
                    'Update rings and staged deployment',
                    'Mobile Application Management (MAM)',
                    'Terms of Use enforcement',
                    'Multi-tenant support'
                ],
                api: {
                    version: 'v1',
                    baseUrl: '/api/v1',
                    documentation: '/api/v1/docs'
                },
                timestamp: new Date().toISOString()
            });
        });

        // API documentation endpoint
        this.app.get('/api/v1/docs', (req, res) => {
            res.json({
                openapi: '3.0.0',
                info: {
                    title: 'OpenDirectory Update Management API',
                    version: '1.0.0',
                    description: 'API for managing updates and remote device actions'
                },
                servers: [
                    {
                        url: '/api/v1',
                        description: 'Update Management API v1'
                    }
                ],
                paths: this.generateOpenAPISpec()
            });
        });

        logger.info('Routes setup completed');
    }

    /**
     * Initialize error handling
     */
    initializeErrorHandling() {
        // Handle 404
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                message: `The requested endpoint ${req.method} ${req.originalUrl} was not found`,
                timestamp: new Date().toISOString()
            });
        });

        // Global error handler
        this.app.use((err, req, res, next) => {
            logger.error('Unhandled error:', err);

            // Log error details for audit
            this.auditLogger.log('service_error', {
                error: err.message,
                stack: err.stack,
                url: req.originalUrl,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });

            // Don't expose internal errors in production
            const isDevelopment = process.env.NODE_ENV === 'development';
            
            res.status(err.statusCode || 500).json({
                error: isDevelopment ? err.message : 'Internal server error',
                ...(isDevelopment && { stack: err.stack }),
                timestamp: new Date().toISOString()
            });
        });

        // Handle uncaught exceptions
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception:', err);
            this.auditLogger.log('uncaught_exception', {
                error: err.message,
                stack: err.stack,
                timestamp: new Date().toISOString()
            });
            process.exit(1);
        });

        // Handle unhandled promise rejections
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
            this.auditLogger.log('unhandled_rejection', {
                reason: reason.toString(),
                timestamp: new Date().toISOString()
            });
        });

        logger.info('Error handling setup completed');
    }

    /**
     * Set up service event listeners for cross-service communication
     */
    setupServiceEventListeners() {
        // Update rings service events
        this.services.updateRings.on('ringCreated', (ring) => {
            logger.info(`Update ring created: ${ring.name}`);
            this.emit('updateRingCreated', ring);
        });

        this.services.updateRings.on('deploymentScheduled', (deployment) => {
            logger.info(`Deployment scheduled: ${deployment.name}`);
            this.emit('deploymentScheduled', deployment);
        });

        // Remote actions service events
        this.services.remoteActions.on('actionQueued', (action) => {
            logger.info(`Remote action queued: ${action.type} for device ${action.deviceId}`);
            this.emit('remoteActionQueued', action);
        });

        // MAM service events
        this.services.mam.on('mamPolicyCreated', (policy) => {
            logger.info(`MAM policy created: ${policy.name}`);
            this.emit('mamPolicyCreated', policy);
        });

        // Terms of Use service events
        this.services.termsOfUse.on('termsCreated', (terms) => {
            logger.info(`Terms of Use created: ${terms.title}`);
            this.emit('termsOfUseCreated', terms);
        });

        this.services.termsOfUse.on('acceptanceRecorded', (acceptance) => {
            logger.info(`Terms acceptance recorded for user: ${acceptance.userId}`);
            this.emit('termsAcceptanceRecorded', acceptance);
        });

        // Multi-tenant service events
        this.services.multiTenant.on('tenantCreated', (tenant) => {
            logger.info(`Tenant created: ${tenant.name} (${tenant.id})`);
            this.emit('tenantCreated', tenant);
        });

        // Cross-service integration
        this.setupCrossServiceIntegration();
    }

    /**
     * Set up cross-service integration
     */
    setupCrossServiceIntegration() {
        // When a tenant is created, set up default update rings
        this.services.multiTenant.on('tenantCreated', async (tenant) => {
            try {
                await this.services.updateRings.createStandardRings(tenant.id);
                logger.info(`Standard update rings created for tenant: ${tenant.id}`);
            } catch (error) {
                logger.error('Error creating standard rings for new tenant:', error);
            }
        });

        // When terms are published, create enforcement policies
        this.services.termsOfUse.on('termsPublished', async (data) => {
            try {
                // Integration with conditional access could happen here
                logger.info(`Terms published, enforcement policies activated: ${data.terms.id}`);
            } catch (error) {
                logger.error('Error setting up terms enforcement:', error);
            }
        });
    }

    /**
     * Generate OpenAPI specification
     */
    generateOpenAPISpec() {
        return {
            '/updates': {
                get: {
                    summary: 'Get update policies',
                    tags: ['Updates'],
                    responses: {
                        '200': {
                            description: 'List of update policies',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'array',
                                        items: { $ref: '#/components/schemas/UpdatePolicy' }
                                    }
                                }
                            }
                        }
                    }
                },
                post: {
                    summary: 'Create update policy',
                    tags: ['Updates'],
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/UpdatePolicyRequest' }
                            }
                        }
                    },
                    responses: {
                        '201': {
                            description: 'Update policy created',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/UpdatePolicy' }
                                }
                            }
                        }
                    }
                }
            },
            '/remote-actions': {
                post: {
                    summary: 'Execute remote action',
                    tags: ['Remote Actions'],
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/RemoteActionRequest' }
                            }
                        }
                    },
                    responses: {
                        '200': {
                            description: 'Remote action executed',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/RemoteActionResponse' }
                                }
                            }
                        }
                    }
                }
            }
            // Additional endpoints would be defined here
        };
    }

    /**
     * Start the service
     */
    async start() {
        try {
            const port = config.port || 3000;
            const host = config.host || '0.0.0.0';

            this.server = this.app.listen(port, host, () => {
                logger.info(`OpenDirectory Update Management Service started on ${host}:${port}`);
                logger.info(`Health check available at: http://${host}:${port}/health`);
                logger.info(`API documentation available at: http://${host}:${port}/api/v1/docs`);
            });

            this.server.on('error', (err) => {
                logger.error('Server error:', err);
                this.emit('error', err);
            });

            // Graceful shutdown handling
            process.on('SIGTERM', () => this.shutdown('SIGTERM'));
            process.on('SIGINT', () => this.shutdown('SIGINT'));

            this.emit('started');
            
            return this.server;

        } catch (error) {
            logger.error('Failed to start service:', error);
            throw error;
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(signal) {
        logger.info(`Received ${signal}, starting graceful shutdown...`);

        if (this.server) {
            this.server.close(async (err) => {
                if (err) {
                    logger.error('Error during server shutdown:', err);
                }

                try {
                    // Close database connections, cleanup resources
                    await this.cleanup();
                    logger.info('Graceful shutdown completed');
                    process.exit(0);
                } catch (cleanupError) {
                    logger.error('Error during cleanup:', cleanupError);
                    process.exit(1);
                }
            });
        }
    }

    /**
     * Cleanup resources
     */
    async cleanup() {
        logger.info('Starting cleanup...');
        
        // Cleanup services
        for (const [serviceName, service] of Object.entries(this.services)) {
            if (service.cleanup && typeof service.cleanup === 'function') {
                try {
                    await service.cleanup();
                    logger.info(`${serviceName} cleaned up successfully`);
                } catch (error) {
                    logger.error(`Error cleaning up ${serviceName}:`, error);
                }
            }
        }

        logger.info('Cleanup completed');
    }
}

// Export service class and start if this file is run directly
module.exports = UpdateManagementService;

if (require.main === module) {
    const service = new UpdateManagementService();
    
    service.start().catch((error) => {
        logger.error('Failed to start Update Management Service:', error);
        process.exit(1);
    });
}