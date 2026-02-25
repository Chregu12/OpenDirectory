/**
 * OpenDirectory Conditional Access & Compliance Service
 * Zero Trust Security Implementation with Device Management
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const winston = require('winston');

// Import core engines and services
const ConditionalAccessEngine = require('./engines/ConditionalAccessEngine');
const DeviceComplianceEngine = require('./engines/DeviceComplianceEngine');
const EncryptionManager = require('./services/EncryptionManager');
const AutopilotDeployment = require('./deployment/AutopilotDeployment');
const EDRIntegration = require('./edr/EDRIntegration');
const PIMService = require('./pim/PIMService');
const EmergencyAccessService = require('./services/EmergencyAccessService');
const AuditLogger = require('./audit/AuditLogger');

// Import controllers
const ConditionalAccessController = require('./controllers/ConditionalAccessController');
const DeviceComplianceController = require('./controllers/DeviceComplianceController');
const EncryptionController = require('./controllers/EncryptionController');
const DeploymentController = require('./controllers/DeploymentController');
const PIMController = require('./controllers/PIMController');
const EmergencyAccessController = require('./controllers/EmergencyAccessController');

// Import middleware
const authMiddleware = require('./middleware/auth');
const auditMiddleware = require('./middleware/audit');
const rateLimitMiddleware = require('./middleware/rateLimit');

// Import configuration
const config = require('./config');

class ConditionalAccessService {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3007;
        this.logger = this.setupLogger();
        
        // Initialize core engines
        this.conditionalAccessEngine = new ConditionalAccessEngine();
        this.deviceComplianceEngine = new DeviceComplianceEngine();
        this.encryptionManager = new EncryptionManager();
        this.autopilotDeployment = new AutopilotDeployment();
        this.edrIntegration = new EDRIntegration();
        this.pimService = new PIMService();
        this.emergencyAccessService = new EmergencyAccessService();
        this.auditLogger = new AuditLogger();
        
        // Initialize controllers
        this.setupControllers();
        
        this.setupMiddleware();
        this.setupRoutes();
        this.setupErrorHandling();
    }

    setupLogger() {
        return winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            defaultMeta: { service: 'conditional-access' },
            transports: [
                new winston.transports.File({ 
                    filename: 'logs/conditional-access-error.log', 
                    level: 'error' 
                }),
                new winston.transports.File({ 
                    filename: 'logs/conditional-access.log' 
                }),
                new winston.transports.Console({
                    format: winston.format.simple()
                })
            ]
        });
    }

    setupControllers() {
        this.conditionalAccessController = new ConditionalAccessController(
            this.conditionalAccessEngine, 
            this.auditLogger
        );
        this.deviceComplianceController = new DeviceComplianceController(
            this.deviceComplianceEngine, 
            this.auditLogger
        );
        this.encryptionController = new EncryptionController(
            this.encryptionManager, 
            this.auditLogger
        );
        this.deploymentController = new DeploymentController(
            this.autopilotDeployment, 
            this.auditLogger
        );
        this.pimController = new PIMController(
            this.pimService, 
            this.auditLogger
        );
        this.emergencyAccessController = new EmergencyAccessController(
            this.emergencyAccessService, 
            this.auditLogger
        );
    }

    setupMiddleware() {
        // Security middleware
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    connectSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                }
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            }
        }));
        
        this.app.use(cors({
            origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
            credentials: true
        }));
        
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true }));
        
        // Rate limiting
        this.app.use(rateLimitMiddleware);
        
        // Audit middleware
        this.app.use(auditMiddleware(this.auditLogger));
        
        // Authentication middleware (applied to protected routes)
        this.app.use('/api/v1', authMiddleware);
    }

    setupRoutes() {
        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'conditional-access',
                version: '1.0.0'
            });
        });

        // API routes
        const apiV1 = express.Router();
        
        // Conditional Access routes
        apiV1.use('/conditional-access', this.conditionalAccessController.getRouter());
        
        // Device Compliance routes
        apiV1.use('/device-compliance', this.deviceComplianceController.getRouter());
        
        // Encryption Management routes
        apiV1.use('/encryption', this.encryptionController.getRouter());
        
        // Deployment routes
        apiV1.use('/deployment', this.deploymentController.getRouter());
        
        // PIM routes
        apiV1.use('/pim', this.pimController.getRouter());
        
        // Emergency Access routes
        apiV1.use('/emergency-access', this.emergencyAccessController.getRouter());
        
        this.app.use('/api/v1', apiV1);

        // Service discovery endpoint
        this.app.get('/discovery', (req, res) => {
            res.json({
                name: 'conditional-access-service',
                version: '1.0.0',
                endpoints: {
                    health: '/health',
                    conditionalAccess: '/api/v1/conditional-access',
                    deviceCompliance: '/api/v1/device-compliance',
                    encryption: '/api/v1/encryption',
                    deployment: '/api/v1/deployment',
                    pim: '/api/v1/pim',
                    emergencyAccess: '/api/v1/emergency-access'
                },
                capabilities: [
                    'zero-trust-access',
                    'device-compliance',
                    'disk-encryption',
                    'autopilot-deployment',
                    'edr-integration',
                    'privileged-identity-management',
                    'emergency-access',
                    'comprehensive-auditing'
                ]
            });
        });
    }

    setupErrorHandling() {
        // 404 handler
        this.app.use((req, res) => {
            res.status(404).json({
                error: 'Not Found',
                message: 'The requested resource was not found',
                timestamp: new Date().toISOString()
            });
        });

        // Global error handler
        this.app.use((err, req, res, next) => {
            this.logger.error('Unhandled error:', {
                error: err.message,
                stack: err.stack,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });

            res.status(err.statusCode || 500).json({
                error: err.name || 'Internal Server Error',
                message: process.env.NODE_ENV === 'production' 
                    ? 'An error occurred while processing your request' 
                    : err.message,
                timestamp: new Date().toISOString()
            });
        });
    }

    async initialize() {
        try {
            this.logger.info('🔐 Initializing Conditional Access Service...');
            
            // Initialize core engines
            await this.conditionalAccessEngine.initialize();
            await this.deviceComplianceEngine.initialize();
            await this.encryptionManager.initialize();
            await this.autopilotDeployment.initialize();
            await this.edrIntegration.initialize();
            await this.pimService.initialize();
            await this.emergencyAccessService.initialize();
            await this.auditLogger.initialize();
            
            this.logger.info('✅ All engines initialized successfully');
            
            // Start background services
            this.startBackgroundServices();
            
            this.logger.info('🚀 Conditional Access Service ready');
            
        } catch (error) {
            this.logger.error('❌ Failed to initialize Conditional Access Service:', error);
            throw error;
        }
    }

    startBackgroundServices() {
        // Start continuous compliance monitoring
        this.deviceComplianceEngine.startContinuousMonitoring();
        
        // Start EDR monitoring
        this.edrIntegration.startThreatMonitoring();
        
        // Start PIM session monitoring
        this.pimService.startSessionMonitoring();
        
        // Start audit log processing
        this.auditLogger.startLogProcessing();
        
        this.logger.info('🔄 Background services started');
    }

    async start() {
        try {
            await this.initialize();
            
            this.server = this.app.listen(this.port, () => {
                this.logger.info(`🔐 Conditional Access Service listening on port ${this.port}`);
                this.logger.info(`📊 Health check: http://localhost:${this.port}/health`);
                this.logger.info(`🔍 Service discovery: http://localhost:${this.port}/discovery`);
            });
            
            // Graceful shutdown
            this.setupGracefulShutdown();
            
        } catch (error) {
            this.logger.error('❌ Failed to start Conditional Access Service:', error);
            process.exit(1);
        }
    }

    setupGracefulShutdown() {
        const shutdown = async (signal) => {
            this.logger.info(`🛑 Received ${signal}. Starting graceful shutdown...`);
            
            if (this.server) {
                this.server.close(async () => {
                    this.logger.info('✅ HTTP server closed');
                    
                    try {
                        // Cleanup resources
                        await this.conditionalAccessEngine.shutdown();
                        await this.deviceComplianceEngine.shutdown();
                        await this.encryptionManager.shutdown();
                        await this.autopilotDeployment.shutdown();
                        await this.edrIntegration.shutdown();
                        await this.pimService.shutdown();
                        await this.emergencyAccessService.shutdown();
                        await this.auditLogger.shutdown();
                        
                        this.logger.info('✅ All services shut down successfully');
                        process.exit(0);
                    } catch (error) {
                        this.logger.error('❌ Error during shutdown:', error);
                        process.exit(1);
                    }
                });
            }
        };

        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));
    }
}

// Start the service
if (require.main === module) {
    const service = new ConditionalAccessService();
    service.start().catch(error => {
        console.error('Failed to start Conditional Access Service:', error);
        process.exit(1);
    });
}

module.exports = ConditionalAccessService;