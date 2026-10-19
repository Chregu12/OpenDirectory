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
const SessionRecorder = require('./pim/sessionRecorder');
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
const { oidcAuth } = require('./middleware/oidcAuth');
const auditMiddleware = require('./middleware/audit');
const { rateLimitMiddleware } = require('./middleware/rateLimit');

// Import database pool
const db = require('./db');

// Import configuration
const config = require('./config');

// ── EventBusClient ────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'conditional-access' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }
// ─────────────────────────────────────────────────────────────────────────────

class ConditionalAccessService {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3007;
        this.logger = this.setupLogger();

        // Initialize core engines
        this.conditionalAccessEngine = new ConditionalAccessEngine();
        this.deviceComplianceEngine = new DeviceComplianceEngine();
        // Encryption manager — pass the DB pool so recovery keys survive a restart
        // (DB-first with in-memory fallback; see EncryptionManager.storeRecoveryKey/getRecoveryKey)
        this.encryptionManager = new EncryptionManager(null, db);
        this.autopilotDeployment = new AutopilotDeployment();
        this.edrIntegration = new EDRIntegration();
        // Emergency access (break-glass) — pass the DB pool so grant/terminate
        // events are written to the WORM break_glass_audit table via BreakGlassAuditRepository
        this.emergencyAccessService = new EmergencyAccessService(db);
        this.auditLogger = new AuditLogger();

        // Session recorder — pass the real DB pool so sessions are persisted
        this.sessionRecorder = new SessionRecorder(db);

        // PIM service — wire in event bus publisher, session recorder, and the DB
        // pool (break-glass activate/terminate events are persisted via
        // BreakGlassAuditRepository; see PIMService constructor)
        this.pimService = new PIMService({
            publishFn: publish,
            sessionRecorder: this.sessionRecorder,
            db
        });

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

        this.app.use(rateLimitMiddleware);
        this.app.use(auditMiddleware(this.auditLogger));

        // Authentication middleware — OIDC/RS256 via JWKS (replaces shared JWT_SECRET)
        this.app.use(oidcAuth({ skipPaths: ['/health', '/metrics', '/discovery'] }));
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

        apiV1.use('/conditional-access', this.conditionalAccessController.getRouter());
        apiV1.use('/device-compliance', this.deviceComplianceController.getRouter());
        apiV1.use('/encryption', this.encryptionController.getRouter());
        apiV1.use('/deployment', this.deploymentController.getRouter());

        // PIM routes (existing controller)
        apiV1.use('/pim', this.pimController.getRouter());

        // ── PIM session recording endpoints ──────────────────────────────────
        const pim = apiV1; // mount under /pim prefix via the router below

        apiV1.get('/pim/sessions', async (req, res, next) => {
            try {
                const { userId, roleId, from, to, limit } = req.query;
                const records = await this.sessionRecorder.listSessionRecords({
                    userId,
                    roleId,
                    from: from ? new Date(from) : undefined,
                    to: to ? new Date(to) : undefined,
                    limit: limit ? parseInt(limit, 10) : 100
                });
                res.json({ sessions: records, total: records.length });
            } catch (err) {
                next(err);
            }
        });

        apiV1.get('/pim/sessions/:id', async (req, res, next) => {
            try {
                const record = await this.sessionRecorder.getSessionRecord(req.params.id);
                if (!record) {
                    return res.status(404).json({ error: 'Session record not found' });
                }
                res.json(record);
            } catch (err) {
                next(err);
            }
        });

        apiV1.get('/pim/sessions/:id/replay', async (req, res, next) => {
            try {
                const activities = await this.sessionRecorder.replaySession(req.params.id);
                res.json({ sessionRecordId: req.params.id, activities, total: activities.length });
            } catch (err) {
                next(err);
            }
        });

        // ── Break-glass endpoints ─────────────────────────────────────────────
        apiV1.post('/pim/breakglass/request', async (req, res, next) => {
            try {
                const { userId, reason, systemsAffected, estimatedDuration } = req.body;
                if (!userId || !reason || !estimatedDuration) {
                    return res.status(400).json({ error: 'userId, reason, and estimatedDuration are required' });
                }
                const result = await this.pimService.requestBreakGlass(userId, {
                    reason,
                    systemsAffected,
                    estimatedDuration
                });
                res.status(201).json(result);
            } catch (err) {
                next(err);
            }
        });

        apiV1.post('/pim/breakglass/:id/activate', async (req, res, next) => {
            try {
                const { managerId } = req.body;
                if (!managerId) {
                    return res.status(400).json({ error: 'managerId is required' });
                }
                const result = await this.pimService.activateBreakGlass(req.params.id, managerId);
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        apiV1.post('/pim/breakglass/:id/terminate', async (req, res, next) => {
            try {
                const { terminatedBy, outcome } = req.body;
                if (!terminatedBy) {
                    return res.status(400).json({ error: 'terminatedBy is required' });
                }
                const result = await this.pimService.terminateBreakGlass(req.params.id, {
                    terminatedBy,
                    outcome: outcome || 'Manual termination'
                });
                res.json(result);
            } catch (err) {
                next(err);
            }
        });

        apiV1.get('/pim/breakglass', async (req, res, next) => {
            try {
                const { from, to } = req.query;
                const events = await this.pimService.listBreakGlassEvents({
                    from: from ? new Date(from) : undefined,
                    to: to ? new Date(to) : undefined
                });
                res.json({ events, total: events.length });
            } catch (err) {
                next(err);
            }
        });

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
                    pimSessions: '/api/v1/pim/sessions',
                    pimBreakGlass: '/api/v1/pim/breakglass',
                    emergencyAccess: '/api/v1/emergency-access'
                },
                capabilities: [
                    'zero-trust-access',
                    'device-compliance',
                    'disk-encryption',
                    'autopilot-deployment',
                    'edr-integration',
                    'privileged-identity-management',
                    'pim-session-recording',
                    'pim-break-glass',
                    'pim-multi-approver-chains',
                    'emergency-access',
                    'comprehensive-auditing'
                ]
            });
        });
    }

    setupErrorHandling() {
        this.app.use((req, res) => {
            res.status(404).json({
                error: 'Not Found',
                message: 'The requested resource was not found',
                timestamp: new Date().toISOString()
            });
        });

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
            this.logger.info('Initializing Conditional Access Service...');

            // Initialize the Postgres pool (encryption recovery keys, break-glass
            // WORM audit, PIM session recordings). db.initDb() is fully
            // self-contained: it catches its own connection errors, logs a
            // warning, and leaves db.isAvailable() === false rather than
            // throwing — so this is safe to call unconditionally, including in
            // environments with no database configured. Without this call the
            // migrations never run and dependents silently stayed in-memory-only.
            try {
                await db.initDb();
            } catch (err) {
                this.logger.warn(`db.initDb() failed unexpectedly, continuing with in-memory fallback: ${err.message}`);
            }

            await this.conditionalAccessEngine.initialize();
            await this.deviceComplianceEngine.initialize();
            await this.encryptionManager.initialize();
            await this.autopilotDeployment.initialize();
            await this.edrIntegration.initialize();
            await this.pimService.initialize();
            await this.emergencyAccessService.initialize();
            await this.auditLogger.initialize();

            this.logger.info('All engines initialized successfully');

            // Wire up EventBus publish calls for security decisions
            this.conditionalAccessEngine.on('accessEvaluated', (ev) => {
                const decision = ev.accessDecision && ev.accessDecision.action;
                const payload = {
                    userId: ev.userId,
                    deviceId: ev.deviceId,
                    resource: ev.application,
                    timestamp: ev.timestamp instanceof Date ? ev.timestamp.toISOString() : ev.timestamp,
                };
                if (decision === 'ALLOW') {
                    publish('security.access.granted', payload);
                } else if (decision === 'DENY' || decision === 'BLOCK') {
                    publish('security.access.denied', { ...payload, reason: ev.accessDecision.reasons && ev.accessDecision.reasons[0] });
                }
            });

            this.pimService.on('elevationApproved', (ev) => {
                publish('security.pim.granted', {
                    userId: ev.userId,
                    role: ev.roleId,
                    justification: ev.approvalReason,
                    timestamp: new Date().toISOString(),
                });
            });

            this.emergencyAccessService.on('emergencyAccessGranted', (ev) => {
                publish('security.emergency.access.activated', {
                    userId: ev.requester,
                    activatedBy: ev.emergencyAccount,
                    timestamp: new Date().toISOString(),
                });
            });

            // Start background services
            this.startBackgroundServices();

            this.logger.info('Conditional Access Service ready');

        } catch (error) {
            this.logger.error('Failed to initialize Conditional Access Service:', error);
            throw error;
        }
    }

    startBackgroundServices() {
        this.deviceComplianceEngine.startContinuousMonitoring();
        this.edrIntegration.startThreatMonitoring();

        // Start PIM session monitoring (startSessionMonitoring() is the
        // backward-compat alias for startPeriodicSessionMonitoring(),
        // see PIMService.js)
        this.pimService.startSessionMonitoring();

        // Start audit log processing
        this.auditLogger.startLogProcessing();
        this.logger.info('Background services started');
    }

    async start() {
        try {
            connectBus().catch(err => this.logger.warn(`EventBusClient connect failed: ${err.message}`));
            await this.initialize();

            this.server = this.app.listen(this.port, () => {
                this.logger.info(`Conditional Access Service listening on port ${this.port}`);
                this.logger.info(`Health check: http://localhost:${this.port}/health`);
                this.logger.info(`Service discovery: http://localhost:${this.port}/discovery`);
            });

            this.setupGracefulShutdown();

        } catch (error) {
            this.logger.error('Failed to start Conditional Access Service:', error);
            process.exit(1);
        }
    }

    setupGracefulShutdown() {
        const shutdown = async (signal) => {
            this.logger.info(`Received ${signal}. Starting graceful shutdown...`);

            if (this.server) {
                this.server.close(async () => {
                    this.logger.info('HTTP server closed');

                    try {
                        await this.conditionalAccessEngine.shutdown();
                        await this.deviceComplianceEngine.shutdown();
                        await this.encryptionManager.shutdown();
                        await this.autopilotDeployment.shutdown();
                        await this.edrIntegration.shutdown();
                        await this.pimService.shutdown();
                        await this.emergencyAccessService.shutdown();
                        await this.auditLogger.shutdown();

                        this.logger.info('All services shut down successfully');
                        process.exit(0);
                    } catch (error) {
                        this.logger.error('Error during shutdown:', error);
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
