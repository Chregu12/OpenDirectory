/**
 * OpenDirectory Enterprise Directory Service
 * Complete Active Directory replacement for Windows, macOS, and Linux
 * 
 * Features:
 * - Active Directory domain services
 * - LDAP directory services
 * - Kerberos authentication
 * - Group Policy management (Windows, macOS, Linux)
 * - Single Sign-On (OAuth2, OIDC, SAML)
 * - Certificate Authority (PKI)
 * - Device join services
 * - DNS integration
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const Redis = require('redis');
const { v4: uuidv4 } = require('uuid');

// ── EventBusClient ────────────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'enterprise-directory' });
async function connectBus() { await _bus.connect(); }
// ─────────────────────────────────────────────────────────────────────────────
const path = require('path');
const fs = require('fs');

// Import configuration and utilities
const config = require('./config');
const { logger, performanceMiddleware, logHelpers } = require('./utils/logger');

// Import services
const ActiveDirectoryService = require('./services/activeDirectoryService');
const LDAPService = require('./services/ldapService');
const KerberosService = require('./services/kerberosService');
const GroupPolicyService = require('./services/groupPolicyService');
const SSOService = require('./services/ssoService');
const DeviceJoinService = require('./services/deviceJoinService');
const CertificateAuthorityService = require('./services/certificateAuthorityService');
const DNSIntegrationService = require('./services/dnsIntegrationService');

// Import controllers
const DirectoryController = require('./controllers/directoryController');
const AuthenticationController = require('./controllers/authenticationController');
const GroupPolicyController = require('./controllers/groupPolicyController');
const SSOController = require('./controllers/ssoController');
const DeviceController = require('./controllers/deviceController');
const CertificateController = require('./controllers/certificateController');

// Import middleware
const authMiddleware = require('./middleware/auth');
const validationMiddleware = require('./middleware/validation');
const auditMiddleware = require('./middleware/audit');

class EnterpriseDirectoryService {
  constructor() {
    this.app = express();
    this.server = null;
    this.services = new Map();
    this.isInitialized = false;
    
    // Database connections
    this.mongodb = null;
    this.redis = null;
    this.rabbitmq = null; // legacy field kept for health-check compat
    
    // Service instances
    this.activeDirectoryService = null;
    this.ldapService = null;
    this.kerberosService = null;
    this.groupPolicyService = null;
    this.ssoService = null;
    this.deviceJoinService = null;
    this.certificateAuthorityService = null;
    this.dnsIntegrationService = null;
    
    // Initialize the service
    this.initialize();
  }

  async initialize() {
    try {
      logger.info('🚀 Initializing OpenDirectory Enterprise Directory Service...');

      // Create necessary directories
      await this.createDirectories();

      // Setup middleware
      this.setupMiddleware();

      // Connect to databases
      await this.connectDatabases();

      // Initialize core services
      await this.initializeServices();

      // Setup routes
      this.setupRoutes();

      // Setup error handling
      this.setupErrorHandling();

      // Setup graceful shutdown
      this.setupGracefulShutdown();

      this.isInitialized = true;
      logger.info('✅ Enterprise Directory Service initialized successfully');

    } catch (error) {
      logger.error('❌ Failed to initialize Enterprise Directory Service:', error);
      process.exit(1);
    }
  }

  async createDirectories() {
    const directories = [
      './data/certs',
      './data/keys', 
      './data/policies',
      './data/policies/computer',
      './data/policies/user',
      './data/policies/templates',
      './data/logs',
      './data/cache',
      './data/kerberos',
      './data/ldap',
      './data/backups'
    ];

    for (const dir of directories) {
      fs.mkdirSync(dir, { recursive: true });
    }

    logger.info('📁 Created data directories');
  }

  setupMiddleware() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "ws:", "wss:"]
        }
      }
    }));

    // Compression
    this.app.use(compression());

    // CORS
    this.app.use(cors({
      origin: true,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Client-ID']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: config.performance.rateLimiting.windowMs,
      max: config.performance.rateLimiting.max,
      message: {
        error: 'Too many requests',
        retryAfter: Math.ceil(config.performance.rateLimiting.windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use(limiter);

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request ID and logging
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || uuidv4();
      req.startTime = Date.now();
      res.setHeader('X-Request-ID', req.id);
      res.setHeader('X-Service', 'enterprise-directory');
      res.setHeader('X-Version', config.server.version);
      next();
    });

    // Performance tracking
    this.app.use(performanceMiddleware);

    // Audit middleware
    this.app.use(auditMiddleware);

    logger.info('🔧 Middleware configured');
  }

  async connectDatabases() {
    try {
      // Connect to MongoDB
      this.mongodb = await mongoose.connect(config.database.mongodb.url, config.database.mongodb.options);
      logger.info('🗄️ Connected to MongoDB');

      // Connect to Redis
      this.redis = Redis.createClient({
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        keyPrefix: config.redis.keyPrefix,
        db: config.redis.db
      });
      
      this.redis.on('error', (error) => {
        logger.error('Redis connection error:', error);
      });
      
      await this.redis.connect();
      logger.info('🔄 Connected to Redis');

      // Connect to generic event bus (fire and forget)
      connectBus().catch((err) => {
        logger.warn(`EventBusClient connection failed (non-critical): ${err.message}`);
      });
      logger.info('🚌 EventBusClient connecting');

    } catch (error) {
      logger.error('❌ Database connection failed:', error);
      throw error;
    }
  }

  async initializeServices() {
    try {
      // Initialize Certificate Authority first (needed by other services)
      this.certificateAuthorityService = new CertificateAuthorityService(config, this.mongodb, this.redis);
      await this.certificateAuthorityService.initialize();
      this.services.set('certificateAuthority', this.certificateAuthorityService);

      // Initialize DNS Integration Service
      this.dnsIntegrationService = new DNSIntegrationService(config, this.mongodb, this.redis);
      await this.dnsIntegrationService.initialize();
      this.services.set('dnsIntegration', this.dnsIntegrationService);

      // Initialize Kerberos Service
      this.kerberosService = new KerberosService(config, this.mongodb, this.redis, this.certificateAuthorityService);
      await this.kerberosService.initialize();
      this.services.set('kerberos', this.kerberosService);

      // Initialize LDAP Service
      this.ldapService = new LDAPService(config, this.mongodb, this.redis, this.kerberosService, this.certificateAuthorityService);
      await this.ldapService.initialize();
      this.services.set('ldap', this.ldapService);

      // Initialize Active Directory Service
      this.activeDirectoryService = new ActiveDirectoryService(config, this.mongodb, this.redis, this.ldapService, this.kerberosService);
      await this.activeDirectoryService.initialize();
      this.services.set('activeDirectory', this.activeDirectoryService);

      // Initialize Group Policy Service
      this.groupPolicyService = new GroupPolicyService(config, this.mongodb, this.redis, this.activeDirectoryService);
      await this.groupPolicyService.initialize();
      this.services.set('groupPolicy', this.groupPolicyService);

      // Initialize SSO Service
      this.ssoService = new SSOService(config, this.mongodb, this.redis, this.activeDirectoryService, this.certificateAuthorityService);
      await this.ssoService.initialize();
      this.services.set('sso', this.ssoService);

      // Initialize Device Join Service
      this.deviceJoinService = new DeviceJoinService(config, this.mongodb, this.redis, this.activeDirectoryService, this.certificateAuthorityService);
      await this.deviceJoinService.initialize();
      this.services.set('deviceJoin', this.deviceJoinService);

      logger.info('🛠️ All services initialized successfully');

    } catch (error) {
      logger.error('❌ Service initialization failed:', error);
      throw error;
    }
  }

  setupRoutes() {
    // Health and status endpoints
    this.app.get('/health', this.healthCheck.bind(this));
    this.app.get('/status', this.statusCheck.bind(this));
    this.app.get('/info', this.serviceInfo.bind(this));

    // Directory services routes
    const directoryController = new DirectoryController(this.activeDirectoryService, this.ldapService);
    this.app.use('/api/directory', directoryController.getRoutes());

    // Authentication routes
    const authController = new AuthenticationController(this.activeDirectoryService, this.kerberosService, this.ssoService);
    this.app.use('/api/auth', authController.getRoutes());

    // Group Policy routes
    const policyController = new GroupPolicyController(this.groupPolicyService);
    this.app.use('/api/policy', authMiddleware, policyController.getRoutes());

    // SSO routes
    const ssoController = new SSOController(this.ssoService);
    this.app.use('/api/sso', ssoController.getRoutes());
    this.app.use('/oauth2', ssoController.getOAuth2Routes());
    this.app.use('/oidc', ssoController.getOIDCRoutes());
    this.app.use('/saml', ssoController.getSAMLRoutes());

    // Device management routes
    const deviceController = new DeviceController(this.deviceJoinService, this.activeDirectoryService);
    this.app.use('/api/devices', authMiddleware, deviceController.getRoutes());

    // Certificate services routes
    const certController = new CertificateController(this.certificateAuthorityService);
    this.app.use('/api/certificates', authMiddleware, certController.getRoutes());

    // LDAP endpoints (direct LDAP protocol handling)
    this.app.use('/ldap', (req, res) => {
      res.status(200).json({
        message: 'LDAP service running',
        port: config.ldap.port,
        securePort: config.ldap.securePort,
        baseDN: config.ldap.baseDN
      });
    });

    // Kerberos endpoints
    this.app.use('/kerberos', (req, res) => {
      res.status(200).json({
        message: 'Kerberos service running',
        realm: config.kerberos.realm,
        kdcPort: config.kerberos.kdcPort,
        adminPort: config.kerberos.adminPort
      });
    });

    // DNS service info
    this.app.use('/dns', (req, res) => {
      res.status(200).json({
        message: 'DNS integration service running',
        port: config.dns.port,
        enabled: config.dns.enabled,
        dynamicUpdates: config.dns.dynamicUpdates
      });
    });

    logger.info('🛣️ Routes configured');
  }

  setupErrorHandling() {
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString()
      });
    });

    // Global error handler
    this.app.use((error, req, res, next) => {
      logHelpers.logError(error, {
        requestId: req.id,
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent']
      });

      const isDevelopment = config.server.environment === 'development';
      
      res.status(error.status || 500).json({
        error: error.message || 'Internal Server Error',
        requestId: req.id,
        timestamp: new Date().toISOString(),
        ...(isDevelopment && { stack: error.stack })
      });
    });

    logger.info('🛡️ Error handling configured');
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      logger.info(`🛑 Received ${signal}, starting graceful shutdown...`);

      // Stop accepting new connections
      if (this.server) {
        this.server.close(() => {
          logger.info('✅ HTTP server closed');
        });
      }

      try {
        // Stop services
        for (const [name, service] of this.services) {
          if (service && typeof service.stop === 'function') {
            await service.stop();
            logger.info(`✅ Stopped ${name} service`);
          }
        }

        // Close database connections
        if (this.mongodb) {
          await mongoose.connection.close();
          logger.info('✅ MongoDB connection closed');
        }

        if (this.redis) {
          await this.redis.quit();
          logger.info('✅ Redis connection closed');
        }

        await _bus.close().catch(() => {});
        logger.info('✅ EventBusClient closed');

        logger.info('✅ Graceful shutdown completed');
        process.exit(0);

      } catch (error) {
        logger.error('❌ Error during shutdown:', error);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGUSR2', () => shutdown('SIGUSR2')); // nodemon restart

    logger.info('🔄 Graceful shutdown handlers configured');
  }

  // Health check endpoint
  async healthCheck(req, res) {
    try {
      const healthChecks = {
        service: 'healthy',
        mongodb: 'unknown',
        redis: 'unknown',
        rabbitmq: 'unknown',
        services: {}
      };

      // Check MongoDB
      try {
        await mongoose.connection.db.admin().ping();
        healthChecks.mongodb = 'healthy';
      } catch (error) {
        healthChecks.mongodb = 'unhealthy';
      }

      // Check Redis
      try {
        await this.redis.ping();
        healthChecks.redis = 'healthy';
      } catch (error) {
        healthChecks.redis = 'unhealthy';
      }

      // Check event bus
      try {
        healthChecks.rabbitmq = _bus.isConnected() ? 'healthy' : 'unhealthy';
      } catch (error) {
        healthChecks.rabbitmq = 'unhealthy';
      }

      // Check individual services
      for (const [name, service] of this.services) {
        try {
          if (service && typeof service.healthCheck === 'function') {
            healthChecks.services[name] = await service.healthCheck();
          } else {
            healthChecks.services[name] = 'running';
          }
        } catch (error) {
          healthChecks.services[name] = 'unhealthy';
        }
      }

      // Determine overall health
      const isHealthy = healthChecks.mongodb === 'healthy' && 
                       healthChecks.redis === 'healthy' && 
                       healthChecks.rabbitmq === 'healthy' &&
                       Object.values(healthChecks.services).every(status => 
                         status === 'healthy' || status === 'running'
                       );

      res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        ...healthChecks
      });

    } catch (error) {
      res.status(503).json({
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  // Status check endpoint
  async statusCheck(req, res) {
    try {
      const status = {
        service: 'enterprise-directory',
        version: config.server.version,
        environment: config.server.environment,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        features: {
          activeDirectory: config.activeDirectory,
          ldap: { port: config.ldap.port, securePort: config.ldap.securePort },
          kerberos: { realm: config.kerberos.realm, kdcPort: config.kerberos.kdcPort },
          groupPolicy: {
            windows: config.groupPolicy.enableWindowsGPO,
            macos: config.groupPolicy.enableMacOSProfiles,
            linux: config.groupPolicy.enableLinuxPolicies
          },
          sso: {
            oauth2: config.sso.oauth2.enabled,
            oidc: config.sso.oidc.enabled,
            saml: config.sso.saml.enabled
          },
          pki: config.pki.enabled,
          dns: config.dns.enabled
        },
        services: {}
      };

      // Get service status
      for (const [name, service] of this.services) {
        try {
          if (service && typeof service.getStatus === 'function') {
            status.services[name] = await service.getStatus();
          } else {
            status.services[name] = { status: 'running' };
          }
        } catch (error) {
          status.services[name] = { status: 'error', error: error.message };
        }
      }

      res.json(status);

    } catch (error) {
      res.status(500).json({
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  // Service info endpoint
  serviceInfo(req, res) {
    res.json({
      name: 'OpenDirectory Enterprise Directory Service',
      description: 'Complete Active Directory replacement for Windows, macOS, and Linux',
      version: config.server.version,
      features: [
        'Active Directory domain services',
        'LDAP directory services',
        'Kerberos authentication',
        'Group Policy management',
        'Single Sign-On (OAuth2, OIDC, SAML)',
        'Certificate Authority (PKI)',
        'Device join services',
        'DNS integration'
      ],
      endpoints: {
        health: '/health',
        status: '/status',
        directory: '/api/directory',
        auth: '/api/auth',
        policy: '/api/policy',
        sso: '/api/sso',
        devices: '/api/devices',
        certificates: '/api/certificates'
      },
      protocols: {
        ldap: { port: config.ldap.port, securePort: config.ldap.securePort },
        kerberos: { kdcPort: config.kerberos.kdcPort, adminPort: config.kerberos.adminPort },
        dns: { port: config.dns.port }
      }
    });
  }

  // Start the service
  start() {
    if (!this.isInitialized) {
      throw new Error('Service not initialized. Call initialize() first.');
    }

    this.server = this.app.listen(config.server.port, config.server.host, () => {
      logger.info(`🚀 OpenDirectory Enterprise Directory Service started`);
      logger.info(`📍 Server running on ${config.server.host}:${config.server.port}`);
      logger.info(`🌍 Environment: ${config.server.environment}`);
      logger.info(`📊 Health check: http://${config.server.host}:${config.server.port}/health`);
      logger.info(`📋 Status: http://${config.server.host}:${config.server.port}/status`);
      logger.info(`📖 Info: http://${config.server.host}:${config.server.port}/info`);
      logger.info(`🔐 LDAP: ldap://${config.server.host}:${config.ldap.port}`);
      logger.info(`🎫 Kerberos: ${config.kerberos.realm}@${config.server.host}:${config.kerberos.kdcPort}`);
      logger.info(`🌐 DNS: ${config.server.host}:${config.dns.port}`);
    });

    return this.server;
  }
}

// Create and start the service
const enterpriseDirectory = new EnterpriseDirectoryService();

// Handle unhandled rejections and exceptions
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start the service
if (require.main === module) {
  enterpriseDirectory.start();
}

module.exports = EnterpriseDirectoryService;