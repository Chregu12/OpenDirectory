/**
 * OpenDirectory Certificate & Network Configuration Service
 * Main service entry point with Enterprise Directory integration
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const mongoose = require('mongoose');
const Redis = require('redis');

// ─── RabbitMQ Event Bus ───────────────────────────────────────────────────────
let channel, connection;

async function connectBus() {
  try {
    const amqplib = require('amqplib');
    const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://opendirectory:changeme@rabbitmq:5672/';
    try {
      connection = await amqplib.connect(RABBITMQ_URL);
      connection.on('error', () => { channel = null; });
      connection.on('close', () => { channel = null; setTimeout(connectBus, 5000); });
      channel = await connection.createChannel();
      await channel.assertExchange('opendirectory.events', 'topic', { durable: true });
      console.log('[bus] RabbitMQ connected');
    } catch (e) {
      console.warn('[bus] RabbitMQ unavailable, retrying in 10s:', e.message);
      setTimeout(connectBus, 10000);
    }
  } catch (e) {
    console.warn('[bus] connectBus error:', e.message);
  }
}

function publish(routingKey, payload) {
  if (!channel) return;
  try {
    channel.publish('opendirectory.events', routingKey,
      Buffer.from(JSON.stringify({ ...payload, _source: 'certificate-network', _ts: Date.now() })),
      { persistent: true, contentType: 'application/json' }
    );
  } catch (e) { /* fail silently */ }
}

// Configuration
const config = require('./config');

// Utilities
const { logger } = require('./utils/logger');

// Core Services
const EnterpriseCAService = require('./services/EnterpriseCAService');
const CertificateLifecycleService = require('./services/CertificateLifecycleService');
const WiFiProfileService = require('./services/WiFiProfileService');
const VPNProfileService = require('./services/VPNProfileService');
const EmailProfileService = require('./services/EmailProfileService');
const RadiusAuthService = require('./services/RadiusAuthService');
const SCEPService = require('./services/SCEPService');
const CertificateDistributionService = require('./services/CertificateDistributionService');

// Enterprise Directory Integration
const IntegrationManager = require('./integrations');

// Routes
const certificateRoutes = require('./routes/certificates');
const profileRoutes = require('./routes/profiles');
const authRoutes = require('./routes/auth');
const healthRoutes = require('./routes/health');

class CertificateNetworkService {
  constructor() {
    this.app = express();
    this.server = null;
    this.mongodb = null;
    this.redis = null;
    
    // Core services
    this.services = {};
    
    // Integration manager
    this.integrationManager = null;
    
    // Service state
    this.initialized = false;
    this.healthy = false;
    
    logger.info('🚀 OpenDirectory Certificate & Network Service starting...');
  }

  async initialize() {
    try {
      // Initialize databases
      await this.initializeDatabases();
      
      // Initialize core services
      await this.initializeCoreServices();
      
      // Initialize Enterprise Directory integration
      await this.initializeIntegration();
      
      // Initialize Express application
      this.initializeExpress();
      
      // Start server
      await this.startServer();
      
      this.initialized = true;
      this.healthy = true;
      
      logger.info('✅ Certificate & Network Service initialized successfully');
      
    } catch (error) {
      logger.error('❌ Failed to initialize Certificate & Network Service:', error);
      throw error;
    }
  }

  async initializeDatabases() {
    try {
      logger.info('🔌 Connecting to databases...');

      // MongoDB connection
      this.mongodb = await mongoose.connect(config.database.mongodb.url, config.database.mongodb.options);
      logger.info('✅ MongoDB connected');

      // Redis connection
      this.redis = Redis.createClient({
        host: config.database.redis.host,
        port: config.database.redis.port,
        password: config.database.redis.password,
        db: config.database.redis.db
      });

      await this.redis.connect();
      logger.info('✅ Redis connected');

    } catch (error) {
      logger.error('❌ Database connection failed:', error);
      throw error;
    }
  }

  async initializeCoreServices() {
    try {
      logger.info('⚙️ Initializing core services...');

      // Enterprise CA Service
      this.services.enterpriseCA = new EnterpriseCAService(config);
      await this.services.enterpriseCA.initialize();
      logger.info('✅ Enterprise CA Service initialized');

      // Certificate Lifecycle Service
      this.services.certificateLifecycle = new CertificateLifecycleService(
        config, 
        this.services.enterpriseCA,
        this.mongodb,
        this.redis
      );
      await this.services.certificateLifecycle.initialize();
      logger.info('✅ Certificate Lifecycle Service initialized');

      // WiFi Profile Service
      this.services.wifiProfile = new WiFiProfileService(config);
      await this.services.wifiProfile.initialize();
      logger.info('✅ WiFi Profile Service initialized');

      // VPN Profile Service
      this.services.vpnProfile = new VPNProfileService(config);
      await this.services.vpnProfile.initialize();
      logger.info('✅ VPN Profile Service initialized');

      // Email Profile Service
      this.services.emailProfile = new EmailProfileService(config);
      await this.services.emailProfile.initialize();
      logger.info('✅ Email Profile Service initialized');

      // RADIUS Authentication Service
      this.services.radiusAuth = new RadiusAuthService(
        config,
        this.services.enterpriseCA,
        this.services.certificateLifecycle
      );
      await this.services.radiusAuth.initialize();
      logger.info('✅ RADIUS Authentication Service initialized');

      // SCEP Service
      this.services.scep = new SCEPService(
        config,
        this.services.enterpriseCA,
        this.services.certificateLifecycle
      );
      await this.services.scep.initialize();
      logger.info('✅ SCEP Service initialized');

      // Certificate Distribution Service
      this.services.certificateDistribution = new CertificateDistributionService(
        config,
        this.services.certificateLifecycle,
        this.services.wifiProfile,
        this.services.vpnProfile,
        this.services.emailProfile
      );
      await this.services.certificateDistribution.initialize();
      logger.info('✅ Certificate Distribution Service initialized');

    } catch (error) {
      logger.error('❌ Core service initialization failed:', error);
      throw error;
    }
  }

  async initializeIntegration() {
    try {
      logger.info('🔗 Initializing Enterprise Directory integration...');

      // Initialize Integration Manager
      this.integrationManager = new IntegrationManager(config, this.services);
      await this.integrationManager.initialize();

      // Set up integration event handlers
      this.setupIntegrationEventHandlers();

      logger.info('✅ Enterprise Directory integration initialized');

    } catch (error) {
      logger.error('❌ Enterprise Directory integration failed:', error);
      // Don't throw error - service can run without integration
      logger.warn('⚠️ Service will continue without Enterprise Directory integration');
    }
  }

  setupIntegrationEventHandlers() {
    if (!this.integrationManager) return;

    // Handle Enterprise Directory connection status
    this.integrationManager.on('enterpriseDirectoryConnected', () => {
      logger.info('🟢 Enterprise Directory integration connected');
    });

    this.integrationManager.on('enterpriseDirectoryDisconnected', () => {
      logger.warn('🟡 Enterprise Directory integration disconnected');
    });

    this.integrationManager.on('enterpriseDirectoryError', (error) => {
      logger.error('🔴 Enterprise Directory integration error:', error);
    });

    // Handle certificate sync events
    this.integrationManager.on('certificateFullSyncCompleted', (stats) => {
      logger.info(`📊 Certificate sync completed: ${stats.processedCount} certificates processed`);
    });

    this.integrationManager.on('profileDeploymentSynced', (event) => {
      logger.debug(`📡 Network profile deployment synced: ${event.profileType}`);
    });

    logger.info('🔗 Integration event handlers configured');
  }

  initializeExpress() {
    logger.info('🌐 Initializing Express application...');

    // Security middleware
    this.app.use(helmet());
    this.app.use(compression());

    // CORS configuration
    this.app.use(cors({
      origin: config.server.corsOrigin,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging
    this.app.use((req, res, next) => {
      logger.debug(`${req.method} ${req.path}`, { 
        ip: req.ip, 
        userAgent: req.get('User-Agent') 
      });
      next();
    });

    // Make services and integration available to routes
    this.app.use((req, res, next) => {
      req.services = this.services;
      req.integrationManager = this.integrationManager;
      next();
    });

    // Publish RabbitMQ events after profile deploy/revoke operations
    this.app.use('/api/profiles', (req, res, next) => {
      const origJson = res.json.bind(res);
      res.json = (body) => {
        if (body && body.success !== false) {
          const url = req.path;
          const profileId = body.profileId || body.id || (body.profile && body.profile.id) || 'unknown';
          const deviceId = req.body && (req.body.targetId || req.body.deviceId) || 'unknown';
          if (req.method === 'POST' && /\/(wifi|vpn|email)\/deploy/.test(url)) {
            const type = url.split('/')[1];
            publish('network.profile.deployed', { profileId, deviceId, type });
          } else if (req.method === 'DELETE' || (req.method === 'POST' && /revoke/.test(url))) {
            publish('network.profile.revoked', { profileId, deviceId });
          }
        }
        return origJson(body);
      };
      next();
    });

    // Routes
    this.app.use('/api/certificates', certificateRoutes);
    this.app.use('/api/profiles', profileRoutes);
    this.app.use('/api/auth', authRoutes);
    this.app.use('/health', healthRoutes);

    // SCEP endpoint
    this.app.use('/scep', this.services.scep.getRouter());

    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        service: 'OpenDirectory Certificate & Network Service',
        version: '1.0.0',
        status: 'running',
        timestamp: new Date().toISOString(),
        enterpriseDirectoryIntegration: this.integrationManager ? 
          this.integrationManager.getStatus().integrationStatus : 'disabled'
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.method} ${req.originalUrl} not found`,
        timestamp: new Date().toISOString()
      });
    });

    // Error handler
    this.app.use((err, req, res, next) => {
      logger.error('Express error:', err);
      
      res.status(err.status || 500).json({
        error: err.name || 'Internal Server Error',
        message: err.message || 'An unexpected error occurred',
        timestamp: new Date().toISOString(),
        ...(config.server.environment === 'development' && { stack: err.stack })
      });
    });

    logger.info('✅ Express application configured');
  }

  async startServer() {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(config.server.port, config.server.host, (error) => {
        if (error) {
          reject(error);
        } else {
          logger.info(`✅ Server listening on ${config.server.host}:${config.server.port}`);
          connectBus();
          resolve();
        }
      });

      this.server.on('error', (error) => {
        logger.error('Server error:', error);
        reject(error);
      });
    });
  }

  async healthCheck() {
    try {
      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        services: {},
        integration: null
      };

      // Check core services
      for (const [name, service] of Object.entries(this.services)) {
        try {
          if (typeof service.healthCheck === 'function') {
            health.services[name] = await service.healthCheck();
          } else {
            health.services[name] = { status: 'running' };
          }
        } catch (error) {
          health.services[name] = { status: 'unhealthy', error: error.message };
          health.status = 'degraded';
        }
      }

      // Check Enterprise Directory integration
      if (this.integrationManager) {
        try {
          health.integration = await this.integrationManager.healthCheck();
          if (health.integration.status === 'unhealthy') {
            health.status = 'degraded';
          }
        } catch (error) {
          health.integration = { status: 'unhealthy', error: error.message };
          health.status = 'degraded';
        }
      } else {
        health.integration = { status: 'disabled' };
      }

      // Check databases
      try {
        await mongoose.connection.db.admin().ping();
        health.databases = { mongodb: 'connected' };
      } catch (error) {
        health.databases = { mongodb: 'disconnected' };
        health.status = 'unhealthy';
      }

      try {
        await this.redis.ping();
        health.databases.redis = 'connected';
      } catch (error) {
        health.databases.redis = 'disconnected';
        if (health.status === 'healthy') health.status = 'degraded';
      }

      this.healthy = (health.status === 'healthy');
      return health;

    } catch (error) {
      this.healthy = false;
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  async stop() {
    logger.info('🛑 Stopping Certificate & Network Service...');

    this.healthy = false;

    // Stop Integration Manager
    if (this.integrationManager) {
      try {
        await this.integrationManager.stop();
        logger.info('✅ Enterprise Directory integration stopped');
      } catch (error) {
        logger.error('❌ Error stopping integration manager:', error);
      }
    }

    // Stop core services
    for (const [name, service] of Object.entries(this.services)) {
      try {
        if (typeof service.stop === 'function') {
          await service.stop();
          logger.info(`✅ ${name} service stopped`);
        }
      } catch (error) {
        logger.error(`❌ Error stopping ${name} service:`, error);
      }
    }

    // Close server
    if (this.server) {
      await new Promise((resolve) => {
        this.server.close(() => {
          logger.info('✅ HTTP server stopped');
          resolve();
        });
      });
    }

    // Close database connections
    try {
      if (this.mongodb) {
        await mongoose.connection.close();
        logger.info('✅ MongoDB connection closed');
      }
    } catch (error) {
      logger.error('❌ Error closing MongoDB connection:', error);
    }

    try {
      if (this.redis) {
        await this.redis.quit();
        logger.info('✅ Redis connection closed');
      }
    } catch (error) {
      logger.error('❌ Error closing Redis connection:', error);
    }

    this.initialized = false;
    logger.info('✅ Certificate & Network Service stopped');
  }

  // Getter methods for external access
  getServices() {
    return this.services;
  }

  getIntegrationManager() {
    return this.integrationManager;
  }

  isHealthy() {
    return this.healthy;
  }

  isInitialized() {
    return this.initialized;
  }
}

// Create and export service instance
const service = new CertificateNetworkService();

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  logger.info('🔄 SIGTERM received, shutting down gracefully...');
  await service.stop();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('🔄 SIGINT received, shutting down gracefully...');
  await service.stop();
  process.exit(0);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit process - just log the error
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  // Exit process for uncaught exceptions
  process.exit(1);
});

// Start the service if this file is run directly
if (require.main === module) {
  service.initialize().catch((error) => {
    logger.error('❌ Failed to start Certificate & Network Service:', error);
    process.exit(1);
  });
}

module.exports = service;