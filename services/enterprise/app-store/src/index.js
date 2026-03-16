'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const Redis = require('ioredis');
const amqplib = require('amqplib');
const winston = require('winston');
const { collectDefaultMetrics, register } = require('prom-client');

const { CatalogManager } = require('./catalog/catalogManager');
const { VersionManager } = require('./catalog/versionManager');
const { AssignmentEngine } = require('./assignment/assignmentEngine');
const { LicenseManager } = require('./assignment/licenseManager');
const { DistributionEngine } = require('./distribution/distributionEngine');
const { InstallTracker } = require('./distribution/installTracker');
const { ClientDetector } = require('./detection/clientDetector');
const { DomainResolver } = require('./detection/domainResolver');
const { createAdminRoutes } = require('./api/routes');
const { createStoreRoutes } = require('./api/storeRoutes');
const defaultCatalog = require('./catalog/defaultCatalog.json');

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'app-store' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT, 10) || 3906;
const PG_CONFIG = {
  host: process.env.PG_HOST || 'localhost',
  port: parseInt(process.env.PG_PORT, 10) || 5432,
  database: process.env.PG_DATABASE || 'appstore',
  user: process.env.PG_USER || 'appstore',
  password: process.env.PG_PASSWORD || 'appstore',
  max: parseInt(process.env.PG_POOL_MAX, 10) || 20,
  idleTimeoutMillis: 30000,
};
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const AMQP_URL = process.env.AMQP_URL || 'amqp://localhost:5672';
const DEVICE_SERVICE_URL = process.env.DEVICE_SERVICE_URL || 'http://localhost:3001';
const IDENTITY_SERVICE_URL = process.env.IDENTITY_SERVICE_URL || 'http://localhost:3002';

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------
collectDefaultMetrics({ prefix: 'appstore_' });

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
async function bootstrap() {
  // --- PostgreSQL ---
  const pool = new Pool(PG_CONFIG);
  pool.on('error', (err) => logger.error('Unexpected PG pool error', err));
  await initDatabase(pool);

  // --- Redis ---
  const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 3, lazyConnect: true });
  redis.on('error', (err) => logger.warn('Redis connection error', { error: err.message }));
  try {
    await redis.connect();
    logger.info('Connected to Redis');
  } catch (err) {
    logger.warn('Redis unavailable – continuing without cache', { error: err.message });
  }

  // --- RabbitMQ ---
  let amqpChannel = null;
  try {
    const amqpConn = await amqplib.connect(AMQP_URL);
    amqpChannel = await amqpConn.createChannel();
    await amqpChannel.assertExchange('opendirectory.events', 'topic', { durable: true });
    await amqpChannel.assertQueue('appstore.device.enrolled', { durable: true });
    await amqpChannel.bindQueue('appstore.device.enrolled', 'opendirectory.events', 'device.enrolled');
    logger.info('Connected to RabbitMQ');
  } catch (err) {
    logger.warn('RabbitMQ unavailable – continuing without messaging', { error: err.message });
  }

  // --- Instantiate components ---
  const catalogManager = new CatalogManager(pool, redis, logger);
  const versionManager = new VersionManager(pool, redis, logger);
  const assignmentEngine = new AssignmentEngine(pool, redis, logger);
  const licenseManager = new LicenseManager(pool, redis, logger);
  const installTracker = new InstallTracker(pool, redis, logger);
  const clientDetector = new ClientDetector({ deviceServiceUrl: DEVICE_SERVICE_URL, identityServiceUrl: IDENTITY_SERVICE_URL }, redis, logger);
  const domainResolver = new DomainResolver(assignmentEngine, catalogManager, redis, logger);
  const distributionEngine = new DistributionEngine(pool, installTracker, licenseManager, catalogManager, amqpChannel, logger);

  // --- Seed default catalog ---
  await seedDefaultCatalog(catalogManager, versionManager);

  // --- Express ---
  const app = express();

  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
  app.use(compression());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later' },
  });
  app.use('/api/', limiter);

  // Health & metrics
  app.get('/health', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'healthy', service: 'app-store', timestamp: new Date().toISOString() });
    } catch {
      res.status(503).json({ status: 'unhealthy', service: 'app-store' });
    }
  });

  app.get('/metrics', async (_req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });

  // Mount routes
  const adminRoutes = createAdminRoutes(catalogManager, versionManager, assignmentEngine, licenseManager, installTracker, logger);
  const storeRoutes = createStoreRoutes(catalogManager, versionManager, assignmentEngine, licenseManager, distributionEngine, installTracker, clientDetector, domainResolver, logger);

  app.use('/api/store', adminRoutes);
  app.use('/api/store', storeRoutes);

  // 404
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

  // Global error handler
  app.use((err, _req, res, _next) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error' });
  });

  // --- HTTP + WebSocket ---
  const server = createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws/install-progress' });

  distributionEngine.setWss(wss);

  wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const deviceId = url.searchParams.get('deviceId');
    if (deviceId) {
      ws._deviceId = deviceId;
      logger.info('WebSocket client connected', { deviceId });
    }

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data);
        distributionEngine.handleAgentMessage(ws, msg);
      } catch (err) {
        logger.warn('Invalid WebSocket message', { error: err.message });
      }
    });

    ws.on('close', () => {
      logger.debug('WebSocket client disconnected', { deviceId: ws._deviceId });
    });
  });

  // --- RabbitMQ consumer: device.enrolled ---
  if (amqpChannel) {
    amqpChannel.consume('appstore.device.enrolled', async (msg) => {
      if (!msg) return;
      try {
        const event = JSON.parse(msg.content.toString());
        logger.info('Device enrolled event received', { deviceId: event.deviceId });
        const mandatoryApps = await assignmentEngine.getMandatoryAppsForDevice(event.deviceId, event);
        for (const assignment of mandatoryApps) {
          await distributionEngine.requestInstall(assignment.app_id, event.deviceId);
        }
        amqpChannel.ack(msg);
      } catch (err) {
        logger.error('Failed to process device.enrolled event', { error: err.message });
        amqpChannel.nack(msg, false, true);
      }
    });
  }

  // --- Start ---
  server.listen(PORT, () => {
    logger.info(`App Store service listening on port ${PORT}`);
  });

  // Graceful shutdown
  const shutdown = async (signal) => {
    logger.info(`${signal} received, shutting down gracefully`);
    server.close();
    wss.close();
    await pool.end();
    redis.disconnect();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// ---------------------------------------------------------------------------
// Database initialisation
// ---------------------------------------------------------------------------
async function initDatabase(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS apps (
        id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        name          TEXT NOT NULL,
        description   TEXT,
        publisher     TEXT,
        category      TEXT NOT NULL DEFAULT 'Utilities',
        icon_url      TEXT,
        platforms     JSONB NOT NULL DEFAULT '{}',
        tags          TEXT[] DEFAULT '{}',
        featured      BOOLEAN DEFAULT false,
        mandatory     BOOLEAN DEFAULT false,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS app_versions (
        id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        version     TEXT NOT NULL,
        changelog   TEXT,
        channel     TEXT NOT NULL DEFAULT 'stable',
        released_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(app_id, version)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS assignments (
        id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        app_id          TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        target_type     TEXT NOT NULL,
        target_id       TEXT NOT NULL,
        assignment_type TEXT NOT NULL DEFAULT 'available',
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(app_id, target_type, target_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        app_id       TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        license_type TEXT NOT NULL DEFAULT 'unlimited',
        total_count  INT DEFAULT 0,
        used_count   INT DEFAULT 0,
        UNIQUE(app_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS license_allocations (
        id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        device_id  TEXT NOT NULL,
        user_id    TEXT,
        allocated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(app_id, device_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS install_jobs (
        id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        app_id       TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        device_id    TEXT NOT NULL,
        action       TEXT NOT NULL DEFAULT 'install',
        status       TEXT NOT NULL DEFAULT 'queued',
        progress     INT DEFAULT 0,
        version      TEXT,
        error        TEXT,
        started_at   TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Full-text search index
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_apps_search ON apps
      USING gin(to_tsvector('english', coalesce(name,'') || ' ' || coalesce(description,'') || ' ' || array_to_string(tags, ' ')))
    `);

    await client.query(`CREATE INDEX IF NOT EXISTS idx_apps_category ON apps(category)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_assignments_target ON assignments(target_type, target_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_assignments_app ON assignments(app_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_install_jobs_device ON install_jobs(device_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_install_jobs_app ON install_jobs(app_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_app_versions_app ON app_versions(app_id)`);

    await client.query('COMMIT');
    logger.info('Database schema initialised');
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Database initialisation failed', { error: err.message });
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// Seed default catalog
// ---------------------------------------------------------------------------
async function seedDefaultCatalog(catalogManager, versionManager) {
  try {
    const existing = await catalogManager.listApps({ limit: 1 });
    if (existing.total > 0) {
      logger.info('Catalog already populated, skipping seed');
      return;
    }

    logger.info(`Seeding default catalog with ${defaultCatalog.apps.length} apps`);
    for (const appDef of defaultCatalog.apps) {
      const { version, changelog, ...appData } = appDef;
      const app = await catalogManager.createApp(appData);
      if (version) {
        await versionManager.addVersion(app.id, {
          version,
          changelog: changelog || `Initial release of ${appData.name}`,
          channel: 'stable',
        });
      }
    }
    logger.info('Default catalog seeded successfully');
  } catch (err) {
    logger.warn('Failed to seed default catalog', { error: err.message });
  }
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
bootstrap().catch((err) => {
  logger.error('Failed to start App Store service', { error: err.message, stack: err.stack });
  process.exit(1);
});
