'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const Redis = require('ioredis');
const amqplib = require('amqplib');
const { WebSocketServer } = require('ws');
const cron = require('node-cron');
const http = require('http');
const fs = require('fs');
const path = require('path');
const promClient = require('prom-client');

const logger = require('./utils/logger');
const ComplianceEvaluator = require('./engines/complianceEvaluator');
const BaselineManager = require('./engines/baselineManager');
const WaiverManager = require('./engines/waiverManager');
const ScoreCalculator = require('./engines/scoreCalculator');
const TrendAnalyzer = require('./engines/trendAnalyzer');
const ReportGenerator = require('./reports/reportGenerator');
const createComplianceRoutes = require('./routes/complianceRoutes');

const PORT = parseInt(process.env.PORT, 10) || 3907;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ─── Prometheus Metrics ─────────────────────────────────────────────

const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const evaluationCounter = new promClient.Counter({
  name: 'compliance_evaluations_total',
  help: 'Total number of compliance evaluations performed',
  labelNames: ['status'],
  registers: [register],
});

const evaluationDuration = new promClient.Histogram({
  name: 'compliance_evaluation_duration_seconds',
  help: 'Duration of compliance evaluations',
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
  registers: [register],
});

const activeConnections = new promClient.Gauge({
  name: 'compliance_ws_active_connections',
  help: 'Number of active WebSocket connections',
  registers: [register],
});

// ─── Database Connection ────────────────────────────────────────────

async function connectPostgres() {
  const pool = new Pool({
    host: process.env.POSTGRES_HOST || process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || process.env.DB_PORT, 10) || 5432,
    database: process.env.POSTGRES_DB || process.env.DB_NAME || 'opendirectory',
    user: process.env.POSTGRES_USER || process.env.DB_USER || 'opendirectory',
    password: process.env.POSTGRES_PASSWORD || process.env.DB_PASSWORD,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });

  pool.on('error', (err) => {
    logger.error('Unexpected PostgreSQL pool error', { error: err.message });
  });

  // Test connection
  const client = await pool.connect();
  const { rows } = await client.query('SELECT NOW() AS now');
  logger.info(`PostgreSQL connected: ${rows[0].now}`);
  client.release();

  return pool;
}

// ─── Redis Connection ───────────────────────────────────────────────

function connectRedis() {
  const redis = new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    password: process.env.REDIS_PASSWORD || undefined,
    db: parseInt(process.env.REDIS_DB, 10) || 0,
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => {
      if (times > 10) {
        logger.error('Redis connection failed after 10 retries');
        return null;
      }
      return Math.min(times * 200, 5000);
    },
    lazyConnect: true,
  });

  redis.on('connect', () => logger.info('Redis connected'));
  redis.on('error', (err) => logger.error(`Redis error: ${err.message}`));
  redis.on('close', () => logger.warn('Redis connection closed'));

  return redis;
}

// ─── RabbitMQ Connection ────────────────────────────────────────────

async function connectRabbitMQ() {
  const url = process.env.RABBITMQ_URL || process.env.AMQP_URL || 'amqp://guest:guest@localhost:5672';

  const connection = await amqplib.connect(url);
  const channel = await connection.createChannel();

  // Declare exchanges and queues
  await channel.assertExchange('compliance.events', 'topic', { durable: true });
  await channel.assertQueue('compliance.evaluations', { durable: true });
  await channel.assertQueue('compliance.alerts', { durable: true });
  await channel.bindQueue('compliance.evaluations', 'compliance.events', 'compliance.evaluation.*');
  await channel.bindQueue('compliance.alerts', 'compliance.events', 'compliance.alert.*');

  connection.on('error', (err) => logger.error(`RabbitMQ connection error: ${err.message}`));
  connection.on('close', () => logger.warn('RabbitMQ connection closed'));

  logger.info('RabbitMQ connected');
  return { connection, channel };
}

// ─── Database Migrations ────────────────────────────────────────────

async function runMigrations(db) {
  const migrationsDir = path.join(__dirname, 'db', 'migrations');

  if (!fs.existsSync(migrationsDir)) {
    logger.warn('Migrations directory not found, skipping');
    return;
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    try {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await db.query(sql);
      logger.info(`Migration applied: ${file}`);
    } catch (error) {
      // Ignore "already exists" errors for idempotent migrations
      if (error.code === '42P07' || error.code === '42710') {
        logger.info(`Migration already applied: ${file}`);
      } else {
        logger.error(`Migration failed: ${file} - ${error.message}`);
        throw error;
      }
    }
  }
}

// ─── WebSocket Server ───────────────────────────────────────────────

function setupWebSocket(server) {
  const wss = new WebSocketServer({ server, path: '/ws/compliance' });
  const clients = new Set();

  wss.on('connection', (ws, req) => {
    clients.add(ws);
    activeConnections.set(clients.size);
    logger.info(`WebSocket client connected (${clients.size} total)`);

    ws.on('close', () => {
      clients.delete(ws);
      activeConnections.set(clients.size);
      logger.info(`WebSocket client disconnected (${clients.size} total)`);
    });

    ws.on('error', (err) => {
      logger.error(`WebSocket error: ${err.message}`);
      clients.delete(ws);
      activeConnections.set(clients.size);
    });

    // Send initial connection confirmation
    ws.send(JSON.stringify({ type: 'connected', timestamp: new Date().toISOString() }));
  });

  // Broadcast function
  function broadcast(data) {
    const message = JSON.stringify(data);
    for (const client of clients) {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(message);
      }
    }
  }

  return { wss, broadcast };
}

// ─── Scheduled Tasks ────────────────────────────────────────────────

function setupScheduledTasks(evaluator, waiverManager, trendAnalyzer) {
  // Clean up expired waivers every hour
  cron.schedule('0 * * * *', async () => {
    try {
      const expired = await waiverManager.cleanupExpired();
      if (expired.length > 0) {
        logger.info(`Cleaned up ${expired.length} expired waivers`);
      }
    } catch (error) {
      logger.error(`Scheduled waiver cleanup failed: ${error.message}`);
    }
  });

  // Analyze trends daily at 2 AM
  cron.schedule('0 2 * * *', async () => {
    try {
      logger.info('Starting scheduled trend analysis');
      await trendAnalyzer.analyzeTrends({ days: 30 });
      logger.info('Scheduled trend analysis completed');
    } catch (error) {
      logger.error(`Scheduled trend analysis failed: ${error.message}`);
    }
  });

  logger.info('Scheduled tasks configured');
}

// ─── Express App ────────────────────────────────────────────────────

function createApp(deps) {
  const app = express();

  // Security middleware
  app.use(helmet());
  app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));

  // Compression
  app.use(compression());

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Rate limiting
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Too many requests, please try again later' },
  });
  app.use(limiter);

  // Request logging
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      if (req.path !== '/health' && req.path !== '/metrics') {
        logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
      }
    });
    next();
  });

  // Health check
  app.get('/health', async (req, res) => {
    try {
      await deps.db.query('SELECT 1');
      res.json({
        status: 'healthy',
        service: 'compliance-engine',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(503).json({
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString(),
      });
    }
  });

  // Prometheus metrics
  app.get('/metrics', async (req, res) => {
    try {
      res.set('Content-Type', register.contentType);
      res.end(await register.metrics());
    } catch (error) {
      res.status(500).end();
    }
  });

  // API routes
  app.use('/api/compliance', createComplianceRoutes(deps));

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Not found' });
  });

  // Global error handler
  app.use((err, req, res, _next) => {
    logger.error(`Unhandled error: ${err.message}`, { error: err, path: req.path });
    res.status(500).json({
      success: false,
      error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    });
  });

  return app;
}

// ─── Main Entry Point ───────────────────────────────────────────────

async function main() {
  logger.info('Starting Compliance Engine service...');

  let db, redis, rabbitMQ;

  try {
    // Connect to PostgreSQL
    db = await connectPostgres();

    // Connect to Redis
    redis = connectRedis();
    try {
      await redis.connect();
    } catch (error) {
      logger.warn(`Redis connection failed (non-critical): ${error.message}`);
      redis = null;
    }

    // Connect to RabbitMQ
    try {
      rabbitMQ = await connectRabbitMQ();
    } catch (error) {
      logger.warn(`RabbitMQ connection failed (non-critical): ${error.message}`);
      rabbitMQ = null;
    }

    // Run database migrations
    await runMigrations(db);

    // Initialize engines
    const eventBus = rabbitMQ ? rabbitMQ.channel : null;
    const baselineManager = new BaselineManager(db);
    const waiverManager = new WaiverManager(db);
    const scoreCalculator = new ScoreCalculator(db);
    const trendAnalyzer = new TrendAnalyzer(db);
    const evaluator = new ComplianceEvaluator(db, redis, eventBus);
    const reportGenerator = new ReportGenerator(db);

    // Load built-in baselines
    try {
      await baselineManager.loadBuiltInBaselines();
    } catch (error) {
      logger.warn(`Failed to load built-in baselines: ${error.message}`);
    }

    // Create Express app
    const deps = {
      db,
      redis,
      eventBus,
      evaluator,
      baselineManager,
      waiverManager,
      scoreCalculator,
      trendAnalyzer,
      reportGenerator,
    };

    const app = createApp(deps);
    const server = http.createServer(app);

    // Setup WebSocket
    const { broadcast } = setupWebSocket(server);
    deps.broadcast = broadcast;

    // Setup scheduled tasks
    setupScheduledTasks(evaluator, waiverManager, trendAnalyzer);

    // Listen for compliance evaluation requests via RabbitMQ
    if (rabbitMQ) {
      rabbitMQ.channel.consume('compliance.evaluations', async (msg) => {
        if (!msg) return;
        try {
          const { deviceId, inventoryData } = JSON.parse(msg.content.toString());
          const timer = evaluationDuration.startTimer();

          const result = await evaluator.evaluateDevice(deviceId, inventoryData);

          timer();
          evaluationCounter.inc({ status: 'success' });

          // Broadcast result via WebSocket
          broadcast({
            type: 'compliance.evaluation.completed',
            deviceId,
            overallScore: result.overallScore,
            timestamp: result.evaluatedAt,
          });

          rabbitMQ.channel.ack(msg);
        } catch (error) {
          evaluationCounter.inc({ status: 'error' });
          logger.error(`Failed to process evaluation message: ${error.message}`);
          rabbitMQ.channel.nack(msg, false, false);
        }
      });
      logger.info('Listening for compliance evaluation messages on RabbitMQ');
    }

    // Start server
    server.listen(PORT, '0.0.0.0', () => {
      logger.info(`Compliance Engine listening on port ${PORT}`);
      logger.info(`Environment: ${NODE_ENV}`);
      logger.info(`Health check: http://0.0.0.0:${PORT}/health`);
      logger.info(`Metrics: http://0.0.0.0:${PORT}/metrics`);
      logger.info(`WebSocket: ws://0.0.0.0:${PORT}/ws/compliance`);
    });

    // Graceful shutdown
    const shutdown = async (signal) => {
      logger.info(`Received ${signal}, shutting down gracefully...`);

      server.close(() => {
        logger.info('HTTP server closed');
      });

      try {
        if (rabbitMQ) {
          await rabbitMQ.channel.close();
          await rabbitMQ.connection.close();
          logger.info('RabbitMQ connection closed');
        }
      } catch (error) {
        logger.error(`Error closing RabbitMQ: ${error.message}`);
      }

      try {
        if (redis) {
          await redis.quit();
          logger.info('Redis connection closed');
        }
      } catch (error) {
        logger.error(`Error closing Redis: ${error.message}`);
      }

      try {
        await db.end();
        logger.info('PostgreSQL pool closed');
      } catch (error) {
        logger.error(`Error closing PostgreSQL: ${error.message}`);
      }

      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

  } catch (error) {
    logger.error(`Failed to start Compliance Engine: ${error.message}`, { error });
    process.exit(1);
  }
}

main();
