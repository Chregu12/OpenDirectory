'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createLogger, format, transports } = require('winston');
const { Pool } = require('pg');
const Redis = require('ioredis');
const amqplib = require('amqplib');
const { WebSocketServer } = require('ws');
const cron = require('node-cron');
const http = require('http');
const path = require('path');
const promClient = require('prom-client');

const BaselineManager = require('./engines/baselineManager');
const ComplianceEvaluator = require('./engines/complianceEvaluator');
const WaiverManager = require('./engines/waiverManager');
const ScoreCalculator = require('./engines/scoreCalculator');
const TrendAnalyzer = require('./engines/trendAnalyzer');
const ReportGenerator = require('./reports/reportGenerator');
const RegulatoryMapper = require('./reports/regulatoryMapper');
const WindowsScanner = require('./scanners/windowsScanner');
const MacosScanner = require('./scanners/macosScanner');
const LinuxScanner = require('./scanners/linuxScanner');

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(format.timestamp(), format.json()),
  defaultMeta: { service: 'compliance-engine' },
  transports: [
    new transports.Console({ format: format.combine(format.colorize(), format.simple()) }),
  ],
});

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------
const metricsRegistry = new promClient.Registry();
promClient.collectDefaultMetrics({ register: metricsRegistry });

const evaluationCounter = new promClient.Counter({
  name: 'compliance_evaluations_total',
  help: 'Total compliance evaluations performed',
  labelNames: ['baseline', 'result'],
  registers: [metricsRegistry],
});

const evaluationDuration = new promClient.Histogram({
  name: 'compliance_evaluation_duration_seconds',
  help: 'Duration of compliance evaluations',
  buckets: [0.1, 0.5, 1, 2, 5, 10],
  registers: [metricsRegistry],
});

const complianceScore = new promClient.Gauge({
  name: 'compliance_score',
  help: 'Current compliance score per device',
  labelNames: ['device_id', 'baseline'],
  registers: [metricsRegistry],
});

// ---------------------------------------------------------------------------
// Infrastructure clients
// ---------------------------------------------------------------------------
const pgPool = new Pool({
  host: process.env.PG_HOST || 'localhost',
  port: parseInt(process.env.PG_PORT, 10) || 5432,
  database: process.env.PG_DATABASE || 'opendirectory',
  user: process.env.PG_USER || 'opendirectory',
  password: process.env.PG_PASSWORD || 'opendirectory',
  max: 20,
});

const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT, 10) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  keyPrefix: 'compliance:',
  retryStrategy: (times) => Math.min(times * 200, 5000),
});

// ---------------------------------------------------------------------------
// Service instances
// ---------------------------------------------------------------------------
const baselineManager = new BaselineManager({ pgPool, logger });
const waiverManager = new WaiverManager({ pgPool, redis, logger });
const scoreCalculator = new ScoreCalculator({ pgPool, redis, logger });
const trendAnalyzer = new TrendAnalyzer({ pgPool, redis, logger });
const evaluator = new ComplianceEvaluator({
  pgPool,
  redis,
  logger,
  baselineManager,
  waiverManager,
  scoreCalculator,
  trendAnalyzer,
});
const reportGenerator = new ReportGenerator({ pgPool, logger, scoreCalculator, trendAnalyzer });
const regulatoryMapper = new RegulatoryMapper({ logger });
const scanners = {
  windows: new WindowsScanner({ logger }),
  macos: new MacosScanner({ logger }),
  linux: new LinuxScanner({ logger }),
};

// ---------------------------------------------------------------------------
// Express application
// ---------------------------------------------------------------------------
const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3907;

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(compression());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT, 10) || 200,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ---------------------------------------------------------------------------
// RabbitMQ
// ---------------------------------------------------------------------------
let amqpChannel = null;
const EXCHANGE = 'opendirectory.events';
const QUEUE_COMPLIANCE = 'compliance-engine.events';

async function connectRabbitMQ() {
  const url = process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672';
  try {
    const conn = await amqplib.connect(url);
    amqpChannel = await conn.createChannel();
    await amqpChannel.assertExchange(EXCHANGE, 'topic', { durable: true });
    await amqpChannel.assertQueue(QUEUE_COMPLIANCE, { durable: true });
    await amqpChannel.bindQueue(QUEUE_COMPLIANCE, EXCHANGE, 'device.heartbeat');
    await amqpChannel.bindQueue(QUEUE_COMPLIANCE, EXCHANGE, 'policy.updated');

    amqpChannel.consume(QUEUE_COMPLIANCE, async (msg) => {
      if (!msg) return;
      try {
        const event = JSON.parse(msg.content.toString());
        await handleEvent(event, msg.fields.routingKey);
        amqpChannel.ack(msg);
      } catch (err) {
        logger.error('Failed to process AMQP message', { error: err.message });
        amqpChannel.nack(msg, false, false);
      }
    });

    conn.on('error', (err) => logger.error('AMQP connection error', { error: err.message }));
    conn.on('close', () => {
      logger.warn('AMQP connection closed, reconnecting in 5s');
      setTimeout(connectRabbitMQ, 5000);
    });

    logger.info('RabbitMQ connected');
  } catch (err) {
    logger.warn('RabbitMQ connection failed, retrying in 5s', { error: err.message });
    setTimeout(connectRabbitMQ, 5000);
  }
}

function publishEvent(routingKey, payload) {
  if (!amqpChannel) return;
  try {
    amqpChannel.publish(
      EXCHANGE,
      routingKey,
      Buffer.from(JSON.stringify({ ...payload, timestamp: new Date().toISOString() })),
      { persistent: true }
    );
  } catch (err) {
    logger.error('Failed to publish event', { routingKey, error: err.message });
  }
}

async function handleEvent(event, routingKey) {
  logger.debug('Received event', { routingKey, deviceId: event.deviceId });
  if (routingKey === 'device.heartbeat' && event.deviceId && event.inventoryData) {
    const result = await evaluator.evaluateDevice(event.deviceId, event.inventoryData);
    if (result) {
      broadcastWS({ type: 'compliance.updated', deviceId: event.deviceId, score: result.score });
      if (result.score === 100) {
        publishEvent('compliance.passed', { deviceId: event.deviceId, score: result.score });
      } else {
        publishEvent('compliance.evaluated', { deviceId: event.deviceId, score: result.score });
      }
      if (result.newViolations && result.newViolations.length > 0) {
        publishEvent('compliance.violation', {
          deviceId: event.deviceId,
          violations: result.newViolations,
        });
      }
    }
  } else if (routingKey === 'policy.updated') {
    logger.info('Policy updated, baselines may need re-evaluation');
  }
}

// ---------------------------------------------------------------------------
// WebSocket for real-time dashboard
// ---------------------------------------------------------------------------
let wssClients = new Set();

function setupWebSocket(server) {
  const wss = new WebSocketServer({ server, path: '/ws/compliance' });
  wss.on('connection', (ws) => {
    wssClients.add(ws);
    logger.debug('WebSocket client connected', { total: wssClients.size });
    ws.on('close', () => wssClients.delete(ws));
    ws.on('error', () => wssClients.delete(ws));
  });
}

function broadcastWS(data) {
  const payload = JSON.stringify(data);
  for (const ws of wssClients) {
    try {
      if (ws.readyState === 1) ws.send(payload);
    } catch (_) {
      wssClients.delete(ws);
    }
  }
}

// ---------------------------------------------------------------------------
// Scheduled compliance evaluation
// ---------------------------------------------------------------------------
const CRON_SCHEDULE = process.env.COMPLIANCE_CRON || '0 */4 * * *';

function startScheduler() {
  cron.schedule(CRON_SCHEDULE, async () => {
    logger.info('Scheduled compliance evaluation starting');
    try {
      const { rows: devices } = await pgPool.query(
        `SELECT DISTINCT device_id FROM compliance_results ORDER BY device_id`
      );
      let evaluated = 0;
      for (const { device_id } of devices) {
        try {
          await evaluator.evaluateDevice(device_id, null);
          evaluated++;
        } catch (err) {
          logger.error('Scheduled evaluation failed for device', { deviceId: device_id, error: err.message });
        }
      }
      logger.info('Scheduled compliance evaluation complete', { evaluated });
      broadcastWS({ type: 'compliance.batch_complete', evaluated, timestamp: new Date().toISOString() });
    } catch (err) {
      logger.error('Scheduled evaluation batch failed', { error: err.message });
    }
  });
  logger.info('Compliance scheduler started', { schedule: CRON_SCHEDULE });
}

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------

// Health check
app.get('/health', async (_req, res) => {
  const checks = { status: 'healthy', uptime: process.uptime(), timestamp: new Date().toISOString() };
  try {
    await pgPool.query('SELECT 1');
    checks.postgres = 'connected';
  } catch {
    checks.postgres = 'disconnected';
    checks.status = 'degraded';
  }
  try {
    await redis.ping();
    checks.redis = 'connected';
  } catch {
    checks.redis = 'disconnected';
    checks.status = 'degraded';
  }
  checks.rabbitmq = amqpChannel ? 'connected' : 'disconnected';
  checks.baselines = baselineManager.getLoadedCount();
  res.status(checks.status === 'healthy' ? 200 : 503).json(checks);
});

// Metrics
app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', metricsRegistry.contentType);
  res.end(await metricsRegistry.metrics());
});

// --- Fleet compliance overview ---
app.get('/api/compliance/status', async (_req, res) => {
  try {
    const { rows: summary } = await pgPool.query(`
      SELECT
        COUNT(DISTINCT device_id) AS total_devices,
        ROUND(AVG(score)::numeric, 2) AS avg_score,
        COUNT(DISTINCT device_id) FILTER (WHERE score = 100) AS fully_compliant,
        COUNT(DISTINCT device_id) FILTER (WHERE score < 70) AS critical_non_compliant,
        SUM(critical_failures) AS total_critical_failures,
        SUM(high_failures) AS total_high_failures
      FROM (
        SELECT DISTINCT ON (device_id) device_id, score, critical_failures, high_failures
        FROM compliance_results
        ORDER BY device_id, scanned_at DESC
      ) latest
    `);
    const baselines = baselineManager.listBaselines();
    res.json({
      overview: summary[0] || {},
      baselinesLoaded: baselines.length,
      activeWaivers: await waiverManager.countActive(),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    logger.error('Failed to get compliance status', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Device compliance detail ---
app.get('/api/compliance/devices/:id', async (req, res) => {
  try {
    const { rows } = await pgPool.query(
      `SELECT * FROM compliance_results WHERE device_id = $1 ORDER BY scanned_at DESC LIMIT 1`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'No compliance data for device' });
    const waivers = await waiverManager.getActiveWaiversForDevice(req.params.id);
    res.json({ ...rows[0], activeWaivers: waivers });
  } catch (err) {
    logger.error('Failed to get device compliance', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Device compliance history ---
app.get('/api/compliance/devices/:id/history', async (req, res) => {
  try {
    const days = parseInt(req.query.days, 10) || 30;
    const { rows } = await pgPool.query(
      `SELECT * FROM compliance_history
       WHERE device_id = $1 AND recorded_at >= NOW() - INTERVAL '1 day' * $2
       ORDER BY recorded_at ASC`,
      [req.params.id, days]
    );
    res.json({ deviceId: req.params.id, days, history: rows });
  } catch (err) {
    logger.error('Failed to get device history', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Trigger compliance scan for device ---
app.post('/api/compliance/devices/:id/scan', async (req, res) => {
  try {
    const inventoryData = req.body.inventoryData || null;
    const result = await evaluator.evaluateDevice(req.params.id, inventoryData);
    if (result) {
      broadcastWS({ type: 'compliance.updated', deviceId: req.params.id, score: result.score });
      evaluationCounter.inc({ baseline: result.baselineId || 'unknown', result: result.score === 100 ? 'pass' : 'fail' });
    }
    res.json(result || { message: 'No applicable baselines for device' });
  } catch (err) {
    logger.error('Failed to scan device', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Compliance scores ---
app.get('/api/compliance/scores', async (req, res) => {
  try {
    const groupBy = req.query.groupBy || 'device';
    let scores;
    if (groupBy === 'ou') {
      scores = await scoreCalculator.calculateOUScores();
    } else if (groupBy === 'domain') {
      scores = await scoreCalculator.calculateDomainScore();
    } else {
      scores = await scoreCalculator.getDeviceScores();
    }
    res.json({ groupBy, scores });
  } catch (err) {
    logger.error('Failed to get scores', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Score trend for device ---
app.get('/api/compliance/scores/:deviceId/trend', async (req, res) => {
  try {
    const days = parseInt(req.query.days, 10) || 30;
    const trend = await trendAnalyzer.getDeviceTrend(req.params.deviceId, days);
    res.json(trend);
  } catch (err) {
    logger.error('Failed to get score trend', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- List baselines ---
app.get('/api/compliance/baselines', (req, res) => {
  const platform = req.query.platform || null;
  const baselines = baselineManager.listBaselines(platform);
  res.json({ baselines, total: baselines.length });
});

// --- Get baseline detail ---
app.get('/api/compliance/baselines/:id', (req, res) => {
  const baseline = baselineManager.getBaselineById(req.params.id);
  if (!baseline) return res.status(404).json({ error: 'Baseline not found' });
  res.json(baseline);
});

// --- Create custom baseline ---
app.post('/api/compliance/baselines', async (req, res) => {
  try {
    const baseline = await baselineManager.createBaseline(req.body);
    res.status(201).json(baseline);
  } catch (err) {
    logger.error('Failed to create baseline', { error: err.message });
    res.status(400).json({ error: err.message });
  }
});

// --- Update baseline ---
app.put('/api/compliance/baselines/:id', async (req, res) => {
  try {
    const baseline = await baselineManager.updateBaseline(req.params.id, req.body);
    if (!baseline) return res.status(404).json({ error: 'Baseline not found' });
    res.json(baseline);
  } catch (err) {
    logger.error('Failed to update baseline', { error: err.message });
    res.status(400).json({ error: err.message });
  }
});

// --- List active waivers ---
app.get('/api/compliance/waivers', async (_req, res) => {
  try {
    const waivers = await waiverManager.getActiveWaivers();
    res.json({ waivers, total: waivers.length });
  } catch (err) {
    logger.error('Failed to get waivers', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Create waiver ---
app.post('/api/compliance/waivers', async (req, res) => {
  try {
    const waiver = await waiverManager.createWaiver(req.body);
    res.status(201).json(waiver);
  } catch (err) {
    logger.error('Failed to create waiver', { error: err.message });
    res.status(400).json({ error: err.message });
  }
});

// --- Revoke waiver ---
app.delete('/api/compliance/waivers/:id', async (req, res) => {
  try {
    const result = await waiverManager.revokeWaiver(req.params.id);
    if (!result) return res.status(404).json({ error: 'Waiver not found' });
    res.json({ message: 'Waiver revoked', waiver: result });
  } catch (err) {
    logger.error('Failed to revoke waiver', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Generate compliance report ---
app.post('/api/compliance/reports', async (req, res) => {
  try {
    const { type, filters, format: fmt } = req.body;
    const report = await reportGenerator.generateReport(type, filters, fmt || 'json');
    if (fmt === 'pdf') {
      res.set('Content-Type', 'application/pdf');
      res.set('Content-Disposition', `attachment; filename=compliance-report-${Date.now()}.pdf`);
      return report.pipe(res);
    }
    if (fmt === 'csv') {
      res.set('Content-Type', 'text/csv');
      res.set('Content-Disposition', `attachment; filename=compliance-report-${Date.now()}.csv`);
      return res.send(report);
    }
    res.json(report);
  } catch (err) {
    logger.error('Failed to generate report', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Regulatory mapping ---
app.get('/api/compliance/regulatory/:framework', async (req, res) => {
  try {
    const { rows } = await pgPool.query(
      `SELECT * FROM compliance_results ORDER BY scanned_at DESC LIMIT 500`
    );
    const mapping = regulatoryMapper.mapToRegulation(rows, req.params.framework);
    res.json(mapping);
  } catch (err) {
    logger.error('Failed to get regulatory mapping', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
async function start() {
  try {
    // Verify Postgres
    await pgPool.query('SELECT 1');
    logger.info('PostgreSQL connected');
  } catch (err) {
    logger.warn('PostgreSQL not available, will retry operations', { error: err.message });
  }

  // Load baselines from JSON files
  const baselinesDir = path.join(__dirname, 'baselines');
  await baselineManager.loadFromDirectory(baselinesDir);
  logger.info('Baselines loaded', { count: baselineManager.getLoadedCount() });

  // Register scanners
  evaluator.registerScanner('windows', scanners.windows);
  evaluator.registerScanner('macos', scanners.macos);
  evaluator.registerScanner('linux', scanners.linux);

  // Connect RabbitMQ (non-blocking)
  connectRabbitMQ();

  // Start cron scheduler
  startScheduler();

  // Start HTTP + WebSocket server
  const server = http.createServer(app);
  setupWebSocket(server);

  server.listen(PORT, () => {
    logger.info(`Compliance Engine running on port ${PORT}`);
  });
}

start().catch((err) => {
  logger.error('Fatal startup error', { error: err.message });
  process.exit(1);
});

module.exports = app;
