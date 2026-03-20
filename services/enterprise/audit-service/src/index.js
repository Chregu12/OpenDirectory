'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { WebSocketServer } = require('ws');
const http = require('http');
const amqplib = require('amqplib');
const Redis = require('ioredis');
const promClient = require('prom-client');
const { v4: uuidv4 } = require('uuid');

const logger = require('./utils/logger');
const { pool, connect: connectPg, runMigrations } = require('./db/postgres');
const IntegrityChecker = require('./storage/integrityChecker');
const EventStore = require('./storage/eventStore');
const EventCollector = require('./collectors/eventCollector');
const SearchEngine = require('./query/searchEngine');
const AuditReportGenerator = require('./reports/auditReportGenerator');
const SyslogForwarder = require('./siem/syslogForwarder');
const WebhookNotifier = require('./siem/webhookNotifier');

// ── Configuration ───────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10) || 3908;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';

// ── Prometheus Metrics ──────────────────────────────────────────────────────────
const metricsRegistry = new promClient.Registry();
promClient.collectDefaultMetrics({ register: metricsRegistry });

const metrics = {
  eventsProcessed: new promClient.Counter({
    name: 'audit_events_processed_total',
    help: 'Total audit events processed',
    labelNames: ['category', 'severity', 'result'],
    registers: [metricsRegistry],
  }),
  httpRequestDuration: new promClient.Histogram({
    name: 'audit_http_request_duration_seconds',
    help: 'HTTP request duration in seconds',
    labelNames: ['method', 'route', 'status'],
    registers: [metricsRegistry],
  }),
  wsConnections: new promClient.Gauge({
    name: 'audit_ws_connections',
    help: 'Number of active WebSocket connections',
    registers: [metricsRegistry],
  }),
};

// ── Express App ─────────────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '1mb' }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});
app.use('/api/', limiter);

// Request timing middleware
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    metrics.httpRequestDuration.observe(
      { method: req.method, route: req.route?.path || req.path, status: res.statusCode },
      durationMs / 1000
    );
  });
  next();
});

// ── WebSocket Server ────────────────────────────────────────────────────────────
const wsClients = new Set();
const wss = new WebSocketServer({ server, path: '/ws/audit' });

wss.on('connection', (ws, req) => {
  wsClients.add(ws);
  metrics.wsConnections.set(wsClients.size);
  logger.info('WebSocket client connected', { remoteAddress: req.socket.remoteAddress, clients: wsClients.size });

  ws.on('close', () => {
    wsClients.delete(ws);
    metrics.wsConnections.set(wsClients.size);
    logger.debug('WebSocket client disconnected', { clients: wsClients.size });
  });

  ws.on('error', (err) => {
    logger.error('WebSocket error', { error: err.message });
    wsClients.delete(ws);
    metrics.wsConnections.set(wsClients.size);
  });

  // Send initial acknowledgement
  ws.send(JSON.stringify({ type: 'connected', message: 'Audit live stream connected' }));
});

// ── Health Endpoint ─────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      service: 'audit-service',
      version: '1.0.0',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      connections: {
        postgres: dbResult.rows.length > 0,
        redis: redis && redis.status === 'ready',
        websocket: wsClients.size,
      },
    });
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      error: err.message,
    });
  }
});

// ── Metrics Endpoint ────────────────────────────────────────────────────────────
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', metricsRegistry.contentType);
    res.end(await metricsRegistry.metrics());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Shared state (initialized on startup) ───────────────────────────────────────
let redis = null;
let eventStore = null;
let searchEngine = null;
let reportGenerator = null;
let integrityChecker = null;
let webhookNotifier = null;

// ── Alert Engine (inline) ───────────────────────────────────────────────────────
class AlertEngine {
  constructor(db, notifier) {
    this.db = db;
    this.notifier = notifier;
    this.rules = [];
  }

  async loadRules() {
    try {
      const result = await this.db.query('SELECT * FROM audit_alert_rules WHERE enabled = true');
      this.rules = result.rows;
      logger.info('Alert rules loaded', { count: this.rules.length });
    } catch (err) {
      logger.error('Failed to load alert rules', { error: err.message });
    }
  }

  async evaluate(event) {
    for (const rule of this.rules) {
      if (!this._matchesRule(rule, event)) continue;

      // Check cooldown
      if (rule.last_triggered) {
        const cooldownMs = (rule.cooldown_minutes || 15) * 60 * 1000;
        if (Date.now() - new Date(rule.last_triggered).getTime() < cooldownMs) {
          continue;
        }
      }

      logger.info('Alert rule triggered', { ruleId: rule.id, ruleName: rule.name, eventId: event.id });

      // Update last_triggered
      try {
        await this.db.query(
          'UPDATE audit_alert_rules SET last_triggered = NOW() WHERE id = $1',
          [rule.id]
        );
        rule.last_triggered = new Date();
      } catch (err) {
        logger.error('Failed to update alert last_triggered', { error: err.message });
      }

      // Send notification
      if (this.notifier) {
        try {
          await this.notifier.notify(rule, event);
        } catch (err) {
          logger.error('Failed to send alert notification', { error: err.message, ruleId: rule.id });
        }
      }
    }
  }

  _matchesRule(rule, event) {
    // Category pattern match
    if (rule.category_pattern) {
      const pattern = rule.category_pattern.replace(/\*/g, '.*');
      if (!new RegExp(`^${pattern}$`).test(event.category)) {
        return false;
      }
    }

    // Severity filter
    if (rule.severity_filter && rule.severity_filter !== event.severity) {
      return false;
    }

    // Condition-based matching (JSONB)
    if (rule.condition) {
      const cond = rule.condition;

      if (cond.action_pattern) {
        const actionPattern = cond.action_pattern.replace(/\*/g, '.*');
        if (!new RegExp(`^${actionPattern}$`).test(event.action)) {
          return false;
        }
      }

      if (cond.result && cond.result !== event.result) {
        return false;
      }

      if (cond.actor_id && cond.actor_id !== event.actor_id) {
        return false;
      }

      if (cond.min_severity) {
        const severityOrder = { debug: 0, info: 1, warning: 2, error: 3, critical: 4 };
        if ((severityOrder[event.severity] || 0) < (severityOrder[cond.min_severity] || 0)) {
          return false;
        }
      }
    }

    return true;
  }
}

// ── API Routes ──────────────────────────────────────────────────────────────────

// GET /api/audit/events - Query events with filters
app.get('/api/audit/events', async (req, res) => {
  try {
    const filters = {
      startTime: req.query.startTime || null,
      endTime: req.query.endTime || null,
      category: req.query.category || null,
      severity: req.query.severity || null,
      actorId: req.query.actorId || null,
      targetId: req.query.targetId || null,
      targetType: req.query.targetType || null,
      action: req.query.action || null,
      result: req.query.result || null,
      source: req.query.source || null,
      correlationId: req.query.correlationId || null,
      limit: req.query.limit,
      offset: req.query.offset,
      sortDir: req.query.sortDir,
    };

    const result = await eventStore.query(filters);
    res.json(result);
  } catch (err) {
    logger.error('GET /api/audit/events failed', { error: err.message });
    res.status(500).json({ error: 'Failed to query audit events' });
  }
});

// GET /api/audit/events/:id - Get single event
app.get('/api/audit/events/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!id || typeof id !== 'string' || id.length > 36) {
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    const event = await eventStore.getById(id);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }
    res.json(event);
  } catch (err) {
    logger.error('GET /api/audit/events/:id failed', { error: err.message, id: req.params.id });
    res.status(500).json({ error: 'Failed to get audit event' });
  }
});

// GET /api/audit/events/correlation/:correlationId - Get correlated events
app.get('/api/audit/events/correlation/:correlationId', async (req, res) => {
  try {
    const correlationId = req.params.correlationId;
    if (!correlationId || correlationId.length > 36) {
      return res.status(400).json({ error: 'Invalid correlation ID' });
    }

    const events = await eventStore.getByCorrelation(correlationId);
    res.json({ correlationId, events, count: events.length });
  } catch (err) {
    logger.error('GET /api/audit/events/correlation/:correlationId failed', { error: err.message });
    res.status(500).json({ error: 'Failed to get correlated events' });
  }
});

// GET /api/audit/timeline/:targetType/:targetId - Get entity timeline
app.get('/api/audit/timeline/:targetType/:targetId', async (req, res) => {
  try {
    const { targetType, targetId } = req.params;
    if (!targetType || !targetId) {
      return res.status(400).json({ error: 'Target type and ID are required' });
    }
    if (targetType.length > 50 || targetId.length > 255) {
      return res.status(400).json({ error: 'Invalid target type or ID length' });
    }

    const options = {
      targetType,
      startTime: req.query.startTime || null,
      endTime: req.query.endTime || null,
      limit: req.query.limit,
      offset: req.query.offset,
    };

    const events = await eventStore.getTimeline(targetId, options);
    res.json({ targetType, targetId, events, count: events.length });
  } catch (err) {
    logger.error('GET /api/audit/timeline failed', { error: err.message });
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

// GET /api/audit/stats - Aggregated statistics
app.get('/api/audit/stats', async (req, res) => {
  try {
    const filters = {
      startTime: req.query.startTime || null,
      endTime: req.query.endTime || null,
      category: req.query.category || null,
    };

    const groupBy = req.query.groupBy || 'category';
    const result = await searchEngine.aggregate(groupBy, filters);
    res.json(result);
  } catch (err) {
    logger.error('GET /api/audit/stats failed', { error: err.message });
    res.status(500).json({ error: 'Failed to get statistics' });
  }
});

// GET /api/audit/categories - List event categories with counts
app.get('/api/audit/categories', async (req, res) => {
  try {
    const categories = await eventStore.getCategories();
    res.json({ categories });
  } catch (err) {
    logger.error('GET /api/audit/categories failed', { error: err.message });
    res.status(500).json({ error: 'Failed to get categories' });
  }
});

// POST /api/audit/search - Full-text search
app.post('/api/audit/search', async (req, res) => {
  try {
    const query = req.body;
    if (!query || typeof query !== 'object') {
      return res.status(400).json({ error: 'Search query body is required' });
    }

    const result = await searchEngine.search(query);
    res.json(result);
  } catch (err) {
    logger.error('POST /api/audit/search failed', { error: err.message });
    res.status(500).json({ error: 'Failed to execute search' });
  }
});

// GET /api/audit/integrity - Verify hash chain integrity
app.get('/api/audit/integrity', async (req, res) => {
  try {
    const startTime = req.query.startTime || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const endTime = req.query.endTime || new Date().toISOString();

    const result = await integrityChecker.verifyChain(startTime, endTime);
    res.json({
      ...result,
      verifiedAt: new Date().toISOString(),
      timeRange: { start: startTime, end: endTime },
    });
  } catch (err) {
    logger.error('GET /api/audit/integrity failed', { error: err.message });
    res.status(500).json({ error: 'Failed to verify integrity' });
  }
});

// POST /api/audit/reports/pdf - Generate PDF report
app.post('/api/audit/reports/pdf', async (req, res) => {
  try {
    const filters = req.body.filters || {};
    const options = req.body.options || {};

    const pdfBuffer = await reportGenerator.generatePDF(filters, options);

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="audit-report-${Date.now()}.pdf"`,
      'Content-Length': pdfBuffer.length,
    });
    res.send(pdfBuffer);
  } catch (err) {
    logger.error('POST /api/audit/reports/pdf failed', { error: err.message });
    res.status(500).json({ error: 'Failed to generate PDF report' });
  }
});

// POST /api/audit/reports/csv - Generate CSV export
app.post('/api/audit/reports/csv', async (req, res) => {
  try {
    const filters = req.body.filters || {};
    const csv = await reportGenerator.generateCSV(filters);

    res.set({
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="audit-export-${Date.now()}.csv"`,
    });
    res.send(csv);
  } catch (err) {
    logger.error('POST /api/audit/reports/csv failed', { error: err.message });
    res.status(500).json({ error: 'Failed to generate CSV export' });
  }
});

// POST /api/audit/reports/compliance/:framework - Generate compliance report
app.post('/api/audit/reports/compliance/:framework', async (req, res) => {
  try {
    const framework = req.params.framework;
    const validFrameworks = ['ISO27001', 'SOC2', 'DSGVO'];
    if (!validFrameworks.includes(framework)) {
      return res.status(400).json({
        error: `Invalid framework. Supported: ${validFrameworks.join(', ')}`,
      });
    }

    const filters = req.body.filters || {};
    const report = await reportGenerator.generateComplianceReport(framework, filters);
    res.json(report);
  } catch (err) {
    logger.error('POST /api/audit/reports/compliance failed', { error: err.message });
    res.status(500).json({ error: 'Failed to generate compliance report' });
  }
});

// GET /api/audit/alerts - List alert rules
app.get('/api/audit/alerts', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_alert_rules ORDER BY created_at DESC');
    res.json({ alerts: result.rows, count: result.rows.length });
  } catch (err) {
    logger.error('GET /api/audit/alerts failed', { error: err.message });
    res.status(500).json({ error: 'Failed to list alert rules' });
  }
});

// POST /api/audit/alerts - Create alert rule
app.post('/api/audit/alerts', async (req, res) => {
  try {
    const { name, description, category_pattern, severity_filter, condition, action, cooldown_minutes } = req.body;

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'Alert rule name is required' });
    }
    if (!condition || typeof condition !== 'object') {
      return res.status(400).json({ error: 'Alert condition is required and must be an object' });
    }
    if (!action || typeof action !== 'object') {
      return res.status(400).json({ error: 'Alert action is required and must be an object' });
    }

    const result = await pool.query(
      `INSERT INTO audit_alert_rules (name, description, category_pattern, severity_filter, condition, action, cooldown_minutes)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [
        name.trim(),
        description || null,
        category_pattern || null,
        severity_filter || null,
        JSON.stringify(condition),
        JSON.stringify(action),
        parseInt(cooldown_minutes, 10) || 15,
      ]
    );

    // Reload alert rules in the engine
    if (alertEngine) {
      await alertEngine.loadRules();
    }

    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('POST /api/audit/alerts failed', { error: err.message });
    res.status(500).json({ error: 'Failed to create alert rule' });
  }
});

// PUT /api/audit/alerts/:id - Update alert rule
app.put('/api/audit/alerts/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!id || id.length > 36) {
      return res.status(400).json({ error: 'Invalid alert rule ID' });
    }

    const { name, description, category_pattern, severity_filter, condition, action, enabled, cooldown_minutes } = req.body;

    const fields = [];
    const values = [];
    let paramIndex = 1;

    if (name !== undefined) { fields.push(`name = $${paramIndex++}`); values.push(name); }
    if (description !== undefined) { fields.push(`description = $${paramIndex++}`); values.push(description); }
    if (category_pattern !== undefined) { fields.push(`category_pattern = $${paramIndex++}`); values.push(category_pattern); }
    if (severity_filter !== undefined) { fields.push(`severity_filter = $${paramIndex++}`); values.push(severity_filter); }
    if (condition !== undefined) { fields.push(`condition = $${paramIndex++}`); values.push(JSON.stringify(condition)); }
    if (action !== undefined) { fields.push(`action = $${paramIndex++}`); values.push(JSON.stringify(action)); }
    if (enabled !== undefined) { fields.push(`enabled = $${paramIndex++}`); values.push(enabled); }
    if (cooldown_minutes !== undefined) { fields.push(`cooldown_minutes = $${paramIndex++}`); values.push(parseInt(cooldown_minutes, 10)); }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(id);
    const result = await pool.query(
      `UPDATE audit_alert_rules SET ${fields.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Alert rule not found' });
    }

    if (alertEngine) {
      await alertEngine.loadRules();
    }

    res.json(result.rows[0]);
  } catch (err) {
    logger.error('PUT /api/audit/alerts/:id failed', { error: err.message });
    res.status(500).json({ error: 'Failed to update alert rule' });
  }
});

// DELETE /api/audit/alerts/:id - Delete alert rule
app.delete('/api/audit/alerts/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!id || id.length > 36) {
      return res.status(400).json({ error: 'Invalid alert rule ID' });
    }

    const result = await pool.query('DELETE FROM audit_alert_rules WHERE id = $1 RETURNING id', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Alert rule not found' });
    }

    if (alertEngine) {
      await alertEngine.loadRules();
    }

    res.json({ deleted: true, id });
  } catch (err) {
    logger.error('DELETE /api/audit/alerts/:id failed', { error: err.message });
    res.status(500).json({ error: 'Failed to delete alert rule' });
  }
});

// GET /api/audit/retention - List retention policies
app.get('/api/audit/retention', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_retention_policies ORDER BY created_at DESC');
    res.json({ policies: result.rows, count: result.rows.length });
  } catch (err) {
    logger.error('GET /api/audit/retention failed', { error: err.message });
    res.status(500).json({ error: 'Failed to list retention policies' });
  }
});

// POST /api/audit/retention - Create retention policy
app.post('/api/audit/retention', async (req, res) => {
  try {
    const { name, category_pattern, retention_days, archive_after_days, enabled } = req.body;

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'Retention policy name is required' });
    }
    if (retention_days !== undefined && (typeof retention_days !== 'number' || retention_days < 1)) {
      return res.status(400).json({ error: 'retention_days must be a positive integer' });
    }

    const result = await pool.query(
      `INSERT INTO audit_retention_policies (name, category_pattern, retention_days, archive_after_days, enabled)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [
        name.trim(),
        category_pattern || null,
        retention_days || 2555,
        archive_after_days || 365,
        enabled !== undefined ? enabled : true,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('POST /api/audit/retention failed', { error: err.message });
    res.status(500).json({ error: 'Failed to create retention policy' });
  }
});

// POST /api/audit/siem/test - Test SIEM forwarding
app.post('/api/audit/siem/test', async (req, res) => {
  try {
    const config = req.body;
    if (!config.host || !config.port) {
      return res.status(400).json({ error: 'SIEM host and port are required' });
    }

    const forwarder = new SyslogForwarder({
      host: config.host,
      port: parseInt(config.port, 10),
      protocol: config.protocol || 'udp',
      format: config.format || 'CEF',
    });

    const testEvent = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      category: 'system',
      severity: 'info',
      action: 'siem.test',
      actor_name: 'admin',
      target_name: 'siem-integration',
      result: 'success',
      details: { test: true },
    };

    await forwarder.connect();
    const success = await forwarder.forward(testEvent);
    await forwarder.close();

    res.json({
      success,
      message: success ? 'Test event forwarded successfully' : 'Failed to forward test event',
      format: config.format || 'CEF',
      formattedMessage: forwarder.format === 'CEF'
        ? forwarder.formatCEF(testEvent)
        : forwarder.formatRFC5424(testEvent),
    });
  } catch (err) {
    logger.error('POST /api/audit/siem/test failed', { error: err.message });
    res.status(500).json({ error: `SIEM test failed: ${err.message}` });
  }
});

// ── 404 Handler ─────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Error Handler ───────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path });
  res.status(500).json({ error: 'Internal server error' });
});

// ── Startup ─────────────────────────────────────────────────────────────────────
let alertEngine = null;

async function start() {
  try {
    // 1. Connect to PostgreSQL
    await connectPg();
    logger.info('PostgreSQL connected');

    // 2. Run migrations
    await runMigrations();
    logger.info('Database migrations complete');

    // 3. Connect to Redis
    redis = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 10) return null;
        return Math.min(times * 200, 5000);
      },
      lazyConnect: true,
    });
    try {
      await redis.connect();
      logger.info('Redis connected');
    } catch (err) {
      logger.warn('Redis connection failed, continuing without cache', { error: err.message });
      redis = null;
    }

    // 4. Initialize integrity checker
    integrityChecker = new IntegrityChecker(pool);
    await integrityChecker.initialize();

    // 5. Initialize stores and engines
    eventStore = new EventStore(pool, integrityChecker);
    searchEngine = new SearchEngine(pool);
    reportGenerator = new AuditReportGenerator(pool);
    webhookNotifier = new WebhookNotifier();

    // 6. Initialize alert engine
    alertEngine = new AlertEngine(pool, webhookNotifier);
    await alertEngine.loadRules();

    // 7. Connect to RabbitMQ and start event collector
    try {
      const amqpConnection = await amqplib.connect(RABBITMQ_URL);
      amqpConnection.on('error', (err) => {
        logger.error('RabbitMQ connection error', { error: err.message });
      });
      amqpConnection.on('close', () => {
        logger.warn('RabbitMQ connection closed');
      });

      const channel = await amqpConnection.createChannel();
      const collector = new EventCollector(pool, channel, integrityChecker, eventStore, alertEngine, wsClients, metrics);
      await collector.start();
      logger.info('RabbitMQ event collector started');
    } catch (err) {
      logger.warn('RabbitMQ connection failed, event collection disabled', { error: err.message });
    }

    // 8. Start HTTP server
    server.listen(PORT, () => {
      logger.info(`Audit service listening on port ${PORT}`, {
        port: PORT,
        env: process.env.NODE_ENV || 'development',
      });
    });
  } catch (err) {
    logger.error('Failed to start audit service', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

// ── Graceful Shutdown ───────────────────────────────────────────────────────────
async function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully...`);

  // Close WebSocket connections
  for (const client of wsClients) {
    try {
      client.close(1001, 'Server shutting down');
    } catch (err) {
      // ignore
    }
  }
  wsClients.clear();

  // Close HTTP server
  server.close(() => {
    logger.info('HTTP server closed');
  });

  // Close Redis
  if (redis) {
    try {
      await redis.quit();
      logger.info('Redis disconnected');
    } catch (err) {
      logger.warn('Redis disconnect error', { error: err.message });
    }
  }

  // Close PostgreSQL pool
  try {
    await pool.end();
    logger.info('PostgreSQL pool closed');
  } catch (err) {
    logger.warn('PostgreSQL pool close error', { error: err.message });
  }

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: String(reason) });
});

start();

module.exports = app;
