const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const EventSource = require('eventsource');

// Import monitoring services
const MetricsCollector = require('./services/metricsCollector');
const AlertManager = require('./services/alertManager');
const LogAggregator = require('./services/logAggregator');
const PerformanceMonitor = require('./services/performanceMonitor');
const PredictiveAnalytics = require('./services/predictiveAnalytics');
const AnomalyDetector = require('./services/anomalyDetector');
const HealthChecker = require('./services/healthChecker');
const ReportGenerator = require('./services/reportGenerator');
const DashboardService = require('./services/dashboardService');
const NotificationService = require('./services/notificationService');
const SLAMonitor = require('./services/slaMonitor');
const CostAnalyzer = require('./services/costAnalyzer');

// Data stores
const TimeSeriesDB = require('./database/timeSeriesDB');
const MetricsCache = require('./cache/metricsCache');
const AlertStore = require('./database/alertStore');

// Utilities
const logger = require('./utils/logger');
const config = require('./config');
const EventBus = require('./events/eventBus');

// ── RabbitMQ Event Bus ────────────────────────────────────────────────────────
let _amqpChannel = null;
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672';
const EVENTS_EXCHANGE = 'opendirectory.events';

async function connectBus(serviceName) {
  const amqplib = require('amqplib');
  try {
    const conn = await amqplib.connect(RABBITMQ_URL);
    conn.on('error', () => { _amqpChannel = null; });
    conn.on('close', () => { _amqpChannel = null; setTimeout(() => connectBus(serviceName), 5000); });
    const ch = await conn.createChannel();
    await ch.assertExchange(EVENTS_EXCHANGE, 'topic', { durable: true });
    _amqpChannel = ch;
    console.log(`[${serviceName}] RabbitMQ connected`);
    return ch;
  } catch (e) {
    console.warn(`[${serviceName}] RabbitMQ unavailable, retrying in 10s:`, e.message);
    setTimeout(() => connectBus(serviceName), 10000);
    return null;
  }
}

function publishEvent(routingKey, payload, source) {
  if (!_amqpChannel) return;
  try {
    _amqpChannel.publish(EVENTS_EXCHANGE, routingKey,
      Buffer.from(JSON.stringify({ ...payload, _timestamp: new Date().toISOString(), _source: source })),
      { persistent: true, contentType: 'application/json' }
    );
  } catch (_) {}
}

async function subscribeToEvents(queueName, routingKeys, handler) {
  if (!_amqpChannel) return;
  try {
    await _amqpChannel.assertQueue(queueName, {
      durable: true,
      arguments: { 'x-message-ttl': 86400000, 'x-max-length': 10000 }
    });
    for (const rk of routingKeys) {
      await _amqpChannel.bindQueue(queueName, EVENTS_EXCHANGE, rk);
    }
    _amqpChannel.prefetch(5);
    _amqpChannel.consume(queueName, async (msg) => {
      if (!msg) return;
      try {
        const payload = JSON.parse(msg.content.toString());
        await handler(msg.fields.routingKey, payload);
        _amqpChannel.ack(msg);
      } catch (e) {
        _amqpChannel.nack(msg, false, !msg.fields.redelivered);
      }
    });
  } catch (e) {
    console.warn('subscribe error:', e.message);
  }
}
// ─────────────────────────────────────────────────────────────────────────────

class EnterpriseMonitoringService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/monitoring'
    });
    
    // Initialize data stores
    this.timeSeriesDB = new TimeSeriesDB();
    this.metricsCache = new MetricsCache();
    this.alertStore = new AlertStore();
    this.eventBus = new EventBus();
    
    // Initialize services
    this.metricsCollector = new MetricsCollector(this.timeSeriesDB, this.metricsCache);
    this.alertManager = new AlertManager(this.alertStore, this.eventBus);
    this.logAggregator = new LogAggregator(this.timeSeriesDB);
    this.performanceMonitor = new PerformanceMonitor(this.timeSeriesDB);
    this.predictiveAnalytics = new PredictiveAnalytics(this.timeSeriesDB);
    this.anomalyDetector = new AnomalyDetector(this.timeSeriesDB, this.alertManager);
    this.healthChecker = new HealthChecker(this.eventBus);
    this.reportGenerator = new ReportGenerator(this.timeSeriesDB);
    this.dashboardService = new DashboardService(this.timeSeriesDB, this.metricsCache);
    this.notificationService = new NotificationService(this.eventBus);
    this.slaMonitor = new SLAMonitor(this.timeSeriesDB, this.alertManager);
    this.costAnalyzer = new CostAnalyzer(this.timeSeriesDB);
    
    // Active connections for real-time updates
    this.activeConnections = new Map();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeEventHandlers();
    this.startBackgroundJobs();
  }

  initializeMiddleware() {
    // Security
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "wss:", "https:"],
        },
      },
    }));

    // Compression
    this.app.use(compression());

    // CORS
    this.app.use(cors({
      origin: config.cors.origins,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    }));

    // Rate limiting
    const monitoringLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 10000, // High limit for monitoring endpoints
      message: 'Rate limit exceeded for monitoring API',
      skip: (req) => req.path.startsWith('/metrics') // Skip for metrics scraping
    });

    this.app.use('/api', monitoringLimiter);

    // Body parsing
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Request tracking
    this.app.use((req, res, next) => {
      req.startTime = Date.now();
      req.id = req.headers['x-request-id'] || this.generateId();
      res.setHeader('X-Request-ID', req.id);
      
      res.on('finish', () => {
        const duration = Date.now() - req.startTime;
        this.metricsCollector.recordAPIMetric(req.method, req.path, res.statusCode, duration);
      });
      
      next();
    });
  }

  initializeWebSocket() {
    this.wss.on('connection', (ws, req) => {
      const connectionId = this.generateId();
      ws.id = connectionId;
      ws.subscriptions = new Set();
      ws.isAlive = true;
      
      this.activeConnections.set(connectionId, {
        ws,
        connectedAt: Date.now(),
        lastActivity: Date.now(),
        subscriptions: new Set()
      });

      logger.info('Monitoring WebSocket connection established', { connectionId });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
          
          // Update last activity
          const connection = this.activeConnections.get(connectionId);
          if (connection) {
            connection.lastActivity = Date.now();
          }
        } catch (error) {
          logger.error('WebSocket message error:', error);
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format',
            timestamp: Date.now()
          }));
        }
      });

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('close', () => {
        this.activeConnections.delete(connectionId);
        logger.info('Monitoring WebSocket connection closed', { connectionId });
      });

      ws.on('error', (error) => {
        logger.error('WebSocket error:', error);
        this.activeConnections.delete(connectionId);
      });

      // Send initial connection info
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        connectionId,
        timestamp: Date.now(),
        availableSubscriptions: [
          'real-time-metrics',
          'alerts',
          'health-status',
          'performance-data',
          'log-stream',
          'anomaly-alerts'
        ]
      }));
    });

    // WebSocket heartbeat
    setInterval(() => {
      this.wss.clients.forEach((ws) => {
        if (!ws.isAlive) {
          return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
  }

  initializeRoutes() {
    // Health check with comprehensive status
    this.app.get('/health', async (req, res) => {
      try {
        const health = await this.healthChecker.getSystemHealth();
        
        res.status(health.status === 'healthy' ? 200 : 503).json({
          ...health,
          service: 'monitoring-service',
          timestamp: Date.now(),
          version: config.version,
          uptime: process.uptime(),
          connections: {
            websocket: this.wss.clients.size,
            active: this.activeConnections.size
          },
          metrics: {
            alertsActive: await this.alertManager.getActiveAlertCount(),
            metricsCollected: await this.metricsCollector.getTotalMetricsCount(),
            anomaliesDetected: await this.anomalyDetector.getAnomalyCount()
          }
        });
      } catch (error) {
        logger.error('Health check error:', error);
        res.status(503).json({
          status: 'unhealthy',
          error: error.message,
          timestamp: Date.now()
        });
      }
    });

    // Prometheus metrics endpoint
    this.app.get('/metrics', async (req, res) => {
      try {
        const metrics = await this.metricsCollector.getPrometheusMetrics();
        res.set('Content-Type', 'text/plain');
        res.send(metrics);
      } catch (error) {
        logger.error('Metrics endpoint error:', error);
        res.status(500).send('# Error retrieving metrics');
      }
    });

    // Real-time metrics API
    this.app.get('/api/metrics/real-time', this.getRealTimeMetrics.bind(this));
    this.app.get('/api/metrics/historical', this.getHistoricalMetrics.bind(this));
    this.app.get('/api/metrics/custom', this.getCustomMetrics.bind(this));
    this.app.post('/api/metrics/ingest', this.ingestMetrics.bind(this));
    
    // Dashboard APIs
    this.app.get('/api/dashboard/overview', this.getDashboardOverview.bind(this));
    this.app.get('/api/dashboard/performance', this.getPerformanceDashboard.bind(this));
    this.app.get('/api/dashboard/security', this.getSecurityDashboard.bind(this));
    this.app.get('/api/dashboard/infrastructure', this.getInfrastructureDashboard.bind(this));
    this.app.get('/api/dashboard/custom/:dashboardId', this.getCustomDashboard.bind(this));
    
    // Alert management
    this.app.get('/api/alerts', this.getAlerts.bind(this));
    this.app.post('/api/alerts', this.createAlert.bind(this));
    this.app.get('/api/alerts/:alertId', this.getAlert.bind(this));
    this.app.put('/api/alerts/:alertId', this.updateAlert.bind(this));
    this.app.delete('/api/alerts/:alertId', this.deleteAlert.bind(this));
    this.app.post('/api/alerts/:alertId/acknowledge', this.acknowledgeAlert.bind(this));
    this.app.post('/api/alerts/bulk-acknowledge', this.bulkAcknowledgeAlerts.bind(this));
    
    // Performance monitoring
    this.app.get('/api/performance/services', this.getServicePerformance.bind(this));
    this.app.get('/api/performance/infrastructure', this.getInfrastructurePerformance.bind(this));
    this.app.get('/api/performance/applications', this.getApplicationPerformance.bind(this));
    this.app.get('/api/performance/bottlenecks', this.getPerformanceBottlenecks.bind(this));
    
    // Log management
    this.app.get('/api/logs/search', this.searchLogs.bind(this));
    this.app.get('/api/logs/stream', this.streamLogs.bind(this));
    this.app.post('/api/logs/ingest', this.ingestLogs.bind(this));
    this.app.get('/api/logs/analysis', this.getLogAnalysis.bind(this));
    
    // Predictive analytics
    this.app.get('/api/analytics/predictions', this.getPredictions.bind(this));
    this.app.get('/api/analytics/trends', this.getTrends.bind(this));
    this.app.get('/api/analytics/capacity', this.getCapacityPredictions.bind(this));
    this.app.get('/api/analytics/anomalies', this.getAnomalies.bind(this));
    
    // SLA monitoring
    this.app.get('/api/sla/status', this.getSLAStatus.bind(this));
    this.app.get('/api/sla/reports', this.getSLAReports.bind(this));
    this.app.post('/api/sla/targets', this.createSLATarget.bind(this));
    this.app.put('/api/sla/targets/:targetId', this.updateSLATarget.bind(this));
    
    // Cost analysis
    this.app.get('/api/cost/analysis', this.getCostAnalysis.bind(this));
    this.app.get('/api/cost/optimization', this.getCostOptimization.bind(this));
    this.app.get('/api/cost/trends', this.getCostTrends.bind(this));
    
    // Reports
    this.app.get('/api/reports/generate', this.generateReport.bind(this));
    this.app.get('/api/reports/scheduled', this.getScheduledReports.bind(this));
    this.app.post('/api/reports/schedule', this.scheduleReport.bind(this));
    this.app.get('/api/reports/:reportId/download', this.downloadReport.bind(this));
    
    // Notification management
    this.app.get('/api/notifications/channels', this.getNotificationChannels.bind(this));
    this.app.post('/api/notifications/channels', this.createNotificationChannel.bind(this));
    this.app.put('/api/notifications/channels/:channelId', this.updateNotificationChannel.bind(this));
    this.app.post('/api/notifications/test', this.testNotification.bind(this));
    
    // Server-Sent Events for real-time updates
    this.app.get('/api/stream/metrics', this.streamMetrics.bind(this));
    this.app.get('/api/stream/alerts', this.streamAlerts.bind(this));
    this.app.get('/api/stream/logs', this.streamLogsSSE.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    try {
      switch (type) {
        case 'subscribe':
          await this.handleSubscription(ws, data.subscription, data.options);
          ws.send(JSON.stringify({
            type: 'subscription_confirmed',
            subscription: data.subscription,
            requestId,
            timestamp: Date.now()
          }));
          break;

        case 'unsubscribe':
          this.handleUnsubscription(ws, data.subscription);
          break;

        case 'get_live_metrics':
          const metrics = await this.dashboardService.getLiveMetrics(data.timeRange);
          ws.send(JSON.stringify({
            type: 'live_metrics',
            data: metrics,
            requestId,
            timestamp: Date.now()
          }));
          break;

        case 'query_metrics':
          const queryResult = await this.metricsCollector.queryMetrics(data.query);
          ws.send(JSON.stringify({
            type: 'query_result',
            data: queryResult,
            requestId,
            timestamp: Date.now()
          }));
          break;

        default:
          ws.send(JSON.stringify({
            type: 'error',
            message: `Unknown message type: ${type}`,
            requestId,
            timestamp: Date.now()
          }));
      }
    } catch (error) {
      logger.error('WebSocket message handling error:', error);
      ws.send(JSON.stringify({
        type: 'error',
        message: error.message,
        requestId,
        timestamp: Date.now()
      }));
    }
  }

  async handleSubscription(ws, subscription, options = {}) {
    ws.subscriptions.add(subscription);
    
    const connection = this.activeConnections.get(ws.id);
    if (connection) {
      connection.subscriptions.add(subscription);
    }

    // Send initial data based on subscription type
    switch (subscription) {
      case 'real-time-metrics':
        const metrics = await this.dashboardService.getRealTimeMetrics();
        ws.send(JSON.stringify({
          type: 'initial_data',
          subscription,
          data: metrics,
          timestamp: Date.now()
        }));
        break;

      case 'alerts':
        const alerts = await this.alertManager.getActiveAlerts();
        ws.send(JSON.stringify({
          type: 'initial_data',
          subscription,
          data: alerts,
          timestamp: Date.now()
        }));
        break;

      case 'health-status':
        const health = await this.healthChecker.getCurrentHealthStatus();
        ws.send(JSON.stringify({
          type: 'initial_data',
          subscription,
          data: health,
          timestamp: Date.now()
        }));
        break;
    }
  }

  initializeEventHandlers() {
    // Alert events
    this.eventBus.on('alert:triggered', (alert) => {
      this.broadcastToSubscribers('alerts', {
        type: 'alert_triggered',
        alert,
        timestamp: Date.now()
      });
    });

    this.eventBus.on('alert:resolved', (alert) => {
      this.broadcastToSubscribers('alerts', {
        type: 'alert_resolved',
        alert,
        timestamp: Date.now()
      });
    });

    // Anomaly detection events
    this.eventBus.on('anomaly:detected', (anomaly) => {
      this.broadcastToSubscribers('anomaly-alerts', {
        type: 'anomaly_detected',
        anomaly,
        timestamp: Date.now()
      });
    });

    // Health status changes
    this.eventBus.on('health:status_change', (status) => {
      this.broadcastToSubscribers('health-status', {
        type: 'health_change',
        status,
        timestamp: Date.now()
      });
    });

    // Performance threshold breaches
    this.eventBus.on('performance:threshold_breach', (breach) => {
      this.broadcastToSubscribers('performance-data', {
        type: 'threshold_breach',
        breach,
        timestamp: Date.now()
      });
    });
  }

  startBackgroundJobs() {
    // Real-time metrics broadcasting
    setInterval(async () => {
      try {
        const metrics = await this.dashboardService.getRealTimeMetrics();
        this.broadcastToSubscribers('real-time-metrics', {
          type: 'metrics_update',
          metrics,
          timestamp: Date.now()
        });
      } catch (error) {
        logger.error('Real-time metrics broadcast error:', error);
      }
    }, config.realTime.metricsInterval);

    // Anomaly detection
    setInterval(async () => {
      try {
        await this.anomalyDetector.detectAnomalies();
      } catch (error) {
        logger.error('Anomaly detection error:', error);
      }
    }, config.anomalyDetection.interval);

    // Predictive analytics
    setInterval(async () => {
      try {
        await this.predictiveAnalytics.generatePredictions();
      } catch (error) {
        logger.error('Predictive analytics error:', error);
      }
    }, config.predictiveAnalytics.interval);

    // SLA monitoring
    setInterval(async () => {
      try {
        await this.slaMonitor.checkSLAs();
      } catch (error) {
        logger.error('SLA monitoring error:', error);
      }
    }, config.sla.checkInterval);

    // Log retention cleanup
    setInterval(async () => {
      try {
        await this.logAggregator.cleanupOldLogs();
      } catch (error) {
        logger.error('Log cleanup error:', error);
      }
    }, config.logging.cleanupInterval);

    // Cost analysis
    setInterval(async () => {
      try {
        await this.costAnalyzer.generateCostReports();
      } catch (error) {
        logger.error('Cost analysis error:', error);
      }
    }, config.costAnalysis.reportInterval);
  }

  // ── Alert API Handlers ────────────────────────────────────────────────────

  async getAlerts(req, res) {
    try {
      const { status, severity, service, limit, offset } = req.query;
      const alerts = await this.alertManager.getAllAlerts({
        status, severity, service,
        limit: limit ? parseInt(limit) : 100,
        offset: offset ? parseInt(offset) : 0,
      });
      res.json({ success: true, data: alerts, requestId: req.id });
    } catch (error) {
      logger.error('Get alerts error:', error);
      res.status(500).json({ error: 'Failed to get alerts', requestId: req.id });
    }
  }

  async createAlert(req, res) {
    try {
      const alert = await this.alertManager.trigger(req.body);
      res.status(201).json({ success: true, data: alert, requestId: req.id });
    } catch (error) {
      logger.error('Create alert error:', error);
      res.status(500).json({ error: 'Failed to create alert', requestId: req.id });
    }
  }

  async getAlert(req, res) {
    try {
      const alert = await this.alertManager.getAlertById(req.params.alertId);
      if (!alert) return res.status(404).json({ error: 'Alert not found', requestId: req.id });
      res.json({ success: true, data: alert, requestId: req.id });
    } catch (error) {
      logger.error('Get alert error:', error);
      res.status(500).json({ error: 'Failed to get alert', requestId: req.id });
    }
  }

  async updateAlert(req, res) {
    try {
      const alert = await this.alertManager.updateAlert(req.params.alertId, req.body);
      if (!alert) return res.status(404).json({ error: 'Alert not found', requestId: req.id });
      res.json({ success: true, data: alert, requestId: req.id });
    } catch (error) {
      logger.error('Update alert error:', error);
      res.status(500).json({ error: 'Failed to update alert', requestId: req.id });
    }
  }

  async deleteAlert(req, res) {
    try {
      const deleted = await this.alertManager.deleteAlert(req.params.alertId);
      if (!deleted) return res.status(404).json({ error: 'Alert not found', requestId: req.id });
      res.json({ success: true, requestId: req.id });
    } catch (error) {
      logger.error('Delete alert error:', error);
      res.status(500).json({ error: 'Failed to delete alert', requestId: req.id });
    }
  }

  async acknowledgeAlert(req, res) {
    try {
      const { acknowledgedBy } = req.body;
      const alert = await this.alertManager.acknowledge(req.params.alertId, acknowledgedBy || 'api');
      if (!alert) return res.status(404).json({ error: 'Alert not found', requestId: req.id });
      res.json({ success: true, data: alert, requestId: req.id });
    } catch (error) {
      logger.error('Acknowledge alert error:', error);
      res.status(500).json({ error: 'Failed to acknowledge alert', requestId: req.id });
    }
  }

  async bulkAcknowledgeAlerts(req, res) {
    try {
      const { alertIds, acknowledgedBy } = req.body;
      if (!Array.isArray(alertIds)) {
        return res.status(400).json({ error: 'alertIds must be an array', requestId: req.id });
      }
      const results = await this.alertManager.bulkAcknowledge(alertIds, acknowledgedBy || 'api');
      res.json({ success: true, data: results, count: results.length, requestId: req.id });
    } catch (error) {
      logger.error('Bulk acknowledge error:', error);
      res.status(500).json({ error: 'Failed to bulk acknowledge alerts', requestId: req.id });
    }
  }

  // ── Performance API Handlers ──────────────────────────────────────────────

  async getServicePerformance(req, res) {
    try {
      const data = await this.performanceMonitor.getServicePerformance();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Service performance error:', error);
      res.status(500).json({ error: 'Failed to get service performance', requestId: req.id });
    }
  }

  async getInfrastructurePerformance(req, res) {
    try {
      const data = await this.performanceMonitor.getInfrastructurePerformance();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Infrastructure performance error:', error);
      res.status(500).json({ error: 'Failed to get infrastructure performance', requestId: req.id });
    }
  }

  async getApplicationPerformance(req, res) {
    try {
      const data = await this.performanceMonitor.getApplicationPerformance();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Application performance error:', error);
      res.status(500).json({ error: 'Failed to get application performance', requestId: req.id });
    }
  }

  async getPerformanceBottlenecks(req, res) {
    try {
      const data = await this.performanceMonitor.getBottlenecks();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Bottlenecks error:', error);
      res.status(500).json({ error: 'Failed to get performance bottlenecks', requestId: req.id });
    }
  }

  // ── Log API Handlers ───────────────────────────────────────────────────────

  async searchLogs(req, res) {
    try {
      const { query, level, service, startTs, endTs, limit, offset } = req.query;
      const results = this.logAggregator.search({
        query, level, service,
        startTs: startTs ? parseInt(startTs) : undefined,
        endTs: endTs ? parseInt(endTs) : undefined,
        limit: limit ? parseInt(limit) : 100,
        offset: offset ? parseInt(offset) : 0,
      });
      res.json({ success: true, data: results, count: results.length, requestId: req.id });
    } catch (error) {
      logger.error('Log search error:', error);
      res.status(500).json({ error: 'Failed to search logs', requestId: req.id });
    }
  }

  async streamLogs(req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    const unsubscribe = this.logAggregator.subscribe((log) => {
      res.write(`data: ${JSON.stringify(log)}\n\n`);
    });

    req.on('close', unsubscribe);
    req.on('error', unsubscribe);
  }

  async streamLogsSSE(req, res) {
    return this.streamLogs(req, res);
  }

  async ingestLogs(req, res) {
    try {
      const entries = Array.isArray(req.body) ? req.body : [req.body];
      const results = this.logAggregator.ingestBatch(entries);
      res.status(201).json({ success: true, count: results.length, requestId: req.id });
    } catch (error) {
      logger.error('Log ingest error:', error);
      res.status(500).json({ error: 'Failed to ingest logs', requestId: req.id });
    }
  }

  async getLogAnalysis(req, res) {
    try {
      const analysis = this.logAggregator.getAnalysis();
      res.json({ success: true, data: analysis, requestId: req.id });
    } catch (error) {
      logger.error('Log analysis error:', error);
      res.status(500).json({ error: 'Failed to get log analysis', requestId: req.id });
    }
  }

  // ── Analytics API Handlers ────────────────────────────────────────────────

  async getPredictions(req, res) {
    try {
      const data = await this.predictiveAnalytics.getPredictions();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Predictions error:', error);
      res.status(500).json({ error: 'Failed to get predictions', requestId: req.id });
    }
  }

  async getTrends(req, res) {
    try {
      const data = await this.predictiveAnalytics.getTrends();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Trends error:', error);
      res.status(500).json({ error: 'Failed to get trends', requestId: req.id });
    }
  }

  async getCapacityPredictions(req, res) {
    try {
      const data = await this.predictiveAnalytics.getCapacityPredictions();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Capacity predictions error:', error);
      res.status(500).json({ error: 'Failed to get capacity predictions', requestId: req.id });
    }
  }

  async getAnomalies(req, res) {
    try {
      const { limit } = req.query;
      const data = await this.anomalyDetector.getAnomalies({ limit: limit ? parseInt(limit) : 50 });
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Anomalies error:', error);
      res.status(500).json({ error: 'Failed to get anomalies', requestId: req.id });
    }
  }

  // ── SLA API Handlers ───────────────────────────────────────────────────────

  async getSLAStatus(req, res) {
    try {
      const data = await this.slaMonitor.getSLAStatus();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('SLA status error:', error);
      res.status(500).json({ error: 'Failed to get SLA status', requestId: req.id });
    }
  }

  async getSLAReports(req, res) {
    try {
      const { period } = req.query;
      const data = await this.slaMonitor.getSLAReports(period || '30d');
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('SLA reports error:', error);
      res.status(500).json({ error: 'Failed to get SLA reports', requestId: req.id });
    }
  }

  async createSLATarget(req, res) {
    try {
      const target = this.slaMonitor.createTarget(req.body);
      res.status(201).json({ success: true, data: target, requestId: req.id });
    } catch (error) {
      logger.error('Create SLA target error:', error);
      res.status(500).json({ error: 'Failed to create SLA target', requestId: req.id });
    }
  }

  async updateSLATarget(req, res) {
    try {
      const target = this.slaMonitor.updateTarget(req.params.targetId, req.body);
      if (!target) return res.status(404).json({ error: 'SLA target not found', requestId: req.id });
      res.json({ success: true, data: target, requestId: req.id });
    } catch (error) {
      logger.error('Update SLA target error:', error);
      res.status(500).json({ error: 'Failed to update SLA target', requestId: req.id });
    }
  }

  // ── Cost API Handlers ──────────────────────────────────────────────────────

  async getCostAnalysis(req, res) {
    try {
      const data = await this.costAnalyzer.getCostAnalysis();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Cost analysis error:', error);
      res.status(500).json({ error: 'Failed to get cost analysis', requestId: req.id });
    }
  }

  async getCostOptimization(req, res) {
    try {
      const data = await this.costAnalyzer.getCostOptimization();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Cost optimization error:', error);
      res.status(500).json({ error: 'Failed to get cost optimization', requestId: req.id });
    }
  }

  async getCostTrends(req, res) {
    try {
      const { period } = req.query;
      const data = await this.costAnalyzer.getCostTrends(period || '30d');
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Cost trends error:', error);
      res.status(500).json({ error: 'Failed to get cost trends', requestId: req.id });
    }
  }

  // ── Report API Handlers ────────────────────────────────────────────────────

  async generateReport(req, res) {
    try {
      const report = await this.reportGenerator.generate(req.query);
      res.json({ success: true, data: report, requestId: req.id });
    } catch (error) {
      logger.error('Generate report error:', error);
      res.status(500).json({ error: 'Failed to generate report', requestId: req.id });
    }
  }

  async getScheduledReports(req, res) {
    try {
      const data = await this.reportGenerator.getScheduled();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Get scheduled reports error:', error);
      res.status(500).json({ error: 'Failed to get scheduled reports', requestId: req.id });
    }
  }

  async scheduleReport(req, res) {
    try {
      const schedule = await this.reportGenerator.schedule(req.body);
      res.status(201).json({ success: true, data: schedule, requestId: req.id });
    } catch (error) {
      logger.error('Schedule report error:', error);
      res.status(500).json({ error: 'Failed to schedule report', requestId: req.id });
    }
  }

  async downloadReport(req, res) {
    try {
      const report = await this.reportGenerator.getReport(req.params.reportId);
      if (!report) return res.status(404).json({ error: 'Report not found', requestId: req.id });
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="report-${req.params.reportId}.json"`);
      res.send(JSON.stringify(report.data, null, 2));
    } catch (error) {
      logger.error('Download report error:', error);
      res.status(500).json({ error: 'Failed to download report', requestId: req.id });
    }
  }

  // ── Notification API Handlers ──────────────────────────────────────────────

  async getNotificationChannels(req, res) {
    try {
      const channels = this.notificationService.getChannels();
      res.json({ success: true, data: channels, requestId: req.id });
    } catch (error) {
      logger.error('Get notification channels error:', error);
      res.status(500).json({ error: 'Failed to get notification channels', requestId: req.id });
    }
  }

  async createNotificationChannel(req, res) {
    try {
      const channel = this.notificationService.createChannel(req.body);
      res.status(201).json({ success: true, data: channel, requestId: req.id });
    } catch (error) {
      logger.error('Create notification channel error:', error);
      res.status(500).json({ error: 'Failed to create notification channel', requestId: req.id });
    }
  }

  async updateNotificationChannel(req, res) {
    try {
      const channel = this.notificationService.updateChannel(req.params.channelId, req.body);
      if (!channel) return res.status(404).json({ error: 'Channel not found', requestId: req.id });
      res.json({ success: true, data: channel, requestId: req.id });
    } catch (error) {
      logger.error('Update notification channel error:', error);
      res.status(500).json({ error: 'Failed to update notification channel', requestId: req.id });
    }
  }

  async testNotification(req, res) {
    try {
      const { channelId } = req.body;
      if (!channelId) return res.status(400).json({ error: 'channelId is required', requestId: req.id });
      const result = await this.notificationService.testChannel(channelId);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) {
      logger.error('Test notification error:', error);
      res.status(500).json({ error: 'Failed to test notification', requestId: req.id });
    }
  }

  // ── SSE alert stream ───────────────────────────────────────────────────────

  async streamAlerts(req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // Send initial active alerts
    try {
      const alerts = await this.alertManager.getActiveAlerts();
      res.write(`data: ${JSON.stringify({ type: 'initial', alerts, timestamp: Date.now() })}\n\n`);
    } catch { /* ignore */ }

    const onAlert = (data) => {
      res.write(`data: ${JSON.stringify({ ...data, timestamp: Date.now() })}\n\n`);
    };

    this.eventBus.on('alert:triggered', onAlert);
    this.eventBus.on('alert:resolved', onAlert);

    req.on('close', () => {
      this.eventBus.off('alert:triggered', onAlert);
      this.eventBus.off('alert:resolved', onAlert);
    });
  }

  // ── Custom metrics ingest / dashboard ─────────────────────────────────────

  async getCustomMetrics(req, res) {
    try {
      const data = await this.metricsCollector.getCustomMetrics(req.query);
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Custom metrics error:', error);
      res.status(500).json({ error: 'Failed to get custom metrics', requestId: req.id });
    }
  }

  async ingestMetrics(req, res) {
    try {
      await this.metricsCollector.ingestMetrics(req.body);
      res.status(201).json({ success: true, requestId: req.id });
    } catch (error) {
      logger.error('Metrics ingest error:', error);
      res.status(500).json({ error: 'Failed to ingest metrics', requestId: req.id });
    }
  }

  async getPerformanceDashboard(req, res) {
    try {
      const { timeRange = '1h' } = req.query;
      const data = await this.dashboardService.getPerformanceDashboard(timeRange);
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Performance dashboard error:', error);
      res.status(500).json({ error: 'Failed to get performance dashboard', requestId: req.id });
    }
  }

  async getSecurityDashboard(req, res) {
    try {
      const { timeRange = '1h' } = req.query;
      const data = await this.dashboardService.getSecurityDashboard(timeRange);
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Security dashboard error:', error);
      res.status(500).json({ error: 'Failed to get security dashboard', requestId: req.id });
    }
  }

  async getInfrastructureDashboard(req, res) {
    try {
      const { timeRange = '1h' } = req.query;
      const data = await this.dashboardService.getInfrastructureDashboard(timeRange);
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Infrastructure dashboard error:', error);
      res.status(500).json({ error: 'Failed to get infrastructure dashboard', requestId: req.id });
    }
  }

  async getCustomDashboard(req, res) {
    try {
      const data = await this.dashboardService.getCustomDashboard(req.params.dashboardId);
      res.json({ success: true, data, requestId: req.id });
    } catch (error) {
      logger.error('Custom dashboard error:', error);
      res.status(500).json({ error: 'Failed to get custom dashboard', requestId: req.id });
    }
  }

  handleUnsubscription(ws, subscription) {
    ws.subscriptions.delete(subscription);
    const connection = this.activeConnections.get(ws.id);
    if (connection) connection.subscriptions.delete(subscription);
  }

  // ── Original API Handlers ─────────────────────────────────────────────────
  // API Handlers
  async getDashboardOverview(req, res) {
    try {
      const { timeRange = '1h' } = req.query;
      
      const overview = await this.dashboardService.getOverview(timeRange);
      
      res.json({
        success: true,
        data: overview,
        timestamp: Date.now(),
        requestId: req.id
      });
    } catch (error) {
      logger.error('Dashboard overview error:', error);
      res.status(500).json({
        error: 'Failed to get dashboard overview',
        requestId: req.id
      });
    }
  }

  async getRealTimeMetrics(req, res) {
    try {
      const { services, metrics, interval = '1m' } = req.query;
      
      const data = await this.metricsCollector.getRealTimeMetrics({
        services: services ? services.split(',') : undefined,
        metrics: metrics ? metrics.split(',') : undefined,
        interval
      });
      
      res.json({
        success: true,
        data,
        timestamp: Date.now(),
        requestId: req.id
      });
    } catch (error) {
      logger.error('Real-time metrics error:', error);
      res.status(500).json({
        error: 'Failed to get real-time metrics',
        requestId: req.id
      });
    }
  }

  async getHistoricalMetrics(req, res) {
    try {
      const {
        services,
        metrics,
        startTime,
        endTime,
        aggregation = '5m'
      } = req.query;
      
      const data = await this.metricsCollector.getHistoricalMetrics({
        services: services ? services.split(',') : undefined,
        metrics: metrics ? metrics.split(',') : undefined,
        startTime: parseInt(startTime),
        endTime: parseInt(endTime),
        aggregation
      });
      
      res.json({
        success: true,
        data,
        requestId: req.id
      });
    } catch (error) {
      logger.error('Historical metrics error:', error);
      res.status(500).json({
        error: 'Failed to get historical metrics',
        requestId: req.id
      });
    }
  }

  async streamMetrics(req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });

    const streamId = this.generateId();
    
    const sendMetrics = async () => {
      try {
        const metrics = await this.dashboardService.getRealTimeMetrics();
        res.write(`data: ${JSON.stringify({
          type: 'metrics',
          data: metrics,
          timestamp: Date.now()
        })}\\n\\n`);
      } catch (error) {
        logger.error('SSE metrics stream error:', error);
      }
    };

    // Send initial data
    await sendMetrics();

    // Send periodic updates
    const interval = setInterval(sendMetrics, 5000);

    req.on('close', () => {
      clearInterval(interval);
      logger.info('SSE metrics stream closed', { streamId });
    });

    req.on('error', (error) => {
      clearInterval(interval);
      logger.error('SSE metrics stream error:', error);
    });
  }

  broadcastToSubscribers(subscription, data) {
    let count = 0;
    this.activeConnections.forEach((connection) => {
      if (connection.ws.readyState === WebSocket.OPEN && 
          connection.subscriptions.has(subscription)) {
        connection.ws.send(JSON.stringify({
          type: 'broadcast',
          subscription,
          data,
          timestamp: Date.now()
        }));
        count++;
      }
    });
    
    if (count > 0) {
      logger.debug(`Broadcast sent to ${count} subscribers`, { subscription });
    }
  }

  generateId() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  errorHandler(error, req, res, next) {
    logger.error('Monitoring service error:', error, {
      requestId: req.id,
      path: req.path,
      method: req.method
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: Date.now(),
      service: 'monitoring-service'
    });
  }

  start(port = process.env.PORT || 3009) {
    // Connect to RabbitMQ event bus (fire and forget)
    connectBus('monitoring-service');

    setTimeout(async () => {
      await subscribeToEvents('monitoring.events', [
        'device.non_compliant',
        'app.install.failed',
        'system.backup.failed',
        'system.backup.completed',
        'compliance.failed',
        'policy.violated',
        'identity.login.failed',
        'admin.#',
      ], async (routingKey, payload) => {
        try {
          const alertData = {
            id: require('crypto').randomUUID(),
            title: `Event: ${routingKey}`,
            message: JSON.stringify(payload),
            severity: routingKey.includes('failed') ? 'critical' : 'warning',
            source: payload._source || 'message-bus',
            status: 'active',
            created_at: new Date().toISOString(),
          };
          if (typeof global.__od_activeAlerts === 'undefined') global.__od_activeAlerts = [];
          global.__od_activeAlerts.unshift(alertData);
          if (global.__od_activeAlerts.length > 200) global.__od_activeAlerts.length = 200;
        } catch (e) {
          logger.warn('monitoring event handler error:', e.message);
        }
      });
    }, 3000);

    this.server.listen(port, () => {
      publishEvent('admin.service.health', { service: 'monitoring', status: 'healthy', timestamp: new Date().toISOString() }, 'monitoring');
      logger.info(`📊 Enterprise Monitoring Service started on port ${port}`);
      logger.info(`🔍 Health check: http://localhost:${port}/health`);
      logger.info(`📈 Metrics: http://localhost:${port}/metrics`);
      logger.info(`🔌 WebSocket: ws://localhost:${port}/ws/monitoring`);
      logger.info(`📺 Features: Real-time Dashboards, Predictive Analytics, SLA Monitoring`);
      logger.info(`🚨 Alerts: Anomaly Detection, Performance Monitoring, Cost Analysis`);
    });
  }

  async gracefulShutdown() {
    logger.info('Starting graceful shutdown of monitoring service...');
    
    // Close WebSocket connections
    this.wss.clients.forEach(client => {
      client.send(JSON.stringify({
        type: 'server_shutdown',
        message: 'Server is shutting down',
        timestamp: Date.now()
      }));
      client.terminate();
    });
    
    // Close HTTP server
    this.server.close(() => {
      logger.info('HTTP server closed');
    });
    
    // Close data stores
    await this.timeSeriesDB.close();
    await this.metricsCache.close();
    await this.alertStore.close();
    
    logger.info('Graceful shutdown completed');
    process.exit(0);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  if (global.monitoringService) {
    global.monitoringService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  if (global.monitoringService) {
    global.monitoringService.gracefulShutdown();
  }
});

// Start the service
const monitoringService = new EnterpriseMonitoringService();
global.monitoringService = monitoringService;
monitoringService.start();

module.exports = EnterpriseMonitoringService;