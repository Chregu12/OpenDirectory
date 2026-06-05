const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');

// Shared RabbitMQ message bus
const MessageBus = require('../../../../packages/service-contracts/src/messageBus');
const { Events }  = require('../../../../packages/service-contracts/src/events');

// PostgreSQL persistence layer
const db = require('./db');

// Import enhanced services
const DeviceManager = require('./services/deviceManager');
const PolicyEngine = require('./services/policyEngine');
const ComplianceScanner = require('./services/complianceScanner');
const EnrollmentService = require('./services/enrollmentService');
const InventoryService = require('./services/inventoryService');
const RemoteActionService = require('./services/remoteActionService');
const GeofencingService = require('./services/geofencingService');
const CertificateManager = require('./services/certificateManager');
const ThreatDetector = require('./services/threatDetector');
const AnalyticsEngine = require('./services/analyticsEngine');
const PolicyAgentService = require('./services/PolicyAgentService');

// HTTP clients — replace cross-service file imports with proper API calls
const updateClient = require('./clients/updateClient');
const networkProfileClient = require('./clients/networkProfileClient');
const licenseClient = require('./clients/licenseClient');
const backupClient = require('./clients/backupClient');

// Enterprise services (local only)
const { AnalyticsBridge } = require('./analytics-bridge');

// Utilities
const logger = require('./utils/logger');
const config = require('./config');
const DatabaseManager = require('./database/manager');
const CacheManager = require('./cache/manager');
const EventBus = require('./events/eventBus');
const MetricsCollector = require('./metrics/collector');
const CircuitBreaker = require('./utils/circuitBreaker');

class EnterpriseDeviceManagementService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/devices'
    });
    
    // Initialize core components
    this.db = new DatabaseManager();
    this.cache = new CacheManager();
    this.eventBus = new EventBus();
    this.metrics = new MetricsCollector();
    this.circuitBreaker = new CircuitBreaker();
    
    // Initialize services
    this.deviceManager = new DeviceManager(this.db, this.cache, this.eventBus);
    this.policyEngine = new PolicyEngine(this.db, this.eventBus);
    this.complianceScanner = new ComplianceScanner(this.db, this.eventBus);
    this.enrollmentService = new EnrollmentService(this.db, this.eventBus);
    this.inventoryService = new InventoryService(this.db, this.cache);
    this.remoteActionService = new RemoteActionService(this.wss, this.eventBus);
    this.geofencingService = new GeofencingService(this.db, this.eventBus);
    this.certificateManager = new CertificateManager(this.db, this.eventBus);
    this.threatDetector = new ThreatDetector(this.db, this.eventBus);
    this.analyticsEngine = new AnalyticsEngine(this.db, this.cache);
    this.policyAgentService = new PolicyAgentService(this);

    // HTTP service clients (microservice isolation — no direct file imports)
    this.updateClient = updateClient;
    this.networkProfileClient = networkProfileClient;
    this.licenseClient = licenseClient;
    this.backupClient = backupClient;

    // Analytics Bridge (connects agent events to AI/ML analytics)
    this.analyticsBridge = new AnalyticsBridge();

    // RabbitMQ message bus — connect in background; failures must not crash service
    this.messageBus = new MessageBus();
    this.messageBus.connect(process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672').catch(err => {
      logger.warn('RabbitMQ unavailable, falling back to Redis cache for command queue', { error: err.message });
    });

    // Connected agent registry: deviceId -> WebSocket connection
    this.connectedAgents = new Map();

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
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // Compression
    this.app.use(compression({
      threshold: 1024,
      level: 6
    }));

    // CORS
    this.app.use(cors({
      origin: config.cors.origins,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-ID', 'X-Request-ID'],
      exposedHeaders: ['X-Total-Count', 'X-Request-ID', 'X-Response-Time']
    }));

    // Rate limiting
    const deviceLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: async (req) => {
        // Dynamic rate limits based on device type and user role
        const deviceType = req.headers['x-device-type'];
        const userRole = req.user?.roles || [];
        
        if (userRole.includes('admin')) return 10000;
        if (deviceType === 'server') return 5000;
        if (deviceType === 'workstation') return 1000;
        return 500;
      },
      message: 'Rate limit exceeded for device operations',
      standardHeaders: true,
      skip: (req) => config.environment === 'development'
    });

    this.app.use('/api/devices', deviceLimiter);

    // Body parsing with size limits
    this.app.use(express.json({ 
      limit: '10mb',
      verify: (req, res, buf) => {
        req.rawBody = buf;
      }
    }));
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: '10mb' 
    }));

    // Request ID middleware
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || this.generateRequestId();
      res.setHeader('X-Request-ID', req.id);
      next();
    });

    // Response time middleware
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        try { res.setHeader('X-Response-Time', `\${duration}ms`); } catch (_) {}
        this.metrics.recordResponseTime(req.route?.path || req.path, duration);
      });
      next();
    });

    // Logging middleware
    this.app.use((req, res, next) => {
      logger.info(`\${req.method} \${req.path}`, {
        requestId: req.id,
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        deviceId: req.headers['x-device-id']
      });
      next();
    });
  }

  initializeWebSocket() {
    this.wss.on('connection', (ws, req) => {
      ws.id = this.generateRequestId();
      ws.deviceId = req.headers['x-device-id'];
      ws.platform = req.headers['x-device-platform'] || 'unknown';
      ws.agentVersion = req.headers['x-agent-version'];
      ws.subscriptions = new Set();
      ws.isAlive = true;
      ws.connectedAt = new Date().toISOString();

      // Register agent in connected devices registry
      if (ws.deviceId) {
        this.connectedAgents.set(ws.deviceId, ws);
        logger.info('Agent registered', {
          connectionId: ws.id,
          deviceId: ws.deviceId,
          platform: ws.platform,
          agentVersion: ws.agentVersion
        });

        // Update last seen in database
        this.deviceManager.updateLastSeen(ws.deviceId).catch(() => {});
      }

      logger.info('WebSocket connection established', {
        connectionId: ws.id,
        deviceId: ws.deviceId
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          logger.error('WebSocket message error:', error);
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format'
          }));
        }
      });

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('close', () => {
        // Remove from connected agents registry
        if (ws.deviceId) {
          this.connectedAgents.delete(ws.deviceId);
          logger.info('Agent disconnected', {
            deviceId: ws.deviceId,
            platform: ws.platform
          });
        }
        logger.info('WebSocket connection closed', {
          connectionId: ws.id,
          deviceId: ws.deviceId
        });
      });

      ws.on('error', (error) => {
        logger.error('WebSocket error:', error);
      });

      // Send initial connection confirmation with server info
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        connectionId: ws.id,
        serverVersion: '1.0.0',
        heartbeatInterval: 30000,
        timestamp: new Date().toISOString()
      }));
    });

    // WebSocket heartbeat - server pings, client pongs
    setInterval(() => {
      this.wss.clients.forEach((ws) => {
        if (!ws.isAlive) {
          if (ws.deviceId) {
            this.connectedAgents.delete(ws.deviceId);
          }
          return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
  }

  initializeRoutes() {
    // Health check with detailed status
    this.app.get('/health', async (req, res) => {
      try {
        const health = {
          status: 'healthy',
          service: 'device-management-service',
          version: config.version,
          uptime: process.uptime(),
          timestamp: new Date().toISOString(),
          checks: {
            database: await this.db.healthCheck(),
            cache: await this.cache.healthCheck(),
            eventBus: await this.eventBus.healthCheck()
          },
          metrics: {
            activeDevices: await this.deviceManager.getActiveDeviceCount(),
            pendingEnrollments: await this.enrollmentService.getPendingCount(),
            complianceViolations: await this.complianceScanner.getViolationCount(),
            wsConnections: this.wss.clients.size
          }
        };

        const allHealthy = Object.values(health.checks).every(check => check.status === 'healthy');
        if (!allHealthy) {
          health.status = 'degraded';
          res.status(503);
        }

        res.json(health);
      } catch (error) {
        logger.error('Health check error:', error);
        res.status(503).json({
          status: 'unhealthy',
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    });

    // Device Management Routes
    this.app.get('/api/devices', this.getDevices.bind(this));
    this.app.post('/api/devices', this.createDevice.bind(this));
    this.app.get('/api/devices/:deviceId', this.getDevice.bind(this));
    this.app.put('/api/devices/:deviceId', this.updateDevice.bind(this));
    this.app.delete('/api/devices/:deviceId', this.deleteDevice.bind(this));
    this.app.post('/api/devices/:deviceId/lock', this.lockDevice.bind(this));
    this.app.post('/api/devices/:deviceId/unlock', this.unlockDevice.bind(this));
    this.app.post('/api/devices/:deviceId/wipe', this.wipeDevice.bind(this));
    // Stammdaten (master data) + photo
    this.app.get('/api/devices/:deviceId/stammdaten', this.getStammdaten.bind(this));
    this.app.put('/api/devices/:deviceId/stammdaten', this.updateStammdaten.bind(this));
    this.app.post('/api/devices/:deviceId/photo', this.uploadPhoto.bind(this));
    this.app.get('/api/devices/:deviceId/photo', this.getPhoto.bind(this));
    
    // Enrollment Routes
    this.app.post('/api/enrollment/initiate', this.initiateEnrollment.bind(this));
    this.app.post('/api/enrollment/complete', this.completeEnrollment.bind(this));
    this.app.post('/api/enrollment/verify', this.verifyEnrollment.bind(this));
    this.app.get('/api/enrollment/:enrollmentId/status', this.getEnrollmentStatus.bind(this));
    this.app.post('/api/enrollment/:enrollmentId/approve', this.approveEnrollment.bind(this));
    this.app.post('/api/enrollment/:enrollmentId/reject', this.rejectEnrollment.bind(this));
    
    // Policy Routes
    this.app.get('/api/policies', this.getPolicies.bind(this));
    this.app.post('/api/policies', this.createPolicy.bind(this));
    this.app.get('/api/policies/:policyId', this.getPolicy.bind(this));
    this.app.put('/api/policies/:policyId', this.updatePolicy.bind(this));
    this.app.delete('/api/policies/:policyId', this.deletePolicy.bind(this));
    this.app.post('/api/policies/:policyId/assign', this.assignPolicy.bind(this));
    this.app.post('/api/policies/:policyId/deploy', this.deployPolicy.bind(this));
    
    // Compliance Routes
    this.app.get('/api/compliance/scan/:deviceId', this.scanDeviceCompliance.bind(this));
    this.app.get('/api/compliance/violations', this.getComplianceViolations.bind(this));
    this.app.post('/api/compliance/remediate/:violationId', this.remediateViolation.bind(this));
    this.app.get('/api/compliance/reports', this.getComplianceReports.bind(this));
    
    // Remote Actions Routes
    this.app.post('/api/remote/execute', this.executeRemoteAction.bind(this));
    this.app.get('/api/remote/actions/:actionId/status', this.getActionStatus.bind(this));
    this.app.post('/api/remote/bulk-action', this.executeBulkAction.bind(this));
    
    // Analytics Routes
    this.app.get('/api/analytics/dashboard', this.getAnalyticsDashboard.bind(this));
    this.app.get('/api/analytics/device-trends', this.getDeviceTrends.bind(this));
    this.app.get('/api/analytics/compliance-metrics', this.getComplianceMetrics.bind(this));
    this.app.get('/api/analytics/security-insights', this.getSecurityInsights.bind(this));
    
    // Certificate Routes
    this.app.get('/api/certificates', this.getCertificates.bind(this));
    this.app.post('/api/certificates/issue', this.issueCertificate.bind(this));
    this.app.post('/api/certificates/:certId/renew', this.renewCertificate.bind(this));
    this.app.post('/api/certificates/:certId/revoke', this.revokeCertificate.bind(this));
    
    // Geofencing Routes
    this.app.get('/api/geofencing/zones', this.getGeofencingZones.bind(this));
    this.app.post('/api/geofencing/zones', this.createGeofencingZone.bind(this));
    this.app.put('/api/geofencing/zones/:zoneId', this.updateGeofencingZone.bind(this));
    this.app.delete('/api/geofencing/zones/:zoneId', this.deleteGeofencingZone.bind(this));
    
    // Bulk Operations Routes
    this.app.post('/api/bulk/import-devices', this.bulkImportDevices.bind(this));
    this.app.post('/api/bulk/update-policies', this.bulkUpdatePolicies.bind(this));
    this.app.post('/api/bulk/compliance-scan', this.bulkComplianceScan.bind(this));
    this.app.get('/api/bulk/operations/:operationId/status', this.getBulkOperationStatus.bind(this));

    // Policy Agent Routes (server-push policy enforcement via WebSocket)
    this.app.post('/api/agent/policy/apply', this.agentApplyPolicy.bind(this));
    this.app.post('/api/agent/policy/apply-bulk', this.agentApplyPolicyBulk.bind(this));
    this.app.post('/api/agent/policy/remove', this.agentRemovePolicy.bind(this));
    this.app.post('/api/agent/policy/check-compliance', this.agentCheckCompliance.bind(this));
    this.app.post('/api/agent/policy/check-device-compliance', this.agentCheckDeviceCompliance.bind(this));
    this.app.post('/api/agent/policy/detect-drift', this.agentDetectDrift.bind(this));
    this.app.post('/api/agent/policy/rollback', this.agentRollbackPolicy.bind(this));
    this.app.post('/api/agent/policy/resync', this.agentResyncPolicies.bind(this));
    this.app.post('/api/agent/policy/apply-module', this.agentApplyPolicyModule.bind(this));
    this.app.get('/api/agent/policy/status/:deviceId', this.agentGetPolicyStatus.bind(this));

    // Update Agent Routes
    this.app.post('/api/agent/update/configure', async (req, res) => {
      const result = await this.updateClient.configureUpdates(req.body.deviceId, req.body.policy);
      if (!result) return res.status(503).json({ error: 'Update service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/update/check-status', async (req, res) => {
      const result = await this.updateClient.checkUpdateStatus(req.body.deviceId);
      if (!result) return res.status(503).json({ error: 'Update service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/update/trigger', async (req, res) => {
      const result = await this.updateClient.triggerUpdate(req.body.deviceId, req.body.options);
      if (!result) return res.status(503).json({ error: 'Update service unavailable' });
      res.json(result);
    });
    this.app.get('/api/agent/update/status/:deviceId', async (req, res) => {
      const result = await this.updateClient.getDeviceUpdateStatus(req.params.deviceId);
      if (!result) return res.status(503).json({ error: 'Update service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/update/configure-winget', async (req, res) => {
      const result = await this.updateClient.configureWingetAutoUpdate(req.body.deviceId, req.body.policy);
      if (!result) return res.status(503).json({ error: 'Update service unavailable' });
      res.json(result);
    });

    // Network Profile Agent Routes
    this.app.post('/api/agent/network/configure-wifi', async (req, res) => {
      const result = await this.networkProfileClient.configureWiFi(req.body.deviceId, req.body.profile);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/network/remove-wifi', async (req, res) => {
      const result = await this.networkProfileClient.removeWiFi(req.body.deviceId, req.body.profileId, req.body.ssid);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/network/configure-vpn', async (req, res) => {
      const result = await this.networkProfileClient.configureVPN(req.body.deviceId, req.body.profile);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/network/remove-vpn', async (req, res) => {
      const result = await this.networkProfileClient.removeVPN(req.body.deviceId, req.body.profileId);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/network/configure-email', async (req, res) => {
      const result = await this.networkProfileClient.configureEmail(req.body.deviceId, req.body.profile);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });
    this.app.post('/api/agent/network/remove-email', async (req, res) => {
      const result = await this.networkProfileClient.removeEmail(req.body.deviceId, req.body.profileId);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });
    this.app.get('/api/agent/network/status/:deviceId', async (req, res) => {
      const result = await this.networkProfileClient.getDeviceProfileState(req.params.deviceId);
      if (!result) return res.status(503).json({ error: 'Network profile service unavailable' });
      res.json(result);
    });

    // Backup & Disaster Recovery Routes
    this.app.post('/api/backup/trigger', async (req, res) => {
      try {
        const jobId = `bak-${Date.now()}`;
        const type = req.body.type || 'incremental';
        const result = await this.backupClient.triggerBackup(type, jobId);
        if (!result) return res.status(503).json({ error: 'Backup service unavailable' });
        res.json({ success: true, jobId, type, status: 'started', startedAt: new Date().toISOString(), ...result });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/backup/status', async (req, res) => {
      try {
        const status = await this.backupClient.getBackupStatus();
        res.json({ success: true, data: status || { error: 'Backup service unavailable' } });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/backup/history', async (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 20;
        const data = await this.backupClient.getBackupHistory(limit);
        res.json({ success: true, data: data || [], limit });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/backup/restore', async (req, res) => {
      try {
        const { backupId } = req.body;
        if (!backupId) return res.status(400).json({ error: 'backupId required' });
        const result = await this.backupClient.restoreBackup(backupId);
        if (!result) return res.status(503).json({ error: 'Backup service unavailable' });
        res.json({ success: true, backupId, status: 'started', startedAt: new Date().toISOString(), ...result });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/dr/health', async (req, res) => {
      try {
        const health = await this.backupClient.getDrHealth();
        res.json({ success: true, data: health || { status: 'not_configured', timestamp: new Date().toISOString() } });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/dr/failover/test', async (req, res) => {
      try {
        const result = await this.backupClient.testFailover();
        if (!result) return res.status(503).json({ error: 'Backup service unavailable' });
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/dr/replication/status', async (req, res) => {
      try {
        const status = await this.backupClient.getReplicationStatus();
        res.json({ success: true, data: status || { active: false, timestamp: new Date().toISOString() } });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/dr/failover/execute', async (req, res) => {
      try {
        const { confirm } = req.body;
        if (confirm !== true) return res.status(400).json({ error: 'Explicit confirmation required: { "confirm": true }' });
        const result = await this.backupClient.executeFailover(confirm);
        if (!result) return res.status(503).json({ error: 'Backup service unavailable' });
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Analytics & Threat Detection Routes
    this.app.get('/api/analytics/threats', (req, res) => {
      try {
        const { severity, limit } = req.query;
        const threats = this.analyticsBridge.getThreats({
          severity, limit: limit ? parseInt(limit) : undefined
        });
        res.json({ success: true, data: threats, total: threats.length });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/analytics/anomalies', (req, res) => {
      try {
        const { deviceId, limit } = req.query;
        const anomalies = this.analyticsBridge.getAnomalies({
          deviceId, limit: limit ? parseInt(limit) : undefined
        });
        res.json({ success: true, data: anomalies, total: anomalies.length });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/analytics/predictions', (req, res) => {
      try {
        const { type, deviceId } = req.query;
        const predictions = this.analyticsBridge.getPredictions({ type, deviceId });
        res.json({ success: true, data: predictions, total: predictions.length });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/analytics/recommendations', (req, res) => {
      try {
        const { category } = req.query;
        const recs = this.analyticsBridge.getRecommendations({ category });
        res.json({ success: true, data: recs, total: recs.length });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/analytics/threats/:threatId/resolve', (req, res) => {
      try {
        const threat = this.analyticsBridge.resolveThreat(req.params.threatId);
        if (!threat) return res.status(404).json({ error: 'Threat not found' });
        res.json({ success: true, data: threat });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/analytics/bridge/metrics', (req, res) => {
      res.json({ success: true, data: this.analyticsBridge.getMetrics() });
    });

    // Dashboard & Reporting Routes
    this.app.get('/api/dashboard', async (req, res) => {
      try {
        const data = await this.licenseClient.getDashboardData();
        if (!data) return res.status(503).json({ error: 'License service unavailable' });
        res.json({ success: true, data });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/dashboard/timeseries/:metric', async (req, res) => {
      try {
        const { metric } = req.params;
        const timeframe = req.query.timeframe || '24h';
        const data = await this.licenseClient.getTimeSeries(metric, timeframe);
        if (!data) return res.status(503).json({ error: 'License service unavailable' });
        res.json({ success: true, data, metric, timeframe });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/reports/templates', async (req, res) => {
      try {
        const data = await this.licenseClient.getReportTemplates();
        if (!data) return res.status(503).json({ error: 'License service unavailable' });
        res.json({ success: true, data });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/reports/generate', async (req, res) => {
      try {
        const { template, format, params } = req.body;
        if (!template || !format) return res.status(400).json({ error: 'template and format required' });
        const report = await this.licenseClient.generateReport(template, format, params || {});
        if (!report) return res.status(503).json({ error: 'License service unavailable' });
        res.json({ success: true, data: report });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Agent Communication Routes (used by OpenDirectory Windows/macOS/Linux agents)
    this.app.post('/api/v1/devices/:deviceId/checkin', this.handleAgentCheckin.bind(this));
    this.app.get('/api/v1/devices/:deviceId/commands/pending', this.getPendingCommands.bind(this));
    this.app.post('/api/v1/devices/:deviceId/commands/:commandId/result', this.handleCommandResult.bind(this));
    this.app.get('/api/v1/devices/:deviceId/policies', this.getDevicePolicies.bind(this));
    this.app.post('/api/v1/devices/:deviceId/notifications', this.pushNotificationToDevice.bind(this));
    this.app.post('/api/v1/notifications/broadcast', this.broadcastNotification.bind(this));
    this.app.post('/api/v1/devices/:deviceId/commands', this.queueCommand.bind(this));
    this.app.get('/api/v1/agents/connected', this.getAgentsStatus.bind(this));
    this.app.get('/api/v1/agents/download/:platform', this.downloadAgent.bind(this));
    this.app.get('/api/v1/agent/windows/download', this.downloadWindowsAgent.bind(this));

    // ── App Store Install (reuses existing queueCommand + WebSocket push) ───
    this.app.post('/api/devices/:deviceId/install-app', this.installApp.bind(this));
    this.app.get('/api/devices/:deviceId/install-jobs', this.getInstallJobs.bind(this));
    this.app.post('/api/devices/:deviceId/install-jobs/:jobId/result', this.reportInstallResult.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    switch (type) {
      case 'subscribe_device_events':
        ws.subscriptions.add('device_events');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'device_events',
          requestId
        }));
        break;

      case 'subscribe_compliance_alerts':
        ws.subscriptions.add('compliance_alerts');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'compliance_alerts',
          requestId
        }));
        break;

      // ── Agent messages (from device agents) ───────────────────────
      case 'agent_register':
        ws.deviceId = data.deviceId || ws.deviceId;
        ws.platform = data.platform || ws.platform;
        ws.agentVersion = data.agentVersion;
        ws.hostname = data.hostname;
        if (ws.deviceId) {
          this.connectedAgents.set(ws.deviceId, ws);
          this.deviceManager.updateLastSeen(ws.deviceId).catch(() => {});
        }
        ws.send(JSON.stringify({
          type: 'agent_registered',
          deviceId: ws.deviceId,
          requestId
        }));

        // Deliver pending messages queued while agent was offline
        if (this.cache && ws.deviceId) {
          try {
            const pendingData = await this.cache.get(`pending:${ws.deviceId}`);
            if (pendingData) {
              const pending = JSON.parse(pendingData);
              for (const msg of pending) {
                ws.send(JSON.stringify({ ...msg, timestamp: new Date().toISOString() }));
              }
              await this.cache.del(`pending:${ws.deviceId}`);
              logger.info(`Delivered ${pending.length} pending messages to ${ws.deviceId}`);
            }
          } catch (e) {
            logger.warn(`Failed to deliver pending messages: ${e.message}`);
          }
        }

        // Drain RabbitMQ device command queue for this agent
        if (this.messageBus && this.messageBus.isConnected() && ws.deviceId) {
          this.messageBus.consumeDeviceCommands(ws.deviceId, (cmd) => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ ...cmd, timestamp: new Date().toISOString() }));
            }
          }, { once: true }).catch(err => {
            logger.warn(`Failed to drain RabbitMQ command queue for ${ws.deviceId}: ${err.message}`);
          });
        }

        logger.info(`Agent registered: ${ws.deviceId} (${ws.platform})`);
        break;

      case 'device_heartbeat':
        if (ws.deviceId || data.deviceId) {
          await this.deviceManager.updateLastSeen(ws.deviceId || data.deviceId);
          ws.send(JSON.stringify({
            type: 'heartbeat_ack',
            timestamp: new Date().toISOString(),
            requestId
          }));
        }
        break;

      case 'compliance_status':
        if (data.deviceId && data.complianceData) {
          await this.complianceScanner.updateComplianceStatus(data.deviceId, data.complianceData);
        }
        break;

      case 'command_result':
        logger.info(`Command result from \${ws.deviceId}: \${data.commandId} - \${data.status}`);
        // Forward results to the correct service based on command prefix
        if (data.commandId && data.commandId.startsWith('pol-')) {
          this.policyAgentService.handleCommandResult(ws.deviceId, data);
        } else if (data.commandId && data.commandId.startsWith('upd-')) {
          this.updateClient.handleCommandResult(ws.deviceId, data).catch(() => {});
        } else if (data.commandId && data.commandId.startsWith('net-')) {
          this.networkProfileClient.handleCommandResult(ws.deviceId, data).catch(() => {});
        }
        // Feed all command results into Analytics Bridge for ML analysis
        if (this.analyticsBridge && data.commandId) {
          this.analyticsBridge.processEvent(ws.deviceId, data.commandId, data);
        }
        this.broadcastToSubscribers('device_events', {
          type: 'command_result',
          deviceId: ws.deviceId,
          commandId: data.commandId,
          status: data.status,
          output: data.output,
          timestamp: data.timestamp || new Date().toISOString()
        });
        break;

      case 'inventory_report':
        if (ws.deviceId && data.inventory) {
          await this.inventoryService.updateInventory(ws.deviceId, data.inventory);
          logger.info(`Inventory updated: \${ws.deviceId}`);
        }
        break;

      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: `Unknown message type: \${type}`,
          requestId
        }));
    }
  }

  // ── Server-Push: send directly to connected agent ──────────────────────
  sendToDevice(deviceId, message) {
    const ws = this.connectedAgents.get(deviceId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ ...message, timestamp: new Date().toISOString() }));
      return true;
    }
    return false;
  }

  sendToDevices(deviceIds, message) {
    const results = { sent: 0, offline: 0 };
    for (const id of deviceIds) {
      if (this.sendToDevice(id, message)) results.sent++;
      else results.offline++;
    }
    return results;
  }

  sendToAllAgents(message, platform = null) {
    let sent = 0;
    this.connectedAgents.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && (!platform || ws.platform === platform)) {
        ws.send(JSON.stringify({ ...message, timestamp: new Date().toISOString() }));
        sent++;
      }
    });
    return sent;
  }

  getConnectedAgents() {
    const agents = [];
    this.connectedAgents.forEach((ws, deviceId) => {
      agents.push({
        deviceId,
        platform: ws.platform,
        agentVersion: ws.agentVersion,
        hostname: ws.hostname,
        connectedAt: ws.connectedAt,
        isAlive: ws.isAlive
      });
    });
    return agents;
  }

  initializeEventHandlers() {
    // Device events
    this.eventBus.on('device:enrolled', this.handleDeviceEnrolled.bind(this));
    this.eventBus.on('device:compliance_violation', this.handleComplianceViolation.bind(this));
    this.eventBus.on('device:threat_detected', this.handleThreatDetected.bind(this));
    this.eventBus.on('device:geofence_violation', this.handleGeofenceViolation.bind(this));
    this.eventBus.on('policy:deployed', this.handlePolicyDeployed.bind(this));

    // PolicyAgentService events → broadcast to dashboard subscribers
    this.policyAgentService.on('complianceViolation', (event) => {
      this.broadcastToSubscribers('compliance_alerts', {
        type: 'policy_compliance_violation',
        ...event,
        timestamp: new Date().toISOString()
      });
    });
    this.policyAgentService.on('driftDetected', (event) => {
      this.broadcastToSubscribers('compliance_alerts', {
        type: 'policy_drift_detected',
        ...event,
        timestamp: new Date().toISOString()
      });
    });
  }

  startBackgroundJobs() {
    // Compliance scanning
    setInterval(async () => {
      try {
        await this.complianceScanner.performScheduledScan();
      } catch (error) {
        logger.error('Scheduled compliance scan error:', error);
      }
    }, config.compliance.scanInterval);

    // Threat detection
    setInterval(async () => {
      try {
        await this.threatDetector.performThreatScan();
      } catch (error) {
        logger.error('Threat detection error:', error);
      }
    }, config.security.threatScanInterval);

    // Certificate renewal
    setInterval(async () => {
      try {
        await this.certificateManager.checkCertificateRenewal();
      } catch (error) {
        logger.error('Certificate renewal check error:', error);
      }
    }, config.certificates.renewalCheckInterval);

    // Analytics aggregation
    setInterval(async () => {
      try {
        await this.analyticsEngine.aggregateMetrics();
      } catch (error) {
        logger.error('Analytics aggregation error:', error);
      }
    }, config.analytics.aggregationInterval);
  }

  // Device Management Handlers
  async getDevices(req, res) {
    try {
      const {
        page = 1,
        limit = 50,
        search,
        status,
        platform,
        complianceStatus,
        sortBy = 'lastSeen',
        sortOrder = 'desc'
      } = req.query;

      const result = await this.circuitBreaker.execute(
        'get-devices',
        () => this.deviceManager.getDevices({
          page: parseInt(page),
          limit: parseInt(limit),
          search,
          status,
          platform,
          complianceStatus,
          sortBy,
          sortOrder
        })
      );

      res.json({
        success: true,
        data: result.devices,
        pagination: result.pagination,
        requestId: req.id
      });
    } catch (error) {
      logger.error('Get devices error:', error);
      res.status(500).json({
        error: 'Failed to retrieve devices',
        requestId: req.id
      });
    }
  }

  async createDevice(req, res) {
    try {
      const deviceData = req.body;
      
      const device = await this.circuitBreaker.execute(
        'create-device',
        () => this.deviceManager.createDevice(deviceData, req.user)
      );

      this.eventBus.emit('device:created', { device, user: req.user });

      res.status(201).json({
        success: true,
        data: device,
        requestId: req.id
      });
    } catch (error) {
      logger.error('Create device error:', error);
      res.status(500).json({
        error: 'Failed to create device',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getDevice(req, res) {
    try {
      const { deviceId } = req.params;
      const { includeCompliance = false, includeHistory = false } = req.query;

      const device = await this.circuitBreaker.execute(
        'get-device',
        () => this.deviceManager.getDevice(deviceId, {
          includeCompliance,
          includeHistory
        })
      );

      if (!device) {
        return res.status(404).json({
          error: 'Device not found',
          requestId: req.id
        });
      }

      res.json({
        success: true,
        data: device,
        requestId: req.id
      });
    } catch (error) {
      logger.error('Get device error:', error);
      res.status(500).json({
        error: 'Failed to retrieve device',
        requestId: req.id
      });
    }
  }

  // ── Stammdaten (master data) ──────────────────────────────────────────────────

  async getStammdaten(req, res) {
    try {
      const { deviceId } = req.params;
      let stammdaten = {};
      if (db.isAvailable()) {
        const r = await db.query(
          `SELECT metadata FROM devices WHERE id = $1`, [deviceId]
        );
        if (r.rows.length) stammdaten = r.rows[0].metadata?.stammdaten || {};
      } else {
        const d = db.getMemoryDevice ? db.getMemoryDevice(deviceId) : null;
        stammdaten = d?.metadata?.stammdaten || {};
      }
      res.json({ success: true, data: stammdaten });
    } catch (err) {
      logger.error('getStammdaten error:', err);
      res.status(500).json({ error: 'Failed to get stammdaten' });
    }
  }

  async updateStammdaten(req, res) {
    try {
      const { deviceId } = req.params;
      const fields = req.body || {};
      // Sanitise: strip photo from this endpoint (use /photo instead)
      delete fields.photo;
      if (db.isAvailable()) {
        await db.query(
          `UPDATE devices
           SET metadata = jsonb_set(
             COALESCE(metadata, '{}'),
             '{stammdaten}',
             COALESCE(metadata->'stammdaten', '{}') || $1::jsonb
           )
           WHERE id = $2`,
          [JSON.stringify(fields), deviceId]
        );
      }
      res.json({ success: true });
    } catch (err) {
      logger.error('updateStammdaten error:', err);
      res.status(500).json({ error: 'Failed to update stammdaten' });
    }
  }

  async uploadPhoto(req, res) {
    try {
      const { deviceId } = req.params;
      const { photo } = req.body; // base64 data URL, e.g. "data:image/jpeg;base64,..."
      if (!photo || !photo.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Invalid photo — send base64 data URL' });
      }
      if (Buffer.byteLength(photo, 'utf8') > 512 * 1024) {
        return res.status(413).json({ error: 'Photo too large — max 512 KB' });
      }
      if (db.isAvailable()) {
        await db.query(
          `UPDATE devices
           SET metadata = jsonb_set(
             COALESCE(metadata, '{}'),
             '{stammdaten,photo}',
             $1::jsonb
           )
           WHERE id = $2`,
          [JSON.stringify(photo), deviceId]
        );
      }
      res.json({ success: true });
    } catch (err) {
      logger.error('uploadPhoto error:', err);
      res.status(500).json({ error: 'Failed to upload photo' });
    }
  }

  async getPhoto(req, res) {
    try {
      const { deviceId } = req.params;
      if (!db.isAvailable()) return res.status(404).json({ error: 'No photo' });
      const r = await db.query(
        `SELECT metadata->'stammdaten'->>'photo' AS photo FROM devices WHERE id = $1`,
        [deviceId]
      );
      const photo = r.rows[0]?.photo;
      if (!photo) return res.status(404).json({ error: 'No photo' });
      // Return as image
      const match = photo.match(/^data:(image\/[a-z+]+);base64,(.+)$/);
      if (match) {
        res.set('Content-Type', match[1]);
        res.send(Buffer.from(match[2], 'base64'));
      } else {
        res.json({ success: true, data: photo });
      }
    } catch (err) {
      logger.error('getPhoto error:', err);
      res.status(500).json({ error: 'Failed to get photo' });
    }
  }

  // Event handlers
  async handleDeviceEnrolled(event) {
    const { device } = event;

    // Broadcast to WebSocket clients
    this.broadcastToSubscribers('device_events', {
      type: 'device_enrolled',
      device: {
        id: device.id,
        name: device.name,
        platform: device.platform,
        enrolledAt: device.enrolledAt
      }
    });

    // Publish domain event to RabbitMQ (fire-and-forget)
    this.messageBus.publish(Events.DEVICE_ENROLLED, {
      deviceId:   device.id,
      hostname:   device.name,
      platform:   device.platform,
      enrolledAt: device.enrolledAt,
    }).catch(() => {});

    // Auto-assign default policies
    await this.policyEngine.assignDefaultPolicies(device.id);

    logger.info('Device enrolled successfully', { deviceId: device.id });
  }

  async handleComplianceViolation(event) {
    const { deviceId, violation } = event;

    // Notify admin dashboard via WebSocket subscription
    this.broadcastToSubscribers('compliance_alerts', {
      type: 'compliance_violation',
      deviceId,
      violation,
      timestamp: new Date().toISOString()
    });

    // Push notification directly to the affected device agent
    this.sendToDevice(deviceId, {
      type: 'notification',
      category: 'compliance_violation',
      title: 'Compliance-Verstoss erkannt',
      body: violation.description || violation.rule,
      data: { rule: violation.rule, details: violation.details, severity: violation.severity }
    });

    // Publish domain event to RabbitMQ (fire-and-forget)
    this.messageBus.publish(Events.DEVICE_NON_COMPLIANT, {
      deviceId,
      violation: {
        rule:     violation.rule,
        severity: violation.severity,
        details:  violation.details,
      },
    }).catch(() => {});

    if (violation.autoRemediable) {
      await this.complianceScanner.autoRemediate(violation.id);
    }
  }

  async handleThreatDetected(event) {
    const { deviceId, threat } = event;

    this.broadcastToSubscribers('security_alerts', {
      type: 'threat_detected',
      deviceId,
      threat,
      timestamp: new Date().toISOString()
    });

    // Push security alert directly to device agent
    this.sendToDevice(deviceId, {
      type: 'notification',
      category: 'security_alert',
      title: 'Sicherheitswarnung',
      body: threat.description,
      data: { severity: threat.severity, threat_type: threat.type }
    });

    if (threat.severity === 'critical') {
      await this.remoteActionService.isolateDevice(deviceId, 'Automatic isolation due to critical threat');
    }
  }

  // ── Agent Communication Handlers (generic, platform-agnostic) ────────────

  async handleAgentCheckin(req, res) {
    try {
      const { deviceId } = req.params;
      const checkinData = req.body;

      await this.deviceManager.updateLastSeen(deviceId);

      if (this.cache) {
        await this.cache.set(`agent:${deviceId}`, JSON.stringify({
          ...checkinData,
          lastCheckin: new Date().toISOString()
        }), 'EX', 300);
      }

      res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        serverVersion: '1.0.0'
      });
    } catch (error) {
      logger.error('Agent checkin error:', error);
      res.status(500).json({ error: 'Checkin failed' });
    }
  }

  async getDevicePolicies(req, res) {
    try {
      const { deviceId } = req.params;
      const policies = await this.policyEngine.getDevicePolicies(deviceId);
      res.json({ policies: policies || [], timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error('Get device policies error:', error);
      res.status(500).json({ error: 'Failed to retrieve policies' });
    }
  }

  // Push notification directly to device via WebSocket (no polling)
  async pushNotificationToDevice(req, res) {
    try {
      const { deviceId } = req.params;
      const notification = req.body;
      const notifMessage = {
        type: 'notification',
        id: this.generateRequestId(),
        ...notification
      };

      const delivered = this.sendToDevice(deviceId, notifMessage);
      logger.info(`Notification \${delivered ? 'pushed' : 'queued'} for device \${deviceId}: \${notification.category}`);

      // If device offline, queue in cache for delivery on reconnect
      if (!delivered && this.cache) {
        const existing = await this.cache.get(`pending:\${deviceId}`);
        const pending = existing ? JSON.parse(existing) : [];
        pending.push(notifMessage);
        await this.cache.set(`pending:\${deviceId}`, JSON.stringify(pending), 'EX', 86400);
      }

      res.json({
        status: delivered ? 'delivered' : 'queued_offline',
        deviceId,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Push notification error:', error);
      res.status(500).json({ error: 'Failed to push notification' });
    }
  }

  // Broadcast notification to multiple devices via WebSocket
  async broadcastNotification(req, res) {
    try {
      const { notification, deviceIds, platform } = req.body;
      const message = {
        type: 'notification',
        id: this.generateRequestId(),
        ...notification
      };

      let results;
      if (deviceIds && deviceIds.length > 0) {
        results = this.sendToDevices(deviceIds, message);
      } else {
        // Broadcast to all connected agents (optionally filtered by platform)
        const sent = this.sendToAllAgents(message, platform);
        results = { sent, offline: 0 };
      }

      logger.info(`Broadcast: \${results.sent} delivered, \${results.offline} offline`);

      res.json({
        status: 'broadcast_sent',
        delivered: results.sent,
        offline: results.offline,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Broadcast notification error:', error);
      res.status(500).json({ error: 'Failed to broadcast notification' });
    }
  }

  // Push command directly to device via WebSocket
  // ── App Store Install via existing agent WebSocket ──────────────────────
  async installApp(req, res) {
    try {
      const { deviceId } = req.params;
      const { appId, appName, packageId, downloadUrl, sha256, format, version, architecture } = req.body;

      if (!packageId && !downloadUrl) {
        return res.status(400).json({ error: 'packageId oder downloadUrl erforderlich' });
      }

      // Build the download URL if only packageId given
      const APP_STORE_URL = process.env.APP_STORE_URL || 'http://app-store:3906';
      const pkgDownloadUrl = downloadUrl || `${APP_STORE_URL}/api/appstore/packages/${packageId}/download`;

      const jobId = `install-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

      // Build store_install command for the agent — reuses existing command type
      const command = {
        type: 'command',
        command_type: 'store_install',
        id: jobId,
        data: {
          appId,
          appName: appName || appId,
          packageInfo: {
            type: 'internal',       // new type — agent downloads from our store
            packageId,
            downloadUrl: pkgDownloadUrl,
            sha256: sha256 || '',
            format: format || 'exe',
            version: version || '1.0.0',
            architecture: architecture || 'x64',
          },
        },
      };

      // Track in-memory job
      if (!global.__od_installJobs) global.__od_installJobs = new Map();
      global.__od_installJobs.set(jobId, {
        jobId, deviceId, appId, appName, packageId, format, version,
        status: 'queued', queuedAt: new Date().toISOString(),
      });

      // Push via WebSocket — if offline, queue via RabbitMQ (preferred) or Redis (fallback)
      const delivered = this.sendToDevice(deviceId, command);
      if (!delivered) {
        let mqQueued = false;
        if (this.messageBus && this.messageBus.isConnected()) {
          mqQueued = await this.messageBus.queueDeviceCommand(deviceId, command).catch(err => {
            logger.warn('RabbitMQ queueDeviceCommand failed, falling back to Redis cache', { error: err.message, deviceId });
            return false;
          });
        }
        if (!mqQueued && this.cache) {
          const existing = await this.cache.get(`pending:${deviceId}`).catch(() => null);
          const pending = existing ? JSON.parse(existing) : [];
          pending.push(command);
          await this.cache.set(`pending:${deviceId}`, JSON.stringify(pending), 'EX', 86400).catch(() => {});
        }
      }

      logger.info(`install-app ${delivered ? 'pushed live' : 'queued offline'}: device=${deviceId} app=${appId} job=${jobId}`);

      res.json({
        jobId,
        status: delivered ? 'delivered' : 'queued_offline',
        message: delivered
          ? 'Installation wird auf dem Gerät ausgeführt'
          : 'Gerät ist offline — Installation wird beim nächsten Check-in gestartet',
      });
    } catch (err) {
      logger.error('installApp error:', err);
      res.status(500).json({ error: err.message });
    }
  }

  async getInstallJobs(req, res) {
    const { deviceId } = req.params;
    const jobs = global.__od_installJobs
      ? [...global.__od_installJobs.values()].filter(j => j.deviceId === deviceId)
      : [];
    res.json(jobs);
  }

  async reportInstallResult(req, res) {
    const { jobId } = req.params;
    const { status, output, error } = req.body;
    let job = null;
    if (global.__od_installJobs?.has(jobId)) {
      job = global.__od_installJobs.get(jobId);
      Object.assign(job, { status, output, error, completedAt: new Date().toISOString() });
    }

    // Publish install result event to RabbitMQ (fire-and-forget)
    if (job) {
      const routingKey = status === 'success'
        ? Events.APP_INSTALL_COMPLETED
        : Events.APP_INSTALL_FAILED;
      this.messageBus.publish(routingKey, {
        jobId,
        deviceId: job.deviceId,
        appId:    job.appId,
        appName:  job.appName,
        status,
        output,
        error,
      }).catch(() => {});
    }

    res.json({ ok: true });
  }

  async queueCommand(req, res) {
    try {
      const { deviceId } = req.params;
      const command = req.body;
      const cmdMessage = {
        type: 'command',
        id: this.generateRequestId(),
        ...command
      };

      const delivered = this.sendToDevice(deviceId, cmdMessage);
      logger.info(`Command \${delivered ? 'pushed' : 'queued'} for device \${deviceId}: \${command.type}`);

      // If device offline, queue via RabbitMQ (preferred) or Redis (fallback)
      if (!delivered) {
        let mqQueued = false;
        if (this.messageBus && this.messageBus.isConnected()) {
          mqQueued = await this.messageBus.queueDeviceCommand(deviceId, cmdMessage).catch(err => {
            logger.warn('RabbitMQ queueDeviceCommand failed, falling back to Redis cache', { error: err.message, deviceId });
            return false;
          });
        }
        if (!mqQueued && this.cache) {
          const existing = await this.cache.get(`pending:\${deviceId}`);
          const pending = existing ? JSON.parse(existing) : [];
          pending.push(cmdMessage);
          await this.cache.set(`pending:\${deviceId}`, JSON.stringify(pending), 'EX', 86400);
        }
      }

      res.json({
        status: delivered ? 'delivered' : 'queued_offline',
        deviceId,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Push command error:', error);
      res.status(500).json({ error: 'Failed to push command' });
    }
  }

  // Get connected agents status
  async getAgentsStatus(req, res) {
    try {
      const { platform } = req.query;
      let agents = this.getConnectedAgents();
      if (platform) {
        agents = agents.filter(a => a.platform === platform);
      }
      res.json({
        total: agents.length,
        agents,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get agents status' });
    }
  }

  // Generic agent download endpoint (serves platform-specific agent)
  async downloadAgent(req, res) {
    try {
      const { platform } = req.params;
      const fs = require('fs');
      const path = require('path');

      const agentFiles = {
        windows: { file: 'OpenDirectoryAgent.ps1', dir: 'windows' },
        macos:   { file: 'OpenDirectoryAgent.sh', dir: 'macos' },
        linux:   { file: 'OpenDirectoryAgent.sh', dir: 'linux' }
      };

      const agent = agentFiles[platform];
      if (!agent) {
        return res.status(400).json({ error: `Unknown platform: \${platform}. Use: windows, macos, linux` });
      }

      const agentPath = path.join(__dirname, '../../../../clients', agent.dir, agent.file);
      if (fs.existsSync(agentPath)) {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="\${agent.file}"`);
        fs.createReadStream(agentPath).pipe(res);
      } else {
        res.status(404).json({ error: `Agent for \${platform} not found` });
      }
    } catch (error) {
      logger.error('Agent download error:', error);
      res.status(500).json({ error: 'Failed to serve agent' });
    }
  }

  async downloadWindowsAgent(req, res) {
    try {
      const agentPath = require('path').join(__dirname, '../../../../clients/windows/OpenDirectoryAgent.ps1');
      const fs = require('fs');

      if (fs.existsSync(agentPath)) {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', 'attachment; filename="OpenDirectoryAgent.ps1"');
        fs.createReadStream(agentPath).pipe(res);
      } else {
        res.status(404).json({ error: 'Agent script not found' });
      }
    } catch (error) {
      logger.error('Agent download error:', error);
      res.status(500).json({ error: 'Failed to serve agent' });
    }
  }

  // ── Policy Agent Service Route Handlers ──────────────────────────────────

  async agentApplyPolicy(req, res) {
    try {
      const { deviceId, policy } = req.body;
      const result = this.policyAgentService.applyPolicy(deviceId, policy);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent apply policy error:', error);
      res.status(500).json({ error: 'Failed to apply policy' });
    }
  }

  async agentApplyPolicyBulk(req, res) {
    try {
      const { deviceIds, policy } = req.body;
      const results = this.policyAgentService.applyPolicyToDevices(deviceIds, policy);
      res.json({ success: true, results });
    } catch (error) {
      logger.error('Agent bulk apply policy error:', error);
      res.status(500).json({ error: 'Failed to apply policy to devices' });
    }
  }

  async agentRemovePolicy(req, res) {
    try {
      const { deviceId, policyId } = req.body;
      const result = this.policyAgentService.removePolicy(deviceId, policyId);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent remove policy error:', error);
      res.status(500).json({ error: 'Failed to remove policy' });
    }
  }

  async agentCheckCompliance(req, res) {
    try {
      const { deviceId, policyId } = req.body;
      const result = this.policyAgentService.checkCompliance(deviceId, policyId);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent check compliance error:', error);
      res.status(500).json({ error: 'Failed to check compliance' });
    }
  }

  async agentCheckDeviceCompliance(req, res) {
    try {
      const { deviceId } = req.body;
      const result = this.policyAgentService.checkDeviceCompliance(deviceId);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent check device compliance error:', error);
      res.status(500).json({ error: 'Failed to check device compliance' });
    }
  }

  async agentDetectDrift(req, res) {
    try {
      const { deviceId } = req.body;
      const result = this.policyAgentService.detectDrift(deviceId);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent detect drift error:', error);
      res.status(500).json({ error: 'Failed to detect drift' });
    }
  }

  async agentRollbackPolicy(req, res) {
    try {
      const { deviceId, policyId } = req.body;
      const result = this.policyAgentService.rollbackPolicy(deviceId, policyId);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent rollback policy error:', error);
      res.status(500).json({ error: 'Failed to rollback policy' });
    }
  }

  async agentResyncPolicies(req, res) {
    try {
      const { deviceId } = req.body;
      const result = this.policyAgentService.resyncPolicies(deviceId);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent resync policies error:', error);
      res.status(500).json({ error: 'Failed to resync policies' });
    }
  }

  async agentApplyPolicyModule(req, res) {
    try {
      const { deviceId, module, settings } = req.body;
      const result = this.policyAgentService.applyPolicyModule(deviceId, module, settings);
      res.json({ success: true, ...result });
    } catch (error) {
      logger.error('Agent apply policy module error:', error);
      res.status(500).json({ error: 'Failed to apply policy module' });
    }
  }

  async agentGetPolicyStatus(req, res) {
    try {
      const { deviceId } = req.params;
      const status = this.policyAgentService.getDevicePolicyStatus(deviceId);
      res.json({ success: true, ...status });
    } catch (error) {
      logger.error('Agent get policy status error:', error);
      res.status(500).json({ error: 'Failed to get policy status' });
    }
  }

  // ── Stub handlers for routes defined in initializeRoutes ─────────────────────

  async initiateEnrollment(req, res) {
    try {
      const result = await this.enrollmentService.initiateEnrollment(req.body);
      res.status(201).json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to initiate enrollment', requestId: req.id }); }
  }

  async completeEnrollment(req, res) {
    try {
      const result = await this.enrollmentService.completeEnrollment(req.body);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to complete enrollment', requestId: req.id }); }
  }

  async verifyEnrollment(req, res) {
    try {
      const result = await this.enrollmentService.verifyEnrollment(req.body);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to verify enrollment', requestId: req.id }); }
  }

  async getEnrollmentStatus(req, res) {
    try {
      const { enrollmentId } = req.params;
      const result = await this.enrollmentService.getEnrollmentStatus(enrollmentId);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get enrollment status', requestId: req.id }); }
  }

  async approveEnrollment(req, res) {
    try {
      const { enrollmentId } = req.params;
      const result = await this.enrollmentService.approveEnrollment(enrollmentId, req.body);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to approve enrollment', requestId: req.id }); }
  }

  async rejectEnrollment(req, res) {
    try {
      const { enrollmentId } = req.params;
      const result = await this.enrollmentService.rejectEnrollment(enrollmentId, req.body);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to reject enrollment', requestId: req.id }); }
  }

  async updateDevice(req, res) {
    try {
      const { deviceId } = req.params;
      const device = await this.circuitBreaker.execute('update-device', () => this.deviceManager.updateDevice(deviceId, req.body));
      res.json({ success: true, data: device, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to update device', requestId: req.id }); }
  }

  async deleteDevice(req, res) {
    try {
      const { deviceId } = req.params;
      await this.circuitBreaker.execute('delete-device', () => this.deviceManager.deleteDevice(deviceId));
      res.json({ success: true, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to delete device', requestId: req.id }); }
  }

  async lockDevice(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to lock device' }); }
  }

  async unlockDevice(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to unlock device' }); }
  }

  async wipeDevice(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to wipe device' }); }
  }

  async getPolicies(req, res) {
    try {
      const policies = await this.policyEngine.getDevicePolicies('*');
      res.json({ success: true, data: policies || [], requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get policies', requestId: req.id }); }
  }

  async createPolicy(req, res) {
    try { res.status(201).json({ success: true, data: { id: this.generateRequestId(), ...req.body }, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to create policy' }); }
  }

  async getPolicy(req, res) {
    try { res.json({ success: true, data: null, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get policy' }); }
  }

  async updatePolicy(req, res) {
    try { res.json({ success: true, data: req.body, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to update policy' }); }
  }

  async deletePolicy(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to delete policy' }); }
  }

  async assignPolicy(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to assign policy' }); }
  }

  async deployPolicy(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to deploy policy' }); }
  }

  async scanDeviceCompliance(req, res) {
    try { res.json({ success: true, data: { compliant: true }, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Compliance scan failed' }); }
  }

  async getComplianceViolations(req, res) {
    try {
      const violations = await this.complianceScanner.getViolations();
      res.json({ success: true, data: violations || [], requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get violations', requestId: req.id }); }
  }

  async remediateViolation(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Remediation failed' }); }
  }

  async getComplianceReports(req, res) {
    try { res.json({ success: true, data: [], requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get reports' }); }
  }

  async executeRemoteAction(req, res) {
    try {
      const result = await this.remoteActionService.executeAction(req.body);
      res.json({ success: true, data: result, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Remote action failed', requestId: req.id }); }
  }

  async getActionStatus(req, res) {
    try {
      const status = await this.remoteActionService.getActionStatus(req.params.actionId);
      res.json({ success: true, data: status, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get action status' }); }
  }

  async executeBulkAction(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Bulk action failed' }); }
  }

  async getAnalyticsDashboard(req, res) {
    try {
      const data = await this.analyticsEngine.getDashboard();
      res.json({ success: true, data, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get analytics dashboard' }); }
  }

  async getDeviceTrends(req, res) {
    try { res.json({ success: true, data: [], requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get device trends' }); }
  }

  async getComplianceMetrics(req, res) {
    try { res.json({ success: true, data: {}, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get compliance metrics' }); }
  }

  async getSecurityInsights(req, res) {
    try { res.json({ success: true, data: {}, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get security insights' }); }
  }

  async getCertificates(req, res) {
    try {
      const certs = await this.certificateManager.getCertificates();
      res.json({ success: true, data: certs, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get certificates' }); }
  }

  async issueCertificate(req, res) {
    try {
      const cert = await this.certificateManager.issueCertificate(req.body);
      res.status(201).json({ success: true, data: cert, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to issue certificate' }); }
  }

  async renewCertificate(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to renew certificate' }); }
  }

  async revokeCertificate(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to revoke certificate' }); }
  }

  async getGeofencingZones(req, res) {
    try {
      const zones = await this.geofencingService.getZones();
      res.json({ success: true, data: zones, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to get geofencing zones' }); }
  }

  async createGeofencingZone(req, res) {
    try {
      const zone = await this.geofencingService.createZone(req.body);
      res.status(201).json({ success: true, data: zone, requestId: req.id });
    } catch (error) { res.status(500).json({ error: 'Failed to create geofencing zone' }); }
  }

  async updateGeofencingZone(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to update geofencing zone' }); }
  }

  async deleteGeofencingZone(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to delete geofencing zone' }); }
  }

  async bulkImportDevices(req, res) {
    try { res.json({ success: true, data: { imported: 0 }, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Bulk import failed' }); }
  }

  async bulkUpdatePolicies(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Bulk update failed' }); }
  }

  async bulkComplianceScan(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Bulk scan failed' }); }
  }

  async getBulkOperationStatus(req, res) {
    try { res.json({ success: true, data: { status: 'completed' }, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get operation status' }); }
  }

  async getPendingCommands(req, res) {
    try { res.json({ commands: [], requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to get pending commands' }); }
  }

  async handleCommandResult(req, res) {
    try { res.json({ success: true, requestId: req.id }); }
    catch (error) { res.status(500).json({ error: 'Failed to handle command result' }); }
  }

  async handleGeofenceViolation(event) {
    logger.warn('Geofence violation', event);
  }

  async handlePolicyDeployed(event) {
    logger.info('Policy deployed', event);
  }

  broadcastToSubscribers(subscription, data) {
    this.wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN && client.subscriptions.has(subscription)) {
        client.send(JSON.stringify({
          type: 'event',
          subscription,
          data,
          timestamp: new Date().toISOString()
        }));
      }
    });
  }

  generateRequestId() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  errorHandler(error, req, res, next) {
    logger.error('Unhandled error:', error, {
      requestId: req.id,
      path: req.path,
      method: req.method
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: new Date().toISOString()
    });
  }

  async start(port = process.env.PORT || 3003) {
    // Initialize PostgreSQL persistence layer
    await db.initDb().catch(err => {
      logger.warn(`[device-db] startup init failed: ${err.message}`);
    });

    this.server.listen(port, () => {
      logger.info(`🖥️  Enterprise Device Management Service started on port \${port}`);
      logger.info(`📊 Health check: http://localhost:\${port}/health`);
      logger.info(`🔌 WebSocket: ws://localhost:\${port}/ws/devices`);
      logger.info(`📱 Features: Enrollment, Compliance, Remote Actions, Analytics`);
      logger.info(`🛡️  Security: Threat Detection, Geofencing, Certificate Management`);
    });
  }

  gracefulShutdown() {
    logger.info('Starting graceful shutdown...');

    this.server.close(async () => {
      logger.info('HTTP server closed');

      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });

      // Close RabbitMQ connection gracefully
      if (this.messageBus) {
        await this.messageBus.close().catch(() => {});
      }

      // Close database connections
      this.db.close();
      this.cache.close();

      logger.info('Graceful shutdown completed');
      process.exit(0);
    });
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Received SIGINT, starting graceful shutdown...');
  if (global.deviceService) {
    global.deviceService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, starting graceful shutdown...');
  if (global.deviceService) {
    global.deviceService.gracefulShutdown();
  }
});

// Cluster mode for production
if (cluster.isMaster && process.env.NODE_ENV === 'production') {
  const numWorkers = process.env.WORKERS || os.cpus().length;
  
  logger.info(`Starting \${numWorkers} workers...`);
  
  for (let i = 0; i < numWorkers; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    logger.error(`Worker \${worker.process.pid} died`);
    cluster.fork();
  });
} else {
  // Start the service
  const deviceService = new EnterpriseDeviceManagementService();
  global.deviceService = deviceService;
  deviceService.start().catch(err => {
    console.error('Failed to start device service:', err);
    process.exit(1);
  });
}

module.exports = EnterpriseDeviceManagementService;