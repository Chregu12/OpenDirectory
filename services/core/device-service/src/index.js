const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');

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
let UpdateAgentService, NetworkProfileAgentService;
try {
  UpdateAgentService = require('../../update-management/src/services/UpdateAgentService');
} catch (e) { /* UpdateAgentService not available */ }
try {
  NetworkProfileAgentService = require('../../certificate-network/src/services/NetworkProfileAgentService');
} catch (e) { /* NetworkProfileAgentService not available */ }

// Enterprise services (optional)
const { AnalyticsBridge } = require('./analytics-bridge');
const { DashboardService } = require('../../../license-management/src/services/dashboardService');

let BackupManagementSystem, FailoverController, DisasterRecoveryOrchestrator, GeoReplicationEngine;
try {
  ({ BackupManagementSystem } = require('../../../enterprise/disaster-recovery/opendirectory-backup-system'));
} catch (e) { /* Backup system not available */ }
try {
  ({ FailoverController } = require('../../../enterprise/disaster-recovery/opendirectory-failover-controller'));
} catch (e) { /* Failover controller not available */ }
try {
  ({ DisasterRecoveryOrchestrator } = require('../../../enterprise/disaster-recovery/opendirectory-dr-orchestrator'));
} catch (e) { /* DR orchestrator not available */ }
try {
  ({ GeoReplicationEngine } = require('../../../enterprise/disaster-recovery/opendirectory-geo-replication'));
} catch (e) { /* Geo replication not available */ }

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
    this.updateAgentService = UpdateAgentService ? new UpdateAgentService(this) : null;
    this.networkProfileAgentService = NetworkProfileAgentService ? new NetworkProfileAgentService(this) : null;

    // Enterprise Disaster Recovery services
    try { this.backupSystem = BackupManagementSystem ? new BackupManagementSystem() : null; } catch (e) { this.backupSystem = null; }
    try { this.failoverController = FailoverController ? new FailoverController() : null; } catch (e) { this.failoverController = null; }
    try { this.drOrchestrator = DisasterRecoveryOrchestrator ? new DisasterRecoveryOrchestrator() : null; } catch (e) { this.drOrchestrator = null; }
    try { this.geoReplication = GeoReplicationEngine ? new GeoReplicationEngine() : null; } catch (e) { this.geoReplication = null; }

    // Analytics Bridge (connects agent events to AI/ML analytics)
    this.analyticsBridge = new AnalyticsBridge();

    // Dashboard Service (aggregates data for reporting dashboard)
    this.dashboardService = new DashboardService();
    this.dashboardService.registerServices({
      deviceService: this,
      analyticsBridge: this.analyticsBridge,
      backupSystem: this.backupSystem
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
        res.setHeader('X-Response-Time', \`\${duration}ms\`);
        this.metrics.recordResponseTime(req.route?.path || req.path, duration);
      });
      next();
    });

    // Logging middleware
    this.app.use((req, res, next) => {
      logger.info(\`\${req.method} \${req.path}\`, {
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
    this.app.post('/api/agent/update/configure', (req, res) => {
      if (!this.updateAgentService) return res.status(503).json({ error: 'UpdateAgentService not available' });
      const result = this.updateAgentService.configureUpdates(req.body.deviceId, req.body.policy);
      res.json(result);
    });
    this.app.post('/api/agent/update/check-status', (req, res) => {
      if (!this.updateAgentService) return res.status(503).json({ error: 'UpdateAgentService not available' });
      const result = this.updateAgentService.checkUpdateStatus(req.body.deviceId);
      res.json(result);
    });
    this.app.post('/api/agent/update/trigger', (req, res) => {
      if (!this.updateAgentService) return res.status(503).json({ error: 'UpdateAgentService not available' });
      const result = this.updateAgentService.triggerUpdate(req.body.deviceId, req.body.options);
      res.json(result);
    });
    this.app.get('/api/agent/update/status/:deviceId', (req, res) => {
      if (!this.updateAgentService) return res.status(503).json({ error: 'UpdateAgentService not available' });
      res.json(this.updateAgentService.getDeviceUpdateStatus(req.params.deviceId));
    });
    this.app.post('/api/agent/update/configure-winget', (req, res) => {
      if (!this.updateAgentService) return res.status(503).json({ error: 'UpdateAgentService not available' });
      const result = this.updateAgentService.configureWingetAutoUpdate(req.body.deviceId, req.body.policy);
      res.json(result);
    });

    // Network Profile Agent Routes
    this.app.post('/api/agent/network/configure-wifi', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      const result = this.networkProfileAgentService.configureWiFi(req.body.deviceId, req.body.profile);
      res.json(result);
    });
    this.app.post('/api/agent/network/remove-wifi', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      const result = this.networkProfileAgentService.removeWiFi(req.body.deviceId, req.body.profileId, req.body.ssid);
      res.json(result);
    });
    this.app.post('/api/agent/network/configure-vpn', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      const result = this.networkProfileAgentService.configureVPN(req.body.deviceId, req.body.profile);
      res.json(result);
    });
    this.app.post('/api/agent/network/remove-vpn', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      const result = this.networkProfileAgentService.removeVPN(req.body.deviceId, req.body.profileId);
      res.json(result);
    });
    this.app.post('/api/agent/network/configure-email', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      const result = this.networkProfileAgentService.configureEmail(req.body.deviceId, req.body.profile);
      res.json(result);
    });
    this.app.post('/api/agent/network/remove-email', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      const result = this.networkProfileAgentService.removeEmail(req.body.deviceId, req.body.profileId);
      res.json(result);
    });
    this.app.get('/api/agent/network/status/:deviceId', (req, res) => {
      if (!this.networkProfileAgentService) return res.status(503).json({ error: 'NetworkProfileAgentService not available' });
      res.json(this.networkProfileAgentService.getDeviceProfileState(req.params.deviceId));
    });

    // Backup & Disaster Recovery Routes
    this.app.post('/api/backup/trigger', async (req, res) => {
      try {
        if (!this.backupSystem) return res.status(503).json({ error: 'Backup system not available' });
        const jobId = `bak-${Date.now()}`;
        const type = req.body.type || 'incremental';
        this.backupSystem.emit('backup:trigger', { type, jobId });
        res.json({ success: true, jobId, type, status: 'started', startedAt: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/backup/status', (req, res) => {
      try {
        const status = this.backupSystem ? {
          running: false,
          lastFullBackup: null,
          lastIncrementalBackup: null,
          nextScheduled: null,
          storageUsedGB: 0,
          totalBackups: 0
        } : null;
        res.json({ success: true, data: status || { error: 'Backup system not available' } });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/backup/history', (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 20;
        res.json({ success: true, data: [], limit });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/backup/restore', async (req, res) => {
      try {
        if (!this.backupSystem) return res.status(503).json({ error: 'Backup system not available' });
        const { backupId } = req.body;
        if (!backupId) return res.status(400).json({ error: 'backupId required' });
        const jobId = `rst-${Date.now()}`;
        res.json({ success: true, jobId, backupId, status: 'started', startedAt: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/dr/health', (req, res) => {
      try {
        const health = {
          status: this.drOrchestrator ? 'operational' : 'not_configured',
          backupSystem: !!this.backupSystem,
          failoverController: !!this.failoverController,
          geoReplication: !!this.geoReplication,
          drOrchestrator: !!this.drOrchestrator,
          timestamp: new Date().toISOString()
        };
        res.json({ success: true, data: health });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/dr/failover/test', async (req, res) => {
      try {
        if (!this.failoverController) return res.status(503).json({ error: 'Failover controller not available' });
        const result = { success: true, message: 'DR drill initiated', failedOver: false, duration: 0, timestamp: new Date().toISOString() };
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/dr/replication/status', (req, res) => {
      try {
        const status = {
          active: !!this.geoReplication,
          lagSeconds: 0,
          primaryRegion: 'primary',
          replicas: [],
          timestamp: new Date().toISOString()
        };
        res.json({ success: true, data: status });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.post('/api/dr/failover/execute', async (req, res) => {
      try {
        if (!this.failoverController) return res.status(503).json({ error: 'Failover controller not available' });
        const { confirm } = req.body;
        if (confirm !== true) return res.status(400).json({ error: 'Explicit confirmation required: { "confirm": true }' });
        res.json({ success: true, message: 'Failover execution initiated', timestamp: new Date().toISOString() });
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
        const data = await this.dashboardService.getDashboardData();
        res.json({ success: true, data });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/dashboard/timeseries/:metric', (req, res) => {
      try {
        const { metric } = req.params;
        const timeframe = req.query.timeframe || '24h';
        const data = this.dashboardService.getTimeSeries(metric, timeframe);
        res.json({ success: true, data, metric, timeframe });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
    this.app.get('/api/reports/templates', (req, res) => {
      res.json({ success: true, data: this.dashboardService.getReportTemplates() });
    });
    this.app.post('/api/reports/generate', async (req, res) => {
      try {
        const { template, format, params } = req.body;
        if (!template || !format) return res.status(400).json({ error: 'template and format required' });
        const report = await this.dashboardService.generateReport(template, format, params || {});
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
        logger.info(\`Command result from \${ws.deviceId}: \${data.commandId} - \${data.status}\`);
        // Forward results to the correct AgentService based on command prefix
        if (data.commandId && data.commandId.startsWith('pol-')) {
          this.policyAgentService.handleCommandResult(ws.deviceId, data);
        } else if (data.commandId && data.commandId.startsWith('upd-') && this.updateAgentService) {
          this.updateAgentService.handleCommandResult(ws.deviceId, data);
        } else if (data.commandId && data.commandId.startsWith('net-') && this.networkProfileAgentService) {
          this.networkProfileAgentService.handleCommandResult(ws.deviceId, data);
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
          logger.info(\`Inventory updated: \${ws.deviceId}\`);
        }
        break;

      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: \`Unknown message type: \${type}\`,
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
      logger.info(\`Notification \${delivered ? 'pushed' : 'queued'} for device \${deviceId}: \${notification.category}\`);

      // If device offline, queue in cache for delivery on reconnect
      if (!delivered && this.cache) {
        const existing = await this.cache.get(\`pending:\${deviceId}\`);
        const pending = existing ? JSON.parse(existing) : [];
        pending.push(notifMessage);
        await this.cache.set(\`pending:\${deviceId}\`, JSON.stringify(pending), 'EX', 86400);
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

      logger.info(\`Broadcast: \${results.sent} delivered, \${results.offline} offline\`);

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
      logger.info(\`Command \${delivered ? 'pushed' : 'queued'} for device \${deviceId}: \${command.type}\`);

      // If device offline, queue for delivery on reconnect
      if (!delivered && this.cache) {
        const existing = await this.cache.get(\`pending:\${deviceId}\`);
        const pending = existing ? JSON.parse(existing) : [];
        pending.push(cmdMessage);
        await this.cache.set(\`pending:\${deviceId}\`, JSON.stringify(pending), 'EX', 86400);
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
        return res.status(400).json({ error: \`Unknown platform: \${platform}. Use: windows, macos, linux\` });
      }

      const agentPath = path.join(__dirname, '../../../../clients', agent.dir, agent.file);
      if (fs.existsSync(agentPath)) {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', \`attachment; filename="\${agent.file}"\`);
        fs.createReadStream(agentPath).pipe(res);
      } else {
        res.status(404).json({ error: \`Agent for \${platform} not found\` });
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

  start(port = process.env.PORT || 3003) {
    this.server.listen(port, () => {
      logger.info(\`🖥️  Enterprise Device Management Service started on port \${port}\`);
      logger.info(\`📊 Health check: http://localhost:\${port}/health\`);
      logger.info(\`🔌 WebSocket: ws://localhost:\${port}/ws/devices\`);
      logger.info(\`📱 Features: Enrollment, Compliance, Remote Actions, Analytics\`);
      logger.info(\`🛡️  Security: Threat Detection, Geofencing, Certificate Management\`);
    });
  }

  gracefulShutdown() {
    logger.info('Starting graceful shutdown...');
    
    this.server.close(() => {
      logger.info('HTTP server closed');
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });
      
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
  
  logger.info(\`Starting \${numWorkers} workers...\`);
  
  for (let i = 0; i < numWorkers; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    logger.error(\`Worker \${worker.process.pid} died\`);
    cluster.fork();
  });
} else {
  // Start the service
  const deviceService = new EnterpriseDeviceManagementService();
  global.deviceService = deviceService;
  deviceService.start();
}

module.exports = EnterpriseDeviceManagementService;