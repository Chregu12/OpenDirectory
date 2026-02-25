const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const EventEmitter = require('events');

/**
 * Enterprise Mobile Threat Defense (MTD) Service
 * Provides comprehensive mobile security and threat detection
 * 
 * Features:
 * - Real-time threat detection and analysis
 * - App reputation and behavior analysis
 * - Network security monitoring
 * - Device integrity validation
 * - Malware detection and quarantine
 * - Phishing protection
 * - Anomaly detection and machine learning
 * - Security incident response
 * - Threat intelligence integration
 * - Advanced persistent threat (APT) detection
 */
class MobileThreatDefenseService extends EventEmitter {
  constructor() {
    super();
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/mtd'
    });
    
    // Configuration
    this.config = {
      threatIntelligence: {
        feeds: [
          {
            name: 'VirusTotal',
            enabled: process.env.VIRUSTOTAL_ENABLED === 'true',
            apiKey: process.env.VIRUSTOTAL_API_KEY || '',
            baseUrl: 'https://www.virustotal.com/vtapi/v2'
          },
          {
            name: 'Abuse.ch',
            enabled: true,
            baseUrl: 'https://urlhaus-api.abuse.ch/v1'
          }
        ],
        updateInterval: 3600000 // 1 hour
      },
      mlModels: {
        malwareDetection: {
          enabled: true,
          confidence: 0.85,
          modelVersion: '1.0.0'
        },
        anomalyDetection: {
          enabled: true,
          sensitivity: 'medium', // low, medium, high
          baselineWindow: 604800000 // 7 days in ms
        },
        behaviorAnalysis: {
          enabled: true,
          patterns: ['network_anomaly', 'app_behavior', 'data_exfiltration']
        }
      },
      scanning: {
        realTimeEnabled: true,
        scheduledScanInterval: 86400000, // 24 hours
        maxConcurrentScans: 10,
        quarantineEnabled: true
      },
      integration: {
        siem: {
          enabled: process.env.SIEM_ENABLED === 'true',
          endpoint: process.env.SIEM_ENDPOINT || '',
          apiKey: process.env.SIEM_API_KEY || ''
        },
        sandbox: {
          enabled: process.env.SANDBOX_ENABLED === 'true',
          endpoint: process.env.SANDBOX_ENDPOINT || '',
          apiKey: process.env.SANDBOX_API_KEY || ''
        }
      }
    };
    
    // In-memory storage (replace with database in production)
    this.threats = new Map();
    this.devices = new Map();
    this.securityIncidents = new Map();
    this.threatIntelligence = new Map();
    this.scanJobs = new Map();
    this.quarantineItems = new Map();
    this.securityPolicies = new Map();
    this.alertRules = new Map();
    this.mlModels = new Map();
    this.behaviorBaselines = new Map();
    this.networkAnalysis = new Map();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeThreatIntelligence();
    this.initializeMLModels();
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
      origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-ID', 'X-Request-ID', 'X-Threat-Context'],
      exposedHeaders: ['X-Total-Count', 'X-Request-ID', 'X-Response-Time', 'X-Threat-Level']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5000, // Higher limit for threat detection
      message: 'Rate limit exceeded for MTD operations',
      standardHeaders: true
    });

    this.app.use('/api/mtd', limiter);

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request ID middleware
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || this.generateId();
      res.setHeader('X-Request-ID', req.id);
      next();
    });

    // Logging middleware
    this.app.use((req, res, next) => {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, {
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
      ws.id = this.generateId();
      ws.deviceId = req.headers['x-device-id'];
      ws.subscriptions = new Set();
      ws.isAlive = true;

      console.log('MTD WebSocket connection established', {
        connectionId: ws.id,
        deviceId: ws.deviceId
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          console.error('MTD WebSocket message error:', error);
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
        console.log('MTD WebSocket connection closed', { 
          connectionId: ws.id,
          deviceId: ws.deviceId 
        });
      });

      // Send initial connection confirmation
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        service: 'mobile-threat-defense',
        connectionId: ws.id,
        timestamp: new Date().toISOString()
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
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'mobile-threat-defense-service',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        capabilities: [
          'real-time-threat-detection',
          'malware-scanning',
          'behavior-analysis',
          'network-monitoring',
          'threat-intelligence',
          'incident-response',
          'ml-anomaly-detection',
          'phishing-protection'
        ],
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid,
        memory: process.memoryUsage(),
        checks: {
          threat_intelligence: this.checkThreatIntelligenceHealth(),
          ml_models: this.checkMLModelsHealth(),
          scanning_engine: this.config.scanning.realTimeEnabled ? 'enabled' : 'disabled',
          websocket: this.wss.clients.size >= 0 ? 'healthy' : 'unhealthy'
        },
        statistics: {
          active_devices: this.devices.size,
          detected_threats: this.threats.size,
          active_incidents: Array.from(this.securityIncidents.values()).filter(i => i.status === 'active').length,
          quarantined_items: this.quarantineItems.size,
          scan_jobs: Array.from(this.scanJobs.values()).filter(j => j.status === 'running').length
        }
      });
    });

    // Threat Detection Routes
    this.app.post('/api/mtd/threats/scan', this.initiateThreatScan.bind(this));
    this.app.get('/api/mtd/threats', this.getThreats.bind(this));
    this.app.get('/api/mtd/threats/:threatId', this.getThreat.bind(this));
    this.app.put('/api/mtd/threats/:threatId/status', this.updateThreatStatus.bind(this));
    this.app.post('/api/mtd/threats/:threatId/quarantine', this.quarantineThreat.bind(this));
    this.app.post('/api/mtd/threats/:threatId/whitelist', this.whitelistThreat.bind(this));

    // Device Security Routes
    this.app.get('/api/mtd/devices', this.getSecureDevices.bind(this));
    this.app.get('/api/mtd/devices/:deviceId/security', this.getDeviceSecurity.bind(this));
    this.app.post('/api/mtd/devices/:deviceId/register', this.registerDevice.bind(this));
    this.app.put('/api/mtd/devices/:deviceId/security-status', this.updateDeviceSecurityStatus.bind(this));
    this.app.post('/api/mtd/devices/:deviceId/isolate', this.isolateDevice.bind(this));
    this.app.post('/api/mtd/devices/:deviceId/restore', this.restoreDevice.bind(this));

    // Security Incident Routes
    this.app.get('/api/mtd/incidents', this.getSecurityIncidents.bind(this));
    this.app.post('/api/mtd/incidents', this.createSecurityIncident.bind(this));
    this.app.get('/api/mtd/incidents/:incidentId', this.getSecurityIncident.bind(this));
    this.app.put('/api/mtd/incidents/:incidentId', this.updateSecurityIncident.bind(this));
    this.app.post('/api/mtd/incidents/:incidentId/respond', this.respondToIncident.bind(this));
    this.app.post('/api/mtd/incidents/:incidentId/close', this.closeIncident.bind(this));

    // Threat Intelligence Routes
    this.app.get('/api/mtd/threat-intelligence', this.getThreatIntelligence.bind(this));
    this.app.post('/api/mtd/threat-intelligence/indicators', this.addThreatIndicators.bind(this));
    this.app.post('/api/mtd/threat-intelligence/feeds/update', this.updateThreatFeeds.bind(this));
    this.app.get('/api/mtd/threat-intelligence/iocs', this.getIOCs.bind(this));

    // Malware Analysis Routes
    this.app.post('/api/mtd/malware/analyze', this.analyzeMalware.bind(this));
    this.app.get('/api/mtd/malware/analysis/:analysisId', this.getMalwareAnalysis.bind(this));
    this.app.post('/api/mtd/malware/sandbox', this.submitToSandbox.bind(this));
    this.app.get('/api/mtd/malware/signatures', this.getMalwareSignatures.bind(this));

    // Network Security Routes
    this.app.get('/api/mtd/network/analysis', this.getNetworkAnalysis.bind(this));
    this.app.post('/api/mtd/network/monitor', this.startNetworkMonitoring.bind(this));
    this.app.get('/api/mtd/network/threats', this.getNetworkThreats.bind(this));
    this.app.post('/api/mtd/network/block', this.blockNetworkThreat.bind(this));

    // Behavior Analysis Routes
    this.app.get('/api/mtd/behavior/baselines', this.getBehaviorBaselines.bind(this));
    this.app.post('/api/mtd/behavior/analyze', this.analyzeBehavior.bind(this));
    this.app.get('/api/mtd/behavior/anomalies', this.getBehaviorAnomalies.bind(this));
    this.app.post('/api/mtd/behavior/pattern', this.createBehaviorPattern.bind(this));

    // Quarantine Management Routes
    this.app.get('/api/mtd/quarantine', this.getQuarantineItems.bind(this));
    this.app.post('/api/mtd/quarantine/:itemId/restore', this.restoreQuarantineItem.bind(this));
    this.app.delete('/api/mtd/quarantine/:itemId', this.deleteQuarantineItem.bind(this));
    this.app.post('/api/mtd/quarantine/bulk-action', this.bulkQuarantineAction.bind(this));

    // Security Policy Routes
    this.app.get('/api/mtd/policies', this.getSecurityPolicies.bind(this));
    this.app.post('/api/mtd/policies', this.createSecurityPolicy.bind(this));
    this.app.put('/api/mtd/policies/:policyId', this.updateSecurityPolicy.bind(this));
    this.app.delete('/api/mtd/policies/:policyId', this.deleteSecurityPolicy.bind(this));
    this.app.post('/api/mtd/policies/:policyId/deploy', this.deploySecurityPolicy.bind(this));

    // Alert Management Routes
    this.app.get('/api/mtd/alerts', this.getSecurityAlerts.bind(this));
    this.app.post('/api/mtd/alerts/rules', this.createAlertRule.bind(this));
    this.app.put('/api/mtd/alerts/rules/:ruleId', this.updateAlertRule.bind(this));
    this.app.post('/api/mtd/alerts/:alertId/acknowledge', this.acknowledgeAlert.bind(this));

    // Analytics and Reporting Routes
    this.app.get('/api/mtd/analytics/dashboard', this.getSecurityDashboard.bind(this));
    this.app.get('/api/mtd/analytics/threat-landscape', this.getThreatLandscape.bind(this));
    this.app.get('/api/mtd/analytics/risk-assessment', this.getRiskAssessment.bind(this));
    this.app.get('/api/mtd/analytics/security-trends', this.getSecurityTrends.bind(this));
    this.app.get('/api/mtd/reports/security', this.generateSecurityReport.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  async initializeThreatIntelligence() {
    console.log('Initializing threat intelligence feeds...');
    
    // Load initial threat intelligence data
    await this.loadThreatIndicators();
    
    // Start threat intelligence update cycle
    this.updateThreatIntelligenceCycle();
  }

  async initializeMLModels() {
    console.log('Initializing ML models for threat detection...');
    
    // Initialize malware detection model
    if (this.config.mlModels.malwareDetection.enabled) {
      this.mlModels.set('malware_detection', {
        version: this.config.mlModels.malwareDetection.modelVersion,
        confidence: this.config.mlModels.malwareDetection.confidence,
        lastUpdated: new Date().toISOString(),
        status: 'ready'
      });
    }
    
    // Initialize anomaly detection model
    if (this.config.mlModels.anomalyDetection.enabled) {
      this.mlModels.set('anomaly_detection', {
        sensitivity: this.config.mlModels.anomalyDetection.sensitivity,
        baselineWindow: this.config.mlModels.anomalyDetection.baselineWindow,
        lastUpdated: new Date().toISOString(),
        status: 'ready'
      });
    }
    
    // Initialize behavior analysis model
    if (this.config.mlModels.behaviorAnalysis.enabled) {
      this.mlModels.set('behavior_analysis', {
        patterns: this.config.mlModels.behaviorAnalysis.patterns,
        lastUpdated: new Date().toISOString(),
        status: 'ready'
      });
    }
  }

  // Threat Detection
  async initiateThreatScan(req, res) {
    try {
      const { 
        targets, 
        scanType = 'full', 
        priority = 'medium',
        scanParameters = {} 
      } = req.body;
      
      if (!targets || !Array.isArray(targets) || targets.length === 0) {
        return res.status(400).json({
          error: 'targets array is required',
          requestId: req.id
        });
      }

      const scanId = this.generateId();
      const scanJob = {
        id: scanId,
        type: scanType,
        targets,
        priority,
        scanParameters,
        status: 'queued',
        createdAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        progress: 0,
        results: [],
        threatsFound: 0,
        errors: []
      };

      this.scanJobs.set(scanId, scanJob);

      // Start scan process
      this.processThreatScan(scanId);

      res.status(201).json({
        success: true,
        data: scanJob,
        requestId: req.id
      });
    } catch (error) {
      console.error('Initiate threat scan error:', error);
      res.status(500).json({
        error: 'Failed to initiate threat scan',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Device Security Management
  async registerDevice(req, res) {
    try {
      const { deviceId } = req.params;
      const deviceData = req.body;
      
      if (!deviceData.platform || !deviceData.osVersion) {
        return res.status(400).json({
          error: 'Missing required fields: platform, osVersion',
          requestId: req.id
        });
      }

      const device = {
        id: deviceId,
        name: deviceData.name || `Device-${deviceId.substring(0, 8)}`,
        platform: deviceData.platform,
        osVersion: deviceData.osVersion,
        securityStatus: 'evaluating',
        registeredAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        riskLevel: 'unknown',
        securityScore: 0,
        threats: {
          active: 0,
          resolved: 0,
          total: 0
        },
        compliance: {
          status: 'unknown',
          violations: []
        },
        monitoring: {
          realTimeEnabled: this.config.scanning.realTimeEnabled,
          lastScanAt: null,
          nextScanAt: null
        },
        isolation: {
          isIsolated: false,
          isolatedAt: null,
          reason: null
        }
      };

      this.devices.set(deviceId, device);

      // Start initial security assessment
      this.performDeviceSecurityAssessment(deviceId);

      res.status(201).json({
        success: true,
        data: device,
        requestId: req.id
      });
    } catch (error) {
      console.error('Register device error:', error);
      res.status(500).json({
        error: 'Failed to register device',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async isolateDevice(req, res) {
    try {
      const { deviceId } = req.params;
      const { reason, duration } = req.body;
      
      const device = this.devices.get(deviceId);
      if (!device) {
        return res.status(404).json({
          error: 'Device not found',
          requestId: req.id
        });
      }

      device.isolation = {
        isIsolated: true,
        isolatedAt: new Date().toISOString(),
        reason: reason || 'Security threat detected',
        duration: duration,
        expiresAt: duration ? new Date(Date.now() + duration * 1000).toISOString() : null
      };

      this.devices.set(deviceId, device);

      // Create security incident
      const incidentId = this.generateId();
      const incident = {
        id: incidentId,
        type: 'device_isolation',
        deviceId,
        severity: 'high',
        status: 'active',
        title: `Device ${device.name} isolated due to security threat`,
        description: reason || 'Security threat detected',
        createdAt: new Date().toISOString(),
        actions: [{
          type: 'isolate_device',
          executedAt: new Date().toISOString(),
          result: 'success'
        }]
      };

      this.securityIncidents.set(incidentId, incident);

      // Broadcast isolation event
      this.broadcastToSubscribers('device_isolated', {
        deviceId,
        deviceName: device.name,
        reason: device.isolation.reason,
        incidentId
      });

      res.json({
        success: true,
        data: {
          deviceId,
          isolationStatus: device.isolation,
          incidentId
        },
        requestId: req.id
      });
    } catch (error) {
      console.error('Isolate device error:', error);
      res.status(500).json({
        error: 'Failed to isolate device',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Security Incident Management
  async createSecurityIncident(req, res) {
    try {
      const incidentData = req.body;
      
      if (!incidentData.type || !incidentData.title) {
        return res.status(400).json({
          error: 'Missing required fields: type, title',
          requestId: req.id
        });
      }

      const incidentId = this.generateId();
      const incident = {
        id: incidentId,
        type: incidentData.type,
        title: incidentData.title,
        description: incidentData.description || '',
        severity: incidentData.severity || 'medium',
        status: 'active',
        deviceId: incidentData.deviceId,
        threatId: incidentData.threatId,
        affectedAssets: incidentData.affectedAssets || [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        assignedTo: incidentData.assignedTo,
        tags: incidentData.tags || [],
        timeline: [{
          action: 'incident_created',
          timestamp: new Date().toISOString(),
          details: 'Security incident created'
        }],
        actions: [],
        containmentStatus: 'none',
        remediationSteps: []
      };

      this.securityIncidents.set(incidentId, incident);

      // Auto-assign severity-based response
      if (incident.severity === 'critical') {
        this.initiateEmergencyResponse(incidentId);
      }

      // Broadcast incident creation
      this.broadcastToSubscribers('incident_created', {
        incidentId,
        type: incident.type,
        severity: incident.severity,
        title: incident.title
      });

      res.status(201).json({
        success: true,
        data: incident,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create security incident error:', error);
      res.status(500).json({
        error: 'Failed to create security incident',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Malware Analysis
  async analyzeMalware(req, res) {
    try {
      const { filePath, fileHash, fileName, deviceId } = req.body;
      
      if (!filePath && !fileHash) {
        return res.status(400).json({
          error: 'Either filePath or fileHash is required',
          requestId: req.id
        });
      }

      const analysisId = this.generateId();
      const analysis = {
        id: analysisId,
        fileName: fileName || 'unknown',
        filePath,
        fileHash: fileHash || this.generateHash(),
        deviceId,
        status: 'analyzing',
        startedAt: new Date().toISOString(),
        completedAt: null,
        results: {
          isMalicious: null,
          threatType: null,
          confidence: 0,
          signatures: [],
          behaviors: [],
          networkActivity: [],
          fileOperations: []
        },
        scanEngines: [
          { name: 'Static Analysis', status: 'running' },
          { name: 'Dynamic Analysis', status: 'queued' },
          { name: 'ML Classification', status: 'queued' },
          { name: 'Signature Matching', status: 'queued' }
        ]
      };

      // Start malware analysis
      this.performMalwareAnalysis(analysisId);

      res.status(201).json({
        success: true,
        data: analysis,
        requestId: req.id
      });
    } catch (error) {
      console.error('Analyze malware error:', error);
      res.status(500).json({
        error: 'Failed to analyze malware',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Behavior Analysis
  async analyzeBehavior(req, res) {
    try {
      const { deviceId, behaviorData, timeWindow = 3600 } = req.body;
      
      if (!deviceId || !behaviorData) {
        return res.status(400).json({
          error: 'Missing required fields: deviceId, behaviorData',
          requestId: req.id
        });
      }

      const device = this.devices.get(deviceId);
      if (!device) {
        return res.status(404).json({
          error: 'Device not found',
          requestId: req.id
        });
      }

      // Get baseline behavior for device
      const baseline = this.behaviorBaselines.get(deviceId);
      
      const analysisResult = await this.performBehaviorAnalysis(deviceId, behaviorData, baseline, timeWindow);

      res.json({
        success: true,
        data: analysisResult,
        requestId: req.id
      });
    } catch (error) {
      console.error('Analyze behavior error:', error);
      res.status(500).json({
        error: 'Failed to analyze behavior',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Analytics and Reporting
  async getSecurityDashboard(req, res) {
    try {
      const dashboard = {
        overview: {
          totalDevices: this.devices.size,
          protectedDevices: Array.from(this.devices.values()).filter(d => d.securityStatus === 'protected').length,
          isolatedDevices: Array.from(this.devices.values()).filter(d => d.isolation.isIsolated).length,
          highRiskDevices: Array.from(this.devices.values()).filter(d => d.riskLevel === 'high').length
        },
        threats: {
          totalThreats: this.threats.size,
          activeThreats: Array.from(this.threats.values()).filter(t => t.status === 'active').length,
          criticalThreats: Array.from(this.threats.values()).filter(t => t.severity === 'critical').length,
          quarantinedItems: this.quarantineItems.size
        },
        incidents: {
          activeIncidents: Array.from(this.securityIncidents.values()).filter(i => i.status === 'active').length,
          criticalIncidents: Array.from(this.securityIncidents.values()).filter(i => i.severity === 'critical').length,
          resolvedToday: this.getIncidentsResolvedToday(),
          averageResolutionTime: this.calculateAverageResolutionTime()
        },
        scanning: {
          activeScans: Array.from(this.scanJobs.values()).filter(s => s.status === 'running').length,
          scansToday: this.getScansToday(),
          averageScanTime: this.calculateAverageScanTime(),
          detectionRate: this.calculateDetectionRate()
        },
        intelligence: {
          threatIndicators: this.threatIntelligence.size,
          lastUpdate: this.getLastThreatIntelligenceUpdate(),
          activeFeedSources: this.getActiveThreatFeeds(),
          newIOCs: this.getNewIOCsToday()
        }
      };

      res.json({
        success: true,
        data: dashboard,
        requestId: req.id
      });
    } catch (error) {
      console.error('Security dashboard error:', error);
      res.status(500).json({
        error: 'Failed to get security dashboard',
        requestId: req.id
      });
    }
  }

  // Helper Methods
  async processThreatScan(scanId) {
    const scanJob = this.scanJobs.get(scanId);
    if (!scanJob) return;

    try {
      scanJob.status = 'running';
      scanJob.startedAt = new Date().toISOString();
      
      const totalTargets = scanJob.targets.length;
      let processedTargets = 0;

      for (const target of scanJob.targets) {
        try {
          const threatAnalysis = await this.analyzeTarget(target, scanJob.scanParameters);
          
          if (threatAnalysis.threatsFound > 0) {
            scanJob.threatsFound += threatAnalysis.threatsFound;
            scanJob.results.push(threatAnalysis);
            
            // Create threat entries
            for (const threat of threatAnalysis.threats) {
              const threatId = this.generateId();
              this.threats.set(threatId, {
                id: threatId,
                ...threat,
                scanId,
                targetId: target.id,
                detectedAt: new Date().toISOString(),
                status: 'active'
              });
            }
          }

          processedTargets++;
          scanJob.progress = Math.floor((processedTargets / totalTargets) * 100);

          this.broadcastToSubscribers('scan_progress', {
            scanId,
            progress: scanJob.progress,
            threatsFound: scanJob.threatsFound
          });

        } catch (targetError) {
          console.error(`Scan error for target ${target.id}:`, targetError);
          scanJob.errors.push({
            targetId: target.id,
            error: targetError.message,
            timestamp: new Date().toISOString()
          });
        }

        this.scanJobs.set(scanId, scanJob);
      }

      scanJob.status = 'completed';
      scanJob.completedAt = new Date().toISOString();

      this.broadcastToSubscribers('scan_completed', {
        scanId,
        threatsFound: scanJob.threatsFound,
        duration: Date.now() - new Date(scanJob.startedAt).getTime()
      });

    } catch (error) {
      console.error('Threat scan processing error:', error);
      scanJob.status = 'failed';
      scanJob.error = error.message;
    }

    this.scanJobs.set(scanId, scanJob);
  }

  async analyzeTarget(target, scanParameters) {
    // Simulate threat analysis
    const analysis = {
      targetId: target.id,
      targetType: target.type,
      threatsFound: 0,
      threats: [],
      scanDuration: Math.random() * 5000 + 1000,
      timestamp: new Date().toISOString()
    };

    // Simulate threat detection with varying probability based on target type
    const threatProbability = target.type === 'app' ? 0.15 : 0.05;
    
    if (Math.random() < threatProbability) {
      const threatTypes = ['malware', 'spyware', 'adware', 'trojan', 'phishing'];
      const threatType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
      
      analysis.threatsFound = 1;
      analysis.threats = [{
        type: threatType,
        name: `${threatType.toUpperCase()}.Mobile.${this.generateId().substring(0, 8)}`,
        severity: Math.random() > 0.7 ? 'critical' : Math.random() > 0.4 ? 'high' : 'medium',
        confidence: Math.random() * 0.3 + 0.7, // 0.7 - 1.0
        description: `${threatType} detected in ${target.type}`,
        indicators: [
          `Suspicious ${target.type} behavior pattern`,
          `Matches known ${threatType} signatures`
        ]
      }];
    }

    return analysis;
  }

  async performDeviceSecurityAssessment(deviceId) {
    const device = this.devices.get(deviceId);
    if (!device) return;

    try {
      // Simulate security assessment
      await new Promise(resolve => setTimeout(resolve, 2000));

      const securityScore = Math.floor(Math.random() * 40) + 60; // 60-100
      const riskLevel = securityScore >= 80 ? 'low' : securityScore >= 60 ? 'medium' : 'high';

      device.securityStatus = 'assessed';
      device.securityScore = securityScore;
      device.riskLevel = riskLevel;
      device.monitoring.lastScanAt = new Date().toISOString();
      device.monitoring.nextScanAt = new Date(Date.now() + this.config.scanning.scheduledScanInterval).toISOString();

      // Add compliance check results
      device.compliance.status = securityScore >= 70 ? 'compliant' : 'non-compliant';
      if (device.compliance.status === 'non-compliant') {
        device.compliance.violations = [
          {
            type: 'security_policy',
            description: 'Device does not meet minimum security requirements',
            severity: 'medium'
          }
        ];
      }

      this.devices.set(deviceId, device);

      this.broadcastToSubscribers('device_assessed', {
        deviceId,
        securityScore,
        riskLevel,
        complianceStatus: device.compliance.status
      });

    } catch (error) {
      console.error('Device security assessment error:', error);
      device.securityStatus = 'assessment_failed';
      this.devices.set(deviceId, device);
    }
  }

  async performMalwareAnalysis(analysisId) {
    // Simulate comprehensive malware analysis
    await new Promise(resolve => setTimeout(resolve, 15000)); // 15 seconds

    const analysis = this.threatIntelligence.get(analysisId);
    if (!analysis) return;

    // Simulate analysis results
    const isMalicious = Math.random() > 0.7;
    
    analysis.status = 'completed';
    analysis.completedAt = new Date().toISOString();
    analysis.results = {
      isMalicious,
      threatType: isMalicious ? ['trojan', 'spyware', 'adware'][Math.floor(Math.random() * 3)] : null,
      confidence: isMalicious ? Math.random() * 0.3 + 0.7 : Math.random() * 0.3,
      signatures: isMalicious ? [`Signature_${this.generateId().substring(0, 8)}`] : [],
      behaviors: isMalicious ? ['Network communication to suspicious domains', 'File system modifications'] : [],
      networkActivity: isMalicious ? ['DNS queries to malicious domains', 'HTTP POST to C&C server'] : [],
      fileOperations: ['File read operations', 'Registry modifications']
    };

    analysis.scanEngines.forEach(engine => {
      engine.status = 'completed';
      engine.result = isMalicious ? 'threat_detected' : 'clean';
    });

    this.broadcastToSubscribers('malware_analysis_completed', {
      analysisId,
      isMalicious,
      threatType: analysis.results.threatType
    });
  }

  async performBehaviorAnalysis(deviceId, behaviorData, baseline, timeWindow) {
    const analysis = {
      deviceId,
      timestamp: new Date().toISOString(),
      timeWindow,
      anomalies: [],
      riskScore: 0,
      recommendation: 'continue_monitoring'
    };

    // Simulate behavior analysis
    if (baseline) {
      // Compare with baseline
      const deviationScore = Math.random();
      
      if (deviationScore > 0.8) {
        analysis.anomalies.push({
          type: 'network_behavior',
          description: 'Unusual network traffic patterns detected',
          severity: 'medium',
          confidence: deviationScore
        });
      }

      if (deviationScore > 0.9) {
        analysis.anomalies.push({
          type: 'app_behavior',
          description: 'Abnormal application execution patterns',
          severity: 'high',
          confidence: deviationScore
        });
      }

      analysis.riskScore = deviationScore * 100;
      
      if (analysis.riskScore > 80) {
        analysis.recommendation = 'investigate_immediately';
      } else if (analysis.riskScore > 60) {
        analysis.recommendation = 'enhanced_monitoring';
      }
    } else {
      // Establish baseline
      this.behaviorBaselines.set(deviceId, {
        established: new Date().toISOString(),
        data: behaviorData,
        updateCount: 1
      });
      
      analysis.recommendation = 'baseline_established';
    }

    return analysis;
  }

  async initiateEmergencyResponse(incidentId) {
    const incident = this.securityIncidents.get(incidentId);
    if (!incident) return;

    // Auto-isolate affected device if specified
    if (incident.deviceId) {
      const device = this.devices.get(incident.deviceId);
      if (device && !device.isolation.isIsolated) {
        device.isolation = {
          isIsolated: true,
          isolatedAt: new Date().toISOString(),
          reason: `Critical incident ${incidentId}: ${incident.title}`,
          duration: null // Indefinite isolation
        };
        
        this.devices.set(incident.deviceId, device);

        incident.actions.push({
          type: 'auto_isolate_device',
          deviceId: incident.deviceId,
          executedAt: new Date().toISOString(),
          result: 'success'
        });
      }
    }

    // Add to timeline
    incident.timeline.push({
      action: 'emergency_response_initiated',
      timestamp: new Date().toISOString(),
      details: 'Automatic emergency response triggered due to critical severity'
    });

    incident.containmentStatus = 'automatic';
    this.securityIncidents.set(incidentId, incident);

    this.broadcastToSubscribers('emergency_response', {
      incidentId,
      deviceId: incident.deviceId,
      actions: incident.actions
    });
  }

  checkThreatIntelligenceHealth() {
    const activeFeeds = this.config.threatIntelligence.feeds.filter(f => f.enabled);
    return activeFeeds.length > 0 ? 'healthy' : 'warning';
  }

  checkMLModelsHealth() {
    const enabledModels = Array.from(this.mlModels.values()).filter(m => m.status === 'ready');
    return enabledModels.length > 0 ? 'healthy' : 'warning';
  }

  async loadThreatIndicators() {
    // Load initial threat intelligence
    const indicators = [
      {
        type: 'hash',
        value: 'a1b2c3d4e5f6789012345678901234567890abcd',
        threatType: 'malware',
        source: 'internal',
        confidence: 0.9
      },
      {
        type: 'domain',
        value: 'malicious-example.com',
        threatType: 'c2',
        source: 'feed_1',
        confidence: 0.85
      }
    ];

    indicators.forEach((indicator, index) => {
      this.threatIntelligence.set(this.generateId(), {
        ...indicator,
        id: this.generateId(),
        addedAt: new Date().toISOString()
      });
    });

    console.log(`Loaded ${indicators.length} threat indicators`);
  }

  updateThreatIntelligenceCycle() {
    setInterval(async () => {
      try {
        await this.updateThreatIntelligence();
      } catch (error) {
        console.error('Threat intelligence update error:', error);
      }
    }, this.config.threatIntelligence.updateInterval);
  }

  async updateThreatIntelligence() {
    console.log('Updating threat intelligence feeds...');
    
    for (const feed of this.config.threatIntelligence.feeds) {
      if (!feed.enabled) continue;

      try {
        // Simulate feed update
        const newIndicators = Math.floor(Math.random() * 10) + 1;
        
        for (let i = 0; i < newIndicators; i++) {
          const indicator = {
            id: this.generateId(),
            type: ['hash', 'domain', 'ip'][Math.floor(Math.random() * 3)],
            value: `indicator_${this.generateId().substring(0, 16)}`,
            threatType: ['malware', 'c2', 'phishing'][Math.floor(Math.random() * 3)],
            source: feed.name,
            confidence: Math.random() * 0.3 + 0.7,
            addedAt: new Date().toISOString()
          };

          this.threatIntelligence.set(indicator.id, indicator);
        }

        console.log(`Updated ${newIndicators} indicators from ${feed.name}`);
      } catch (error) {
        console.error(`Failed to update feed ${feed.name}:`, error);
      }
    }
  }

  // Analytics helper methods
  getIncidentsResolvedToday() {
    const today = new Date().toDateString();
    return Array.from(this.securityIncidents.values())
      .filter(i => i.status === 'resolved' && new Date(i.updatedAt).toDateString() === today)
      .length;
  }

  calculateAverageResolutionTime() {
    const resolvedIncidents = Array.from(this.securityIncidents.values())
      .filter(i => i.status === 'resolved' && i.resolvedAt);
    
    if (resolvedIncidents.length === 0) return 0;

    const totalTime = resolvedIncidents.reduce((sum, incident) => {
      const created = new Date(incident.createdAt);
      const resolved = new Date(incident.resolvedAt);
      return sum + (resolved - created);
    }, 0);

    return Math.round(totalTime / resolvedIncidents.length / (1000 * 60)); // minutes
  }

  getScansToday() {
    const today = new Date().toDateString();
    return Array.from(this.scanJobs.values())
      .filter(s => new Date(s.createdAt).toDateString() === today)
      .length;
  }

  calculateAverageScanTime() {
    const completedScans = Array.from(this.scanJobs.values())
      .filter(s => s.status === 'completed' && s.startedAt && s.completedAt);
    
    if (completedScans.length === 0) return 0;

    const totalTime = completedScans.reduce((sum, scan) => {
      const started = new Date(scan.startedAt);
      const completed = new Date(scan.completedAt);
      return sum + (completed - started);
    }, 0);

    return Math.round(totalTime / completedScans.length / 1000); // seconds
  }

  calculateDetectionRate() {
    const completedScans = Array.from(this.scanJobs.values())
      .filter(s => s.status === 'completed');
    
    if (completedScans.length === 0) return 0;

    const scansWithThreats = completedScans.filter(s => s.threatsFound > 0).length;
    return Math.round((scansWithThreats / completedScans.length) * 100);
  }

  getLastThreatIntelligenceUpdate() {
    const indicators = Array.from(this.threatIntelligence.values());
    if (indicators.length === 0) return null;

    return indicators
      .map(i => new Date(i.addedAt))
      .reduce((latest, current) => current > latest ? current : latest)
      .toISOString();
  }

  getActiveThreatFeeds() {
    return this.config.threatIntelligence.feeds.filter(f => f.enabled).length;
  }

  getNewIOCsToday() {
    const today = new Date().toDateString();
    return Array.from(this.threatIntelligence.values())
      .filter(i => new Date(i.addedAt).toDateString() === today)
      .length;
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    switch (type) {
      case 'subscribe_threat_alerts':
        ws.subscriptions.add('threat_detected');
        ws.subscriptions.add('device_isolated');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'threat_alerts',
          requestId
        }));
        break;

      case 'subscribe_security_events':
        ws.subscriptions.add('incident_created');
        ws.subscriptions.add('emergency_response');
        ws.subscriptions.add('scan_completed');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'security_events',
          requestId
        }));
        break;

      case 'threat_report':
        if (data.deviceId && data.threatData) {
          await this.processThreatReport(data.deviceId, data.threatData);
          ws.send(JSON.stringify({
            type: 'threat_report_received',
            deviceId: data.deviceId,
            requestId
          }));
        }
        break;

      case 'device_heartbeat':
        if (data.deviceId) {
          const device = this.devices.get(data.deviceId);
          if (device) {
            device.lastSeenAt = new Date().toISOString();
            this.devices.set(data.deviceId, device);
          }

          ws.send(JSON.stringify({
            type: 'heartbeat_ack',
            timestamp: new Date().toISOString(),
            requestId
          }));
        }
        break;

      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: `Unknown message type: ${type}`,
          requestId
        }));
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

  startBackgroundJobs() {
    // Scheduled security scans
    setInterval(async () => {
      try {
        await this.performScheduledScans();
      } catch (error) {
        console.error('Scheduled scan error:', error);
      }
    }, this.config.scanning.scheduledScanInterval);

    // Threat intelligence updates
    setInterval(async () => {
      try {
        await this.updateThreatIntelligence();
      } catch (error) {
        console.error('Threat intelligence update error:', error);
      }
    }, this.config.threatIntelligence.updateInterval);

    // Device health monitoring
    setInterval(() => {
      this.monitorDeviceHealth();
    }, 5 * 60 * 1000); // Every 5 minutes

    // Cleanup old data
    setInterval(() => {
      this.cleanupOldData();
    }, 24 * 60 * 60 * 1000); // Daily
  }

  async performScheduledScans() {
    console.log('Performing scheduled security scans...');
    
    const devicesToScan = Array.from(this.devices.values())
      .filter(device => {
        if (!device.monitoring.nextScanAt) return true;
        return new Date() >= new Date(device.monitoring.nextScanAt);
      });

    for (const device of devicesToScan) {
      const scanId = this.generateId();
      const scanJob = {
        id: scanId,
        type: 'scheduled',
        targets: [{ id: device.id, type: 'device' }],
        priority: 'low',
        scanParameters: { automated: true },
        status: 'queued',
        createdAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        progress: 0,
        results: [],
        threatsFound: 0,
        errors: []
      };

      this.scanJobs.set(scanId, scanJob);
      this.processThreatScan(scanId);

      // Update next scan time
      device.monitoring.nextScanAt = new Date(Date.now() + this.config.scanning.scheduledScanInterval).toISOString();
      this.devices.set(device.id, device);
    }
  }

  monitorDeviceHealth() {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    
    for (const device of this.devices.values()) {
      const lastSeen = new Date(device.lastSeenAt);
      
      if (lastSeen < fiveMinutesAgo && device.securityStatus !== 'offline') {
        device.securityStatus = 'offline';
        this.devices.set(device.id, device);

        this.broadcastToSubscribers('device_offline', {
          deviceId: device.id,
          deviceName: device.name,
          lastSeen: device.lastSeenAt
        });
      }
    }
  }

  cleanupOldData() {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    // Cleanup old scan jobs
    for (const [scanId, scanJob] of this.scanJobs) {
      if (scanJob.completedAt && new Date(scanJob.completedAt) < thirtyDaysAgo) {
        this.scanJobs.delete(scanId);
      }
    }

    // Cleanup resolved incidents
    for (const [incidentId, incident] of this.securityIncidents) {
      if (incident.status === 'resolved' && incident.resolvedAt && new Date(incident.resolvedAt) < thirtyDaysAgo) {
        this.securityIncidents.delete(incidentId);
      }
    }

    console.log('Old data cleanup completed');
  }

  generateHash() {
    return crypto.randomBytes(20).toString('hex');
  }

  generateId() {
    return crypto.randomBytes(16).toString('hex');
  }

  errorHandler(error, req, res, next) {
    console.error('Mobile Threat Defense Service Error:', error, {
      requestId: req.id,
      path: req.path,
      method: req.method,
      stack: error.stack
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: new Date().toISOString(),
      service: 'mobile-threat-defense'
    });
  }

  start(port = process.env.MTD_SERVICE_PORT || 3014) {
    this.server.listen(port, () => {
      console.log(`🛡️  Mobile Threat Defense Service started on port ${port}`);
      console.log(`🔍 Real-time scanning: ${this.config.scanning.realTimeEnabled ? 'Enabled' : 'Disabled'}`);
      console.log(`🧠 ML models: ${Array.from(this.mlModels.keys()).join(', ')}`);
      console.log(`📊 Health check: http://localhost:${port}/health`);
      console.log(`🔌 WebSocket: ws://localhost:${port}/ws/mtd`);
      console.log(`⚠️  Features: Threat Detection, Malware Analysis, Behavior Analysis, Incident Response`);
    });

    return this.server;
  }

  gracefulShutdown() {
    console.log('Starting Mobile Threat Defense Service graceful shutdown...');
    
    this.server.close(() => {
      console.log('Mobile Threat Defense Service HTTP server closed');
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });
      
      console.log('Mobile Threat Defense Service graceful shutdown completed');
      process.exit(0);
    });
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Received SIGINT, starting graceful shutdown...');
  if (global.mtdService) {
    global.mtdService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, starting graceful shutdown...');
  if (global.mtdService) {
    global.mtdService.gracefulShutdown();
  }
});

// Start the service
const mtdService = new MobileThreatDefenseService();
global.mtdService = mtdService;
mtdService.start();

module.exports = MobileThreatDefenseService;