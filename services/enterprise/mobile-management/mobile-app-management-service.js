const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');

/**
 * Enterprise Mobile App Management (MAM) Service
 * Provides comprehensive mobile application management with app-specific policies
 * 
 * Features:
 * - App-specific data protection policies
 * - Conditional access controls
 * - App wrapping and SDK integration
 * - Data leak prevention
 * - App performance monitoring
 * - License management integration
 * - App store management
 * - Custom app distribution
 * - App compliance scanning
 * - Mobile app catalog
 */
class MobileAppManagementService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/mam'
    });
    
    // Configuration
    this.config = {
      appStorageBasePath: process.env.APP_STORAGE_PATH || '/tmp/mam-apps',
      maxAppSize: parseInt(process.env.MAX_APP_SIZE) || 500 * 1024 * 1024, // 500MB
      supportedPlatforms: ['ios', 'android'],
      wrappingService: {
        enabled: process.env.APP_WRAPPING_ENABLED === 'true',
        endpoint: process.env.APP_WRAPPING_ENDPOINT || '',
        apiKey: process.env.APP_WRAPPING_API_KEY || ''
      },
      intune: {
        tenantId: process.env.INTUNE_TENANT_ID || '',
        clientId: process.env.INTUNE_CLIENT_ID || '',
        clientSecret: process.env.INTUNE_CLIENT_SECRET || '',
        enabled: false
      },
      awsS3: {
        bucket: process.env.AWS_S3_BUCKET || '',
        region: process.env.AWS_S3_REGION || 'us-east-1',
        accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || ''
      }
    };
    
    // In-memory storage (replace with database in production)
    this.apps = new Map();
    this.appPolicies = new Map();
    this.appVersions = new Map();
    this.appInstallations = new Map();
    this.appCatalog = new Map();
    this.appCategories = new Map();
    this.dataProtectionPolicies = new Map();
    this.conditionalAccessPolicies = new Map();
    this.appLicenses = new Map();
    this.appUsageStats = new Map();
    this.wrappingJobs = new Map();
    this.appComplianceScans = new Map();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.setupFileStorage();
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
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-ID', 'X-Request-ID', 'X-App-Version'],
      exposedHeaders: ['X-Total-Count', 'X-Request-ID', 'X-Response-Time']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 2000, // Higher limit for app operations
      message: 'Rate limit exceeded for MAM operations',
      standardHeaders: true
    });

    this.app.use('/api/mam', limiter);

    // Body parsing
    this.app.use(express.json({ limit: '100mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '100mb' }));

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

      console.log('MAM WebSocket connection established', {
        connectionId: ws.id,
        deviceId: ws.deviceId
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          console.error('MAM WebSocket message error:', error);
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
        console.log('MAM WebSocket connection closed', { 
          connectionId: ws.id,
          deviceId: ws.deviceId 
        });
      });

      // Send initial connection confirmation
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        service: 'mobile-app-management',
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

  setupFileStorage() {
    // Configure multer for app uploads
    this.upload = multer({
      dest: this.config.appStorageBasePath,
      limits: {
        fileSize: this.config.maxAppSize
      },
      fileFilter: (req, file, cb) => {
        const allowedExtensions = ['.apk', '.ipa', '.msi', '.exe', '.dmg'];
        const ext = path.extname(file.originalname).toLowerCase();
        
        if (allowedExtensions.includes(ext)) {
          cb(null, true);
        } else {
          cb(new Error(`Unsupported file type: ${ext}`), false);
        }
      }
    });
  }

  initializeRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'mobile-app-management-service',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        capabilities: [
          'app-catalog-management',
          'app-policy-enforcement',
          'data-protection-policies',
          'conditional-access',
          'app-wrapping',
          'performance-monitoring',
          'license-management',
          'compliance-scanning',
          'custom-app-distribution'
        ],
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid,
        memory: process.memoryUsage(),
        checks: {
          file_storage: this.checkFileStorageHealth(),
          app_wrapping: this.config.wrappingService.enabled ? 'configured' : 'disabled',
          websocket: this.wss.clients.size >= 0 ? 'healthy' : 'unhealthy'
        },
        statistics: {
          managed_apps: this.apps.size,
          app_policies: this.appPolicies.size,
          app_installations: this.appInstallations.size,
          active_licenses: Array.from(this.appLicenses.values()).filter(l => l.status === 'active').length,
          catalog_entries: this.appCatalog.size
        }
      });
    });

    // App Management Routes
    this.app.get('/api/mam/apps', this.getApps.bind(this));
    this.app.post('/api/mam/apps', this.upload.single('appFile'), this.createApp.bind(this));
    this.app.get('/api/mam/apps/:appId', this.getApp.bind(this));
    this.app.put('/api/mam/apps/:appId', this.updateApp.bind(this));
    this.app.delete('/api/mam/apps/:appId', this.deleteApp.bind(this));
    this.app.post('/api/mam/apps/:appId/versions', this.upload.single('appFile'), this.createAppVersion.bind(this));
    this.app.get('/api/mam/apps/:appId/versions', this.getAppVersions.bind(this));

    // App Installation Routes
    this.app.post('/api/mam/apps/:appId/install', this.installApp.bind(this));
    this.app.post('/api/mam/apps/:appId/uninstall', this.uninstallApp.bind(this));
    this.app.get('/api/mam/installations', this.getInstallations.bind(this));
    this.app.get('/api/mam/installations/:installationId', this.getInstallation.bind(this));
    this.app.put('/api/mam/installations/:installationId/status', this.updateInstallationStatus.bind(this));

    // App Policy Management Routes
    this.app.get('/api/mam/policies', this.getAppPolicies.bind(this));
    this.app.post('/api/mam/policies', this.createAppPolicy.bind(this));
    this.app.get('/api/mam/policies/:policyId', this.getAppPolicy.bind(this));
    this.app.put('/api/mam/policies/:policyId', this.updateAppPolicy.bind(this));
    this.app.delete('/api/mam/policies/:policyId', this.deleteAppPolicy.bind(this));
    this.app.post('/api/mam/policies/:policyId/assign', this.assignAppPolicy.bind(this));

    // Data Protection Policy Routes
    this.app.get('/api/mam/data-protection-policies', this.getDataProtectionPolicies.bind(this));
    this.app.post('/api/mam/data-protection-policies', this.createDataProtectionPolicy.bind(this));
    this.app.put('/api/mam/data-protection-policies/:policyId', this.updateDataProtectionPolicy.bind(this));
    this.app.delete('/api/mam/data-protection-policies/:policyId', this.deleteDataProtectionPolicy.bind(this));

    // Conditional Access Policy Routes
    this.app.get('/api/mam/conditional-access-policies', this.getConditionalAccessPolicies.bind(this));
    this.app.post('/api/mam/conditional-access-policies', this.createConditionalAccessPolicy.bind(this));
    this.app.put('/api/mam/conditional-access-policies/:policyId', this.updateConditionalAccessPolicy.bind(this));
    this.app.delete('/api/mam/conditional-access-policies/:policyId', this.deleteConditionalAccessPolicy.bind(this));

    // App Catalog Routes
    this.app.get('/api/mam/catalog', this.getAppCatalog.bind(this));
    this.app.post('/api/mam/catalog/entries', this.createCatalogEntry.bind(this));
    this.app.put('/api/mam/catalog/entries/:entryId', this.updateCatalogEntry.bind(this));
    this.app.delete('/api/mam/catalog/entries/:entryId', this.deleteCatalogEntry.bind(this));
    this.app.get('/api/mam/catalog/categories', this.getAppCategories.bind(this));
    this.app.post('/api/mam/catalog/categories', this.createAppCategory.bind(this));

    // App Wrapping Routes
    this.app.post('/api/mam/wrapping/jobs', this.createWrappingJob.bind(this));
    this.app.get('/api/mam/wrapping/jobs', this.getWrappingJobs.bind(this));
    this.app.get('/api/mam/wrapping/jobs/:jobId', this.getWrappingJob.bind(this));
    this.app.post('/api/mam/wrapping/jobs/:jobId/cancel', this.cancelWrappingJob.bind(this));

    // License Management Routes
    this.app.get('/api/mam/licenses', this.getAppLicenses.bind(this));
    this.app.post('/api/mam/licenses', this.createAppLicense.bind(this));
    this.app.put('/api/mam/licenses/:licenseId', this.updateAppLicense.bind(this));
    this.app.post('/api/mam/licenses/:licenseId/assign', this.assignLicense.bind(this));
    this.app.post('/api/mam/licenses/:licenseId/revoke', this.revokeLicense.bind(this));

    // Compliance and Security Routes
    this.app.post('/api/mam/compliance/scan', this.startComplianceScan.bind(this));
    this.app.get('/api/mam/compliance/scans', this.getComplianceScans.bind(this));
    this.app.get('/api/mam/compliance/scans/:scanId', this.getComplianceScan.bind(this));
    this.app.get('/api/mam/compliance/violations', this.getComplianceViolations.bind(this));
    this.app.post('/api/mam/compliance/remediate/:violationId', this.remediateViolation.bind(this));

    // Usage Analytics Routes
    this.app.get('/api/mam/analytics/dashboard', this.getAnalyticsDashboard.bind(this));
    this.app.get('/api/mam/analytics/app-usage', this.getAppUsageAnalytics.bind(this));
    this.app.get('/api/mam/analytics/performance', this.getAppPerformanceAnalytics.bind(this));
    this.app.get('/api/mam/analytics/security-insights', this.getSecurityInsights.bind(this));
    this.app.post('/api/mam/analytics/usage-data', this.reportUsageData.bind(this));

    // App Distribution Routes
    this.app.get('/api/mam/distribution/channels', this.getDistributionChannels.bind(this));
    this.app.post('/api/mam/distribution/channels', this.createDistributionChannel.bind(this));
    this.app.post('/api/mam/distribution/:appId/publish', this.publishApp.bind(this));
    this.app.post('/api/mam/distribution/:appId/unpublish', this.unpublishApp.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  // App Management
  async createApp(req, res) {
    try {
      const appData = req.body;
      const appFile = req.file;
      
      if (!appData.name || !appData.platform) {
        return res.status(400).json({
          error: 'Missing required fields: name, platform',
          requestId: req.id
        });
      }

      if (!this.config.supportedPlatforms.includes(appData.platform)) {
        return res.status(400).json({
          error: `Unsupported platform: ${appData.platform}`,
          supportedPlatforms: this.config.supportedPlatforms,
          requestId: req.id
        });
      }

      const appId = this.generateId();
      const app = {
        id: appId,
        name: appData.name,
        description: appData.description || '',
        platform: appData.platform,
        packageName: appData.packageName || '',
        bundleId: appData.bundleId || '',
        version: appData.version || '1.0.0',
        category: appData.category || 'general',
        developer: appData.developer || '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: 'draft',
        isManaged: true,
        size: appFile ? appFile.size : 0,
        downloadCount: 0,
        installCount: 0,
        rating: 0,
        metadata: {
          minOSVersion: appData.minOSVersion || '',
          permissions: appData.permissions || [],
          features: appData.features || [],
          supportedDevices: appData.supportedDevices || [],
          fileHash: appFile ? this.calculateFileHash(appFile.path) : null,
          originalFilename: appFile ? appFile.originalname : null,
          storagePath: appFile ? appFile.path : null
        },
        security: {
          isWrapped: false,
          hasDataProtection: false,
          complianceStatus: 'pending',
          lastScanDate: null,
          securityScore: 0
        }
      };

      this.apps.set(appId, app);

      // If app file uploaded, start analysis
      if (appFile) {
        this.analyzeAppFile(appId, appFile);
      }

      res.status(201).json({
        success: true,
        data: app,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create app error:', error);
      res.status(500).json({
        error: 'Failed to create app',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getApps(req, res) {
    try {
      const {
        page = 1,
        limit = 50,
        search,
        platform,
        category,
        status,
        isManaged,
        sortBy = 'updatedAt',
        sortOrder = 'desc'
      } = req.query;

      let apps = Array.from(this.apps.values());

      // Apply filters
      if (search) {
        apps = apps.filter(app => 
          app.name.toLowerCase().includes(search.toLowerCase()) ||
          app.description.toLowerCase().includes(search.toLowerCase()) ||
          app.developer.toLowerCase().includes(search.toLowerCase())
        );
      }

      if (platform) {
        apps = apps.filter(app => app.platform === platform);
      }

      if (category) {
        apps = apps.filter(app => app.category === category);
      }

      if (status) {
        apps = apps.filter(app => app.status === status);
      }

      if (isManaged !== undefined) {
        apps = apps.filter(app => app.isManaged === (isManaged === 'true'));
      }

      // Apply sorting
      apps.sort((a, b) => {
        const aVal = a[sortBy];
        const bVal = b[sortBy];
        
        if (sortOrder === 'desc') {
          return bVal > aVal ? 1 : -1;
        } else {
          return aVal > bVal ? 1 : -1;
        }
      });

      // Apply pagination
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + limit;
      const paginatedApps = apps.slice(startIndex, endIndex);

      res.json({
        success: true,
        data: paginatedApps,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: apps.length,
          pages: Math.ceil(apps.length / limit)
        },
        requestId: req.id
      });
    } catch (error) {
      console.error('Get apps error:', error);
      res.status(500).json({
        error: 'Failed to retrieve apps',
        requestId: req.id
      });
    }
  }

  // App Installation Management
  async installApp(req, res) {
    try {
      const { appId } = req.params;
      const { deviceIds, userIds, installParameters = {} } = req.body;
      
      const app = this.apps.get(appId);
      if (!app) {
        return res.status(404).json({
          error: 'App not found',
          requestId: req.id
        });
      }

      if (!deviceIds || !Array.isArray(deviceIds) || deviceIds.length === 0) {
        return res.status(400).json({
          error: 'deviceIds array is required',
          requestId: req.id
        });
      }

      const installations = [];
      
      for (const deviceId of deviceIds) {
        const installationId = this.generateId();
        const installation = {
          id: installationId,
          appId,
          appName: app.name,
          appVersion: app.version,
          deviceId,
          userId: userIds ? userIds[deviceIds.indexOf(deviceId)] : null,
          status: 'pending',
          installParameters,
          requestedAt: new Date().toISOString(),
          installedAt: null,
          lastStatusUpdate: new Date().toISOString(),
          progress: 0,
          errorMessage: null,
          installSize: app.size
        };

        this.appInstallations.set(installationId, installation);
        installations.push(installation);

        // Simulate installation process
        this.simulateAppInstallation(installationId);
      }

      // Update app install count
      app.installCount += deviceIds.length;
      this.apps.set(appId, app);

      res.json({
        success: true,
        data: installations,
        requestId: req.id
      });
    } catch (error) {
      console.error('Install app error:', error);
      res.status(500).json({
        error: 'Failed to install app',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // App Policy Management
  async createAppPolicy(req, res) {
    try {
      const policyData = req.body;
      
      if (!policyData.name || !policyData.type) {
        return res.status(400).json({
          error: 'Missing required fields: name, type',
          requestId: req.id
        });
      }

      const policyId = this.generateId();
      const policy = {
        id: policyId,
        name: policyData.name,
        description: policyData.description || '',
        type: policyData.type, // 'data-protection', 'conditional-access', 'app-configuration'
        platform: policyData.platform || 'all',
        rules: policyData.rules || [],
        settings: policyData.settings || {},
        enforcement: policyData.enforcement || 'warn', // 'block', 'warn', 'allow'
        scope: policyData.scope || 'all-apps', // 'all-apps', 'selected-apps'
        targetApps: policyData.targetApps || [],
        targetGroups: policyData.targetGroups || [],
        isActive: policyData.isActive !== false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        appliedCount: 0
      };

      this.appPolicies.set(policyId, policy);

      res.status(201).json({
        success: true,
        data: policy,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create app policy error:', error);
      res.status(500).json({
        error: 'Failed to create app policy',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Data Protection Policies
  async createDataProtectionPolicy(req, res) {
    try {
      const policyData = req.body;
      
      if (!policyData.name) {
        return res.status(400).json({
          error: 'Missing required field: name',
          requestId: req.id
        });
      }

      const policyId = this.generateId();
      const policy = {
        id: policyId,
        name: policyData.name,
        description: policyData.description || '',
        platform: policyData.platform || 'all',
        dataProtectionRules: {
          encryptionRequired: policyData.encryptionRequired || true,
          preventDataBackup: policyData.preventDataBackup || false,
          preventScreenCapture: policyData.preventScreenCapture || false,
          preventCopyPaste: policyData.preventCopyPaste || false,
          watermarkText: policyData.watermarkText || '',
          allowedDataSharing: policyData.allowedDataSharing || [],
          blockedDataSharing: policyData.blockedDataSharing || []
        },
        accessControls: {
          requirePinOrBiometric: policyData.requirePinOrBiometric || true,
          pinComplexity: policyData.pinComplexity || 'medium',
          sessionTimeout: policyData.sessionTimeout || 30, // minutes
          maxFailedAttempts: policyData.maxFailedAttempts || 5,
          wipeDataAfterFailures: policyData.wipeDataAfterFailures || true
        },
        networkControls: {
          preventOpenWifi: policyData.preventOpenWifi || true,
          allowedNetworks: policyData.allowedNetworks || [],
          blockedNetworks: policyData.blockedNetworks || [],
          vpnRequired: policyData.vpnRequired || false
        },
        targetApps: policyData.targetApps || [],
        isActive: policyData.isActive !== false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        appliedDevices: 0
      };

      this.dataProtectionPolicies.set(policyId, policy);

      res.status(201).json({
        success: true,
        data: policy,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create data protection policy error:', error);
      res.status(500).json({
        error: 'Failed to create data protection policy',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // App Wrapping
  async createWrappingJob(req, res) {
    try {
      const { appId, wrappingParameters = {} } = req.body;
      
      if (!appId) {
        return res.status(400).json({
          error: 'Missing required field: appId',
          requestId: req.id
        });
      }

      const app = this.apps.get(appId);
      if (!app) {
        return res.status(404).json({
          error: 'App not found',
          requestId: req.id
        });
      }

      if (!this.config.wrappingService.enabled) {
        return res.status(400).json({
          error: 'App wrapping service is not enabled',
          requestId: req.id
        });
      }

      const jobId = this.generateId();
      const wrappingJob = {
        id: jobId,
        appId,
        appName: app.name,
        appVersion: app.version,
        status: 'queued',
        wrappingParameters: {
          enableDataProtection: wrappingParameters.enableDataProtection || true,
          enableThreatDetection: wrappingParameters.enableThreatDetection || true,
          enableAnalytics: wrappingParameters.enableAnalytics || false,
          customPolicies: wrappingParameters.customPolicies || [],
          ...wrappingParameters
        },
        createdAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        progress: 0,
        logs: [],
        outputAppPath: null,
        errorMessage: null
      };

      this.wrappingJobs.set(jobId, wrappingJob);

      // Start wrapping process
      this.processAppWrapping(jobId);

      res.status(201).json({
        success: true,
        data: wrappingJob,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create wrapping job error:', error);
      res.status(500).json({
        error: 'Failed to create app wrapping job',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Compliance Scanning
  async startComplianceScan(req, res) {
    try {
      const { appIds, scanType = 'security', scanParameters = {} } = req.body;
      
      if (!appIds || !Array.isArray(appIds) || appIds.length === 0) {
        return res.status(400).json({
          error: 'appIds array is required',
          requestId: req.id
        });
      }

      const scanId = this.generateId();
      const scan = {
        id: scanId,
        type: scanType,
        appIds,
        scanParameters,
        status: 'running',
        startedAt: new Date().toISOString(),
        completedAt: null,
        progress: 0,
        results: [],
        summary: {
          totalApps: appIds.length,
          passedApps: 0,
          failedApps: 0,
          criticalIssues: 0,
          warnings: 0
        }
      };

      this.appComplianceScans.set(scanId, scan);

      // Start compliance scanning
      this.performComplianceScan(scanId);

      res.status(201).json({
        success: true,
        data: scan,
        requestId: req.id
      });
    } catch (error) {
      console.error('Start compliance scan error:', error);
      res.status(500).json({
        error: 'Failed to start compliance scan',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Analytics
  async getAnalyticsDashboard(req, res) {
    try {
      const dashboard = {
        overview: {
          totalApps: this.apps.size,
          managedApps: Array.from(this.apps.values()).filter(a => a.isManaged).length,
          activeInstallations: Array.from(this.appInstallations.values()).filter(i => i.status === 'installed').length,
          pendingInstallations: Array.from(this.appInstallations.values()).filter(i => i.status === 'pending').length
        },
        policies: {
          totalPolicies: this.appPolicies.size,
          activePolicies: Array.from(this.appPolicies.values()).filter(p => p.isActive).length,
          dataProtectionPolicies: this.dataProtectionPolicies.size,
          conditionalAccessPolicies: this.conditionalAccessPolicies.size
        },
        security: {
          wrappedApps: Array.from(this.apps.values()).filter(a => a.security.isWrapped).length,
          protectedApps: Array.from(this.apps.values()).filter(a => a.security.hasDataProtection).length,
          complianceViolations: this.countComplianceViolations(),
          averageSecurityScore: this.calculateAverageSecurityScore()
        },
        usage: {
          totalDownloads: Array.from(this.apps.values()).reduce((sum, a) => sum + a.downloadCount, 0),
          totalInstalls: Array.from(this.apps.values()).reduce((sum, a) => sum + a.installCount, 0),
          activeUsers: this.countActiveUsers(),
          topApps: this.getTopApps(5)
        },
        licenses: {
          totalLicenses: this.appLicenses.size,
          activeLicenses: Array.from(this.appLicenses.values()).filter(l => l.status === 'active').length,
          expiringSoon: this.countExpiringLicenses(),
          utilizationRate: this.calculateLicenseUtilization()
        }
      };

      res.json({
        success: true,
        data: dashboard,
        requestId: req.id
      });
    } catch (error) {
      console.error('Analytics dashboard error:', error);
      res.status(500).json({
        error: 'Failed to get analytics dashboard',
        requestId: req.id
      });
    }
  }

  // Helper Methods
  async simulateAppInstallation(installationId) {
    const installation = this.appInstallations.get(installationId);
    if (!installation) return;

    const progressSteps = [10, 25, 50, 75, 90, 100];
    let stepIndex = 0;

    const updateProgress = () => {
      if (stepIndex < progressSteps.length) {
        installation.progress = progressSteps[stepIndex];
        installation.lastStatusUpdate = new Date().toISOString();

        if (installation.progress === 100) {
          installation.status = 'installed';
          installation.installedAt = new Date().toISOString();
          
          this.broadcastToSubscribers('app_installed', {
            installationId,
            appId: installation.appId,
            deviceId: installation.deviceId,
            status: installation.status
          });
        } else {
          this.broadcastToSubscribers('installation_progress', {
            installationId,
            progress: installation.progress
          });
        }

        this.appInstallations.set(installationId, installation);
        stepIndex++;

        if (stepIndex < progressSteps.length) {
          setTimeout(updateProgress, Math.random() * 2000 + 1000); // 1-3 seconds
        }
      }
    };

    // Start installation simulation
    setTimeout(() => {
      installation.status = 'installing';
      installation.lastStatusUpdate = new Date().toISOString();
      this.appInstallations.set(installationId, installation);
      updateProgress();
    }, 1000);
  }

  async processAppWrapping(jobId) {
    const job = this.wrappingJobs.get(jobId);
    if (!job) return;

    try {
      job.status = 'processing';
      job.startedAt = new Date().toISOString();
      job.logs.push(`[${new Date().toISOString()}] Starting app wrapping process`);

      // Simulate wrapping process with progress updates
      const steps = [
        { progress: 10, message: 'Analyzing app structure' },
        { progress: 25, message: 'Extracting app components' },
        { progress: 40, message: 'Injecting security policies' },
        { progress: 60, message: 'Adding data protection layer' },
        { progress: 80, message: 'Rebuilding app package' },
        { progress: 95, message: 'Signing wrapped app' },
        { progress: 100, message: 'App wrapping completed' }
      ];

      for (const step of steps) {
        await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 1000));
        
        job.progress = step.progress;
        job.logs.push(`[${new Date().toISOString()}] ${step.message}`);
        
        this.broadcastToSubscribers('wrapping_progress', {
          jobId,
          progress: job.progress,
          message: step.message
        });

        this.wrappingJobs.set(jobId, job);
      }

      job.status = 'completed';
      job.completedAt = new Date().toISOString();
      job.outputAppPath = `/wrapped-apps/${job.appId}_wrapped.apk`;

      // Update original app
      const app = this.apps.get(job.appId);
      if (app) {
        app.security.isWrapped = true;
        app.security.hasDataProtection = true;
        app.security.securityScore = Math.floor(Math.random() * 30) + 70; // 70-100
        this.apps.set(job.appId, app);
      }

      this.broadcastToSubscribers('wrapping_completed', {
        jobId,
        appId: job.appId,
        status: job.status,
        outputPath: job.outputAppPath
      });

    } catch (error) {
      job.status = 'failed';
      job.errorMessage = error.message;
      job.logs.push(`[${new Date().toISOString()}] ERROR: ${error.message}`);
      
      this.broadcastToSubscribers('wrapping_failed', {
        jobId,
        appId: job.appId,
        error: error.message
      });
    }

    this.wrappingJobs.set(jobId, job);
  }

  async performComplianceScan(scanId) {
    const scan = this.appComplianceScans.get(scanId);
    if (!scan) return;

    try {
      const totalApps = scan.appIds.length;
      let processedApps = 0;

      for (const appId of scan.appIds) {
        const app = this.apps.get(appId);
        if (!app) continue;

        // Simulate app compliance check
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));

        const complianceResult = {
          appId,
          appName: app.name,
          status: Math.random() > 0.3 ? 'passed' : 'failed',
          issues: [],
          warnings: [],
          scannedAt: new Date().toISOString()
        };

        if (complianceResult.status === 'failed') {
          complianceResult.issues = [
            {
              severity: 'critical',
              type: 'security_vulnerability',
              description: 'App contains known security vulnerability',
              recommendation: 'Update app to latest version'
            },
            {
              severity: 'medium',
              type: 'privacy_issue',
              description: 'App accesses sensitive data without proper justification',
              recommendation: 'Review app permissions and privacy policy'
            }
          ];
        }

        if (Math.random() > 0.7) {
          complianceResult.warnings = [
            {
              type: 'outdated_dependency',
              description: 'App uses outdated library versions',
              recommendation: 'Update dependencies to latest secure versions'
            }
          ];
        }

        scan.results.push(complianceResult);
        
        // Update summary
        if (complianceResult.status === 'passed') {
          scan.summary.passedApps++;
        } else {
          scan.summary.failedApps++;
        }
        
        scan.summary.criticalIssues += complianceResult.issues.filter(i => i.severity === 'critical').length;
        scan.summary.warnings += complianceResult.warnings.length;

        processedApps++;
        scan.progress = Math.floor((processedApps / totalApps) * 100);

        this.broadcastToSubscribers('scan_progress', {
          scanId,
          progress: scan.progress,
          processedApps,
          totalApps
        });

        this.appComplianceScans.set(scanId, scan);
      }

      scan.status = 'completed';
      scan.completedAt = new Date().toISOString();

      this.broadcastToSubscribers('scan_completed', {
        scanId,
        summary: scan.summary,
        totalIssues: scan.summary.criticalIssues + scan.summary.warnings
      });

    } catch (error) {
      scan.status = 'failed';
      scan.errorMessage = error.message;
      
      this.broadcastToSubscribers('scan_failed', {
        scanId,
        error: error.message
      });
    }

    this.appComplianceScans.set(scanId, scan);
  }

  calculateFileHash(filePath) {
    // Simulate file hash calculation
    return crypto.randomBytes(32).toString('hex');
  }

  async analyzeAppFile(appId, appFile) {
    // Simulate app file analysis
    setTimeout(() => {
      const app = this.apps.get(appId);
      if (app) {
        app.status = 'analyzed';
        app.metadata.fileHash = this.calculateFileHash(appFile.path);
        app.security.lastScanDate = new Date().toISOString();
        app.security.securityScore = Math.floor(Math.random() * 40) + 50; // 50-90
        this.apps.set(appId, app);

        this.broadcastToSubscribers('app_analyzed', {
          appId,
          securityScore: app.security.securityScore,
          status: app.status
        });
      }
    }, 3000);
  }

  countComplianceViolations() {
    return Array.from(this.appComplianceScans.values())
      .flatMap(scan => scan.results || [])
      .filter(result => result.status === 'failed').length;
  }

  calculateAverageSecurityScore() {
    const apps = Array.from(this.apps.values()).filter(a => a.security.securityScore > 0);
    if (apps.length === 0) return 0;

    const totalScore = apps.reduce((sum, app) => sum + app.security.securityScore, 0);
    return Math.round((totalScore / apps.length) * 100) / 100;
  }

  countActiveUsers() {
    const uniqueUsers = new Set();
    for (const installation of this.appInstallations.values()) {
      if (installation.userId && installation.status === 'installed') {
        uniqueUsers.add(installation.userId);
      }
    }
    return uniqueUsers.size;
  }

  getTopApps(limit) {
    return Array.from(this.apps.values())
      .sort((a, b) => b.installCount - a.installCount)
      .slice(0, limit)
      .map(app => ({
        id: app.id,
        name: app.name,
        installCount: app.installCount,
        platform: app.platform
      }));
  }

  countExpiringLicenses() {
    const thirtyDaysFromNow = new Date();
    thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);

    return Array.from(this.appLicenses.values())
      .filter(license => 
        license.expiresAt && 
        new Date(license.expiresAt) <= thirtyDaysFromNow &&
        license.status === 'active'
      ).length;
  }

  calculateLicenseUtilization() {
    const activeLicenses = Array.from(this.appLicenses.values())
      .filter(l => l.status === 'active');
    
    if (activeLicenses.length === 0) return 0;

    const totalSeats = activeLicenses.reduce((sum, l) => sum + (l.totalSeats || 0), 0);
    const usedSeats = activeLicenses.reduce((sum, l) => sum + (l.usedSeats || 0), 0);

    return totalSeats > 0 ? Math.round((usedSeats / totalSeats) * 100) : 0;
  }

  checkFileStorageHealth() {
    try {
      require('fs').accessSync(this.config.appStorageBasePath);
      return 'healthy';
    } catch (error) {
      return 'unhealthy';
    }
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    switch (type) {
      case 'subscribe_mam_events':
        ws.subscriptions.add('mam_events');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'mam_events',
          requestId
        }));
        break;

      case 'subscribe_app_installations':
        ws.subscriptions.add('app_installed');
        ws.subscriptions.add('installation_progress');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'app_installations',
          requestId
        }));
        break;

      case 'subscribe_compliance_events':
        ws.subscriptions.add('scan_progress');
        ws.subscriptions.add('scan_completed');
        ws.subscriptions.add('scan_failed');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'compliance_events',
          requestId
        }));
        break;

      case 'app_usage_report':
        if (data.appId && data.usageData) {
          await this.recordAppUsage(data.appId, data.usageData);
          ws.send(JSON.stringify({
            type: 'usage_recorded',
            appId: data.appId,
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
    // License expiration check - daily
    setInterval(() => {
      this.checkLicenseExpirations();
    }, 24 * 60 * 60 * 1000);

    // App security scan - weekly
    setInterval(() => {
      this.performRoutineSecurityScan();
    }, 7 * 24 * 60 * 60 * 1000);

    // Usage analytics aggregation - hourly
    setInterval(() => {
      this.aggregateUsageAnalytics();
    }, 60 * 60 * 1000);

    // Cleanup old jobs - daily
    setInterval(() => {
      this.cleanupOldJobs();
    }, 24 * 60 * 60 * 1000);
  }

  async checkLicenseExpirations() {
    console.log('Checking for license expirations...');
    
    const expiringLicenses = Array.from(this.appLicenses.values())
      .filter(license => {
        if (!license.expiresAt || license.status !== 'active') return false;
        
        const expiryDate = new Date(license.expiresAt);
        const warningDate = new Date();
        warningDate.setDate(warningDate.getDate() + 30); // 30 days warning
        
        return expiryDate <= warningDate;
      });

    for (const license of expiringLicenses) {
      this.broadcastToSubscribers('license_expiring', {
        licenseId: license.id,
        appName: license.appName,
        expiresAt: license.expiresAt,
        daysUntilExpiry: Math.ceil((new Date(license.expiresAt) - new Date()) / (1000 * 60 * 60 * 24))
      });
    }
  }

  async performRoutineSecurityScan() {
    console.log('Performing routine security scan...');
    
    const unscannedApps = Array.from(this.apps.values())
      .filter(app => {
        if (!app.security.lastScanDate) return true;
        
        const lastScan = new Date(app.security.lastScanDate);
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        
        return lastScan < weekAgo;
      });

    if (unscannedApps.length > 0) {
      const scanId = this.generateId();
      const scan = {
        id: scanId,
        type: 'routine_security',
        appIds: unscannedApps.map(app => app.id),
        scanParameters: { automated: true },
        status: 'running',
        startedAt: new Date().toISOString(),
        completedAt: null,
        progress: 0,
        results: [],
        summary: {
          totalApps: unscannedApps.length,
          passedApps: 0,
          failedApps: 0,
          criticalIssues: 0,
          warnings: 0
        }
      };

      this.appComplianceScans.set(scanId, scan);
      this.performComplianceScan(scanId);
    }
  }

  aggregateUsageAnalytics() {
    console.log('Aggregating usage analytics...');
    // Implementation for usage analytics aggregation
  }

  cleanupOldJobs() {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    // Cleanup old wrapping jobs
    for (const [jobId, job] of this.wrappingJobs) {
      if (job.completedAt && new Date(job.completedAt) < thirtyDaysAgo) {
        this.wrappingJobs.delete(jobId);
      }
    }

    // Cleanup old compliance scans
    for (const [scanId, scan] of this.appComplianceScans) {
      if (scan.completedAt && new Date(scan.completedAt) < thirtyDaysAgo) {
        this.appComplianceScans.delete(scanId);
      }
    }

    console.log('Old jobs cleanup completed');
  }

  generateId() {
    return crypto.randomBytes(16).toString('hex');
  }

  errorHandler(error, req, res, next) {
    console.error('Mobile App Management Service Error:', error, {
      requestId: req.id,
      path: req.path,
      method: req.method,
      stack: error.stack
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: new Date().toISOString(),
      service: 'mobile-app-management'
    });
  }

  start(port = process.env.MAM_SERVICE_PORT || 3013) {
    this.server.listen(port, () => {
      console.log(`📱 Mobile App Management Service started on port ${port}`);
      console.log(`🛡️  App wrapping: ${this.config.wrappingService.enabled ? 'Enabled' : 'Disabled'}`);
      console.log(`☁️  Cloud storage: ${this.config.awsS3.bucket ? 'Configured' : 'Local only'}`);
      console.log(`📊 Health check: http://localhost:${port}/health`);
      console.log(`🔌 WebSocket: ws://localhost:${port}/ws/mam`);
      console.log(`⚙️  Features: App Policies, Data Protection, Wrapping, Compliance`);
    });

    return this.server;
  }

  gracefulShutdown() {
    console.log('Starting Mobile App Management Service graceful shutdown...');
    
    this.server.close(() => {
      console.log('Mobile App Management Service HTTP server closed');
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });
      
      console.log('Mobile App Management Service graceful shutdown completed');
      process.exit(0);
    });
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Received SIGINT, starting graceful shutdown...');
  if (global.mamService) {
    global.mamService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, starting graceful shutdown...');
  if (global.mamService) {
    global.mamService.gracefulShutdown();
  }
});

// Start the service
const mamService = new MobileAppManagementService();
global.mamService = mamService;
mamService.start();

module.exports = MobileAppManagementService;