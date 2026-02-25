const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const cron = require('node-cron');
const moment = require('moment');
const axios = require('axios');
const winston = require('winston');

/**
 * Enterprise License Management Service
 * Comprehensive software license tracking, compliance monitoring, and optimization
 * 
 * Features:
 * - Software License Tracking (all license types)
 * - License Compliance Monitoring with automated violation detection
 * - License Optimization with cost analysis and recommendations
 * - Software Asset Management with inventory and lifecycle tracking
 * - Real-time license usage tracking and alerts
 * - Integration with mobile app licenses
 * - Comprehensive audit and reporting capabilities
 * - Cost optimization and recommendation engine
 */
class LicenseManagementService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/license'
    });
    
    // Configuration
    this.config = {
      servicePort: process.env.LICENSE_SERVICE_PORT || 3018,
      databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost/opendirectory_licenses',
      mobileManagementServiceUrl: process.env.MOBILE_SERVICE_URL || 'http://mobile-management:3013',
      alertingEnabled: process.env.ALERTING_ENABLED === 'true',
      emailConfig: {
        smtp: {
          host: process.env.SMTP_HOST || 'localhost',
          port: process.env.SMTP_PORT || 587,
          user: process.env.SMTP_USER || '',
          password: process.env.SMTP_PASSWORD || ''
        }
      },
      compliance: {
        autoRemediation: process.env.AUTO_REMEDIATION === 'true',
        alertThresholds: {
          utilization: parseInt(process.env.UTILIZATION_THRESHOLD) || 85,
          expiry: parseInt(process.env.EXPIRY_WARNING_DAYS) || 30,
          overusage: parseInt(process.env.OVERUSAGE_THRESHOLD) || 5
        }
      }
    };
    
    // Initialize logger
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'license-management' },
      transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ]
    });
    
    // In-memory storage (replace with database in production)
    this.licenses = new Map();
    this.licenseTypes = new Map();
    this.software = new Map();
    this.vendors = new Map();
    this.installations = new Map();
    this.usage = new Map();
    this.compliance = new Map();
    this.violations = new Map();
    this.alerts = new Map();
    this.reports = new Map();
    this.optimizations = new Map();
    this.auditLogs = new Map();
    this.renewals = new Map();
    this.contracts = new Map();
    this.costCenters = new Map();
    this.assetInventory = new Map();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeLicenseTypes();
    this.initializeVendors();
    this.setupScheduledJobs();
    this.startBackgroundServices();
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
    this.app.use(compression());

    // CORS
    this.app.use(cors({
      origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 1000, // Limit each IP to 1000 requests per windowMs
      message: 'Rate limit exceeded for license management operations',
      standardHeaders: true
    });

    this.app.use('/api/license', limiter);

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request ID middleware
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || uuidv4();
      res.setHeader('X-Request-ID', req.id);
      next();
    });

    // Logging middleware
    this.app.use((req, res, next) => {
      this.logger.info('Request received', {
        requestId: req.id,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
      next();
    });
  }

  initializeWebSocket() {
    this.wss.on('connection', (ws, req) => {
      ws.id = uuidv4();
      ws.subscriptions = new Set();
      ws.isAlive = true;

      this.logger.info('WebSocket connection established', {
        connectionId: ws.id,
        ip: req.socket.remoteAddress
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          this.logger.error('WebSocket message error', { error: error.message });
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
        this.logger.info('WebSocket connection closed', { connectionId: ws.id });
      });

      ws.on('error', (error) => {
        this.logger.error('WebSocket error', { connectionId: ws.id, error: error.message });
      });

      // Send initial connection confirmation
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        service: 'license-management',
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
        service: 'license-management-service',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        capabilities: [
          'software-license-tracking',
          'license-compliance-monitoring',
          'license-optimization',
          'software-asset-management',
          'real-time-usage-tracking',
          'mobile-license-integration',
          'audit-reporting',
          'cost-analysis',
          'renewal-management'
        ],
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid,
        memory: process.memoryUsage(),
        statistics: {
          total_licenses: this.licenses.size,
          active_licenses: Array.from(this.licenses.values()).filter(l => l.status === 'active').length,
          software_items: this.software.size,
          compliance_violations: this.violations.size,
          pending_renewals: Array.from(this.renewals.values()).filter(r => r.status === 'pending').length
        }
      });
    });

    // License Management Routes
    this.app.get('/api/license/licenses', this.getLicenses.bind(this));
    this.app.post('/api/license/licenses', this.createLicense.bind(this));
    this.app.get('/api/license/licenses/:licenseId', this.getLicense.bind(this));
    this.app.put('/api/license/licenses/:licenseId', this.updateLicense.bind(this));
    this.app.delete('/api/license/licenses/:licenseId', this.deleteLicense.bind(this));
    this.app.post('/api/license/licenses/:licenseId/assign', this.assignLicense.bind(this));
    this.app.post('/api/license/licenses/:licenseId/revoke', this.revokeLicense.bind(this));
    this.app.post('/api/license/licenses/:licenseId/renew', this.renewLicense.bind(this));

    // License Types Management
    this.app.get('/api/license/types', this.getLicenseTypes.bind(this));
    this.app.post('/api/license/types', this.createLicenseType.bind(this));
    this.app.put('/api/license/types/:typeId', this.updateLicenseType.bind(this));
    this.app.delete('/api/license/types/:typeId', this.deleteLicenseType.bind(this));

    // Software Management Routes
    this.app.get('/api/license/software', this.getSoftware.bind(this));
    this.app.post('/api/license/software', this.createSoftware.bind(this));
    this.app.get('/api/license/software/:softwareId', this.getSoftwareDetails.bind(this));
    this.app.put('/api/license/software/:softwareId', this.updateSoftware.bind(this));
    this.app.delete('/api/license/software/:softwareId', this.deleteSoftware.bind(this));

    // Vendor Management Routes
    this.app.get('/api/license/vendors', this.getVendors.bind(this));
    this.app.post('/api/license/vendors', this.createVendor.bind(this));
    this.app.put('/api/license/vendors/:vendorId', this.updateVendor.bind(this));
    this.app.delete('/api/license/vendors/:vendorId', this.deleteVendor.bind(this));

    // Usage Tracking Routes
    this.app.get('/api/license/usage', this.getUsage.bind(this));
    this.app.post('/api/license/usage/track', this.trackUsage.bind(this));
    this.app.get('/api/license/usage/:licenseId', this.getLicenseUsage.bind(this));
    this.app.get('/api/license/usage/software/:softwareId', this.getSoftwareUsage.bind(this));

    // Compliance Monitoring Routes
    this.app.get('/api/license/compliance/overview', this.getComplianceOverview.bind(this));
    this.app.post('/api/license/compliance/scan', this.startComplianceScan.bind(this));
    this.app.get('/api/license/compliance/scans', this.getComplianceScans.bind(this));
    this.app.get('/api/license/compliance/violations', this.getViolations.bind(this));
    this.app.post('/api/license/compliance/violations/:violationId/resolve', this.resolveViolation.bind(this));
    this.app.get('/api/license/compliance/reports', this.getComplianceReports.bind(this));

    // Optimization Routes
    this.app.get('/api/license/optimization/recommendations', this.getOptimizationRecommendations.bind(this));
    this.app.post('/api/license/optimization/analyze', this.analyzeOptimization.bind(this));
    this.app.get('/api/license/optimization/cost-analysis', this.getCostAnalysis.bind(this));
    this.app.get('/api/license/optimization/utilization', this.getUtilizationAnalysis.bind(this));

    // Asset Management Routes
    this.app.get('/api/license/assets', this.getAssets.bind(this));
    this.app.post('/api/license/assets/discovery', this.startAssetDiscovery.bind(this));
    this.app.get('/api/license/assets/:assetId', this.getAsset.bind(this));
    this.app.put('/api/license/assets/:assetId', this.updateAsset.bind(this));
    this.app.post('/api/license/assets/:assetId/retire', this.retireAsset.bind(this));

    // Mobile Integration Routes
    this.app.get('/api/license/mobile/sync', this.syncMobileLicenses.bind(this));
    this.app.post('/api/license/mobile/track', this.trackMobileUsage.bind(this));
    this.app.get('/api/license/mobile/compliance', this.getMobileCompliance.bind(this));

    // Reporting Routes
    this.app.get('/api/license/reports', this.getReports.bind(this));
    this.app.post('/api/license/reports/generate', this.generateReport.bind(this));
    this.app.get('/api/license/reports/:reportId', this.getReport.bind(this));
    this.app.get('/api/license/reports/:reportId/download', this.downloadReport.bind(this));

    // Dashboard Routes
    this.app.get('/api/license/dashboard', this.getDashboard.bind(this));
    this.app.get('/api/license/dashboard/metrics', this.getDashboardMetrics.bind(this));
    this.app.get('/api/license/dashboard/alerts', this.getDashboardAlerts.bind(this));

    // Audit Routes
    this.app.get('/api/license/audit/logs', this.getAuditLogs.bind(this));
    this.app.post('/api/license/audit/export', this.exportAuditLogs.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  initializeLicenseTypes() {
    // Perpetual Licenses
    this.licenseTypes.set('perpetual', {
      id: 'perpetual',
      name: 'Perpetual License',
      description: 'One-time purchase with permanent usage rights',
      category: 'perpetual',
      features: ['permanent_usage', 'no_expiry', 'upgrade_options'],
      defaultTerms: {
        duration: null,
        renewable: false,
        transferable: true,
        concurrent: false
      }
    });

    // Subscription Licenses
    this.licenseTypes.set('subscription', {
      id: 'subscription',
      name: 'Subscription License',
      description: 'Recurring payment model with time-limited usage',
      category: 'subscription',
      features: ['time_limited', 'auto_renewal', 'cloud_based'],
      defaultTerms: {
        duration: 12, // months
        renewable: true,
        transferable: false,
        concurrent: false
      }
    });

    // Concurrent/Floating Licenses
    this.licenseTypes.set('concurrent', {
      id: 'concurrent',
      name: 'Concurrent License',
      description: 'Floating license pool with concurrent usage limits',
      category: 'concurrent',
      features: ['floating_pool', 'concurrent_users', 'check_in_out'],
      defaultTerms: {
        duration: 12,
        renewable: true,
        transferable: false,
        concurrent: true
      }
    });

    // Per-Device Licenses
    this.licenseTypes.set('per_device', {
      id: 'per_device',
      name: 'Per-Device License',
      description: 'License tied to specific device or hardware',
      category: 'device_based',
      features: ['device_locked', 'hardware_binding', 'mobile_support'],
      defaultTerms: {
        duration: 12,
        renewable: true,
        transferable: false,
        concurrent: false
      }
    });

    // Open Source Licenses
    this.licenseTypes.set('open_source', {
      id: 'open_source',
      name: 'Open Source License',
      description: 'Open source software with specific license terms',
      category: 'open_source',
      features: ['free_usage', 'source_code_access', 'distribution_rights'],
      defaultTerms: {
        duration: null,
        renewable: false,
        transferable: true,
        concurrent: false
      }
    });

    // Cloud Service Licenses
    this.licenseTypes.set('cloud_service', {
      id: 'cloud_service',
      name: 'Cloud Service License',
      description: 'Cloud-based service with usage-based billing',
      category: 'cloud',
      features: ['usage_based', 'scalable', 'cloud_native'],
      defaultTerms: {
        duration: 1, // month
        renewable: true,
        transferable: false,
        concurrent: false
      }
    });
  }

  initializeVendors() {
    // Microsoft
    this.vendors.set('microsoft', {
      id: 'microsoft',
      name: 'Microsoft Corporation',
      description: 'Software and cloud services provider',
      website: 'https://www.microsoft.com',
      supportContact: {
        email: 'support@microsoft.com',
        phone: '+1-800-642-7676'
      },
      products: ['Windows', 'Office', 'Azure', 'SQL Server', 'Exchange'],
      licenseTypes: ['subscription', 'perpetual', 'cloud_service']
    });

    // Adobe
    this.vendors.set('adobe', {
      id: 'adobe',
      name: 'Adobe Inc.',
      description: 'Creative software and digital media solutions',
      website: 'https://www.adobe.com',
      supportContact: {
        email: 'support@adobe.com',
        phone: '+1-800-833-6687'
      },
      products: ['Creative Cloud', 'Acrobat', 'Photoshop', 'Illustrator'],
      licenseTypes: ['subscription', 'perpetual']
    });

    // Autodesk
    this.vendors.set('autodesk', {
      id: 'autodesk',
      name: 'Autodesk, Inc.',
      description: '3D design, engineering and entertainment software',
      website: 'https://www.autodesk.com',
      supportContact: {
        email: 'support@autodesk.com',
        phone: '+1-800-538-6401'
      },
      products: ['AutoCAD', 'Maya', '3ds Max', 'Inventor'],
      licenseTypes: ['subscription', 'concurrent']
    });
  }

  // License Management Methods
  async getLicenses(req, res) {
    try {
      const {
        page = 1,
        limit = 50,
        search,
        vendor,
        software,
        type,
        status,
        expiringWithin,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      let licenses = Array.from(this.licenses.values());

      // Apply filters
      if (search) {
        licenses = licenses.filter(license => 
          license.name.toLowerCase().includes(search.toLowerCase()) ||
          license.description.toLowerCase().includes(search.toLowerCase()) ||
          license.licenseKey.toLowerCase().includes(search.toLowerCase())
        );
      }

      if (vendor) {
        licenses = licenses.filter(license => license.vendorId === vendor);
      }

      if (software) {
        licenses = licenses.filter(license => license.softwareId === software);
      }

      if (type) {
        licenses = licenses.filter(license => license.type === type);
      }

      if (status) {
        licenses = licenses.filter(license => license.status === status);
      }

      if (expiringWithin) {
        const days = parseInt(expiringWithin);
        const cutoffDate = moment().add(days, 'days').toDate();
        licenses = licenses.filter(license => 
          license.expiryDate && 
          new Date(license.expiryDate) <= cutoffDate
        );
      }

      // Apply sorting
      licenses.sort((a, b) => {
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
      const paginatedLicenses = licenses.slice(startIndex, endIndex);

      // Enrich with additional data
      const enrichedLicenses = paginatedLicenses.map(license => ({
        ...license,
        vendor: this.vendors.get(license.vendorId),
        software: this.software.get(license.softwareId),
        usage: this.calculateLicenseUsage(license.id),
        compliance: this.checkLicenseCompliance(license.id)
      }));

      res.json({
        success: true,
        data: enrichedLicenses,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: licenses.length,
          pages: Math.ceil(licenses.length / limit)
        },
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Get licenses error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to retrieve licenses',
        requestId: req.id
      });
    }
  }

  async createLicense(req, res) {
    try {
      const licenseData = req.body;
      
      if (!licenseData.name || !licenseData.vendorId || !licenseData.softwareId || !licenseData.type) {
        return res.status(400).json({
          error: 'Missing required fields: name, vendorId, softwareId, type',
          requestId: req.id
        });
      }

      const licenseId = uuidv4();
      const license = {
        id: licenseId,
        name: licenseData.name,
        description: licenseData.description || '',
        vendorId: licenseData.vendorId,
        softwareId: licenseData.softwareId,
        type: licenseData.type,
        licenseKey: licenseData.licenseKey || '',
        purchaseDate: licenseData.purchaseDate || new Date().toISOString(),
        expiryDate: licenseData.expiryDate || null,
        renewalDate: licenseData.renewalDate || null,
        status: licenseData.status || 'active',
        quantity: licenseData.quantity || 1,
        cost: licenseData.cost || 0,
        currency: licenseData.currency || 'USD',
        costCenter: licenseData.costCenter || '',
        purchaseOrder: licenseData.purchaseOrder || '',
        contractId: licenseData.contractId || '',
        terms: {
          renewable: licenseData.terms?.renewable || false,
          autoRenewal: licenseData.terms?.autoRenewal || false,
          transferable: licenseData.terms?.transferable || false,
          concurrent: licenseData.terms?.concurrent || false,
          maxUsers: licenseData.terms?.maxUsers || licenseData.quantity,
          allowedPlatforms: licenseData.terms?.allowedPlatforms || [],
          restrictions: licenseData.terms?.restrictions || []
        },
        compliance: {
          requiresActivation: licenseData.compliance?.requiresActivation || false,
          requiresRegistration: licenseData.compliance?.requiresRegistration || false,
          allowsRemoteAccess: licenseData.compliance?.allowsRemoteAccess || true,
          geoRestrictions: licenseData.compliance?.geoRestrictions || [],
          usageReporting: licenseData.compliance?.usageReporting || false
        },
        maintenance: {
          included: licenseData.maintenance?.included || false,
          expiryDate: licenseData.maintenance?.expiryDate || null,
          cost: licenseData.maintenance?.cost || 0,
          autoRenewal: licenseData.maintenance?.autoRenewal || false
        },
        assignments: [],
        usageHistory: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: licenseData.createdBy || 'system'
      };

      this.licenses.set(licenseId, license);

      // Log audit event
      this.logAuditEvent('license_created', {
        licenseId,
        licenseName: license.name,
        vendorId: license.vendorId,
        softwareId: license.softwareId,
        createdBy: license.createdBy
      });

      // Broadcast to WebSocket subscribers
      this.broadcastToSubscribers('license_created', {
        licenseId,
        license: license
      });

      res.status(201).json({
        success: true,
        data: license,
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Create license error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to create license',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async trackUsage(req, res) {
    try {
      const { licenseId, userId, deviceId, action, metadata = {} } = req.body;
      
      if (!licenseId || !userId || !action) {
        return res.status(400).json({
          error: 'Missing required fields: licenseId, userId, action',
          requestId: req.id
        });
      }

      const license = this.licenses.get(licenseId);
      if (!license) {
        return res.status(404).json({
          error: 'License not found',
          requestId: req.id
        });
      }

      const usageId = uuidv4();
      const usageRecord = {
        id: usageId,
        licenseId,
        userId,
        deviceId,
        action, // 'start', 'stop', 'heartbeat', 'feature_access'
        timestamp: new Date().toISOString(),
        metadata,
        duration: metadata.duration || 0,
        features: metadata.features || [],
        location: metadata.location || '',
        ipAddress: req.ip || '',
        userAgent: req.headers['user-agent'] || ''
      };

      // Store usage record
      if (!this.usage.has(licenseId)) {
        this.usage.set(licenseId, []);
      }
      this.usage.get(licenseId).push(usageRecord);

      // Update license usage statistics
      this.updateLicenseUsageStats(license, usageRecord);

      // Check for compliance violations
      this.checkUsageCompliance(license, usageRecord);

      // Broadcast real-time usage update
      this.broadcastToSubscribers('usage_tracked', {
        licenseId,
        usageRecord,
        currentUsage: this.calculateCurrentUsage(licenseId)
      });

      res.json({
        success: true,
        data: usageRecord,
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Track usage error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to track usage',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async startComplianceScan(req, res) {
    try {
      const { licenseIds, scanType = 'full', scanParameters = {} } = req.body;
      
      const scanId = uuidv4();
      const scan = {
        id: scanId,
        type: scanType,
        licenseIds: licenseIds || Array.from(this.licenses.keys()),
        scanParameters,
        status: 'running',
        startedAt: new Date().toISOString(),
        completedAt: null,
        progress: 0,
        results: [],
        violations: [],
        summary: {
          totalLicenses: 0,
          compliantLicenses: 0,
          nonCompliantLicenses: 0,
          criticalViolations: 0,
          warningViolations: 0
        }
      };

      this.compliance.set(scanId, scan);

      // Start compliance scanning in background
      this.performComplianceScan(scanId);

      res.status(201).json({
        success: true,
        data: scan,
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Start compliance scan error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to start compliance scan',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getOptimizationRecommendations(req, res) {
    try {
      const recommendations = this.generateOptimizationRecommendations();

      res.json({
        success: true,
        data: recommendations,
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Get optimization recommendations error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to get optimization recommendations',
        requestId: req.id
      });
    }
  }

  async syncMobileLicenses(req, res) {
    try {
      // Sync with mobile management service
      const response = await axios.get(`${this.config.mobileManagementServiceUrl}/api/mam/licenses`);
      const mobileLicenses = response.data.data || [];

      let syncedCount = 0;
      let createdCount = 0;
      let updatedCount = 0;

      for (const mobileLicense of mobileLicenses) {
        const existingLicense = Array.from(this.licenses.values())
          .find(l => l.externalId === mobileLicense.id && l.source === 'mobile');

        if (existingLicense) {
          // Update existing license
          existingLicense.updatedAt = new Date().toISOString();
          existingLicense.mobileData = mobileLicense;
          this.licenses.set(existingLicense.id, existingLicense);
          updatedCount++;
        } else {
          // Create new license from mobile data
          const licenseId = uuidv4();
          const license = {
            id: licenseId,
            name: mobileLicense.appName || 'Mobile App License',
            description: `Mobile license for ${mobileLicense.appName}`,
            vendorId: 'mobile',
            softwareId: mobileLicense.appId || licenseId,
            type: 'per_device',
            externalId: mobileLicense.id,
            source: 'mobile',
            status: mobileLicense.status === 'active' ? 'active' : 'inactive',
            quantity: mobileLicense.totalSeats || 1,
            cost: 0,
            currency: 'USD',
            mobileData: mobileLicense,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            createdBy: 'mobile-sync'
          };

          this.licenses.set(licenseId, license);
          createdCount++;
        }
        syncedCount++;
      }

      this.logger.info('Mobile licenses synced', {
        total: syncedCount,
        created: createdCount,
        updated: updatedCount
      });

      res.json({
        success: true,
        data: {
          totalSynced: syncedCount,
          created: createdCount,
          updated: updatedCount
        },
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Sync mobile licenses error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to sync mobile licenses',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getDashboard(req, res) {
    try {
      const dashboard = {
        overview: {
          totalLicenses: this.licenses.size,
          activeLicenses: Array.from(this.licenses.values()).filter(l => l.status === 'active').length,
          expiringLicenses: this.countExpiringLicenses(30),
          violations: this.violations.size,
          totalCost: this.calculateTotalCost(),
          utilizationRate: this.calculateOverallUtilization()
        },
        licensesByType: this.getLicensesByType(),
        licensesByVendor: this.getLicensesByVendor(),
        utilizationMetrics: this.getUtilizationMetrics(),
        complianceStatus: this.getComplianceStatus(),
        costAnalysis: this.getCostAnalysisData(),
        recentActivity: this.getRecentActivity(),
        upcomingRenewals: this.getUpcomingRenewals(90),
        topRecommendations: this.getTopRecommendations(5)
      };

      res.json({
        success: true,
        data: dashboard,
        requestId: req.id
      });
    } catch (error) {
      this.logger.error('Get dashboard error', { error: error.message, requestId: req.id });
      res.status(500).json({
        error: 'Failed to get dashboard',
        requestId: req.id
      });
    }
  }

  // Helper Methods
  calculateLicenseUsage(licenseId) {
    const usageRecords = this.usage.get(licenseId) || [];
    const currentUsage = this.calculateCurrentUsage(licenseId);
    
    return {
      currentUsers: currentUsage.activeUsers,
      maxUsers: currentUsage.maxConcurrent,
      utilizationRate: currentUsage.utilizationRate,
      totalSessions: usageRecords.length,
      avgSessionDuration: this.calculateAvgSessionDuration(usageRecords)
    };
  }

  calculateCurrentUsage(licenseId) {
    const license = this.licenses.get(licenseId);
    const usageRecords = this.usage.get(licenseId) || [];
    
    // Calculate active users in last hour
    const oneHourAgo = moment().subtract(1, 'hour').toDate();
    const recentUsage = usageRecords.filter(record => 
      new Date(record.timestamp) >= oneHourAgo &&
      record.action === 'start'
    );

    const activeUsers = new Set(recentUsage.map(r => r.userId)).size;
    const maxUsers = license?.terms?.maxUsers || license?.quantity || 1;
    
    return {
      activeUsers,
      maxConcurrent: maxUsers,
      utilizationRate: maxUsers > 0 ? (activeUsers / maxUsers) * 100 : 0
    };
  }

  updateLicenseUsageStats(license, usageRecord) {
    // Update license statistics based on usage
    if (!license.stats) {
      license.stats = {
        totalSessions: 0,
        uniqueUsers: new Set(),
        lastUsed: null,
        peakConcurrentUsers: 0
      };
    }

    if (usageRecord.action === 'start') {
      license.stats.totalSessions++;
      license.stats.uniqueUsers.add(usageRecord.userId);
      license.stats.lastUsed = usageRecord.timestamp;
    }

    license.updatedAt = new Date().toISOString();
    this.licenses.set(license.id, license);
  }

  checkUsageCompliance(license, usageRecord) {
    const currentUsage = this.calculateCurrentUsage(license.id);
    
    // Check for overusage
    if (currentUsage.utilizationRate > 100) {
      this.createViolation(license.id, 'overusage', {
        currentUsers: currentUsage.activeUsers,
        maxUsers: currentUsage.maxConcurrent,
        overageCount: currentUsage.activeUsers - currentUsage.maxConcurrent
      });
    }

    // Check for unauthorized platforms
    if (license.terms.allowedPlatforms.length > 0) {
      const userAgent = usageRecord.userAgent || '';
      const isAuthorizedPlatform = license.terms.allowedPlatforms.some(platform =>
        userAgent.toLowerCase().includes(platform.toLowerCase())
      );
      
      if (!isAuthorizedPlatform) {
        this.createViolation(license.id, 'unauthorized_platform', {
          userAgent,
          allowedPlatforms: license.terms.allowedPlatforms
        });
      }
    }
  }

  createViolation(licenseId, type, details) {
    const violationId = uuidv4();
    const violation = {
      id: violationId,
      licenseId,
      type,
      severity: this.getViolationSeverity(type),
      details,
      status: 'open',
      detectedAt: new Date().toISOString(),
      resolvedAt: null,
      resolvedBy: null,
      resolution: null
    };

    this.violations.set(violationId, violation);

    // Broadcast violation alert
    this.broadcastToSubscribers('violation_detected', {
      violationId,
      violation
    });

    // Create alert if severity is high
    if (violation.severity === 'critical' || violation.severity === 'high') {
      this.createAlert(licenseId, violation);
    }

    this.logger.warn('Compliance violation detected', {
      violationId,
      licenseId,
      type,
      severity: violation.severity
    });
  }

  getViolationSeverity(type) {
    const severityMap = {
      'overusage': 'critical',
      'expired': 'critical',
      'unauthorized_platform': 'medium',
      'geo_restriction': 'high',
      'concurrent_limit': 'high',
      'maintenance_expired': 'low'
    };

    return severityMap[type] || 'medium';
  }

  createAlert(licenseId, violation) {
    const alertId = uuidv4();
    const alert = {
      id: alertId,
      type: 'compliance_violation',
      licenseId,
      violationId: violation.id,
      severity: violation.severity,
      title: `License Compliance Violation: ${violation.type}`,
      message: this.generateViolationMessage(violation),
      status: 'open',
      createdAt: new Date().toISOString(),
      acknowledgedAt: null,
      acknowledgedBy: null
    };

    this.alerts.set(alertId, alert);

    // Send email notification if configured
    if (this.config.alertingEnabled) {
      this.sendAlertNotification(alert);
    }
  }

  generateViolationMessage(violation) {
    switch (violation.type) {
      case 'overusage':
        return `License is being overused. Current users: ${violation.details.currentUsers}, Maximum allowed: ${violation.details.maxUsers}`;
      case 'expired':
        return `License has expired and is no longer valid for use.`;
      case 'unauthorized_platform':
        return `Software is being used on an unauthorized platform: ${violation.details.userAgent}`;
      default:
        return `License violation of type: ${violation.type}`;
    }
  }

  async performComplianceScan(scanId) {
    const scan = this.compliance.get(scanId);
    if (!scan) return;

    try {
      const totalLicenses = scan.licenseIds.length;
      let processedLicenses = 0;

      for (const licenseId of scan.licenseIds) {
        const license = this.licenses.get(licenseId);
        if (!license) continue;

        // Simulate compliance check delay
        await new Promise(resolve => setTimeout(resolve, 100));

        const complianceResult = this.checkLicenseCompliance(licenseId);
        scan.results.push(complianceResult);

        if (!complianceResult.isCompliant) {
          scan.violations.push(...complianceResult.violations);
          scan.summary.nonCompliantLicenses++;
          
          // Update summary based on violation severity
          complianceResult.violations.forEach(violation => {
            if (violation.severity === 'critical') {
              scan.summary.criticalViolations++;
            } else {
              scan.summary.warningViolations++;
            }
          });
        } else {
          scan.summary.compliantLicenses++;
        }

        processedLicenses++;
        scan.progress = Math.floor((processedLicenses / totalLicenses) * 100);

        // Broadcast progress update
        this.broadcastToSubscribers('scan_progress', {
          scanId,
          progress: scan.progress,
          processedLicenses,
          totalLicenses
        });

        this.compliance.set(scanId, scan);
      }

      scan.status = 'completed';
      scan.completedAt = new Date().toISOString();
      scan.summary.totalLicenses = totalLicenses;

      // Broadcast scan completion
      this.broadcastToSubscribers('scan_completed', {
        scanId,
        summary: scan.summary
      });

      this.logger.info('Compliance scan completed', {
        scanId,
        totalLicenses,
        violations: scan.summary.criticalViolations + scan.summary.warningViolations
      });

    } catch (error) {
      scan.status = 'failed';
      scan.errorMessage = error.message;
      
      this.logger.error('Compliance scan failed', {
        scanId,
        error: error.message
      });
    }

    this.compliance.set(scanId, scan);
  }

  checkLicenseCompliance(licenseId) {
    const license = this.licenses.get(licenseId);
    const violations = [];
    let isCompliant = true;

    if (!license) {
      return { isCompliant: false, violations: [] };
    }

    // Check expiry
    if (license.expiryDate && new Date(license.expiryDate) < new Date()) {
      violations.push({
        type: 'expired',
        severity: 'critical',
        message: 'License has expired',
        expiryDate: license.expiryDate
      });
      isCompliant = false;
    }

    // Check usage limits
    const currentUsage = this.calculateCurrentUsage(licenseId);
    if (currentUsage.utilizationRate > 100) {
      violations.push({
        type: 'overusage',
        severity: 'critical',
        message: 'License usage exceeds allowed limits',
        currentUsers: currentUsage.activeUsers,
        maxUsers: currentUsage.maxConcurrent
      });
      isCompliant = false;
    }

    // Check maintenance expiry
    if (license.maintenance?.included && license.maintenance.expiryDate) {
      if (new Date(license.maintenance.expiryDate) < new Date()) {
        violations.push({
          type: 'maintenance_expired',
          severity: 'low',
          message: 'License maintenance has expired',
          maintenanceExpiryDate: license.maintenance.expiryDate
        });
      }
    }

    return {
      licenseId,
      isCompliant,
      violations,
      lastChecked: new Date().toISOString()
    };
  }

  generateOptimizationRecommendations() {
    const recommendations = [];

    // Analyze underutilized licenses
    for (const [licenseId, license] of this.licenses) {
      if (license.status !== 'active') continue;

      const usage = this.calculateLicenseUsage(licenseId);
      
      if (usage.utilizationRate < 50) {
        recommendations.push({
          id: uuidv4(),
          type: 'underutilization',
          priority: 'medium',
          licenseId,
          licenseName: license.name,
          title: 'Underutilized License',
          description: `License is only ${usage.utilizationRate.toFixed(1)}% utilized`,
          recommendation: 'Consider reducing license quantity or reallocating unused licenses',
          potentialSavings: this.calculatePotentialSavings(license, 'reduce_quantity'),
          actions: ['reduce_quantity', 'reallocate_licenses', 'analyze_usage_patterns']
        });
      }
    }

    // Analyze duplicate software
    const softwareGroups = this.groupLicensesBySoftware();
    for (const [softwareId, licenses] of softwareGroups) {
      if (licenses.length > 1) {
        const totalCost = licenses.reduce((sum, license) => sum + (license.cost || 0), 0);
        
        recommendations.push({
          id: uuidv4(),
          type: 'consolidation',
          priority: 'high',
          softwareId,
          title: 'License Consolidation Opportunity',
          description: `Multiple licenses found for the same software (${licenses.length} licenses)`,
          recommendation: 'Consolidate licenses with a single vendor for better pricing',
          potentialSavings: totalCost * 0.15, // Estimate 15% savings
          actions: ['consolidate_licenses', 'negotiate_volume_pricing', 'standardize_vendor']
        });
      }
    }

    // Analyze expiring licenses
    const expiringLicenses = this.getExpiringLicenses(90);
    for (const license of expiringLicenses) {
      const usage = this.calculateLicenseUsage(license.id);
      
      recommendations.push({
        id: uuidv4(),
        type: 'renewal_optimization',
        priority: 'high',
        licenseId: license.id,
        licenseName: license.name,
        title: 'License Renewal Optimization',
        description: `License expires in ${moment(license.expiryDate).diff(moment(), 'days')} days`,
        recommendation: usage.utilizationRate < 70 ? 
          'Consider reducing quantity before renewal' : 
          'Negotiate better terms for renewal',
        potentialSavings: this.calculateRenewalSavings(license, usage),
        actions: ['negotiate_renewal', 'assess_alternatives', 'optimize_quantity']
      });
    }

    // Sort by potential savings
    recommendations.sort((a, b) => (b.potentialSavings || 0) - (a.potentialSavings || 0));

    return recommendations;
  }

  setupScheduledJobs() {
    // Daily compliance check
    cron.schedule('0 2 * * *', () => {
      this.logger.info('Running daily compliance check');
      this.runDailyComplianceCheck();
    });

    // Weekly optimization analysis
    cron.schedule('0 9 * * 1', () => {
      this.logger.info('Running weekly optimization analysis');
      this.runWeeklyOptimizationAnalysis();
    });

    // Monthly license audit
    cron.schedule('0 10 1 * *', () => {
      this.logger.info('Running monthly license audit');
      this.runMonthlyLicenseAudit();
    });

    // Hourly usage cleanup
    cron.schedule('0 * * * *', () => {
      this.cleanupOldUsageRecords();
    });
  }

  async runDailyComplianceCheck() {
    const scanId = uuidv4();
    const scan = {
      id: scanId,
      type: 'daily_automated',
      licenseIds: Array.from(this.licenses.keys()),
      status: 'running',
      startedAt: new Date().toISOString(),
      automated: true
    };

    this.compliance.set(scanId, scan);
    await this.performComplianceScan(scanId);
  }

  // WebSocket message handling
  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    switch (type) {
      case 'subscribe_license_events':
        ws.subscriptions.add('license_created');
        ws.subscriptions.add('license_updated');
        ws.subscriptions.add('license_deleted');
        ws.subscriptions.add('usage_tracked');
        ws.subscriptions.add('violation_detected');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'license_events',
          requestId
        }));
        break;

      case 'subscribe_compliance_events':
        ws.subscriptions.add('scan_progress');
        ws.subscriptions.add('scan_completed');
        ws.subscriptions.add('violation_detected');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'compliance_events',
          requestId
        }));
        break;

      case 'get_realtime_usage':
        if (data.licenseId) {
          const currentUsage = this.calculateCurrentUsage(data.licenseId);
          ws.send(JSON.stringify({
            type: 'realtime_usage',
            licenseId: data.licenseId,
            usage: currentUsage,
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

  logAuditEvent(action, details) {
    const auditId = uuidv4();
    const auditLog = {
      id: auditId,
      action,
      details,
      timestamp: new Date().toISOString(),
      service: 'license-management'
    };

    this.auditLogs.set(auditId, auditLog);

    // Keep only last 10000 audit logs
    if (this.auditLogs.size > 10000) {
      const oldestKey = this.auditLogs.keys().next().value;
      this.auditLogs.delete(oldestKey);
    }
  }

  // Utility methods for dashboard and reporting
  countExpiringLicenses(days) {
    const cutoffDate = moment().add(days, 'days').toDate();
    return Array.from(this.licenses.values())
      .filter(license => 
        license.expiryDate && 
        new Date(license.expiryDate) <= cutoffDate &&
        license.status === 'active'
      ).length;
  }

  calculateTotalCost() {
    return Array.from(this.licenses.values())
      .reduce((sum, license) => sum + (license.cost || 0), 0);
  }

  calculateOverallUtilization() {
    const activeLicenses = Array.from(this.licenses.values())
      .filter(l => l.status === 'active');
    
    if (activeLicenses.length === 0) return 0;

    const totalUtilization = activeLicenses
      .reduce((sum, license) => {
        const usage = this.calculateLicenseUsage(license.id);
        return sum + usage.utilizationRate;
      }, 0);

    return totalUtilization / activeLicenses.length;
  }

  startBackgroundServices() {
    // Start mobile license sync service
    setInterval(() => {
      this.syncMobileLicensesBackground();
    }, 5 * 60 * 1000); // Every 5 minutes

    // Start usage analytics aggregation
    setInterval(() => {
      this.aggregateUsageAnalytics();
    }, 60 * 60 * 1000); // Every hour
  }

  async syncMobileLicensesBackground() {
    try {
      await axios.get(`${this.config.mobileManagementServiceUrl}/api/mam/licenses`);
      // Process mobile license sync in background
    } catch (error) {
      this.logger.error('Background mobile sync error', { error: error.message });
    }
  }

  errorHandler(error, req, res, next) {
    this.logger.error('License Management Service Error', {
      error: error.message,
      stack: error.stack,
      requestId: req?.id,
      path: req?.path,
      method: req?.method
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req?.id,
      timestamp: new Date().toISOString(),
      service: 'license-management'
    });
  }

  start(port = this.config.servicePort) {
    this.server.listen(port, () => {
      this.logger.info(`🔐 License Management Service started on port ${port}`);
      console.log(`🔐 License Management Service started on port ${port}`);
      console.log(`📊 Health check: http://localhost:${port}/health`);
      console.log(`🔌 WebSocket: ws://localhost:${port}/ws/license`);
      console.log(`⚙️  Features: License Tracking, Compliance, Optimization, Asset Management`);
      console.log(`🚀 Service ready for license management operations`);
    });

    return this.server;
  }

  gracefulShutdown() {
    this.logger.info('Starting License Management Service graceful shutdown');
    
    this.server.close(() => {
      this.logger.info('License Management Service HTTP server closed');
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });
      
      this.logger.info('License Management Service graceful shutdown completed');
      process.exit(0);
    });
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Received SIGINT, starting graceful shutdown...');
  if (global.licenseService) {
    global.licenseService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, starting graceful shutdown...');
  if (global.licenseService) {
    global.licenseService.gracefulShutdown();
  }
});

// Start the service
const licenseService = new LicenseManagementService();
global.licenseService = licenseService;
licenseService.start();

module.exports = LicenseManagementService;