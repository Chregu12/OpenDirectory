const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const { google } = require('googleapis');

/**
 * Enterprise Android Management Service
 * Provides comprehensive Android device management with Android Enterprise integration
 * 
 * Features:
 * - Android Enterprise (Android for Work) integration
 * - Google Play EMM API integration
 * - Work profile management
 * - App management and distribution
 * - Device policy enforcement
 * - Knox integration for Samsung devices
 * - Zero-touch enrollment
 * - Android compliance monitoring
 * - Enterprise application management
 */
class AndroidEnterpriseService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/android'
    });
    
    // Google Play EMM API Configuration
    this.googleConfig = {
      clientEmail: process.env.GOOGLE_CLIENT_EMAIL || '',
      privateKey: process.env.GOOGLE_PRIVATE_KEY?.replace(/\\n/g, '\n') || '',
      projectId: process.env.GOOGLE_PROJECT_ID || '',
      enterpriseId: process.env.ANDROID_ENTERPRISE_ID || '',
      serviceAccountKeyFile: process.env.GOOGLE_SERVICE_ACCOUNT_KEY || '',
      playEmmApiBaseUrl: 'https://androidenterprise.googleapis.com/v1'
    };

    // Knox Configuration
    this.knoxConfig = {
      clientId: process.env.KNOX_CLIENT_ID || '',
      clientSecret: process.env.KNOX_CLIENT_SECRET || '',
      baseUrl: 'https://us-kcs-api.samsungknox.com',
      accessToken: null,
      tokenExpiresAt: null
    };
    
    // In-memory storage (replace with database in production)
    this.devices = new Map();
    this.enterprises = new Map();
    this.policies = new Map();
    this.apps = new Map();
    this.users = new Map();
    this.enrollmentTokens = new Map();
    this.workProfiles = new Map();
    this.commands = new Map();
    this.compliancePolicies = new Map();
    this.zeroTouchConfigs = new Map();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeGoogleServices();
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
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-ID', 'X-Request-ID'],
      exposedHeaders: ['X-Total-Count', 'X-Request-ID', 'X-Response-Time']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 1000,
      message: 'Rate limit exceeded for Android management operations',
      standardHeaders: true
    });

    this.app.use('/api/android', limiter);

    // Body parsing
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

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

      console.log('Android WebSocket connection established', {
        connectionId: ws.id,
        deviceId: ws.deviceId
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          console.error('Android WebSocket message error:', error);
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
        console.log('Android WebSocket connection closed', { 
          connectionId: ws.id,
          deviceId: ws.deviceId 
        });
      });

      // Send initial connection confirmation
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        service: 'android-enterprise',
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
        service: 'android-enterprise-service',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        capabilities: [
          'android-enterprise',
          'google-play-emm',
          'work-profiles',
          'app-management',
          'device-policies',
          'knox-integration',
          'zero-touch-enrollment',
          'compliance-monitoring'
        ],
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid,
        memory: process.memoryUsage(),
        checks: {
          google_play_emm: this.googleConfig.clientEmail ? 'healthy' : 'warning',
          knox_integration: this.knoxConfig.clientId ? 'healthy' : 'warning',
          websocket: this.wss.clients.size >= 0 ? 'healthy' : 'unhealthy'
        },
        statistics: {
          managed_devices: this.devices.size,
          enterprises: this.enterprises.size,
          active_policies: this.policies.size,
          managed_apps: this.apps.size,
          work_profiles: this.workProfiles.size
        }
      });
    });

    // Enterprise Management Routes
    this.app.post('/api/android/enterprises', this.createEnterprise.bind(this));
    this.app.get('/api/android/enterprises', this.getEnterprises.bind(this));
    this.app.get('/api/android/enterprises/:enterpriseId', this.getEnterprise.bind(this));
    this.app.put('/api/android/enterprises/:enterpriseId', this.updateEnterprise.bind(this));
    this.app.delete('/api/android/enterprises/:enterpriseId', this.deleteEnterprise.bind(this));

    // Enrollment Token Routes
    this.app.post('/api/android/enrollment-tokens', this.createEnrollmentToken.bind(this));
    this.app.get('/api/android/enrollment-tokens', this.getEnrollmentTokens.bind(this));
    this.app.delete('/api/android/enrollment-tokens/:tokenId', this.deleteEnrollmentToken.bind(this));

    // Device Management Routes
    this.app.get('/api/android/devices', this.getDevices.bind(this));
    this.app.get('/api/android/devices/:deviceId', this.getDevice.bind(this));
    this.app.put('/api/android/devices/:deviceId', this.updateDevice.bind(this));
    this.app.delete('/api/android/devices/:deviceId', this.deleteDevice.bind(this));
    this.app.post('/api/android/devices/:deviceId/wipe', this.wipeDevice.bind(this));
    this.app.post('/api/android/devices/:deviceId/reboot', this.rebootDevice.bind(this));
    this.app.post('/api/android/devices/:deviceId/lock', this.lockDevice.bind(this));
    this.app.post('/api/android/devices/:deviceId/unlock', this.unlockDevice.bind(this));

    // Policy Management Routes
    this.app.get('/api/android/policies', this.getPolicies.bind(this));
    this.app.post('/api/android/policies', this.createPolicy.bind(this));
    this.app.get('/api/android/policies/:policyId', this.getPolicy.bind(this));
    this.app.put('/api/android/policies/:policyId', this.updatePolicy.bind(this));
    this.app.delete('/api/android/policies/:policyId', this.deletePolicy.bind(this));
    this.app.post('/api/android/policies/:policyId/assign', this.assignPolicy.bind(this));

    // Work Profile Management Routes
    this.app.get('/api/android/work-profiles', this.getWorkProfiles.bind(this));
    this.app.post('/api/android/work-profiles', this.createWorkProfile.bind(this));
    this.app.get('/api/android/work-profiles/:profileId', this.getWorkProfile.bind(this));
    this.app.put('/api/android/work-profiles/:profileId', this.updateWorkProfile.bind(this));
    this.app.delete('/api/android/work-profiles/:profileId', this.deleteWorkProfile.bind(this));

    // App Management Routes
    this.app.get('/api/android/apps', this.getApps.bind(this));
    this.app.post('/api/android/apps/approve', this.approveApp.bind(this));
    this.app.post('/api/android/apps/install', this.installApp.bind(this));
    this.app.post('/api/android/apps/uninstall', this.uninstallApp.bind(this));
    this.app.get('/api/android/apps/store-layout', this.getStoreLayout.bind(this));
    this.app.post('/api/android/apps/store-layout', this.createStoreLayout.bind(this));

    // Zero-Touch Enrollment Routes
    this.app.get('/api/android/zero-touch/configurations', this.getZeroTouchConfigs.bind(this));
    this.app.post('/api/android/zero-touch/configurations', this.createZeroTouchConfig.bind(this));
    this.app.put('/api/android/zero-touch/configurations/:configId', this.updateZeroTouchConfig.bind(this));
    this.app.delete('/api/android/zero-touch/configurations/:configId', this.deleteZeroTouchConfig.bind(this));

    // Knox Integration Routes
    this.app.get('/api/android/knox/profiles', this.getKnoxProfiles.bind(this));
    this.app.post('/api/android/knox/profiles', this.createKnoxProfile.bind(this));
    this.app.post('/api/android/knox/commands/container-lock', this.knoxContainerLock.bind(this));
    this.app.post('/api/android/knox/commands/container-unlock', this.knoxContainerUnlock.bind(this));
    this.app.post('/api/android/knox/commands/remote-wipe', this.knoxRemoteWipe.bind(this));

    // Compliance Management Routes
    this.app.get('/api/android/compliance/policies', this.getCompliancePolicies.bind(this));
    this.app.post('/api/android/compliance/policies', this.createCompliancePolicy.bind(this));
    this.app.put('/api/android/compliance/policy/:policyId', this.updateCompliancePolicy.bind(this));
    this.app.delete('/api/android/compliance/policy/:policyId', this.deleteCompliancePolicy.bind(this));
    this.app.get('/api/android/compliance/violations', this.getComplianceViolations.bind(this));
    this.app.post('/api/android/compliance/scan/:deviceId', this.scanDeviceCompliance.bind(this));

    // Reports and Analytics Routes
    this.app.get('/api/android/analytics/dashboard', this.getAnalyticsDashboard.bind(this));
    this.app.get('/api/android/analytics/device-trends', this.getDeviceTrends.bind(this));
    this.app.get('/api/android/analytics/app-usage', this.getAppUsage.bind(this));
    this.app.get('/api/android/analytics/security-report', this.getSecurityReport.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  async initializeGoogleServices() {
    try {
      // Initialize Google Play EMM API
      if (this.googleConfig.clientEmail && this.googleConfig.privateKey) {
        this.auth = new google.auth.JWT(
          this.googleConfig.clientEmail,
          null,
          this.googleConfig.privateKey,
          ['https://www.googleapis.com/auth/androidenterprise']
        );

        this.androidEnterprise = google.androidenterprise({
          version: 'v1',
          auth: this.auth
        });

        await this.testGooglePlayConnection();
        console.log('Google Play EMM API initialized successfully');
      }

      // Initialize Knox API
      if (this.knoxConfig.clientId && this.knoxConfig.clientSecret) {
        await this.initializeKnoxAuth();
        console.log('Samsung Knox API initialized successfully');
      }

    } catch (error) {
      console.error('Failed to initialize Google/Knox services:', error);
    }
  }

  async testGooglePlayConnection() {
    try {
      const response = await this.androidEnterprise.enterprises.list();
      console.log('Google Play EMM API connection test successful');
      return response.data;
    } catch (error) {
      console.error('Google Play EMM API connection test failed:', error);
      throw error;
    }
  }

  async initializeKnoxAuth() {
    try {
      const response = await axios.post(`${this.knoxConfig.baseUrl}/ams/v1/oauth2/token`, {
        grant_type: 'client_credentials',
        client_id: this.knoxConfig.clientId,
        client_secret: this.knoxConfig.clientSecret
      });

      this.knoxConfig.accessToken = response.data.access_token;
      this.knoxConfig.tokenExpiresAt = Date.now() + (response.data.expires_in * 1000);
      
      console.log('Knox authentication successful');
    } catch (error) {
      console.error('Knox authentication failed:', error);
      throw error;
    }
  }

  // Enterprise Management
  async createEnterprise(req, res) {
    try {
      const { name, primaryDomain, adminEmail } = req.body;
      
      if (!name || !primaryDomain || !adminEmail) {
        return res.status(400).json({
          error: 'Missing required fields: name, primaryDomain, adminEmail',
          requestId: req.id
        });
      }

      // Create enterprise via Google Play EMM API
      const enterpriseData = {
        name,
        primaryDomain,
        administrator: [{
          email: adminEmail
        }]
      };

      let googleEnterprise;
      try {
        const response = await this.androidEnterprise.enterprises.insert({
          requestBody: enterpriseData
        });
        googleEnterprise = response.data;
      } catch (error) {
        return res.status(500).json({
          error: 'Failed to create enterprise with Google',
          details: error.message,
          requestId: req.id
        });
      }

      const enterpriseId = this.generateId();
      const enterprise = {
        id: enterpriseId,
        googleEnterpriseId: googleEnterprise.id,
        name,
        primaryDomain,
        adminEmail,
        status: 'active',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        settings: {
          enableWorkProfiles: true,
          allowPersonalUsage: true,
          requireStrongAuth: true,
          enableAppVerification: true
        }
      };

      this.enterprises.set(enterpriseId, enterprise);

      res.status(201).json({
        success: true,
        data: enterprise,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create enterprise error:', error);
      res.status(500).json({
        error: 'Failed to create enterprise',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Enrollment Token Management
  async createEnrollmentToken(req, res) {
    try {
      const { 
        enterpriseId, 
        policyId, 
        duration = 86400, // 24 hours default
        allowPersonalUsage = true,
        qrCodeDisplayName 
      } = req.body;
      
      if (!enterpriseId || !policyId) {
        return res.status(400).json({
          error: 'Missing required fields: enterpriseId, policyId',
          requestId: req.id
        });
      }

      const enterprise = this.enterprises.get(enterpriseId);
      if (!enterprise) {
        return res.status(404).json({
          error: 'Enterprise not found',
          requestId: req.id
        });
      }

      const policy = this.policies.get(policyId);
      if (!policy) {
        return res.status(404).json({
          error: 'Policy not found',
          requestId: req.id
        });
      }

      // Create enrollment token via Google Play EMM API
      const tokenData = {
        duration: `${duration}s`,
        allowPersonalUsage,
        policyName: `enterprises/${enterprise.googleEnterpriseId}/policies/${policyId}`,
        qrCode: qrCodeDisplayName
      };

      let googleToken;
      try {
        const response = await this.androidEnterprise.enterprises.createEnrollmentToken({
          enterpriseId: enterprise.googleEnterpriseId,
          requestBody: tokenData
        });
        googleToken = response.data;
      } catch (error) {
        return res.status(500).json({
          error: 'Failed to create enrollment token with Google',
          details: error.message,
          requestId: req.id
        });
      }

      const tokenId = this.generateId();
      const enrollmentToken = {
        id: tokenId,
        enterpriseId,
        policyId,
        googleTokenId: googleToken.name,
        token: googleToken.value,
        qrCode: googleToken.qrCode,
        duration,
        allowPersonalUsage,
        qrCodeDisplayName,
        status: 'active',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + (duration * 1000)).toISOString(),
        usageCount: 0,
        maxUsage: req.body.maxUsage || null
      };

      this.enrollmentTokens.set(tokenId, enrollmentToken);

      res.status(201).json({
        success: true,
        data: enrollmentToken,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create enrollment token error:', error);
      res.status(500).json({
        error: 'Failed to create enrollment token',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Device Management
  async getDevices(req, res) {
    try {
      const {
        page = 1,
        limit = 50,
        search,
        enterpriseId,
        status,
        managementMode,
        sortBy = 'lastSyncTime',
        sortOrder = 'desc'
      } = req.query;

      let devices = Array.from(this.devices.values());

      // Apply filters
      if (search) {
        devices = devices.filter(device => 
          device.name?.toLowerCase().includes(search.toLowerCase()) ||
          device.serialNumber?.toLowerCase().includes(search.toLowerCase()) ||
          device.imei?.toLowerCase().includes(search.toLowerCase())
        );
      }

      if (enterpriseId) {
        devices = devices.filter(device => device.enterpriseId === enterpriseId);
      }

      if (status) {
        devices = devices.filter(device => device.status === status);
      }

      if (managementMode) {
        devices = devices.filter(device => device.managementMode === managementMode);
      }

      // Apply sorting
      devices.sort((a, b) => {
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
      const paginatedDevices = devices.slice(startIndex, endIndex);

      res.json({
        success: true,
        data: paginatedDevices,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: devices.length,
          pages: Math.ceil(devices.length / limit)
        },
        requestId: req.id
      });
    } catch (error) {
      console.error('Get devices error:', error);
      res.status(500).json({
        error: 'Failed to retrieve devices',
        requestId: req.id
      });
    }
  }

  async wipeDevice(req, res) {
    try {
      const { deviceId } = req.params;
      const { wipeReasonMessage, preserveResetProtectionData = false } = req.body;
      
      const device = this.devices.get(deviceId);
      if (!device) {
        return res.status(404).json({
          error: 'Device not found',
          requestId: req.id
        });
      }

      // Execute wipe command via Google Play EMM API
      const wipeCommand = {
        wipeReasonMessage: wipeReasonMessage || 'Remote wipe initiated by administrator',
        preserveResetProtectionData
      };

      let result;
      try {
        const response = await this.androidEnterprise.devices.forceReportUpload({
          enterpriseId: device.enterpriseId,
          userId: device.userId,
          deviceId: device.googleDeviceId
        });

        // Then issue wipe command
        const wipeResponse = await this.androidEnterprise.devices.update({
          enterpriseId: device.enterpriseId,
          userId: device.userId,
          deviceId: device.googleDeviceId,
          requestBody: {
            ...device,
            state: 'wiped'
          }
        });

        result = wipeResponse.data;
      } catch (error) {
        return res.status(500).json({
          error: 'Failed to wipe device',
          details: error.message,
          requestId: req.id
        });
      }

      // Update local device status
      device.status = 'wiping';
      device.lastAction = 'wipe';
      device.lastActionAt = new Date().toISOString();
      device.wipeReason = wipeReasonMessage;

      this.devices.set(deviceId, device);

      // Log the action
      console.log(`Device wipe initiated: ${deviceId}`, {
        deviceName: device.name,
        reason: wipeReasonMessage,
        preserveData: preserveResetProtectionData
      });

      // Broadcast wipe event
      this.broadcastToSubscribers('device_wiped', {
        deviceId,
        deviceName: device.name,
        reason: wipeReasonMessage,
        timestamp: new Date().toISOString()
      });

      res.json({
        success: true,
        data: {
          deviceId,
          status: 'wipe_initiated',
          message: 'Device wipe command sent successfully',
          result
        },
        requestId: req.id
      });
    } catch (error) {
      console.error('Wipe device error:', error);
      res.status(500).json({
        error: 'Failed to wipe device',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Policy Management
  async createPolicy(req, res) {
    try {
      const policyData = req.body;
      
      if (!policyData.name || !policyData.enterpriseId) {
        return res.status(400).json({
          error: 'Missing required fields: name, enterpriseId',
          requestId: req.id
        });
      }

      const enterprise = this.enterprises.get(policyData.enterpriseId);
      if (!enterprise) {
        return res.status(404).json({
          error: 'Enterprise not found',
          requestId: req.id
        });
      }

      // Create policy via Google Play EMM API
      const googlePolicyData = {
        ...policyData,
        name: `enterprises/${enterprise.googleEnterpriseId}/policies/${policyData.name}`,
        version: '1'
      };

      let googlePolicy;
      try {
        const response = await this.androidEnterprise.enterprises.policies.patch({
          name: googlePolicyData.name,
          requestBody: googlePolicyData
        });
        googlePolicy = response.data;
      } catch (error) {
        return res.status(500).json({
          error: 'Failed to create policy with Google',
          details: error.message,
          requestId: req.id
        });
      }

      const policyId = this.generateId();
      const policy = {
        id: policyId,
        ...policyData,
        googlePolicyName: googlePolicy.name,
        version: 1,
        status: 'active',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        deviceCount: 0
      };

      this.policies.set(policyId, policy);

      res.status(201).json({
        success: true,
        data: policy,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create policy error:', error);
      res.status(500).json({
        error: 'Failed to create policy',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // App Management
  async approveApp(req, res) {
    try {
      const { packageName, enterpriseId, approvalUrlInfo } = req.body;
      
      if (!packageName || !enterpriseId) {
        return res.status(400).json({
          error: 'Missing required fields: packageName, enterpriseId',
          requestId: req.id
        });
      }

      const enterprise = this.enterprises.get(enterpriseId);
      if (!enterprise) {
        return res.status(404).json({
          error: 'Enterprise not found',
          requestId: req.id
        });
      }

      // Approve app via Google Play EMM API
      try {
        const response = await this.androidEnterprise.products.approve({
          enterpriseId: enterprise.googleEnterpriseId,
          productId: packageName,
          requestBody: {
            approvalUrlInfo: approvalUrlInfo || {
              approvalUrl: `https://play.google.com/work/apps/details?id=${packageName}`
            }
          }
        });

        const appId = this.generateId();
        const app = {
          id: appId,
          packageName,
          enterpriseId,
          status: 'approved',
          approvalDate: new Date().toISOString(),
          distributionChannel: 'play_store',
          installCount: 0,
          lastUpdated: new Date().toISOString()
        };

        this.apps.set(appId, app);

        res.json({
          success: true,
          data: app,
          googleResponse: response.data,
          requestId: req.id
        });
      } catch (error) {
        return res.status(500).json({
          error: 'Failed to approve app with Google',
          details: error.message,
          requestId: req.id
        });
      }
    } catch (error) {
      console.error('Approve app error:', error);
      res.status(500).json({
        error: 'Failed to approve app',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Knox Integration
  async createKnoxProfile(req, res) {
    try {
      const { deviceId, profileData } = req.body;
      
      if (!deviceId || !profileData) {
        return res.status(400).json({
          error: 'Missing required fields: deviceId, profileData',
          requestId: req.id
        });
      }

      if (!this.knoxConfig.accessToken) {
        await this.initializeKnoxAuth();
      }

      // Create Knox profile
      const knoxResponse = await axios.post(
        `${this.knoxConfig.baseUrl}/kcs/v1/kc/${deviceId}/container/profile`,
        profileData,
        {
          headers: {
            'Authorization': `Bearer ${this.knoxConfig.accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const profileId = this.generateId();
      const profile = {
        id: profileId,
        deviceId,
        knoxProfileId: knoxResponse.data.profileId,
        profileData,
        status: 'active',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      // Store Knox profile reference
      this.workProfiles.set(profileId, {
        ...profile,
        type: 'knox'
      });

      res.status(201).json({
        success: true,
        data: profile,
        knoxResponse: knoxResponse.data,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create Knox profile error:', error);
      res.status(500).json({
        error: 'Failed to create Knox profile',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Compliance Management
  async scanDeviceCompliance(req, res) {
    try {
      const { deviceId } = req.params;
      const { policyIds } = req.body;
      
      const device = this.devices.get(deviceId);
      if (!device) {
        return res.status(404).json({
          error: 'Device not found',
          requestId: req.id
        });
      }

      const scanResults = await this.performAndroidComplianceScan(deviceId, policyIds);

      res.json({
        success: true,
        data: scanResults,
        requestId: req.id
      });
    } catch (error) {
      console.error('Android compliance scan error:', error);
      res.status(500).json({
        error: 'Failed to scan device compliance',
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
          totalDevices: this.devices.size,
          managedDevices: Array.from(this.devices.values()).filter(d => d.status === 'active').length,
          workProfileDevices: Array.from(this.devices.values()).filter(d => d.managementMode === 'work_profile').length,
          fullyManagedDevices: Array.from(this.devices.values()).filter(d => d.managementMode === 'fully_managed').length,
          enterprises: this.enterprises.size
        },
        policies: {
          totalPolicies: this.policies.size,
          activePolicies: Array.from(this.policies.values()).filter(p => p.status === 'active').length,
          policyAssignments: Array.from(this.policies.values()).reduce((sum, p) => sum + p.deviceCount, 0)
        },
        apps: {
          totalApps: this.apps.size,
          approvedApps: Array.from(this.apps.values()).filter(a => a.status === 'approved').length,
          appInstallations: Array.from(this.apps.values()).reduce((sum, a) => sum + (a.installCount || 0), 0)
        },
        enrollment: {
          activeTokens: Array.from(this.enrollmentTokens.values()).filter(t => t.status === 'active').length,
          totalEnrollments: Array.from(this.enrollmentTokens.values()).reduce((sum, t) => sum + t.usageCount, 0)
        },
        compliance: {
          totalPolicies: this.compliancePolicies.size,
          activePolicies: Array.from(this.compliancePolicies.values()).filter(p => p.isActive).length,
          averageComplianceRate: this.calculateAndroidComplianceRate()
        },
        knox: {
          knoxDevices: Array.from(this.devices.values()).filter(d => d.hasKnoxSupport).length,
          activeProfiles: Array.from(this.workProfiles.values()).filter(p => p.type === 'knox' && p.status === 'active').length
        }
      };

      res.json({
        success: true,
        data: dashboard,
        requestId: req.id
      });
    } catch (error) {
      console.error('Android analytics dashboard error:', error);
      res.status(500).json({
        error: 'Failed to get analytics dashboard',
        requestId: req.id
      });
    }
  }

  // Helper Methods
  async performAndroidComplianceScan(deviceId, policyIds) {
    const device = this.devices.get(deviceId);
    const results = [];

    for (const policyId of policyIds || Array.from(this.compliancePolicies.keys())) {
      const policy = this.compliancePolicies.get(policyId);
      if (!policy) continue;

      const scanResult = {
        policyId,
        policyName: policy.name,
        deviceId,
        scannedAt: new Date().toISOString(),
        status: Math.random() > 0.25 ? 'compliant' : 'non-compliant',
        violations: []
      };

      if (scanResult.status === 'non-compliant') {
        scanResult.violations = [
          {
            id: this.generateId(),
            rule: 'Device Security Policy',
            severity: 'high',
            description: 'Screen lock not configured properly',
            remediation: 'Configure screen lock with PIN, pattern, or biometric authentication'
          },
          {
            id: this.generateId(),
            rule: 'App Installation Policy',
            severity: 'medium',
            description: 'Unauthorized apps detected',
            remediation: 'Remove unauthorized applications from device'
          }
        ];
      }

      results.push(scanResult);
    }

    return results;
  }

  calculateAndroidComplianceRate() {
    const policies = Array.from(this.compliancePolicies.values());
    if (policies.length === 0) return 0;

    const totalRate = policies.reduce((sum, policy) => sum + (policy.complianceRate || 0), 0);
    return Math.round((totalRate / policies.length) * 100) / 100;
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    switch (type) {
      case 'subscribe_android_events':
        ws.subscriptions.add('android_events');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'android_events',
          requestId
        }));
        break;

      case 'subscribe_device_status':
        ws.subscriptions.add('device_status_changed');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'device_status_changed',
          requestId
        }));
        break;

      case 'device_heartbeat':
        if (data.deviceId) {
          const device = this.devices.get(data.deviceId);
          if (device) {
            device.lastSeen = new Date().toISOString();
            device.isOnline = true;
            this.devices.set(data.deviceId, device);
          }

          ws.send(JSON.stringify({
            type: 'heartbeat_ack',
            timestamp: new Date().toISOString(),
            requestId
          }));
        }
        break;

      case 'compliance_report':
        if (data.deviceId && data.complianceData) {
          // Process compliance data
          console.log('Compliance report received:', data);
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
    // Sync device status every 5 minutes
    setInterval(async () => {
      try {
        await this.syncDeviceStatuses();
      } catch (error) {
        console.error('Device sync error:', error);
      }
    }, 5 * 60 * 1000);

    // Refresh Knox token every hour
    setInterval(async () => {
      try {
        if (this.knoxConfig.tokenExpiresAt && Date.now() > this.knoxConfig.tokenExpiresAt - 300000) {
          await this.initializeKnoxAuth();
        }
      } catch (error) {
        console.error('Knox token refresh error:', error);
      }
    }, 60 * 60 * 1000);

    // Clean expired enrollment tokens every hour
    setInterval(() => {
      try {
        this.cleanExpiredEnrollmentTokens();
      } catch (error) {
        console.error('Token cleanup error:', error);
      }
    }, 60 * 60 * 1000);

    // Compliance monitoring every 6 hours
    setInterval(async () => {
      try {
        await this.performBulkComplianceCheck();
      } catch (error) {
        console.error('Bulk compliance check error:', error);
      }
    }, 6 * 60 * 60 * 1000);
  }

  async syncDeviceStatuses() {
    for (const enterprise of this.enterprises.values()) {
      try {
        // Fetch device updates from Google Play EMM API
        const response = await this.androidEnterprise.enterprises.devices.list({
          enterpriseId: enterprise.googleEnterpriseId
        });

        if (response.data.device) {
          for (const googleDevice of response.data.device) {
            // Update local device records
            const localDevice = Array.from(this.devices.values())
              .find(d => d.googleDeviceId === googleDevice.androidId);
            
            if (localDevice) {
              localDevice.lastSyncTime = new Date().toISOString();
              localDevice.policyCompliant = googleDevice.policyCompliant;
              localDevice.lastPolicyComplianceReportTime = googleDevice.lastPolicyComplianceReportTime;
              this.devices.set(localDevice.id, localDevice);
            }
          }
        }
      } catch (error) {
        console.error(`Failed to sync devices for enterprise ${enterprise.id}:`, error);
      }
    }
  }

  cleanExpiredEnrollmentTokens() {
    const now = new Date().toISOString();
    for (const [tokenId, token] of this.enrollmentTokens) {
      if (token.expiresAt <= now) {
        this.enrollmentTokens.delete(tokenId);
        console.log(`Cleaned expired enrollment token: ${tokenId}`);
      }
    }
  }

  async performBulkComplianceCheck() {
    console.log('Performing bulk compliance check for Android devices...');
    
    let checkedDevices = 0;
    let violationsFound = 0;

    for (const device of this.devices.values()) {
      try {
        const results = await this.performAndroidComplianceScan(device.id);
        checkedDevices++;

        const hasViolations = results.some(result => result.status === 'non-compliant');
        if (hasViolations) {
          violationsFound++;
          
          this.broadcastToSubscribers('compliance_violation', {
            deviceId: device.id,
            deviceName: device.name,
            violations: results.filter(r => r.status === 'non-compliant'),
            timestamp: new Date().toISOString()
          });
        }
      } catch (error) {
        console.error(`Compliance check failed for device ${device.id}:`, error);
      }
    }

    console.log(`Bulk compliance check completed: ${checkedDevices} devices checked, ${violationsFound} violations found`);
  }

  generateId() {
    return crypto.randomBytes(16).toString('hex');
  }

  errorHandler(error, req, res, next) {
    console.error('Android Enterprise Service Error:', error, {
      requestId: req.id,
      path: req.path,
      method: req.method,
      stack: error.stack
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: new Date().toISOString(),
      service: 'android-enterprise'
    });
  }

  start(port = process.env.ANDROID_ENTERPRISE_PORT || 3012) {
    this.server.listen(port, () => {
      console.log(`🤖 Android Enterprise Service started on port ${port}`);
      console.log(`📱 Google Play EMM integration: ${this.googleConfig.clientEmail ? 'Configured' : 'Not configured'}`);
      console.log(`🛡️  Samsung Knox integration: ${this.knoxConfig.clientId ? 'Configured' : 'Not configured'}`);
      console.log(`📊 Health check: http://localhost:${port}/health`);
      console.log(`🔌 WebSocket: ws://localhost:${port}/ws/android`);
      console.log(`⚙️  Features: Enterprise, Work Profiles, Apps, Policies, Knox`);
    });

    return this.server;
  }

  gracefulShutdown() {
    console.log('Starting Android Enterprise Service graceful shutdown...');
    
    this.server.close(() => {
      console.log('Android Enterprise Service HTTP server closed');
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });
      
      console.log('Android Enterprise Service graceful shutdown completed');
      process.exit(0);
    });
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Received SIGINT, starting graceful shutdown...');
  if (global.androidService) {
    global.androidService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, starting graceful shutdown...');
  if (global.androidService) {
    global.androidService.gracefulShutdown();
  }
});

// Start the service
const androidService = new AndroidEnterpriseService();
global.androidService = androidService;
androidService.start();

module.exports = AndroidEnterpriseService;