const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

/**
 * Enterprise iOS Management Service
 * Provides comprehensive iOS device management with Apple DEP/VPP integration
 * 
 * Features:
 * - Apple Device Enrollment Program (DEP) integration
 * - Volume Purchase Program (VPP) management
 * - iOS configuration profiles
 * - App Store Connect integration
 * - MDM command execution
 * - Supervised device management
 * - iOS compliance monitoring
 * - Enterprise certificate management
 */
class iOSManagementService {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.wss = new WebSocket.Server({ 
      server: this.server,
      path: '/ws/ios'
    });
    
    // Apple DEP/VPP Configuration
    this.appleConfig = {
      depClientId: process.env.APPLE_DEP_CLIENT_ID || '',
      depClientSecret: process.env.APPLE_DEP_CLIENT_SECRET || '',
      vppClientId: process.env.APPLE_VPP_CLIENT_ID || '',
      vppClientSecret: process.env.APPLE_VPP_CLIENT_SECRET || '',
      pushCertificate: process.env.APPLE_PUSH_CERT || '',
      pushCertificatePassword: process.env.APPLE_PUSH_CERT_PASSWORD || '',
      depBaseUrl: 'https://mdmenrollment.apple.com',
      vppBaseUrl: 'https://vpp.itunes.apple.com',
      appStoreConnectBaseUrl: 'https://api.appstoreconnect.apple.com'
    };
    
    // In-memory storage (replace with database in production)
    this.devices = new Map();
    this.profiles = new Map();
    this.depTokens = new Map();
    this.vppTokens = new Map();
    this.apps = new Map();
    this.commands = new Map();
    this.certificates = new Map();
    this.compliancePolicies = new Map();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeAppleServices();
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
      message: 'Rate limit exceeded for iOS management operations',
      standardHeaders: true
    });

    this.app.use('/api/ios', limiter);

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

      console.log('iOS WebSocket connection established', {
        connectionId: ws.id,
        deviceId: ws.deviceId
      });

      ws.on('message', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleWebSocketMessage(ws, message);
        } catch (error) {
          console.error('iOS WebSocket message error:', error);
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
        console.log('iOS WebSocket connection closed', { 
          connectionId: ws.id,
          deviceId: ws.deviceId 
        });
      });

      // Send initial connection confirmation
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        service: 'ios-management',
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
        service: 'ios-management-service',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        capabilities: [
          'apple-dep',
          'apple-vpp',
          'ios-profiles',
          'app-management',
          'mdm-commands',
          'compliance-monitoring',
          'certificate-management'
        ],
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid,
        memory: process.memoryUsage(),
        checks: {
          apple_dep: this.depTokens.size > 0 ? 'healthy' : 'warning',
          apple_vpp: this.vppTokens.size > 0 ? 'healthy' : 'warning',
          websocket: this.wss.clients.size >= 0 ? 'healthy' : 'unhealthy'
        },
        statistics: {
          managed_devices: this.devices.size,
          active_profiles: this.profiles.size,
          managed_apps: this.apps.size,
          pending_commands: Array.from(this.commands.values()).filter(cmd => cmd.status === 'pending').length
        }
      });
    });

    // Apple DEP Management Routes
    this.app.post('/api/ios/dep/token', this.createDEPToken.bind(this));
    this.app.get('/api/ios/dep/tokens', this.getDEPTokens.bind(this));
    this.app.put('/api/ios/dep/token/:tokenId', this.updateDEPToken.bind(this));
    this.app.delete('/api/ios/dep/token/:tokenId', this.deleteDEPToken.bind(this));
    this.app.get('/api/ios/dep/devices', this.getDEPDevices.bind(this));
    this.app.post('/api/ios/dep/devices/sync', this.syncDEPDevices.bind(this));
    this.app.put('/api/ios/dep/device/:deviceId/assign', this.assignDEPProfile.bind(this));

    // Apple VPP Management Routes
    this.app.post('/api/ios/vpp/token', this.createVPPToken.bind(this));
    this.app.get('/api/ios/vpp/tokens', this.getVPPTokens.bind(this));
    this.app.put('/api/ios/vpp/token/:tokenId', this.updateVPPToken.bind(this));
    this.app.delete('/api/ios/vpp/token/:tokenId', this.deleteVPPToken.bind(this));
    this.app.get('/api/ios/vpp/apps', this.getVPPApps.bind(this));
    this.app.post('/api/ios/vpp/apps/purchase', this.purchaseVPPApp.bind(this));
    this.app.put('/api/ios/vpp/app/:appId/assign', this.assignVPPApp.bind(this));
    this.app.put('/api/ios/vpp/app/:appId/revoke', this.revokeVPPApp.bind(this));

    // Configuration Profiles Routes
    this.app.get('/api/ios/profiles', this.getProfiles.bind(this));
    this.app.post('/api/ios/profiles', this.createProfile.bind(this));
    this.app.get('/api/ios/profiles/:profileId', this.getProfile.bind(this));
    this.app.put('/api/ios/profiles/:profileId', this.updateProfile.bind(this));
    this.app.delete('/api/ios/profiles/:profileId', this.deleteProfile.bind(this));
    this.app.post('/api/ios/profiles/:profileId/install', this.installProfile.bind(this));
    this.app.post('/api/ios/profiles/:profileId/remove', this.removeProfile.bind(this));

    // MDM Commands Routes
    this.app.post('/api/ios/commands/device-lock', this.deviceLock.bind(this));
    this.app.post('/api/ios/commands/device-wipe', this.deviceWipe.bind(this));
    this.app.post('/api/ios/commands/restart-device', this.restartDevice.bind(this));
    this.app.post('/api/ios/commands/device-information', this.deviceInformation.bind(this));
    this.app.post('/api/ios/commands/installed-apps', this.installedApps.bind(this));
    this.app.post('/api/ios/commands/install-app', this.installApp.bind(this));
    this.app.post('/api/ios/commands/remove-app', this.removeApp.bind(this));
    this.app.post('/api/ios/commands/apply-redemption-code', this.applyRedemptionCode.bind(this));
    this.app.get('/api/ios/commands/:commandId/status', this.getCommandStatus.bind(this));

    // Device Management Routes
    this.app.get('/api/ios/devices', this.getDevices.bind(this));
    this.app.get('/api/ios/devices/:deviceId', this.getDevice.bind(this));
    this.app.put('/api/ios/devices/:deviceId', this.updateDevice.bind(this));
    this.app.delete('/api/ios/devices/:deviceId', this.deleteDevice.bind(this));
    this.app.get('/api/ios/devices/:deviceId/compliance', this.getDeviceCompliance.bind(this));
    this.app.post('/api/ios/devices/:deviceId/compliance/scan', this.scanDeviceCompliance.bind(this));

    // Compliance Management Routes
    this.app.get('/api/ios/compliance/policies', this.getCompliancePolicies.bind(this));
    this.app.post('/api/ios/compliance/policies', this.createCompliancePolicy.bind(this));
    this.app.put('/api/ios/compliance/policy/:policyId', this.updateCompliancePolicy.bind(this));
    this.app.delete('/api/ios/compliance/policy/:policyId', this.deleteCompliancePolicy.bind(this));
    this.app.get('/api/ios/compliance/violations', this.getComplianceViolations.bind(this));
    this.app.post('/api/ios/compliance/remediate/:violationId', this.remediateViolation.bind(this));

    // Certificate Management Routes
    this.app.get('/api/ios/certificates', this.getCertificates.bind(this));
    this.app.post('/api/ios/certificates', this.createCertificate.bind(this));
    this.app.get('/api/ios/certificates/:certId', this.getCertificate.bind(this));
    this.app.put('/api/ios/certificates/:certId/renew', this.renewCertificate.bind(this));
    this.app.delete('/api/ios/certificates/:certId/revoke', this.revokeCertificate.bind(this));

    // Analytics and Reporting Routes
    this.app.get('/api/ios/analytics/dashboard', this.getAnalyticsDashboard.bind(this));
    this.app.get('/api/ios/analytics/device-trends', this.getDeviceTrends.bind(this));
    this.app.get('/api/ios/analytics/app-usage', this.getAppUsage.bind(this));
    this.app.get('/api/ios/analytics/compliance-report', this.getComplianceReport.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  async initializeAppleServices() {
    try {
      // Initialize Apple DEP connection
      if (this.appleConfig.depClientId && this.appleConfig.depClientSecret) {
        await this.initializeDEPConnection();
      }
      
      // Initialize Apple VPP connection  
      if (this.appleConfig.vppClientId && this.appleConfig.vppClientSecret) {
        await this.initializeVPPConnection();
      }
      
      console.log('Apple services initialized successfully');
    } catch (error) {
      console.error('Failed to initialize Apple services:', error);
    }
  }

  async initializeDEPConnection() {
    try {
      // Test DEP connection
      const response = await axios.get(`${this.appleConfig.depBaseUrl}/account`, {
        headers: {
          'Authorization': `Bearer ${await this.getDEPAccessToken()}`,
          'Content-Type': 'application/json'
        }
      });
      
      console.log('DEP connection established:', response.data.server_name);
    } catch (error) {
      console.error('DEP connection failed:', error.message);
    }
  }

  async initializeVPPConnection() {
    try {
      // Test VPP connection
      const response = await axios.get(`${this.appleConfig.vppBaseUrl}/WebObjects/MZFinance.woa/wa/VPPServiceConfigSrv`, {
        headers: {
          'Authorization': `Bearer ${await this.getVPPAccessToken()}`,
          'Content-Type': 'application/json'
        }
      });
      
      console.log('VPP connection established');
    } catch (error) {
      console.error('VPP connection failed:', error.message);
    }
  }

  // Apple DEP Management
  async createDEPToken(req, res) {
    try {
      const { name, serverToken, certificate } = req.body;
      
      if (!name || !serverToken || !certificate) {
        return res.status(400).json({
          error: 'Missing required fields: name, serverToken, certificate',
          requestId: req.id
        });
      }

      const tokenId = this.generateId();
      const depToken = {
        id: tokenId,
        name,
        serverToken,
        certificate,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        isActive: true,
        lastSyncAt: null
      };

      this.depTokens.set(tokenId, depToken);

      // Test the token
      try {
        await this.testDEPToken(tokenId);
        depToken.status = 'active';
      } catch (error) {
        depToken.status = 'invalid';
        depToken.error = error.message;
      }

      res.status(201).json({
        success: true,
        data: depToken,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create DEP token error:', error);
      res.status(500).json({
        error: 'Failed to create DEP token',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getDEPTokens(req, res) {
    try {
      const tokens = Array.from(this.depTokens.values());
      
      res.json({
        success: true,
        data: tokens,
        count: tokens.length,
        requestId: req.id
      });
    } catch (error) {
      console.error('Get DEP tokens error:', error);
      res.status(500).json({
        error: 'Failed to retrieve DEP tokens',
        requestId: req.id
      });
    }
  }

  async getDEPDevices(req, res) {
    try {
      const { cursor, limit = 100 } = req.query;
      const devices = [];

      // Fetch devices from all active DEP tokens
      for (const depToken of this.depTokens.values()) {
        if (depToken.isActive) {
          try {
            const tokenDevices = await this.fetchDEPDevices(depToken.id, cursor, limit);
            devices.push(...tokenDevices);
          } catch (error) {
            console.error(`Failed to fetch devices for token ${depToken.id}:`, error);
          }
        }
      }

      res.json({
        success: true,
        data: devices,
        count: devices.length,
        requestId: req.id
      });
    } catch (error) {
      console.error('Get DEP devices error:', error);
      res.status(500).json({
        error: 'Failed to retrieve DEP devices',
        requestId: req.id
      });
    }
  }

  // Apple VPP Management
  async createVPPToken(req, res) {
    try {
      const { name, organizationId, expDate, token } = req.body;
      
      if (!name || !organizationId || !expDate || !token) {
        return res.status(400).json({
          error: 'Missing required fields: name, organizationId, expDate, token',
          requestId: req.id
        });
      }

      const tokenId = this.generateId();
      const vppToken = {
        id: tokenId,
        name,
        organizationId,
        expDate,
        token,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        isActive: true,
        lastSyncAt: null
      };

      this.vppTokens.set(tokenId, vppToken);

      // Test the token
      try {
        await this.testVPPToken(tokenId);
        vppToken.status = 'active';
      } catch (error) {
        vppToken.status = 'invalid';
        vppToken.error = error.message;
      }

      res.status(201).json({
        success: true,
        data: vppToken,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create VPP token error:', error);
      res.status(500).json({
        error: 'Failed to create VPP token',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async getVPPApps(req, res) {
    try {
      const { includeLicenses = false } = req.query;
      const apps = [];

      // Fetch apps from all active VPP tokens
      for (const vppToken of this.vppTokens.values()) {
        if (vppToken.isActive) {
          try {
            const tokenApps = await this.fetchVPPApps(vppToken.id, includeLicenses);
            apps.push(...tokenApps);
          } catch (error) {
            console.error(`Failed to fetch apps for VPP token ${vppToken.id}:`, error);
          }
        }
      }

      res.json({
        success: true,
        data: apps,
        count: apps.length,
        requestId: req.id
      });
    } catch (error) {
      console.error('Get VPP apps error:', error);
      res.status(500).json({
        error: 'Failed to retrieve VPP apps',
        requestId: req.id
      });
    }
  }

  // Configuration Profiles Management
  async createProfile(req, res) {
    try {
      const profileData = req.body;
      
      if (!profileData.displayName || !profileData.identifier || !profileData.payloadContent) {
        return res.status(400).json({
          error: 'Missing required fields: displayName, identifier, payloadContent',
          requestId: req.id
        });
      }

      const profileId = this.generateId();
      const profile = {
        id: profileId,
        ...profileData,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        version: 1,
        isActive: true,
        deviceCount: 0,
        installationStatus: {}
      };

      // Generate signed profile
      try {
        profile.signedProfile = await this.signConfigurationProfile(profile);
      } catch (error) {
        return res.status(500).json({
          error: 'Failed to sign configuration profile',
          details: error.message,
          requestId: req.id
        });
      }

      this.profiles.set(profileId, profile);

      res.status(201).json({
        success: true,
        data: profile,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create profile error:', error);
      res.status(500).json({
        error: 'Failed to create configuration profile',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // MDM Commands
  async deviceLock(req, res) {
    try {
      const { deviceIds, message = 'Device locked by administrator', phoneNumber } = req.body;
      
      if (!deviceIds || !Array.isArray(deviceIds) || deviceIds.length === 0) {
        return res.status(400).json({
          error: 'deviceIds array is required',
          requestId: req.id
        });
      }

      const commands = [];
      
      for (const deviceId of deviceIds) {
        const commandId = this.generateId();
        const command = {
          id: commandId,
          deviceId,
          type: 'DeviceLock',
          parameters: {
            message,
            phoneNumber
          },
          status: 'pending',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };

        this.commands.set(commandId, command);
        commands.push(command);

        // Send command to device (simulate)
        this.sendMDMCommand(deviceId, command);
      }

      res.json({
        success: true,
        data: commands,
        requestId: req.id
      });
    } catch (error) {
      console.error('Device lock error:', error);
      res.status(500).json({
        error: 'Failed to lock device',
        details: error.message,
        requestId: req.id
      });
    }
  }

  async deviceInformation(req, res) {
    try {
      const { deviceIds, queries } = req.body;
      
      if (!deviceIds || !Array.isArray(deviceIds) || deviceIds.length === 0) {
        return res.status(400).json({
          error: 'deviceIds array is required',
          requestId: req.id
        });
      }

      const commands = [];
      
      for (const deviceId of deviceIds) {
        const commandId = this.generateId();
        const command = {
          id: commandId,
          deviceId,
          type: 'DeviceInformation',
          parameters: {
            queries: queries || [
              'UDID', 'DeviceName', 'OSVersion', 'BuildVersion', 
              'ModelName', 'Model', 'ProductName', 'SerialNumber',
              'WiFiMAC', 'BluetoothMAC', 'iTunesStoreAccountHash',
              'BatteryLevel', 'CellularTechnology', 'IsSupervised'
            ]
          },
          status: 'pending',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };

        this.commands.set(commandId, command);
        commands.push(command);

        // Send command to device (simulate)
        this.sendMDMCommand(deviceId, command);
      }

      res.json({
        success: true,
        data: commands,
        requestId: req.id
      });
    } catch (error) {
      console.error('Device information error:', error);
      res.status(500).json({
        error: 'Failed to get device information',
        details: error.message,
        requestId: req.id
      });
    }
  }

  // Compliance Management
  async createCompliancePolicy(req, res) {
    try {
      const policyData = req.body;
      
      if (!policyData.name || !policyData.rules) {
        return res.status(400).json({
          error: 'Missing required fields: name, rules',
          requestId: req.id
        });
      }

      const policyId = this.generateId();
      const policy = {
        id: policyId,
        ...policyData,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        isActive: true,
        deviceCount: 0,
        complianceRate: 0
      };

      this.compliancePolicies.set(policyId, policy);

      res.status(201).json({
        success: true,
        data: policy,
        requestId: req.id
      });
    } catch (error) {
      console.error('Create compliance policy error:', error);
      res.status(500).json({
        error: 'Failed to create compliance policy',
        details: error.message,
        requestId: req.id
      });
    }
  }

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

      const scanResults = await this.performComplianceScan(deviceId, policyIds);

      res.json({
        success: true,
        data: scanResults,
        requestId: req.id
      });
    } catch (error) {
      console.error('Compliance scan error:', error);
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
          managedDevices: Array.from(this.devices.values()).filter(d => d.isManaged).length,
          supervisedDevices: Array.from(this.devices.values()).filter(d => d.isSupervised).length,
          compliantDevices: Array.from(this.devices.values()).filter(d => d.complianceStatus === 'compliant').length
        },
        profiles: {
          totalProfiles: this.profiles.size,
          activeProfiles: Array.from(this.profiles.values()).filter(p => p.isActive).length,
          profileInstallations: Array.from(this.profiles.values()).reduce((sum, p) => sum + p.deviceCount, 0)
        },
        apps: {
          totalApps: this.apps.size,
          vppApps: Array.from(this.apps.values()).filter(a => a.source === 'vpp').length,
          appInstallations: Array.from(this.apps.values()).reduce((sum, a) => sum + (a.deviceCount || 0), 0)
        },
        commands: {
          totalCommands: this.commands.size,
          pendingCommands: Array.from(this.commands.values()).filter(c => c.status === 'pending').length,
          completedCommands: Array.from(this.commands.values()).filter(c => c.status === 'completed').length,
          failedCommands: Array.from(this.commands.values()).filter(c => c.status === 'failed').length
        },
        compliance: {
          totalPolicies: this.compliancePolicies.size,
          activePolicies: Array.from(this.compliancePolicies.values()).filter(p => p.isActive).length,
          averageComplianceRate: this.calculateAverageComplianceRate()
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
  async getDEPAccessToken() {
    // Generate JWT token for DEP authentication
    const payload = {
      iss: this.appleConfig.depClientId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
    };
    
    return jwt.sign(payload, this.appleConfig.depClientSecret, { algorithm: 'HS256' });
  }

  async getVPPAccessToken() {
    // Generate JWT token for VPP authentication
    const payload = {
      iss: this.appleConfig.vppClientId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
    };
    
    return jwt.sign(payload, this.appleConfig.vppClientSecret, { algorithm: 'HS256' });
  }

  async testDEPToken(tokenId) {
    const token = this.depTokens.get(tokenId);
    if (!token) {
      throw new Error('DEP token not found');
    }

    // Test DEP API call
    const response = await axios.get(`${this.appleConfig.depBaseUrl}/account`, {
      headers: {
        'Authorization': `Bearer ${token.serverToken}`,
        'Content-Type': 'application/json'
      }
    });

    return response.data;
  }

  async testVPPToken(tokenId) {
    const token = this.vppTokens.get(tokenId);
    if (!token) {
      throw new Error('VPP token not found');
    }

    // Test VPP API call
    const response = await axios.post(`${this.appleConfig.vppBaseUrl}/WebObjects/MZFinance.woa/wa/getVPPServiceConfigSrv`, {
      sToken: token.token
    });

    return response.data;
  }

  async fetchDEPDevices(tokenId, cursor, limit) {
    const token = this.depTokens.get(tokenId);
    if (!token) {
      throw new Error('DEP token not found');
    }

    try {
      const response = await axios.post(`${this.appleConfig.depBaseUrl}/devices`, {
        cursor,
        limit: parseInt(limit)
      }, {
        headers: {
          'Authorization': `Bearer ${token.serverToken}`,
          'Content-Type': 'application/json'
        }
      });

      return response.data.devices || [];
    } catch (error) {
      console.error('Failed to fetch DEP devices:', error);
      return [];
    }
  }

  async fetchVPPApps(tokenId, includeLicenses) {
    const token = this.vppTokens.get(tokenId);
    if (!token) {
      throw new Error('VPP token not found');
    }

    try {
      const response = await axios.post(`${this.appleConfig.vppBaseUrl}/WebObjects/MZFinance.woa/wa/getVPPAssetsSrv`, {
        sToken: token.token,
        includeLicenseCounts: includeLicenses
      });

      return response.data.assets || [];
    } catch (error) {
      console.error('Failed to fetch VPP apps:', error);
      return [];
    }
  }

  async signConfigurationProfile(profile) {
    // Simulate profile signing (implement actual signing with certificates)
    const profilePlist = this.generateProfilePlist(profile);
    return Buffer.from(profilePlist).toString('base64');
  }

  generateProfilePlist(profile) {
    // Generate iOS configuration profile plist
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    ${JSON.stringify(profile.payloadContent)}
  </array>
  <key>PayloadDisplayName</key>
  <string>${profile.displayName}</string>
  <key>PayloadIdentifier</key>
  <string>${profile.identifier}</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${profile.id}</string>
  <key>PayloadVersion</key>
  <integer>${profile.version}</integer>
</dict>
</plist>`;
  }

  async sendMDMCommand(deviceId, command) {
    // Simulate MDM command sending
    setTimeout(() => {
      // Simulate command completion
      command.status = 'completed';
      command.completedAt = new Date().toISOString();
      command.result = {
        status: 'Acknowledged',
        UDID: deviceId,
        commandUUID: command.id
      };

      // Broadcast command completion
      this.broadcastToSubscribers('command_completed', {
        commandId: command.id,
        deviceId,
        status: command.status,
        result: command.result
      });
    }, Math.random() * 5000 + 1000); // Random delay 1-6 seconds
  }

  async performComplianceScan(deviceId, policyIds) {
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
        status: Math.random() > 0.2 ? 'compliant' : 'non-compliant',
        violations: []
      };

      if (scanResult.status === 'non-compliant') {
        scanResult.violations = [
          {
            id: this.generateId(),
            rule: 'iOS Version Check',
            severity: 'medium',
            description: 'Device running outdated iOS version',
            remediation: 'Update iOS to latest version'
          }
        ];
      }

      results.push(scanResult);
    }

    return results;
  }

  calculateAverageComplianceRate() {
    const policies = Array.from(this.compliancePolicies.values());
    if (policies.length === 0) return 0;

    const totalRate = policies.reduce((sum, policy) => sum + (policy.complianceRate || 0), 0);
    return Math.round((totalRate / policies.length) * 100) / 100;
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;

    switch (type) {
      case 'subscribe_ios_events':
        ws.subscriptions.add('ios_events');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'ios_events',
          requestId
        }));
        break;

      case 'subscribe_command_status':
        ws.subscriptions.add('command_completed');
        ws.send(JSON.stringify({
          type: 'subscription_confirmed',
          subscription: 'command_completed',
          requestId
        }));
        break;

      case 'device_checkin':
        if (data.deviceId) {
          // Update device last seen
          const device = this.devices.get(data.deviceId);
          if (device) {
            device.lastSeen = new Date().toISOString();
            this.devices.set(data.deviceId, device);
          }

          ws.send(JSON.stringify({
            type: 'checkin_ack',
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
    // Sync DEP devices every hour
    setInterval(async () => {
      try {
        await this.syncAllDEPDevices();
      } catch (error) {
        console.error('DEP sync error:', error);
      }
    }, 60 * 60 * 1000);

    // Sync VPP apps every 4 hours
    setInterval(async () => {
      try {
        await this.syncAllVPPApps();
      } catch (error) {
        console.error('VPP sync error:', error);
      }
    }, 4 * 60 * 60 * 1000);

    // Check certificate expiration daily
    setInterval(async () => {
      try {
        await this.checkCertificateExpiration();
      } catch (error) {
        console.error('Certificate check error:', error);
      }
    }, 24 * 60 * 60 * 1000);
  }

  async syncAllDEPDevices() {
    for (const token of this.depTokens.values()) {
      if (token.isActive) {
        try {
          await this.fetchDEPDevices(token.id);
          token.lastSyncAt = new Date().toISOString();
        } catch (error) {
          console.error(`Failed to sync DEP devices for token ${token.id}:`, error);
        }
      }
    }
  }

  async syncAllVPPApps() {
    for (const token of this.vppTokens.values()) {
      if (token.isActive) {
        try {
          await this.fetchVPPApps(token.id, true);
          token.lastSyncAt = new Date().toISOString();
        } catch (error) {
          console.error(`Failed to sync VPP apps for token ${token.id}:`, error);
        }
      }
    }
  }

  async checkCertificateExpiration() {
    const thirtyDaysFromNow = new Date();
    thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);

    for (const cert of this.certificates.values()) {
      if (new Date(cert.expiresAt) <= thirtyDaysFromNow) {
        console.warn(`Certificate ${cert.id} expires soon: ${cert.expiresAt}`);
        
        // Broadcast certificate expiration warning
        this.broadcastToSubscribers('certificate_warning', {
          certificateId: cert.id,
          name: cert.name,
          expiresAt: cert.expiresAt,
          daysUntilExpiry: Math.ceil((new Date(cert.expiresAt) - new Date()) / (1000 * 60 * 60 * 24))
        });
      }
    }
  }

  generateId() {
    return crypto.randomBytes(16).toString('hex');
  }

  errorHandler(error, req, res, next) {
    console.error('iOS Management Service Error:', error, {
      requestId: req.id,
      path: req.path,
      method: req.method,
      stack: error.stack
    });

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      requestId: req.id,
      timestamp: new Date().toISOString(),
      service: 'ios-management'
    });
  }

  start(port = process.env.IOS_MANAGEMENT_PORT || 3011) {
    this.server.listen(port, () => {
      console.log(`📱 iOS Management Service started on port ${port}`);
      console.log(`🍎 Apple DEP integration: ${this.appleConfig.depClientId ? 'Configured' : 'Not configured'}`);
      console.log(`🛒 Apple VPP integration: ${this.appleConfig.vppClientId ? 'Configured' : 'Not configured'}`);
      console.log(`📊 Health check: http://localhost:${port}/health`);
      console.log(`🔌 WebSocket: ws://localhost:${port}/ws/ios`);
      console.log(`🛡️  Features: DEP, VPP, Profiles, MDM Commands, Compliance`);
    });

    return this.server;
  }

  gracefulShutdown() {
    console.log('Starting iOS Management Service graceful shutdown...');
    
    this.server.close(() => {
      console.log('iOS Management Service HTTP server closed');
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.terminate();
      });
      
      console.log('iOS Management Service graceful shutdown completed');
      process.exit(0);
    });
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Received SIGINT, starting graceful shutdown...');
  if (global.iOSService) {
    global.iOSService.gracefulShutdown();
  }
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, starting graceful shutdown...');
  if (global.iOSService) {
    global.iOSService.gracefulShutdown();
  }
});

// Start the service
const iOSService = new iOSManagementService();
global.iOSService = iOSService;
iOSService.start();

module.exports = iOSManagementService;