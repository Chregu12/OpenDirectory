const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const WebSocket = require('ws');
const EventEmitter = require('events');
const cluster = require('cluster');
const os = require('os');
const { promisify } = require('util');
const CircuitBreaker = require('opossum');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const ioredis = require('ioredis');
const { v4: uuidv4 } = require('uuid');

const logger = require('./utils/logger');
const config = require('./utils/config');

// Enhanced network management modules
const DNSManager = require('./services/dnsManager');
const DHCPManager = require('./services/dhcpManager');
const FileShareManager = require('./services/fileShareManager');
const NetworkDiscovery = require('./services/networkDiscovery');
const VLANManager = require('./services/vlanManager');
const FirewallManager = require('./services/firewallManager');
const VPNManager = require('./services/vpnManager');
const LoadBalancer = require('./services/loadBalancer');
const NetworkMonitoring = require('./services/networkMonitoring');
const SecurityScanner = require('./services/securityScanner');
const BandwidthManager = require('./services/bandwidthManager');
const NetworkAnalytics = require('./services/networkAnalytics');
const PolicyEngine = require('./services/policyEngine');
const ComplianceManager = require('./services/complianceManager');

class EnterpriseNetworkInfrastructureService extends EventEmitter {
  constructor() {
    super();
    
    this.app = express();
    this.server = null;
    this.wss = null;
    this.workers = new Map();
    this.redis = null;
    this.circuitBreakers = new Map();
    this.requestId = 0;
    
    // Enhanced network management services
    this.dnsManager = new DNSManager();
    this.dhcpManager = new DHCPManager();
    this.fileShareManager = new FileShareManager();
    this.networkDiscovery = new NetworkDiscovery();
    this.vlanManager = new VLANManager();
    this.firewallManager = new FirewallManager();
    this.vpnManager = new VPNManager();
    this.loadBalancer = new LoadBalancer();
    this.networkMonitoring = new NetworkMonitoring();
    this.securityScanner = new SecurityScanner();
    this.bandwidthManager = new BandwidthManager();
    this.networkAnalytics = new NetworkAnalytics();
    this.policyEngine = new PolicyEngine();
    this.complianceManager = new ComplianceManager();
    
    // Circuit breakers for resilience
    this.initializeCircuitBreakers();
    
    // Event handlers
    this.setupEventHandlers();
    
    // Initialize services
    this.initializeRedis();
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
  }
  
  initializeRedis() {
    this.redis = new ioredis({
      host: config.redis.host || 'localhost',
      port: config.redis.port || 6379,
      password: config.redis.password,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true
    });
    
    this.redis.on('connect', () => {
      logger.info('🔌 Connected to Redis');
    });
    
    this.redis.on('error', (error) => {
      logger.error('❌ Redis connection error:', error);
    });
  }
  
  initializeCircuitBreakers() {
    const breakerOptions = {
      timeout: 3000,
      errorThresholdPercentage: 50,
      resetTimeout: 30000
    };
    
    this.circuitBreakers.set('dns', new CircuitBreaker(this.dnsManager.performOperation.bind(this.dnsManager), breakerOptions));
    this.circuitBreakers.set('dhcp', new CircuitBreaker(this.dhcpManager.performOperation.bind(this.dhcpManager), breakerOptions));
    this.circuitBreakers.set('fileShare', new CircuitBreaker(this.fileShareManager.performOperation.bind(this.fileShareManager), breakerOptions));
    this.circuitBreakers.set('firewall', new CircuitBreaker(this.firewallManager.performOperation.bind(this.firewallManager), breakerOptions));
    
    // Circuit breaker event handlers
    this.circuitBreakers.forEach((breaker, service) => {
      breaker.on('open', () => {
        logger.warn(`🔴 Circuit breaker OPEN for ${service}`);
        this.emit('circuitBreakerOpen', service);
      });
      
      breaker.on('halfOpen', () => {
        logger.info(`🟡 Circuit breaker HALF-OPEN for ${service}`);
        this.emit('circuitBreakerHalfOpen', service);
      });
      
      breaker.on('close', () => {
        logger.info(`🟢 Circuit breaker CLOSED for ${service}`);
        this.emit('circuitBreakerClosed', service);
      });
    });
  }

  initializeMiddleware() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "ws:", "wss:"]
        }
      }
    }));
    
    // Compression
    this.app.use(compression());
    
    // CORS with enhanced configuration
    this.app.use(cors({
      origin: config.cors.allowedOrigins || ['http://localhost:3000'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Network-Zone']
    }));
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 1000, // limit each IP to 1000 requests per windowMs
      message: 'Too many requests from this IP',
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use(limiter);
    
    // Body parsing with size limits
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request ID and logging
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || this.generateRequestId();
      res.setHeader('X-Request-ID', req.id);
      
      const startTime = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info(`${req.method} ${req.path} - ${res.statusCode}`, { 
          requestId: req.id, 
          ip: req.ip, 
          duration,
          userAgent: req.headers['user-agent']
        });
      });
      
      next();
    });
    
    // Network zone detection
    this.app.use(async (req, res, next) => {
      try {
        req.networkZone = await this.networkDiscovery.detectNetworkZone(req.ip);
        next();
      } catch (error) {
        logger.warn('Failed to detect network zone:', error);
        req.networkZone = 'unknown';
        next();
      }
    });
  }

  initializeWebSocket() {
    this.wss = new WebSocket.Server({ 
      port: config.websocket.port || 8081,
      verifyClient: this.verifyWebSocketClient.bind(this),
      perMessageDeflate: true,
      maxPayload: 1024 * 1024 // 1MB
    });
    
    this.wss.on('connection', (ws, req) => {
      ws.id = this.generateRequestId();
      ws.isAlive = true;
      ws.subscriptions = new Set();
      ws.networkZone = req.headers['x-network-zone'] || 'unknown';
      ws.authenticated = false;
      ws.permissions = [];
      ws.lastActivity = Date.now();
      
      logger.info('🔌 WebSocket client connected', { 
        clientId: ws.id, 
        ip: req.socket.remoteAddress,
        networkZone: ws.networkZone
      });
      
      ws.on('message', async (message) => {
        try {
          ws.lastActivity = Date.now();
          const data = JSON.parse(message);
          await this.handleWebSocketMessage(ws, data);
        } catch (error) {
          logger.error('❌ Invalid WebSocket message:', error, { clientId: ws.id });
          ws.send(JSON.stringify({ 
            error: 'Invalid message format',
            requestId: data?.requestId,
            timestamp: new Date().toISOString()
          }));
        }
      });
      
      ws.on('pong', () => {
        ws.isAlive = true;
      });
      
      ws.on('close', (code, reason) => {
        logger.info('🔌 WebSocket client disconnected', { 
          clientId: ws.id,
          code,
          reason: reason.toString()
        });
        this.cleanupClientSubscriptions(ws);
      });
      
      ws.on('error', (error) => {
        logger.error('❌ WebSocket error:', error, { clientId: ws.id });
      });
      
      // Send initial connection confirmation
      ws.send(JSON.stringify({
        type: 'connectionEstablished',
        clientId: ws.id,
        timestamp: new Date().toISOString(),
        capabilities: [
          'networkDiscovery',
          'dnsManagement',
          'dhcpManagement',
          'firewallManagement',
          'vpnManagement',
          'networkMonitoring',
          'securityScanning',
          'bandwidthManagement',
          'networkAnalytics',
          'policyEngine',
          'complianceReporting'
        ]
      }));
    });
    
    // Enhanced health check with activity monitoring
    setInterval(() => {
      const now = Date.now();
      this.wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
          logger.warn('⚠️ Terminating inactive WebSocket client', { clientId: ws.id });
          return ws.terminate();
        }
        
        // Check for inactive connections (30 minutes)
        if (now - ws.lastActivity > 30 * 60 * 1000) {
          logger.warn('⚠️ Terminating idle WebSocket client', { clientId: ws.id });
          return ws.terminate();
        }
        
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
    
    // Broadcast network status updates
    setInterval(() => {
      this.broadcastNetworkStatus();
    }, 60000);
    
    logger.info(`🌐 Enhanced Network WebSocket server started on port ${config.websocket.port || 8081}`);
  }

  async handleWebSocketMessage(ws, message) {
    const { type, data, requestId } = message;
    
    try {
      // Authentication check for protected operations
      if (this.requiresAuth(type) && !ws.authenticated) {
        ws.send(JSON.stringify({
          error: 'Authentication required',
          requestId,
          timestamp: new Date().toISOString()
        }));
        return;
      }
      
      // Permission check
      if (this.requiresPermission(type) && !this.hasPermission(ws, type)) {
        ws.send(JSON.stringify({
          error: 'Insufficient permissions',
          requestId,
          requiredPermission: this.getRequiredPermission(type),
          timestamp: new Date().toISOString()
        }));
        return;
      }
      
      switch (type) {
        case 'authenticate':
          await this.handleAuthentication(ws, data, requestId);
          break;
          
        case 'subscribe':
          await this.handleSubscription(ws, data.subscription, data.options, requestId);
          break;
        
        case 'unsubscribe':
          await this.handleUnsubscription(ws, data.subscription, requestId);
          break;
        
        case 'networkScan':
          await this.handleNetworkScan(ws, data, requestId);
          break;
        
        case 'networkDiscovery':
          await this.handleNetworkDiscovery(ws, data, requestId);
          break;
        
        case 'dnsQuery':
          await this.handleDNSQuery(ws, data, requestId);
          break;
        
        case 'dnsManagement':
          await this.handleDNSManagement(ws, data, requestId);
          break;
        
        case 'dhcpLease':
          await this.handleDHCPLease(ws, data, requestId);
          break;
        
        case 'dhcpManagement':
          await this.handleDHCPManagement(ws, data, requestId);
          break;
        
        case 'firewallRule':
          await this.handleFirewallRule(ws, data, requestId);
          break;
        
        case 'vpnManagement':
          await this.handleVPNManagement(ws, data, requestId);
          break;
        
        case 'bandwidthControl':
          await this.handleBandwidthControl(ws, data, requestId);
          break;
        
        case 'securityScan':
          await this.handleSecurityScan(ws, data, requestId);
          break;
        
        case 'complianceCheck':
          await this.handleComplianceCheck(ws, data, requestId);
          break;
        
        case 'networkAnalytics':
          await this.handleNetworkAnalytics(ws, data, requestId);
          break;
        
        case 'policyApply':
          await this.handlePolicyApplication(ws, data, requestId);
          break;
        
        case 'getNetworkStatus':
          await this.sendNetworkStatus(ws, requestId);
          break;
        
        default:
          ws.send(JSON.stringify({
            error: 'Unknown message type',
            requestId,
            supportedTypes: [
              'authenticate', 'subscribe', 'unsubscribe', 'networkScan', 
              'networkDiscovery', 'dnsQuery', 'dnsManagement', 'dhcpLease', 
              'dhcpManagement', 'firewallRule', 'vpnManagement', 
              'bandwidthControl', 'securityScan', 'complianceCheck', 
              'networkAnalytics', 'policyApply', 'getNetworkStatus'
            ],
            timestamp: new Date().toISOString()
          }));
      }
    } catch (error) {
      logger.error('❌ WebSocket message handling error:', error, { clientId: ws.id, type });
      ws.send(JSON.stringify({
        error: 'Message processing failed',
        requestId,
        details: config.environment === 'development' ? error.message : 'Internal error',
        timestamp: new Date().toISOString()
      }));
    }
  }

  async handleAuthentication(ws, data, requestId) {
    try {
      const { token, clientType } = data;
      
      // Validate token (in real implementation, verify JWT or session token)
      const authResult = await this.validateAuthToken(token);
      
      if (authResult.valid) {
        ws.authenticated = true;
        ws.user = authResult.user;
        ws.permissions = authResult.permissions;
        ws.clientType = clientType;
        
        ws.send(JSON.stringify({
          type: 'authenticationResult',
          requestId,
          success: true,
          permissions: ws.permissions,
          timestamp: new Date().toISOString()
        }));
        
        logger.info('✅ WebSocket client authenticated', { 
          clientId: ws.id, 
          userId: ws.user?.id,
          permissions: ws.permissions.length
        });
      } else {
        ws.send(JSON.stringify({
          type: 'authenticationResult',
          requestId,
          success: false,
          error: 'Invalid authentication token',
          timestamp: new Date().toISOString()
        }));
      }
    } catch (error) {
      logger.error('❌ Authentication error:', error, { clientId: ws.id });
      ws.send(JSON.stringify({
        type: 'authenticationResult',
        requestId,
        success: false,
        error: 'Authentication failed',
        timestamp: new Date().toISOString()
      }));
    }
  }
  
  async handleNetworkScan(ws, data, requestId) {
    const { target, scanType = 'discovery', options = {} } = data;
    
    try {
      const breaker = this.circuitBreakers.get('networkDiscovery') || 
        new CircuitBreaker(this.networkDiscovery.scan.bind(this.networkDiscovery));
      
      const result = await breaker.fire(target, scanType, options);
      
      ws.send(JSON.stringify({
        type: 'networkScanResult',
        requestId,
        data: result,
        timestamp: new Date().toISOString()
      }));
      
      // Log scan activity
      logger.info('🔍 Network scan completed', {
        clientId: ws.id,
        target,
        scanType,
        devicesFound: result.devices?.length || 0
      });
      
      // Broadcast scan update to subscribers
      this.broadcastToSubscribers('networkScan', {
        target,
        scanType,
        timestamp: new Date().toISOString(),
        devicesFound: result.devices?.length || 0
      });
      
    } catch (error) {
      logger.error('❌ Network scan failed:', error, { clientId: ws.id, target });
      ws.send(JSON.stringify({
        type: 'networkScanResult',
        requestId,
        error: 'Network scan failed',
        details: error.message,
        timestamp: new Date().toISOString()
      }));
    }
  }
  
  async handleNetworkDiscovery(ws, data, requestId) {
    try {
      const { subnet, method = 'ping', deep = false } = data;
      
      const discoveryResult = await this.networkDiscovery.discoverDevices(subnet, {
        method,
        deep,
        timeout: 30000
      });
      
      ws.send(JSON.stringify({
        type: 'networkDiscoveryResult',
        requestId,
        data: discoveryResult,
        timestamp: new Date().toISOString()
      }));
      
      // Update network analytics
      await this.networkAnalytics.recordDiscoveryEvent({
        subnet,
        method,
        devicesFound: discoveryResult.devices.length,
        timestamp: new Date()
      });
      
    } catch (error) {
      logger.error('❌ Network discovery failed:', error);
      ws.send(JSON.stringify({
        type: 'networkDiscoveryResult',
        requestId,
        error: 'Network discovery failed',
        details: error.message,
        timestamp: new Date().toISOString()
      }));
    }
  }

  setupEventHandlers() {
    // DNS events
    this.dnsManager.on('recordCreated', (record) => {
      this.broadcast('dnsRecordCreated', record);
      this.auditLog('DNS_RECORD_CREATED', record);
    });
    
    this.dnsManager.on('recordUpdated', (record) => {
      this.broadcast('dnsRecordUpdated', record);
      this.auditLog('DNS_RECORD_UPDATED', record);
    });
    
    this.dnsManager.on('recordDeleted', (recordId) => {
      this.broadcast('dnsRecordDeleted', { recordId });
      this.auditLog('DNS_RECORD_DELETED', { recordId });
    });
    
    // DHCP events
    this.dhcpManager.on('leaseAssigned', (lease) => {
      this.broadcast('dhcpLeaseAssigned', lease);
      this.auditLog('DHCP_LEASE_ASSIGNED', lease);
    });
    
    this.dhcpManager.on('leaseExpired', (lease) => {
      this.broadcast('dhcpLeaseExpired', lease);
      this.auditLog('DHCP_LEASE_EXPIRED', lease);
    });
    
    this.dhcpManager.on('leaseRenewed', (lease) => {
      this.broadcast('dhcpLeaseRenewed', lease);
    });
    
    // Network discovery events
    this.networkDiscovery.on('deviceDiscovered', (device) => {
      this.broadcast('deviceDiscovered', device);
      this.networkAnalytics.recordDeviceEvent('discovered', device);
    });
    
    this.networkDiscovery.on('deviceOffline', (device) => {
      this.broadcast('deviceOffline', device);
      this.networkAnalytics.recordDeviceEvent('offline', device);
    });
    
    this.networkDiscovery.on('deviceOnline', (device) => {
      this.broadcast('deviceOnline', device);
      this.networkAnalytics.recordDeviceEvent('online', device);
    });
    
    // Security events
    this.securityScanner.on('vulnerabilityDetected', (vulnerability) => {
      this.broadcast('securityAlert', vulnerability);
      this.auditLog('SECURITY_VULNERABILITY_DETECTED', vulnerability);
    });
    
    this.securityScanner.on('intrusionDetected', (intrusion) => {
      this.broadcast('securityAlert', intrusion);
      this.auditLog('NETWORK_INTRUSION_DETECTED', intrusion);
    });
    
    // Firewall events
    this.firewallManager.on('ruleAdded', (rule) => {
      this.broadcast('firewallRuleAdded', rule);
      this.auditLog('FIREWALL_RULE_ADDED', rule);
    });
    
    this.firewallManager.on('ruleBlocked', (event) => {
      this.broadcast('firewallBlocked', event);
    });
    
    // VPN events
    this.vpnManager.on('connectionEstablished', (connection) => {
      this.broadcast('vpnConnectionEstablished', connection);
      this.auditLog('VPN_CONNECTION_ESTABLISHED', connection);
    });
    
    this.vpnManager.on('connectionTerminated', (connection) => {
      this.broadcast('vpnConnectionTerminated', connection);
      this.auditLog('VPN_CONNECTION_TERMINATED', connection);
    });
    
    // Bandwidth management events
    this.bandwidthManager.on('bandwidthExceeded', (event) => {
      this.broadcast('bandwidthAlert', event);
      this.auditLog('BANDWIDTH_LIMIT_EXCEEDED', event);
    });
    
    // Policy engine events
    this.policyEngine.on('policyViolation', (violation) => {
      this.broadcast('policyViolation', violation);
      this.auditLog('POLICY_VIOLATION', violation);
    });
    
    this.policyEngine.on('policyApplied', (policy) => {
      this.broadcast('policyApplied', policy);
      this.auditLog('POLICY_APPLIED', policy);
    });
    
    // Network monitoring events
    this.networkMonitoring.on('performanceAlert', (alert) => {
      this.broadcast('networkPerformanceAlert', alert);
    });
    
    this.networkMonitoring.on('outageDetected', (outage) => {
      this.broadcast('networkOutage', outage);
      this.auditLog('NETWORK_OUTAGE_DETECTED', outage);
    });
    
    // File share events
    this.fileShareManager.on('shareCreated', (share) => {
      this.broadcast('fileShareCreated', share);
      this.auditLog('FILE_SHARE_CREATED', share);
    });
    
    this.fileShareManager.on('accessGranted', (access) => {
      this.broadcast('fileShareAccessGranted', access);
      this.auditLog('FILE_SHARE_ACCESS_GRANTED', access);
    });
    
    this.fileShareManager.on('accessDenied', (access) => {
      this.broadcast('fileShareAccessDenied', access);
      this.auditLog('FILE_SHARE_ACCESS_DENIED', access);
    });
    
    // Compliance events
    this.complianceManager.on('complianceViolation', (violation) => {
      this.broadcast('complianceViolation', violation);
      this.auditLog('COMPLIANCE_VIOLATION', violation);
    });
    
    // Circuit breaker events
    this.on('circuitBreakerOpen', (service) => {
      this.broadcast('serviceUnavailable', { service, reason: 'Circuit breaker open' });
    });
  }

  generateRequestId() {
    return `net-${++this.requestId}-${Date.now()}`;
  }
  
  requiresAuth(messageType) {
    const protectedOperations = [
      'dnsManagement', 'dhcpManagement', 'firewallRule', 
      'vpnManagement', 'bandwidthControl', 'policyApply',
      'securityScan', 'complianceCheck'
    ];
    return protectedOperations.includes(messageType);
  }
  
  requiresPermission(messageType) {
    return this.requiresAuth(messageType);
  }
  
  hasPermission(ws, messageType) {
    if (!ws.permissions || ws.permissions.length === 0) {
      return false;
    }
    
    const permissionMap = {
      'dnsManagement': ['network:dns:manage'],
      'dhcpManagement': ['network:dhcp:manage'],
      'firewallRule': ['network:firewall:manage'],
      'vpnManagement': ['network:vpn:manage'],
      'bandwidthControl': ['network:bandwidth:manage'],
      'policyApply': ['network:policy:manage'],
      'securityScan': ['network:security:scan'],
      'complianceCheck': ['network:compliance:check']
    };
    
    const requiredPerms = permissionMap[messageType] || [];
    return requiredPerms.some(perm => ws.permissions.includes(perm)) || 
           ws.permissions.includes('network:admin');
  }
  
  getRequiredPermission(messageType) {
    const permissionMap = {
      'dnsManagement': 'network:dns:manage',
      'dhcpManagement': 'network:dhcp:manage',
      'firewallRule': 'network:firewall:manage',
      'vpnManagement': 'network:vpn:manage',
      'bandwidthControl': 'network:bandwidth:manage',
      'policyApply': 'network:policy:manage',
      'securityScan': 'network:security:scan',
      'complianceCheck': 'network:compliance:check'
    };
    
    return permissionMap[messageType] || 'network:read';
  }
  
  async validateAuthToken(token) {
    try {
      // In real implementation, validate JWT token or session
      // This is a placeholder implementation
      if (!token) {
        return { valid: false, error: 'No token provided' };
      }
      
      // Mock validation - replace with real JWT verification
      if (token === 'mock-admin-token') {
        return {
          valid: true,
          user: { id: 'admin', username: 'admin' },
          permissions: ['network:admin']
        };
      }
      
      if (token === 'mock-user-token') {
        return {
          valid: true,
          user: { id: 'user1', username: 'user1' },
          permissions: ['network:read', 'network:dns:manage']
        };
      }
      
      return { valid: false, error: 'Invalid token' };
    } catch (error) {
      logger.error('❌ Token validation error:', error);
      return { valid: false, error: 'Token validation failed' };
    }
  }
  
  auditLog(action, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action,
      data,
      service: 'network-infrastructure'
    };
    
    logger.info('📋 Network audit log', logEntry);
    
    // Store in Redis for audit trail
    if (this.redis) {
      this.redis.lpush('network:audit:log', JSON.stringify(logEntry)).catch(err => {
        logger.warn('Failed to store audit log:', err);
      });
    }
  }
  
  async broadcastNetworkStatus() {
    try {
      const status = {
        timestamp: new Date().toISOString(),
        dns: await this.dnsManager.getStatus(),
        dhcp: await this.dhcpManager.getStatus(),
        firewall: await this.firewallManager.getStatus(),
        vpn: await this.vpnManager.getStatus(),
        bandwidth: await this.bandwidthManager.getStatus(),
        security: await this.securityScanner.getStatus(),
        compliance: await this.complianceManager.getStatus(),
        performance: await this.networkMonitoring.getPerformanceMetrics()
      };
      
      this.broadcast('networkStatus', status);
    } catch (error) {
      logger.error('❌ Failed to broadcast network status:', error);
    }
  }
  
  async sendNetworkStatus(ws, requestId) {
    try {
      const status = {
        timestamp: new Date().toISOString(),
        dns: await this.dnsManager.getStatus(),
        dhcp: await this.dhcpManager.getStatus(),
        firewall: await this.firewallManager.getStatus(),
        vpn: await this.vpnManager.getStatus(),
        bandwidth: await this.bandwidthManager.getStatus(),
        security: await this.securityScanner.getStatus(),
        compliance: await this.complianceManager.getStatus(),
        performance: await this.networkMonitoring.getPerformanceMetrics()
      };
      
      ws.send(JSON.stringify({
        type: 'networkStatusResult',
        requestId,
        data: status,
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      logger.error('❌ Failed to send network status:', error);
      ws.send(JSON.stringify({
        type: 'networkStatusResult',
        requestId,
        error: 'Failed to retrieve network status',
        timestamp: new Date().toISOString()
      }));
    }
  }

  verifyWebSocketClient(info) {
    // In production, implement proper client verification
    return true;
  }

  broadcast(type, data) {
    const message = JSON.stringify({
      type,
      data,
      timestamp: new Date().toISOString()
    });

    this.wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  broadcastToSubscribers(subscription, data) {
    const message = JSON.stringify({
      type: 'subscriptionUpdate',
      subscription,
      data,
      timestamp: new Date().toISOString()
    });

    this.wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN && client.subscriptions.has(subscription)) {
        client.send(message);
      }
    });
  }

  cleanupClientSubscriptions(ws) {
    ws.subscriptions.clear();
  }

  async handleSubscription(ws, subscription, options, requestId) {
    ws.subscriptions.add(subscription);
    ws.send(JSON.stringify({
      type: 'subscriptionConfirmed',
      requestId,
      subscription,
      timestamp: new Date().toISOString()
    }));
  }

  async handleUnsubscription(ws, subscription, requestId) {
    ws.subscriptions.delete(subscription);
    ws.send(JSON.stringify({
      type: 'unsubscriptionConfirmed',
      requestId,
      subscription,
      timestamp: new Date().toISOString()
    }));
  }

  // Placeholder handlers for additional WebSocket message types
  async handleDNSQuery(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'dnsQueryResult', requestId, data: 'Mock DNS query result' }));
  }

  async handleDNSManagement(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'dnsManagementResult', requestId, data: 'Mock DNS management result' }));
  }

  async handleDHCPLease(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'dhcpLeaseResult', requestId, data: 'Mock DHCP lease result' }));
  }

  async handleDHCPManagement(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'dhcpManagementResult', requestId, data: 'Mock DHCP management result' }));
  }

  async handleFirewallRule(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'firewallRuleResult', requestId, data: 'Mock firewall rule result' }));
  }

  async handleVPNManagement(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'vpnManagementResult', requestId, data: 'Mock VPN management result' }));
  }

  async handleBandwidthControl(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'bandwidthControlResult', requestId, data: 'Mock bandwidth control result' }));
  }

  async handleSecurityScan(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'securityScanResult', requestId, data: 'Mock security scan result' }));
  }

  async handleComplianceCheck(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'complianceCheckResult', requestId, data: 'Mock compliance check result' }));
  }

  async handleNetworkAnalytics(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'networkAnalyticsResult', requestId, data: 'Mock network analytics result' }));
  }

  async handlePolicyApplication(ws, data, requestId) {
    // Implementation would go here
    ws.send(JSON.stringify({ type: 'policyApplicationResult', requestId, data: 'Mock policy application result' }));
  }

  initializeRoutes() {
    // Enhanced health check with detailed status
    this.app.get('/health', async (req, res) => {
      try {
        const healthStatus = {
          status: 'healthy',
          service: 'enterprise-network-infrastructure',
          version: process.env.npm_package_version || '2.0.0',
          uptime: process.uptime(),
          timestamp: new Date().toISOString(),
          environment: config.environment || 'development',
          pid: process.pid,
          memory: process.memoryUsage(),
          services: {
            dns: await this.dnsManager.getHealthStatus(),
            dhcp: await this.dhcpManager.getHealthStatus(),
            firewall: await this.firewallManager.getHealthStatus(),
            vpn: await this.vpnManager.getHealthStatus(),
            monitoring: await this.networkMonitoring.getHealthStatus(),
            security: await this.securityScanner.getHealthStatus(),
            analytics: await this.networkAnalytics.getHealthStatus()
          },
          websocket: {
            connected: this.wss.clients.size,
            port: config.websocket.port || 8081
          },
          redis: this.redis ? 'connected' : 'disconnected'
        };
        
        res.json(healthStatus);
      } catch (error) {
        logger.error('❌ Health check error:', error);
        res.status(503).json({
          status: 'unhealthy',
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    });
    
    // Detailed system metrics endpoint
    this.app.get('/api/network/metrics', async (req, res) => {
      try {
        const metrics = await this.networkAnalytics.getDetailedMetrics();
        res.json(metrics);
      } catch (error) {
        logger.error('❌ Metrics error:', error);
        res.status(500).json({ error: 'Failed to retrieve metrics' });
      }
    });

    // DNS management routes with enhanced functionality
    this.app.get('/api/network/dns/records', this.getDNSRecords.bind(this));
    this.app.post('/api/network/dns/records', this.createDNSRecord.bind(this));
    this.app.put('/api/network/dns/records/:id', this.updateDNSRecord.bind(this));
    this.app.delete('/api/network/dns/records/:id', this.deleteDNSRecord.bind(this));
    this.app.get('/api/network/dns/zones', this.getDNSZones.bind(this));
    this.app.post('/api/network/dns/zones', this.createDNSZone.bind(this));
    this.app.get('/api/network/dns/analytics', this.getDNSAnalytics.bind(this));
    
    // DHCP management routes with reservation management
    this.app.get('/api/network/dhcp/leases', this.getDHCPLeases.bind(this));
    this.app.post('/api/network/dhcp/leases', this.createDHCPLease.bind(this));
    this.app.delete('/api/network/dhcp/leases/:id', this.releaseDHCPLease.bind(this));
    this.app.get('/api/network/dhcp/reservations', this.getDHCPReservations.bind(this));
    this.app.post('/api/network/dhcp/reservations', this.createDHCPReservation.bind(this));
    this.app.get('/api/network/dhcp/scopes', this.getDHCPScopes.bind(this));
    this.app.post('/api/network/dhcp/scopes', this.createDHCPScope.bind(this));
    
    // Enhanced network discovery and monitoring
    this.app.post('/api/network/scan', this.performNetworkScan.bind(this));
    this.app.get('/api/network/devices', this.getDiscoveredDevices.bind(this));
    this.app.get('/api/network/topology', this.getNetworkTopology.bind(this));
    this.app.get('/api/network/performance', this.getNetworkPerformance.bind(this));
    this.app.post('/api/network/trace', this.performNetworkTrace.bind(this));
    
    // Security and compliance
    this.app.post('/api/network/security/scan', this.performSecurityScan.bind(this));
    this.app.get('/api/network/security/vulnerabilities', this.getVulnerabilities.bind(this));
    this.app.get('/api/network/compliance/report', this.getComplianceReport.bind(this));
    this.app.post('/api/network/compliance/remediate', this.remediateCompliance.bind(this));
    
    // File share management with enhanced permissions
    this.app.get('/api/network/shares', this.getFileShares.bind(this));
    this.app.post('/api/network/shares', this.createFileShare.bind(this));
    this.app.put('/api/network/shares/:id', this.updateFileShare.bind(this));
    this.app.delete('/api/network/shares/:id', this.deleteFileShare.bind(this));
    this.app.get('/api/network/shares/:id/permissions', this.getSharePermissions.bind(this));
    this.app.post('/api/network/shares/:id/permissions', this.setSharePermissions.bind(this));
    
    // VLAN management with advanced features
    this.app.get('/api/network/vlans', this.getVLANs.bind(this));
    this.app.post('/api/network/vlans', this.createVLAN.bind(this));
    this.app.put('/api/network/vlans/:id', this.updateVLAN.bind(this));
    this.app.delete('/api/network/vlans/:id', this.deleteVLAN.bind(this));
    this.app.get('/api/network/vlans/:id/devices', this.getVLANDevices.bind(this));
    
    // Enhanced firewall management
    this.app.get('/api/network/firewall/rules', this.getFirewallRules.bind(this));
    this.app.post('/api/network/firewall/rules', this.createFirewallRule.bind(this));
    this.app.put('/api/network/firewall/rules/:id', this.updateFirewallRule.bind(this));
    this.app.delete('/api/network/firewall/rules/:id', this.deleteFirewallRule.bind(this));
    this.app.get('/api/network/firewall/logs', this.getFirewallLogs.bind(this));
    this.app.post('/api/network/firewall/block', this.blockTraffic.bind(this));
    
    // VPN management with certificate handling
    this.app.get('/api/network/vpn/connections', this.getVPNConnections.bind(this));
    this.app.post('/api/network/vpn/connect', this.establishVPNConnection.bind(this));
    this.app.post('/api/network/vpn/disconnect', this.terminateVPNConnection.bind(this));
    this.app.get('/api/network/vpn/certificates', this.getVPNCertificates.bind(this));
    this.app.post('/api/network/vpn/certificates', this.generateVPNCertificate.bind(this));
    
    // Bandwidth management
    this.app.get('/api/network/bandwidth/usage', this.getBandwidthUsage.bind(this));
    this.app.post('/api/network/bandwidth/limit', this.setBandwidthLimit.bind(this));
    this.app.get('/api/network/bandwidth/policies', this.getBandwidthPolicies.bind(this));
    this.app.post('/api/network/bandwidth/policies', this.createBandwidthPolicy.bind(this));
    
    // Load balancer with health checks
    this.app.get('/api/network/loadbalancer/status', this.getLoadBalancerStatus.bind(this));
    this.app.post('/api/network/loadbalancer/configure', this.configureLoadBalancer.bind(this));
    this.app.get('/api/network/loadbalancer/pools', this.getLoadBalancerPools.bind(this));
    this.app.post('/api/network/loadbalancer/pools', this.createLoadBalancerPool.bind(this));
    
    // Policy engine endpoints
    this.app.get('/api/network/policies', this.getNetworkPolicies.bind(this));
    this.app.post('/api/network/policies', this.createNetworkPolicy.bind(this));
    this.app.put('/api/network/policies/:id', this.updateNetworkPolicy.bind(this));
    this.app.delete('/api/network/policies/:id', this.deleteNetworkPolicy.bind(this));
    this.app.post('/api/network/policies/:id/apply', this.applyNetworkPolicy.bind(this));
    
    // Network analytics and reporting
    this.app.get('/api/network/analytics/traffic', this.getTrafficAnalytics.bind(this));
    this.app.get('/api/network/analytics/performance', this.getPerformanceAnalytics.bind(this));
    this.app.get('/api/network/analytics/security', this.getSecurityAnalytics.bind(this));
    this.app.get('/api/network/reports/usage', this.generateUsageReport.bind(this));
    this.app.get('/api/network/reports/security', this.generateSecurityReport.bind(this));

    // Enhanced error handling with detailed logging
    this.app.use(this.errorHandler.bind(this));
  }

  errorHandler(error, req, res, next) {
    const errorId = uuidv4();
    
    logger.error('❌ Network service error:', {
      errorId,
      error: error.message,
      stack: config.environment === 'development' ? error.stack : undefined,
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      requestId: req.id,
      networkZone: req.networkZone,
      timestamp: new Date().toISOString()
    });
    
    // Store error in Redis for analysis
    if (this.redis) {
      this.redis.lpush('network:errors', JSON.stringify({
        errorId,
        message: error.message,
        url: req.url,
        method: req.method,
        timestamp: new Date().toISOString(),
        requestId: req.id
      })).catch(err => {
        logger.warn('Failed to store error in Redis:', err);
      });
    }
    
    // Broadcast error to monitoring subscribers
    this.broadcastToSubscribers('error', {
      errorId,
      service: 'network-infrastructure',
      message: error.message,
      url: req.url,
      timestamp: new Date().toISOString()
    });
    
    res.status(error.status || 500).json({
      error: config.environment === 'development' ? error.message : 'Internal server error',
      errorId,
      timestamp: new Date().toISOString(),
      requestId: req.id,
      support: 'Please contact support with the error ID for assistance'
    });
  }

  start(port = process.env.PORT || 3003) {
    this.server = this.app.listen(port, () => {
      logger.info(`🌐 Enterprise Network Infrastructure Service started on port ${port}`);
      logger.info(`📊 Health check: http://localhost:${port}/health`);
      logger.info(`🔧 Network management: http://localhost:${port}/api/network`);
      logger.info(`🌐 WebSocket server: ws://localhost:${config.websocket.port || 8081}`);
      logger.info(`🔒 Security features: Enabled`);
      logger.info(`📈 Analytics: Enabled`);
      logger.info(`📋 Compliance monitoring: Enabled`);
      
      // Start background services
      this.startBackgroundServices();
    });
  }
  
  startBackgroundServices() {
    // Start continuous network monitoring
    setInterval(async () => {
      try {
        await this.networkMonitoring.performHealthCheck();
        await this.securityScanner.performSecurityScan();
        await this.complianceManager.performComplianceCheck();
      } catch (error) {
        logger.error('❌ Background service error:', error);
      }
    }, 5 * 60 * 1000); // Every 5 minutes
    
    // Start analytics collection
    setInterval(async () => {
      try {
        await this.networkAnalytics.collectMetrics();
      } catch (error) {
        logger.error('❌ Analytics collection error:', error);
      }
    }, 60 * 1000); // Every minute
    
    logger.info('🔄 Background services started');
  }
  
  async gracefulShutdown() {
    logger.info('🛑 Starting graceful shutdown...');
    
    // Close WebSocket connections
    if (this.wss) {
      this.wss.clients.forEach((ws) => {
        ws.close(1001, 'Server shutting down');
      });
      this.wss.close();
    }
    
    // Close HTTP server
    if (this.server) {
      this.server.close(() => {
        logger.info('✅ HTTP server closed');
      });
    }
    
    // Close Redis connection
    if (this.redis) {
      await this.redis.quit();
      logger.info('✅ Redis connection closed');
    }
    
    // Cleanup services
    await this.networkMonitoring.cleanup();
    await this.securityScanner.cleanup();
    await this.networkAnalytics.cleanup();
    
    logger.info('✅ Graceful shutdown completed');
    process.exit(0);
  }
  
  // Additional handler methods for new endpoints would be implemented here
  // These are placeholder implementations - in a real system, these would
  // contain the full business logic
  
  async getDNSAnalytics(req, res) {
    try {
      const analytics = await this.networkAnalytics.getDNSAnalytics();
      res.json({ analytics, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  }
  
  async getNetworkTopology(req, res) {
    try {
      const topology = await this.networkDiscovery.getNetworkTopology();
      res.json({ topology, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  }
  
  async performSecurityScan(req, res) {
    try {
      const { target, scanType = 'vulnerability' } = req.body;
      const result = await this.securityScanner.performScan(target, scanType);
      res.json({ result, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  }
  
  async getComplianceReport(req, res) {
    try {
      const { framework = 'SOC2' } = req.query;
      const report = await this.complianceManager.generateReport(framework);
      res.json({ report, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  }
  
  async getBandwidthUsage(req, res) {
    try {
      const { timeRange = '24h' } = req.query;
      const usage = await this.bandwidthManager.getUsageReport(timeRange);
      res.json({ usage, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  }
  
  async createNetworkPolicy(req, res) {
    try {
      const policy = await this.policyEngine.createPolicy(req.body);
      this.auditLog('NETWORK_POLICY_CREATED', { policy });
      res.status(201).json({ policy, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  }

  // Placeholder implementations for route handlers
  async getDNSRecords(req, res) { res.json({ message: 'DNS records endpoint - implementation needed' }); }
  async createDNSRecord(req, res) { res.json({ message: 'Create DNS record endpoint - implementation needed' }); }
  async updateDNSRecord(req, res) { res.json({ message: 'Update DNS record endpoint - implementation needed' }); }
  async deleteDNSRecord(req, res) { res.json({ message: 'Delete DNS record endpoint - implementation needed' }); }
  async getDNSZones(req, res) { res.json({ message: 'DNS zones endpoint - implementation needed' }); }
  async createDNSZone(req, res) { res.json({ message: 'Create DNS zone endpoint - implementation needed' }); }
  async getDHCPLeases(req, res) { res.json({ message: 'DHCP leases endpoint - implementation needed' }); }
  async createDHCPLease(req, res) { res.json({ message: 'Create DHCP lease endpoint - implementation needed' }); }
  async releaseDHCPLease(req, res) { res.json({ message: 'Release DHCP lease endpoint - implementation needed' }); }
  async getDHCPReservations(req, res) { res.json({ message: 'DHCP reservations endpoint - implementation needed' }); }
  async createDHCPReservation(req, res) { res.json({ message: 'Create DHCP reservation endpoint - implementation needed' }); }
  async getDHCPScopes(req, res) { res.json({ message: 'DHCP scopes endpoint - implementation needed' }); }
  async createDHCPScope(req, res) { res.json({ message: 'Create DHCP scope endpoint - implementation needed' }); }
  async performNetworkScan(req, res) { res.json({ message: 'Network scan endpoint - implementation needed' }); }
  async getDiscoveredDevices(req, res) { res.json({ message: 'Discovered devices endpoint - implementation needed' }); }
  async getNetworkPerformance(req, res) { res.json({ message: 'Network performance endpoint - implementation needed' }); }
  async performNetworkTrace(req, res) { res.json({ message: 'Network trace endpoint - implementation needed' }); }
  async getVulnerabilities(req, res) { res.json({ message: 'Vulnerabilities endpoint - implementation needed' }); }
  async remediateCompliance(req, res) { res.json({ message: 'Remediate compliance endpoint - implementation needed' }); }
  async getFileShares(req, res) { res.json({ message: 'File shares endpoint - implementation needed' }); }
  async createFileShare(req, res) { res.json({ message: 'Create file share endpoint - implementation needed' }); }
  async updateFileShare(req, res) { res.json({ message: 'Update file share endpoint - implementation needed' }); }
  async deleteFileShare(req, res) { res.json({ message: 'Delete file share endpoint - implementation needed' }); }
  async getSharePermissions(req, res) { res.json({ message: 'Share permissions endpoint - implementation needed' }); }
  async setSharePermissions(req, res) { res.json({ message: 'Set share permissions endpoint - implementation needed' }); }
  async getVLANs(req, res) { res.json({ message: 'VLANs endpoint - implementation needed' }); }
  async createVLAN(req, res) { res.json({ message: 'Create VLAN endpoint - implementation needed' }); }
  async updateVLAN(req, res) { res.json({ message: 'Update VLAN endpoint - implementation needed' }); }
  async deleteVLAN(req, res) { res.json({ message: 'Delete VLAN endpoint - implementation needed' }); }
  async getVLANDevices(req, res) { res.json({ message: 'VLAN devices endpoint - implementation needed' }); }
  async getFirewallRules(req, res) { res.json({ message: 'Firewall rules endpoint - implementation needed' }); }
  async createFirewallRule(req, res) { res.json({ message: 'Create firewall rule endpoint - implementation needed' }); }
  async updateFirewallRule(req, res) { res.json({ message: 'Update firewall rule endpoint - implementation needed' }); }
  async deleteFirewallRule(req, res) { res.json({ message: 'Delete firewall rule endpoint - implementation needed' }); }
  async getFirewallLogs(req, res) { res.json({ message: 'Firewall logs endpoint - implementation needed' }); }
  async blockTraffic(req, res) { res.json({ message: 'Block traffic endpoint - implementation needed' }); }
  async getVPNConnections(req, res) { res.json({ message: 'VPN connections endpoint - implementation needed' }); }
  async establishVPNConnection(req, res) { res.json({ message: 'Establish VPN connection endpoint - implementation needed' }); }
  async terminateVPNConnection(req, res) { res.json({ message: 'Terminate VPN connection endpoint - implementation needed' }); }
  async getVPNCertificates(req, res) { res.json({ message: 'VPN certificates endpoint - implementation needed' }); }
  async generateVPNCertificate(req, res) { res.json({ message: 'Generate VPN certificate endpoint - implementation needed' }); }
  async setBandwidthLimit(req, res) { res.json({ message: 'Set bandwidth limit endpoint - implementation needed' }); }
  async getBandwidthPolicies(req, res) { res.json({ message: 'Bandwidth policies endpoint - implementation needed' }); }
  async createBandwidthPolicy(req, res) { res.json({ message: 'Create bandwidth policy endpoint - implementation needed' }); }
  async getLoadBalancerStatus(req, res) { res.json({ message: 'Load balancer status endpoint - implementation needed' }); }
  async configureLoadBalancer(req, res) { res.json({ message: 'Configure load balancer endpoint - implementation needed' }); }
  async getLoadBalancerPools(req, res) { res.json({ message: 'Load balancer pools endpoint - implementation needed' }); }
  async createLoadBalancerPool(req, res) { res.json({ message: 'Create load balancer pool endpoint - implementation needed' }); }
  async getNetworkPolicies(req, res) { res.json({ message: 'Network policies endpoint - implementation needed' }); }
  async updateNetworkPolicy(req, res) { res.json({ message: 'Update network policy endpoint - implementation needed' }); }
  async deleteNetworkPolicy(req, res) { res.json({ message: 'Delete network policy endpoint - implementation needed' }); }
  async applyNetworkPolicy(req, res) { res.json({ message: 'Apply network policy endpoint - implementation needed' }); }
  async getTrafficAnalytics(req, res) { res.json({ message: 'Traffic analytics endpoint - implementation needed' }); }
  async getPerformanceAnalytics(req, res) { res.json({ message: 'Performance analytics endpoint - implementation needed' }); }
  async getSecurityAnalytics(req, res) { res.json({ message: 'Security analytics endpoint - implementation needed' }); }
  async generateUsageReport(req, res) { res.json({ message: 'Usage report endpoint - implementation needed' }); }
  async generateSecurityReport(req, res) { res.json({ message: 'Security report endpoint - implementation needed' }); }
}

// Graceful shutdown handling
process.on('SIGTERM', () => {
  logger.info('🛑 SIGTERM received, starting graceful shutdown');
  if (global.networkService) {
    global.networkService.gracefulShutdown();
  }
});

process.on('SIGINT', () => {
  logger.info('🛑 SIGINT received, starting graceful shutdown');
  if (global.networkService) {
    global.networkService.gracefulShutdown();
  }
});

// Start the service if not in cluster mode
if (!cluster.isMaster) {
  const networkService = new EnterpriseNetworkInfrastructureService();
  global.networkService = networkService;
  networkService.start();
} else {
  // Cluster mode: fork workers
  const numCPUs = Math.min(os.cpus().length, config.cluster?.maxWorkers || 4);
  logger.info(`🖥️ Starting ${numCPUs} network service workers`);
  
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    logger.warn(`⚠️ Worker ${worker.process.pid} died (code: ${code}, signal: ${signal})`);
    if (!worker.exitedAfterDisconnect) {
      logger.info('🔄 Restarting worker');
      cluster.fork();
    }
  });
  
  cluster.on('listening', (worker, address) => {
    logger.info(`✅ Worker ${worker.process.pid} listening on ${address.address}:${address.port}`);
  });
}

module.exports = EnterpriseNetworkInfrastructureService;