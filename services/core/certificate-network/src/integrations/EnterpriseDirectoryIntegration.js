/**
 * OpenDirectory Certificate & Network Enterprise Directory Integration
 * Provides seamless integration with Enterprise Directory Service for user authentication,
 * group membership resolution, and policy application
 */

const EventEmitter = require('events');
const axios = require('axios');
const { logger } = require('../utils/logger');

class EnterpriseDirectoryIntegration extends EventEmitter {
  constructor(config) {
    super();
    
    this.config = config;
    this.enterpriseDirectoryConfig = config.enterpriseDirectory;
    this.baseURL = this.enterpriseDirectoryConfig.serviceURL;
    this.sharedSecret = this.enterpriseDirectoryConfig.sharedSecret;
    
    // HTTP client for API calls
    this.apiClient = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'X-Service-Auth': this.sharedSecret,
        'X-Service-Name': 'certificate-network'
      }
    });
    
    // Cache for user and group data
    this.cache = new Map();
    this.cacheTimeout = 300000; // 5 minutes
    
    // Connection state
    this.connected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    
    logger.info('🔗 Enterprise Directory Integration initialized');
  }

  async initialize() {
    try {
      logger.info('🔌 Connecting to Enterprise Directory Service...');

      // Test connectivity
      await this.testConnection();
      
      // Set up event listeners for directory events
      this.setupEventListeners();
      
      // Start periodic health checks
      this.startHealthChecks();
      
      this.connected = true;
      this.reconnectAttempts = 0;
      
      logger.info('✅ Connected to Enterprise Directory Service');
      this.emit('connected');

    } catch (error) {
      logger.error('❌ Failed to connect to Enterprise Directory Service:', error);
      this.scheduleReconnect();
      throw error;
    }
  }

  async testConnection() {
    try {
      const response = await this.apiClient.get('/health');
      if (response.status !== 200) {
        throw new Error(`Enterprise Directory Service health check failed: ${response.status}`);
      }
      
      logger.debug('Enterprise Directory Service health check passed');
      return true;
      
    } catch (error) {
      throw new Error(`Cannot connect to Enterprise Directory Service: ${error.message}`);
    }
  }

  setupEventListeners() {
    // Listen for our own connection events
    this.on('connected', () => {
      logger.info('🟢 Enterprise Directory Integration connected');
    });

    this.on('disconnected', () => {
      logger.warn('🔴 Enterprise Directory Integration disconnected');
      this.connected = false;
    });

    this.on('error', (error) => {
      logger.error('❌ Enterprise Directory Integration error:', error);
      this.connected = false;
    });
  }

  startHealthChecks() {
    // Health check every 60 seconds
    this.healthCheckInterval = setInterval(async () => {
      try {
        if (this.connected) {
          await this.testConnection();
        }
      } catch (error) {
        logger.error('Health check failed:', error);
        this.connected = false;
        this.emit('disconnected');
        this.scheduleReconnect();
      }
    }, 60000);
  }

  scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logger.error('❌ Max reconnection attempts reached. Giving up.');
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    
    logger.info(`⏳ Scheduling reconnection attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    setTimeout(async () => {
      try {
        await this.initialize();
      } catch (error) {
        logger.error('Reconnection failed:', error);
        this.scheduleReconnect();
      }
    }, delay);
  }

  // User Management Integration
  async authenticateUser(username, password, clientInfo = {}) {
    try {
      logger.debug(`🔐 Authenticating user: ${username}`);

      const response = await this.apiClient.post('/api/auth/authenticate', {
        username,
        password,
        clientInfo: {
          ...clientInfo,
          service: 'certificate-network',
          timestamp: new Date().toISOString()
        }
      });

      if (response.data.success) {
        const user = response.data.user;
        
        // Cache user data
        this.cacheUserData(user);
        
        logger.info(`✅ User authenticated: ${username}`);
        this.emit('userAuthenticated', { user, clientInfo });
        
        return {
          success: true,
          user: {
            objectGUID: user.objectGUID,
            sAMAccountName: user.sAMAccountName,
            userPrincipalName: user.userPrincipalName,
            distinguishedName: user.distinguishedName,
            displayName: user.displayName,
            mail: user.mail,
            department: user.department,
            title: user.title,
            groups: user.groups || [],
            certificateAttributes: this.extractCertificateAttributes(user)
          }
        };
      } else {
        logger.warn(`❌ Authentication failed for user: ${username}`);
        return { success: false, reason: response.data.reason };
      }

    } catch (error) {
      logger.error('Authentication error:', error);
      return { success: false, reason: 'Authentication service unavailable' };
    }
  }

  async getUserByIdentifier(identifier, type = 'auto') {
    try {
      // Check cache first
      const cacheKey = `user:${type}:${identifier}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) {
        logger.debug(`📋 Retrieved user from cache: ${identifier}`);
        return cached;
      }

      logger.debug(`🔍 Looking up user: ${identifier} (${type})`);

      const response = await this.apiClient.get('/api/users/lookup', {
        params: { identifier, type }
      });

      if (response.data.success && response.data.user) {
        const user = response.data.user;
        
        // Cache the result
        this.cacheUserData(user, cacheKey);
        
        return {
          success: true,
          user: {
            objectGUID: user.objectGUID,
            sAMAccountName: user.sAMAccountName,
            userPrincipalName: user.userPrincipalName,
            distinguishedName: user.distinguishedName,
            displayName: user.displayName,
            mail: user.mail,
            department: user.department,
            title: user.title,
            groups: user.groups || [],
            certificateAttributes: this.extractCertificateAttributes(user)
          }
        };
      } else {
        return { success: false, reason: 'User not found' };
      }

    } catch (error) {
      logger.error('User lookup error:', error);
      return { success: false, reason: 'Lookup service unavailable' };
    }
  }

  async getUserGroups(userGUID) {
    try {
      // Check cache first
      const cacheKey = `groups:${userGUID}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) {
        return cached;
      }

      logger.debug(`🔍 Getting groups for user: ${userGUID}`);

      const response = await this.apiClient.get(`/api/users/${userGUID}/groups`);

      if (response.data.success) {
        const groups = response.data.groups.map(group => ({
          objectGUID: group.objectGUID,
          sAMAccountName: group.sAMAccountName,
          distinguishedName: group.distinguishedName,
          displayName: group.displayName,
          description: group.description,
          groupType: group.groupType,
          groupScope: group.groupScope
        }));

        // Cache the result
        this.setCachedData(cacheKey, { success: true, groups });
        
        return { success: true, groups };
      } else {
        return { success: false, reason: 'Groups not found' };
      }

    } catch (error) {
      logger.error('Group lookup error:', error);
      return { success: false, reason: 'Group lookup service unavailable' };
    }
  }

  // Computer Management Integration
  async getComputerByIdentifier(identifier, type = 'auto') {
    try {
      logger.debug(`🖥️ Looking up computer: ${identifier} (${type})`);

      const response = await this.apiClient.get('/api/computers/lookup', {
        params: { identifier, type }
      });

      if (response.data.success && response.data.computer) {
        const computer = response.data.computer;
        
        return {
          success: true,
          computer: {
            objectGUID: computer.objectGUID,
            sAMAccountName: computer.sAMAccountName,
            distinguishedName: computer.distinguishedName,
            dNSHostName: computer.dNSHostName,
            operatingSystem: computer.operatingSystem,
            operatingSystemVersion: computer.operatingSystemVersion,
            groups: computer.groups || []
          }
        };
      } else {
        return { success: false, reason: 'Computer not found' };
      }

    } catch (error) {
      logger.error('Computer lookup error:', error);
      return { success: false, reason: 'Computer lookup service unavailable' };
    }
  }

  async joinComputer(computerInfo) {
    try {
      logger.info(`🔌 Joining computer to domain: ${computerInfo.computerName}`);

      const response = await this.apiClient.post('/api/computers/join', {
        ...computerInfo,
        joiningService: 'certificate-network',
        timestamp: new Date().toISOString()
      });

      if (response.data.success) {
        this.emit('computerJoined', { computer: response.data.computer });
        return response.data;
      } else {
        return { success: false, reason: response.data.reason };
      }

    } catch (error) {
      logger.error('Computer join error:', error);
      return { success: false, reason: 'Computer join service unavailable' };
    }
  }

  // Group Policy Integration
  async getUserPolicies(userGUID) {
    try {
      logger.debug(`📋 Getting policies for user: ${userGUID}`);

      const response = await this.apiClient.get(`/api/users/${userGUID}/policies`);

      if (response.data.success) {
        return {
          success: true,
          policies: response.data.policies,
          certificatePolicies: this.extractCertificatePolicies(response.data.policies),
          networkPolicies: this.extractNetworkPolicies(response.data.policies)
        };
      } else {
        return { success: false, reason: 'Policies not found' };
      }

    } catch (error) {
      logger.error('Policy lookup error:', error);
      return { success: false, reason: 'Policy service unavailable' };
    }
  }

  async getComputerPolicies(computerGUID) {
    try {
      logger.debug(`📋 Getting policies for computer: ${computerGUID}`);

      const response = await this.apiClient.get(`/api/computers/${computerGUID}/policies`);

      if (response.data.success) {
        return {
          success: true,
          policies: response.data.policies,
          certificatePolicies: this.extractCertificatePolicies(response.data.policies),
          networkPolicies: this.extractNetworkPolicies(response.data.policies)
        };
      } else {
        return { success: false, reason: 'Policies not found' };
      }

    } catch (error) {
      logger.error('Computer policy lookup error:', error);
      return { success: false, reason: 'Policy service unavailable' };
    }
  }

  // Certificate Integration Methods
  async notifyCertificateIssued(certificateInfo) {
    try {
      logger.debug(`📜 Notifying certificate issued: ${certificateInfo.subject}`);

      await this.apiClient.post('/api/certificates/issued', {
        ...certificateInfo,
        issuedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

      this.emit('certificateNotified', { action: 'issued', certificate: certificateInfo });

    } catch (error) {
      logger.error('Certificate notification error:', error);
    }
  }

  async notifyCertificateRevoked(certificateInfo) {
    try {
      logger.debug(`🚫 Notifying certificate revoked: ${certificateInfo.serialNumber}`);

      await this.apiClient.post('/api/certificates/revoked', {
        ...certificateInfo,
        revokedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

      this.emit('certificateNotified', { action: 'revoked', certificate: certificateInfo });

    } catch (error) {
      logger.error('Certificate revocation notification error:', error);
    }
  }

  async updateUserCertificates(userGUID, certificates) {
    try {
      logger.debug(`📜 Updating certificates for user: ${userGUID}`);

      await this.apiClient.put(`/api/users/${userGUID}/certificates`, {
        certificates,
        updatedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

      // Invalidate user cache
      this.invalidateUserCache(userGUID);

    } catch (error) {
      logger.error('User certificate update error:', error);
    }
  }

  // Utility Methods
  extractCertificateAttributes(user) {
    return {
      userCertificate: user.userCertificate || [],
      userSMIMECertificate: user.userSMIMECertificate || [],
      certificateTemplates: user.certificateTemplates || [],
      autoEnrollmentEnabled: user.autoEnrollmentEnabled || false,
      certificateThumbprints: user.certificateThumbprints || []
    };
  }

  extractCertificatePolicies(policies) {
    return policies.filter(policy => 
      policy.type === 'certificate' || 
      policy.category === 'PKI' ||
      policy.name.toLowerCase().includes('certificate')
    );
  }

  extractNetworkPolicies(policies) {
    return policies.filter(policy => 
      policy.type === 'network' || 
      policy.category === 'WiFi' ||
      policy.category === 'VPN' ||
      policy.category === 'Email' ||
      policy.name.toLowerCase().includes('network') ||
      policy.name.toLowerCase().includes('wifi') ||
      policy.name.toLowerCase().includes('vpn')
    );
  }

  // Cache Management
  cacheUserData(user, customKey = null) {
    const key = customKey || `user:guid:${user.objectGUID}`;
    this.setCachedData(key, { success: true, user });
    
    // Also cache by different identifiers
    if (!customKey) {
      this.setCachedData(`user:sam:${user.sAMAccountName}`, { success: true, user });
      this.setCachedData(`user:upn:${user.userPrincipalName}`, { success: true, user });
      if (user.mail) {
        this.setCachedData(`user:mail:${user.mail}`, { success: true, user });
      }
    }
  }

  setCachedData(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  getCachedData(key) {
    const cached = this.cache.get(key);
    if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
      return cached.data;
    }
    
    if (cached) {
      this.cache.delete(key);
    }
    
    return null;
  }

  invalidateUserCache(userGUID) {
    // Remove all cache entries for this user
    const keysToDelete = [];
    for (const [key, value] of this.cache.entries()) {
      if (key.includes(userGUID) || 
          (value.data.user && value.data.user.objectGUID === userGUID)) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => this.cache.delete(key));
  }

  // Health and Status
  getStatus() {
    return {
      connected: this.connected,
      baseURL: this.baseURL,
      reconnectAttempts: this.reconnectAttempts,
      cacheSize: this.cache.size,
      lastHealthCheck: this.lastHealthCheck || null
    };
  }

  async stop() {
    logger.info('🛑 Stopping Enterprise Directory Integration...');
    
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    
    this.cache.clear();
    this.connected = false;
    
    logger.info('✅ Enterprise Directory Integration stopped');
  }
}

module.exports = EnterpriseDirectoryIntegration;