/**
 * OpenDirectory Certificate & Network Enterprise Directory Integration
 * Main integration module that coordinates all directory synchronization services
 */

const EventEmitter = require('events');
const { logger } = require('../utils/logger');
const EnterpriseDirectoryIntegration = require('./EnterpriseDirectoryIntegration');
const CertificateDirectorySync = require('./CertificateDirectorySync');
const NetworkProfileDirectorySync = require('./NetworkProfileDirectorySync');

class IntegrationManager extends EventEmitter {
  constructor(config, services) {
    super();
    
    this.config = config;
    this.services = services;
    
    // Integration components
    this.enterpriseDirectoryIntegration = null;
    this.certificateSync = null;
    this.networkProfileSync = null;
    
    // State tracking
    this.initialized = false;
    this.integrationStatus = {
      enterpriseDirectory: 'disconnected',
      certificateSync: 'stopped',
      networkProfileSync: 'stopped'
    };
    
    logger.info('🔗 Integration Manager initialized');
  }

  async initialize() {
    try {
      if (this.initialized) {
        logger.warn('Integration Manager already initialized');
        return;
      }

      logger.info('🚀 Starting Enterprise Directory Integration...');

      // Initialize Enterprise Directory Integration
      await this.initializeEnterpriseDirectoryIntegration();

      // Initialize Certificate Directory Sync
      await this.initializeCertificateSync();

      // Initialize Network Profile Directory Sync
      await this.initializeNetworkProfileSync();

      // Set up cross-service event handling
      this.setupCrossServiceEvents();

      this.initialized = true;
      logger.info('✅ Enterprise Directory Integration initialized successfully');

      this.emit('initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Enterprise Directory Integration:', error);
      throw error;
    }
  }

  async initializeEnterpriseDirectoryIntegration() {
    try {
      if (!this.config.enterpriseDirectory.enabled) {
        logger.info('📵 Enterprise Directory integration disabled');
        return;
      }

      this.enterpriseDirectoryIntegration = new EnterpriseDirectoryIntegration(this.config);
      
      // Set up event listeners
      this.enterpriseDirectoryIntegration.on('connected', () => {
        this.integrationStatus.enterpriseDirectory = 'connected';
        this.emit('enterpriseDirectoryConnected');
        logger.info('🟢 Enterprise Directory connected');
      });

      this.enterpriseDirectoryIntegration.on('disconnected', () => {
        this.integrationStatus.enterpriseDirectory = 'disconnected';
        this.emit('enterpriseDirectoryDisconnected');
        logger.warn('🔴 Enterprise Directory disconnected');
      });

      this.enterpriseDirectoryIntegration.on('error', (error) => {
        logger.error('Enterprise Directory error:', error);
        this.emit('enterpriseDirectoryError', error);
      });

      // Initialize the connection
      await this.enterpriseDirectoryIntegration.initialize();

      logger.info('✅ Enterprise Directory Integration component initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Enterprise Directory Integration:', error);
      throw error;
    }
  }

  async initializeCertificateSync() {
    try {
      if (!this.enterpriseDirectoryIntegration) {
        logger.warn('⚠️ Skipping Certificate Sync - Enterprise Directory not available');
        return;
      }

      this.certificateSync = new CertificateDirectorySync(
        this.config,
        this.enterpriseDirectoryIntegration,
        this.services.certificateLifecycle,
        this.services.enterpriseCA
      );

      // Set up event listeners
      this.certificateSync.on('fullSyncCompleted', (stats) => {
        logger.info(`📊 Certificate full sync completed: ${stats.processedCount} processed`);
        this.emit('certificateFullSyncCompleted', stats);
      });

      this.certificateSync.on('certificateSynced', (event) => {
        this.emit('certificateSynced', event);
      });

      // Initialize certificate sync
      await this.certificateSync.initialize();

      this.integrationStatus.certificateSync = 'running';
      logger.info('✅ Certificate Directory Sync initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Certificate Directory Sync:', error);
      this.integrationStatus.certificateSync = 'error';
      throw error;
    }
  }

  async initializeNetworkProfileSync() {
    try {
      if (!this.enterpriseDirectoryIntegration) {
        logger.warn('⚠️ Skipping Network Profile Sync - Enterprise Directory not available');
        return;
      }

      this.networkProfileSync = new NetworkProfileDirectorySync(
        this.config,
        this.enterpriseDirectoryIntegration,
        this.services.wifiProfile,
        this.services.vpnProfile,
        this.services.emailProfile
      );

      // Set up event listeners
      this.networkProfileSync.on('profileDeploymentSynced', (event) => {
        logger.debug(`📡 Network profile deployment synced: ${event.profileType} - ${event.action}`);
        this.emit('profileDeploymentSynced', event);
      });

      // Initialize network profile sync
      await this.networkProfileSync.initialize();

      this.integrationStatus.networkProfileSync = 'running';
      logger.info('✅ Network Profile Directory Sync initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Network Profile Directory Sync:', error);
      this.integrationStatus.networkProfileSync = 'error';
      throw error;
    }
  }

  setupCrossServiceEvents() {
    // Coordinate between certificate and network services for certificate-based authentication

    // When a new certificate is issued, check if it should trigger network profile updates
    if (this.certificateSync && this.networkProfileSync) {
      this.certificateSync.on('certificateSynced', async (event) => {
        if (event.action === 'issued' && event.certificate) {
          await this.handleCertificateIssuedForNetworkProfiles(event.certificate, event.enrollmentInfo);
        }
      });

      // When a certificate is revoked, update network profiles to remove certificate-based auth
      this.certificateSync.on('certificateSynced', async (event) => {
        if (event.action === 'revoked' && event.certificate) {
          await this.handleCertificateRevokedForNetworkProfiles(event.certificate, event.revocationInfo);
        }
      });
    }

    logger.info('🔗 Cross-service event handlers configured');
  }

  async handleCertificateIssuedForNetworkProfiles(certificate, enrollmentInfo) {
    try {
      logger.debug(`🔗 Processing certificate issuance for network profiles: ${certificate.subject.commonName}`);

      // Check if this certificate should trigger network profile updates
      if (certificate.template === 'UserAuthentication' || certificate.template === 'ComputerAuthentication') {
        
        // Get the user or computer information
        let ownerInfo = null;
        if (enrollmentInfo.userGUID) {
          const userResult = await this.enterpriseDirectoryIntegration.getUserByIdentifier(enrollmentInfo.userGUID, 'guid');
          if (userResult.success) {
            ownerInfo = { type: 'user', data: userResult.user };
          }
        } else if (enrollmentInfo.computerGUID) {
          const computerResult = await this.enterpriseDirectoryIntegration.getComputerByIdentifier(enrollmentInfo.computerGUID, 'guid');
          if (computerResult.success) {
            ownerInfo = { type: 'computer', data: computerResult.computer };
          }
        }

        if (ownerInfo) {
          // Trigger network profile updates with new certificate
          if (ownerInfo.type === 'user') {
            await this.networkProfileSync.processUserNetworkPolicies(ownerInfo.data);
          } else if (ownerInfo.type === 'computer') {
            await this.networkProfileSync.processComputerNetworkPolicies(ownerInfo.data);
          }
        }
      }

    } catch (error) {
      logger.error('Certificate-triggered network profile update error:', error);
    }
  }

  async handleCertificateRevokedForNetworkProfiles(certificate, revocationInfo) {
    try {
      logger.debug(`🔗 Processing certificate revocation for network profiles: ${certificate.serialNumber}`);

      // For revoked certificates, we may need to update network profiles
      // to remove certificate-based authentication or switch to alternative auth methods
      
      // This would typically involve:
      // 1. Identifying which network profiles use this certificate
      // 2. Either removing the profiles or switching to password auth
      // 3. Notifying users/administrators of the change

      this.emit('certificateRevokedNetworkProfileUpdate', { certificate, revocationInfo });

    } catch (error) {
      logger.error('Certificate revocation network profile update error:', error);
    }
  }

  // API Methods for other services to use

  async authenticateUser(username, password, clientInfo = {}) {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.authenticateUser(username, password, clientInfo);
  }

  async getUserByIdentifier(identifier, type = 'auto') {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.getUserByIdentifier(identifier, type);
  }

  async getComputerByIdentifier(identifier, type = 'auto') {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.getComputerByIdentifier(identifier, type);
  }

  async getUserGroups(userGUID) {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.getUserGroups(userGUID);
  }

  async getUserPolicies(userGUID) {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.getUserPolicies(userGUID);
  }

  async getComputerPolicies(computerGUID) {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.getComputerPolicies(computerGUID);
  }

  async joinComputer(computerInfo) {
    if (!this.enterpriseDirectoryIntegration) {
      throw new Error('Enterprise Directory integration not available');
    }

    return await this.enterpriseDirectoryIntegration.joinComputer(computerInfo);
  }

  async notifyCertificateIssued(certificateInfo) {
    if (!this.enterpriseDirectoryIntegration) {
      return; // Silently ignore if not available
    }

    return await this.enterpriseDirectoryIntegration.notifyCertificateIssued(certificateInfo);
  }

  async notifyCertificateRevoked(certificateInfo) {
    if (!this.enterpriseDirectoryIntegration) {
      return; // Silently ignore if not available
    }

    return await this.enterpriseDirectoryIntegration.notifyCertificateRevoked(certificateInfo);
  }

  // Management Methods

  async performFullCertificateSync() {
    if (!this.certificateSync) {
      throw new Error('Certificate sync not available');
    }

    return await this.certificateSync.performFullSync();
  }

  async performNetworkPolicySync() {
    if (!this.networkProfileSync) {
      throw new Error('Network profile sync not available');
    }

    return await this.networkProfileSync.syncNetworkPolicies();
  }

  // Status and Health

  getStatus() {
    return {
      initialized: this.initialized,
      integrationStatus: this.integrationStatus,
      components: {
        enterpriseDirectory: this.enterpriseDirectoryIntegration?.getStatus() || null,
        certificateSync: this.certificateSync?.getStatus() || null,
        networkProfileSync: this.networkProfileSync?.getStatus() || null
      }
    };
  }

  async healthCheck() {
    try {
      const health = {
        status: 'healthy',
        components: {}
      };

      // Check Enterprise Directory connection
      if (this.enterpriseDirectoryIntegration) {
        try {
          await this.enterpriseDirectoryIntegration.testConnection();
          health.components.enterpriseDirectory = 'healthy';
        } catch (error) {
          health.components.enterpriseDirectory = 'unhealthy';
          health.status = 'degraded';
        }
      } else {
        health.components.enterpriseDirectory = 'disabled';
      }

      // Check Certificate Sync
      if (this.certificateSync) {
        const certSyncStatus = this.certificateSync.getStatus();
        health.components.certificateSync = certSyncStatus.enterpriseDirectoryConnected ? 'healthy' : 'degraded';
        if (health.components.certificateSync !== 'healthy' && health.status === 'healthy') {
          health.status = 'degraded';
        }
      } else {
        health.components.certificateSync = 'disabled';
      }

      // Check Network Profile Sync
      if (this.networkProfileSync) {
        const networkSyncStatus = this.networkProfileSync.getStatus();
        health.components.networkProfileSync = networkSyncStatus.enterpriseDirectoryConnected ? 'healthy' : 'degraded';
        if (health.components.networkProfileSync !== 'healthy' && health.status === 'healthy') {
          health.status = 'degraded';
        }
      } else {
        health.components.networkProfileSync = 'disabled';
      }

      return health;

    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  async stop() {
    logger.info('🛑 Stopping Enterprise Directory Integration...');

    if (this.networkProfileSync) {
      await this.networkProfileSync.stop();
    }

    if (this.certificateSync) {
      await this.certificateSync.stop();
    }

    if (this.enterpriseDirectoryIntegration) {
      await this.enterpriseDirectoryIntegration.stop();
    }

    this.initialized = false;
    this.integrationStatus = {
      enterpriseDirectory: 'disconnected',
      certificateSync: 'stopped',
      networkProfileSync: 'stopped'
    };

    logger.info('✅ Enterprise Directory Integration stopped');
  }
}

module.exports = IntegrationManager;