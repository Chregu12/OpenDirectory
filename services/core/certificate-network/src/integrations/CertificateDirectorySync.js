/**
 * OpenDirectory Certificate Directory Sync Service
 * Synchronizes certificate information between the Certificate Network Service
 * and the Enterprise Directory Service for seamless integration
 */

const EventEmitter = require('events');
const { logger } = require('../utils/logger');

class CertificateDirectorySync extends EventEmitter {
  constructor(config, enterpriseDirectoryIntegration, certificateLifecycleService, enterpriseCAService) {
    super();
    
    this.config = config;
    this.enterpriseDirectory = enterpriseDirectoryIntegration;
    this.certificateLifecycle = certificateLifecycleService;
    this.enterpriseCA = enterpriseCAService;
    
    // Sync state tracking
    this.syncInProgress = false;
    this.lastFullSync = null;
    this.syncErrors = [];
    
    // Sync configuration
    this.fullSyncInterval = config.certificateSync.fullSyncInterval || 3600000; // 1 hour
    this.incrementalSyncInterval = config.certificateSync.incrementalSyncInterval || 300000; // 5 minutes
    this.batchSize = config.certificateSync.batchSize || 100;
    
    logger.info('🔄 Certificate Directory Sync Service initialized');
  }

  async initialize() {
    try {
      logger.info('🚀 Starting Certificate Directory Sync...');

      // Wait for Enterprise Directory to be connected
      if (!this.enterpriseDirectory.connected) {
        await new Promise((resolve) => {
          this.enterpriseDirectory.once('connected', resolve);
        });
      }

      // Set up event listeners
      this.setupEventListeners();
      
      // Perform initial full synchronization
      await this.performFullSync();
      
      // Schedule periodic syncs
      this.schedulePeriodicSyncs();
      
      logger.info('✅ Certificate Directory Sync initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Certificate Directory Sync:', error);
      throw error;
    }
  }

  setupEventListeners() {
    // Listen for certificate lifecycle events
    this.certificateLifecycle.on('certificateIssued', this.handleCertificateIssued.bind(this));
    this.certificateLifecycle.on('certificateRevoked', this.handleCertificateRevoked.bind(this));
    this.certificateLifecycle.on('certificateRenewed', this.handleCertificateRenewed.bind(this));
    this.certificateLifecycle.on('certificateExpired', this.handleCertificateExpired.bind(this));

    // Listen for CA events
    this.enterpriseCA.on('crlUpdated', this.handleCRLUpdated.bind(this));
    this.enterpriseCA.on('caRootUpdated', this.handleCAUpdate.bind(this));

    // Listen for directory events
    this.enterpriseDirectory.on('userAuthenticated', this.handleUserAuthenticated.bind(this));
    this.enterpriseDirectory.on('computerJoined', this.handleComputerJoined.bind(this));
    this.enterpriseDirectory.on('disconnected', this.handleDirectoryDisconnected.bind(this));
    this.enterpriseDirectory.on('connected', this.handleDirectoryReconnected.bind(this));

    logger.info('🔗 Certificate sync event listeners configured');
  }

  // Certificate Event Handlers
  async handleCertificateIssued(event) {
    try {
      const { certificate, enrollmentInfo } = event;
      
      logger.info(`📜 Syncing issued certificate: ${certificate.subject.commonName}`);

      // Notify Enterprise Directory
      await this.enterpriseDirectory.notifyCertificateIssued({
        serialNumber: certificate.serialNumber,
        subject: certificate.subject,
        issuer: certificate.issuer,
        notBefore: certificate.validity.notBefore,
        notAfter: certificate.validity.notAfter,
        template: enrollmentInfo.template,
        thumbprint: certificate.thumbprint,
        keyUsage: certificate.keyUsage,
        enhancedKeyUsage: certificate.enhancedKeyUsage,
        subjectAlternativeNames: certificate.subjectAlternativeNames,
        userGUID: enrollmentInfo.userGUID,
        computerGUID: enrollmentInfo.computerGUID
      });

      // Update user/computer certificate attributes
      if (enrollmentInfo.userGUID) {
        await this.updateUserCertificateReferences(enrollmentInfo.userGUID, certificate);
      }

      if (enrollmentInfo.computerGUID) {
        await this.updateComputerCertificateReferences(enrollmentInfo.computerGUID, certificate);
      }

      this.emit('certificateSynced', { action: 'issued', certificate, enrollmentInfo });

    } catch (error) {
      logger.error('Certificate issue sync error:', error);
      this.recordSyncError('certificateIssued', error);
    }
  }

  async handleCertificateRevoked(event) {
    try {
      const { certificate, revocationInfo } = event;
      
      logger.info(`🚫 Syncing revoked certificate: ${certificate.serialNumber}`);

      // Notify Enterprise Directory
      await this.enterpriseDirectory.notifyCertificateRevoked({
        serialNumber: certificate.serialNumber,
        thumbprint: certificate.thumbprint,
        revocationDate: revocationInfo.revocationDate,
        revocationReason: revocationInfo.reason,
        revokedBy: revocationInfo.revokedBy
      });

      // Remove certificate references from user/computer objects
      if (certificate.userGUID) {
        await this.removeUserCertificateReferences(certificate.userGUID, certificate);
      }

      if (certificate.computerGUID) {
        await this.removeComputerCertificateReferences(certificate.computerGUID, certificate);
      }

      this.emit('certificateSynced', { action: 'revoked', certificate, revocationInfo });

    } catch (error) {
      logger.error('Certificate revocation sync error:', error);
      this.recordSyncError('certificateRevoked', error);
    }
  }

  async handleCertificateRenewed(event) {
    try {
      const { oldCertificate, newCertificate, enrollmentInfo } = event;
      
      logger.info(`🔄 Syncing renewed certificate: ${newCertificate.subject.commonName}`);

      // Handle as both revocation of old and issuance of new
      await this.handleCertificateRevoked({
        certificate: oldCertificate,
        revocationInfo: {
          revocationDate: new Date(),
          reason: 'certificateHold', // Superseded
          revokedBy: 'System - Certificate Renewal'
        }
      });

      await this.handleCertificateIssued({
        certificate: newCertificate,
        enrollmentInfo
      });

      this.emit('certificateSynced', { action: 'renewed', oldCertificate, newCertificate });

    } catch (error) {
      logger.error('Certificate renewal sync error:', error);
      this.recordSyncError('certificateRenewed', error);
    }
  }

  async handleCertificateExpired(event) {
    try {
      const { certificate } = event;
      
      logger.info(`⏰ Syncing expired certificate: ${certificate.serialNumber}`);

      // Notify directory of expiration for cleanup
      await this.enterpriseDirectory.notifyCertificateRevoked({
        serialNumber: certificate.serialNumber,
        thumbprint: certificate.thumbprint,
        revocationDate: certificate.validity.notAfter,
        revocationReason: 'expired',
        revokedBy: 'System - Certificate Expiration'
      });

      this.emit('certificateSynced', { action: 'expired', certificate });

    } catch (error) {
      logger.error('Certificate expiration sync error:', error);
      this.recordSyncError('certificateExpired', error);
    }
  }

  // Directory Event Handlers
  async handleUserAuthenticated(event) {
    try {
      const { user } = event;
      
      // Check if user needs certificate auto-enrollment
      await this.checkAutoEnrollment(user);

    } catch (error) {
      logger.error('User authentication sync error:', error);
    }
  }

  async handleComputerJoined(event) {
    try {
      const { computer } = event;
      
      // Automatically enroll computer for machine authentication certificate
      await this.enrollComputerCertificate(computer);

    } catch (error) {
      logger.error('Computer join sync error:', error);
    }
  }

  async handleDirectoryDisconnected() {
    logger.warn('🔴 Enterprise Directory disconnected - pausing certificate sync');
    this.pausePeriodicSyncs();
  }

  async handleDirectoryReconnected() {
    logger.info('🟢 Enterprise Directory reconnected - resuming certificate sync');
    this.schedulePeriodicSyncs();
    
    // Perform incremental sync to catch up
    await this.performIncrementalSync();
  }

  async handleCRLUpdated(event) {
    try {
      const { crl, caInfo } = event;
      
      // Notify directory of CRL update for LDAP publishing
      await this.publishCRLToDirectory(crl, caInfo);

    } catch (error) {
      logger.error('CRL update sync error:', error);
    }
  }

  async handleCAUpdate(event) {
    try {
      const { caCertificate, caInfo } = event;
      
      // Publish updated CA certificate to directory
      await this.publishCACertificateToDirectory(caCertificate, caInfo);

    } catch (error) {
      logger.error('CA update sync error:', error);
    }
  }

  // Sync Operations
  async performFullSync() {
    if (this.syncInProgress) {
      logger.warn('Full sync already in progress, skipping');
      return;
    }

    try {
      this.syncInProgress = true;
      logger.info('🔄 Starting full certificate directory sync...');

      const startTime = Date.now();
      let processedCount = 0;
      let errorCount = 0;

      // Sync all active certificates
      const certificates = await this.certificateLifecycle.getAllActiveCertificates();
      
      for (let i = 0; i < certificates.length; i += this.batchSize) {
        const batch = certificates.slice(i, i + this.batchSize);
        
        try {
          await this.syncCertificateBatch(batch);
          processedCount += batch.length;
          
          logger.debug(`Synced certificate batch: ${processedCount}/${certificates.length}`);
          
        } catch (error) {
          logger.error('Certificate batch sync error:', error);
          errorCount += batch.length;
        }
      }

      // Sync all CRLs
      await this.syncAllCRLs();

      // Sync CA certificates
      await this.syncCACertificates();

      const duration = Date.now() - startTime;
      this.lastFullSync = new Date();

      logger.info(`✅ Full sync completed: ${processedCount} certificates processed, ${errorCount} errors, ${duration}ms`);
      
      this.emit('fullSyncCompleted', {
        processedCount,
        errorCount,
        duration,
        timestamp: this.lastFullSync
      });

    } catch (error) {
      logger.error('Full sync failed:', error);
      this.recordSyncError('fullSync', error);
    } finally {
      this.syncInProgress = false;
    }
  }

  async performIncrementalSync() {
    try {
      logger.debug('🔄 Starting incremental certificate sync...');

      const since = this.lastFullSync || new Date(Date.now() - this.fullSyncInterval);
      const changes = await this.certificateLifecycle.getCertificateChangesSince(since);

      for (const change of changes) {
        try {
          await this.syncCertificateChange(change);
        } catch (error) {
          logger.error('Certificate change sync error:', error);
          this.recordSyncError('incrementalSync', error);
        }
      }

      logger.debug(`✅ Incremental sync completed: ${changes.length} changes processed`);

    } catch (error) {
      logger.error('Incremental sync failed:', error);
      this.recordSyncError('incrementalSync', error);
    }
  }

  async syncCertificateBatch(certificates) {
    const syncPromises = certificates.map(cert => this.syncSingleCertificate(cert));
    await Promise.allSettled(syncPromises);
  }

  async syncSingleCertificate(certificate) {
    try {
      // Determine if this is a user or computer certificate
      let ownerInfo = null;
      
      if (certificate.userGUID) {
        const userResult = await this.enterpriseDirectory.getUserByIdentifier(certificate.userGUID, 'guid');
        if (userResult.success) {
          ownerInfo = { type: 'user', data: userResult.user };
        }
      } else if (certificate.computerGUID) {
        const computerResult = await this.enterpriseDirectory.getComputerByIdentifier(certificate.computerGUID, 'guid');
        if (computerResult.success) {
          ownerInfo = { type: 'computer', data: computerResult.computer };
        }
      }

      if (ownerInfo) {
        await this.updateOwnerCertificateReferences(ownerInfo, certificate);
      }

      // Notify directory of certificate existence
      await this.enterpriseDirectory.notifyCertificateIssued({
        serialNumber: certificate.serialNumber,
        subject: certificate.subject,
        issuer: certificate.issuer,
        notBefore: certificate.validity.notBefore,
        notAfter: certificate.validity.notAfter,
        template: certificate.template,
        thumbprint: certificate.thumbprint,
        userGUID: certificate.userGUID,
        computerGUID: certificate.computerGUID
      });

    } catch (error) {
      throw new Error(`Failed to sync certificate ${certificate.serialNumber}: ${error.message}`);
    }
  }

  async syncCertificateChange(change) {
    switch (change.action) {
      case 'issued':
        await this.handleCertificateIssued(change);
        break;
      case 'revoked':
        await this.handleCertificateRevoked(change);
        break;
      case 'renewed':
        await this.handleCertificateRenewed(change);
        break;
      case 'expired':
        await this.handleCertificateExpired(change);
        break;
      default:
        logger.warn(`Unknown certificate change action: ${change.action}`);
    }
  }

  // Auto-enrollment and Certificate Management
  async checkAutoEnrollment(user) {
    try {
      // Get user's group policies to determine auto-enrollment requirements
      const policiesResult = await this.enterpriseDirectory.getUserPolicies(user.objectGUID);
      if (!policiesResult.success) {
        return;
      }

      const certificatePolicies = policiesResult.certificatePolicies;
      
      for (const policy of certificatePolicies) {
        if (policy.autoEnrollment && policy.enabled) {
          await this.processAutoEnrollment(user, policy);
        }
      }

    } catch (error) {
      logger.error('Auto-enrollment check error:', error);
    }
  }

  async processAutoEnrollment(user, policy) {
    try {
      logger.info(`🔄 Processing auto-enrollment for user ${user.sAMAccountName}, template: ${policy.template}`);

      // Check if user already has a valid certificate for this template
      const existingCerts = await this.certificateLifecycle.getUserCertificatesByTemplate(
        user.objectGUID, 
        policy.template
      );

      const validCerts = existingCerts.filter(cert => 
        cert.status === 'active' && 
        cert.validity.notAfter > new Date()
      );

      // If no valid certificate exists or renewal is needed
      if (validCerts.length === 0 || this.shouldRenewCertificate(validCerts[0], policy)) {
        await this.enrollUserCertificate(user, policy);
      }

    } catch (error) {
      logger.error('Auto-enrollment processing error:', error);
    }
  }

  async enrollUserCertificate(user, policy) {
    try {
      const enrollmentRequest = {
        template: policy.template,
        subject: {
          commonName: user.displayName,
          organizationalUnit: user.department,
          organization: this.config.pki.organization,
          country: this.config.pki.country,
          emailAddress: user.mail
        },
        subjectAlternativeNames: {
          email: [user.mail],
          userPrincipalName: [user.userPrincipalName]
        },
        userGUID: user.objectGUID,
        autoEnrollment: true,
        requestedBy: 'System - Auto-enrollment'
      };

      const result = await this.certificateLifecycle.enrollCertificate(enrollmentRequest);
      
      if (result.success) {
        logger.info(`✅ Auto-enrolled certificate for user: ${user.sAMAccountName}`);
      } else {
        logger.error(`❌ Auto-enrollment failed for user: ${user.sAMAccountName} - ${result.error}`);
      }

    } catch (error) {
      logger.error('User certificate enrollment error:', error);
    }
  }

  async enrollComputerCertificate(computer) {
    try {
      logger.info(`🖥️ Auto-enrolling computer certificate: ${computer.sAMAccountName}`);

      const enrollmentRequest = {
        template: 'ComputerAuthentication',
        subject: {
          commonName: computer.dNSHostName,
          organizationalUnit: 'Computers',
          organization: this.config.pki.organization,
          country: this.config.pki.country
        },
        subjectAlternativeNames: {
          dnsNames: [computer.dNSHostName],
          ipAddresses: computer.networkAddresses || []
        },
        computerGUID: computer.objectGUID,
        autoEnrollment: true,
        requestedBy: 'System - Computer Join'
      };

      const result = await this.certificateLifecycle.enrollCertificate(enrollmentRequest);
      
      if (result.success) {
        logger.info(`✅ Auto-enrolled computer certificate: ${computer.sAMAccountName}`);
      } else {
        logger.error(`❌ Computer auto-enrollment failed: ${computer.sAMAccountName} - ${result.error}`);
      }

    } catch (error) {
      logger.error('Computer certificate enrollment error:', error);
    }
  }

  shouldRenewCertificate(certificate, policy) {
    if (!certificate || !certificate.validity) {
      return true;
    }

    const now = new Date();
    const expiration = new Date(certificate.validity.notAfter);
    const renewalThreshold = policy.renewalThresholdDays || 30;
    const renewalTime = new Date(expiration.getTime() - (renewalThreshold * 24 * 60 * 60 * 1000));

    return now >= renewalTime;
  }

  // Certificate Reference Management
  async updateUserCertificateReferences(userGUID, certificate) {
    try {
      const certificates = await this.certificateLifecycle.getUserCertificates(userGUID);
      const certRefs = certificates.map(cert => ({
        thumbprint: cert.thumbprint,
        serialNumber: cert.serialNumber,
        template: cert.template,
        issuer: cert.issuer,
        subject: cert.subject,
        notAfter: cert.validity.notAfter
      }));

      await this.enterpriseDirectory.updateUserCertificates(userGUID, certRefs);

    } catch (error) {
      logger.error('User certificate reference update error:', error);
    }
  }

  async updateComputerCertificateReferences(computerGUID, certificate) {
    try {
      // Similar to user certificates but for computer objects
      const certificates = await this.certificateLifecycle.getComputerCertificates(computerGUID);
      const certRefs = certificates.map(cert => ({
        thumbprint: cert.thumbprint,
        serialNumber: cert.serialNumber,
        template: cert.template,
        issuer: cert.issuer,
        subject: cert.subject,
        notAfter: cert.validity.notAfter
      }));

      await this.enterpriseDirectory.updateComputerCertificates(computerGUID, certRefs);

    } catch (error) {
      logger.error('Computer certificate reference update error:', error);
    }
  }

  async updateOwnerCertificateReferences(ownerInfo, certificate) {
    if (ownerInfo.type === 'user') {
      await this.updateUserCertificateReferences(ownerInfo.data.objectGUID, certificate);
    } else if (ownerInfo.type === 'computer') {
      await this.updateComputerCertificateReferences(ownerInfo.data.objectGUID, certificate);
    }
  }

  async removeUserCertificateReferences(userGUID, certificate) {
    // Implementation would remove specific certificate from user's certificate list
    await this.updateUserCertificateReferences(userGUID, certificate);
  }

  async removeComputerCertificateReferences(computerGUID, certificate) {
    // Implementation would remove specific certificate from computer's certificate list
    await this.updateComputerCertificateReferences(computerGUID, certificate);
  }

  // CRL and CA Certificate Publishing
  async publishCRLToDirectory(crl, caInfo) {
    try {
      logger.info(`📋 Publishing CRL to directory: ${caInfo.commonName}`);

      // Implementation would publish CRL to LDAP directory for client consumption
      await this.enterpriseDirectory.apiClient.post('/api/pki/crl', {
        crl: crl.toString('base64'),
        caInfo,
        publishedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('CRL publishing error:', error);
    }
  }

  async publishCACertificateToDirectory(caCertificate, caInfo) {
    try {
      logger.info(`🏛️ Publishing CA certificate to directory: ${caInfo.commonName}`);

      await this.enterpriseDirectory.apiClient.post('/api/pki/ca-certificate', {
        certificate: caCertificate.toString('base64'),
        caInfo,
        publishedBy: 'certificate-network',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('CA certificate publishing error:', error);
    }
  }

  async syncAllCRLs() {
    try {
      const crls = await this.enterpriseCA.getAllCRLs();
      for (const crl of crls) {
        await this.publishCRLToDirectory(crl.data, crl.caInfo);
      }
    } catch (error) {
      logger.error('CRL sync error:', error);
    }
  }

  async syncCACertificates() {
    try {
      const caCertificates = await this.enterpriseCA.getAllCACertificates();
      for (const ca of caCertificates) {
        await this.publishCACertificateToDirectory(ca.certificate, ca.info);
      }
    } catch (error) {
      logger.error('CA certificate sync error:', error);
    }
  }

  // Scheduling and Management
  schedulePeriodicSyncs() {
    if (this.fullSyncTimer) {
      clearInterval(this.fullSyncTimer);
    }
    if (this.incrementalSyncTimer) {
      clearInterval(this.incrementalSyncTimer);
    }

    // Schedule full sync
    this.fullSyncTimer = setInterval(async () => {
      try {
        await this.performFullSync();
      } catch (error) {
        logger.error('Scheduled full sync error:', error);
      }
    }, this.fullSyncInterval);

    // Schedule incremental sync
    this.incrementalSyncTimer = setInterval(async () => {
      try {
        await this.performIncrementalSync();
      } catch (error) {
        logger.error('Scheduled incremental sync error:', error);
      }
    }, this.incrementalSyncInterval);

    logger.info('📅 Certificate sync timers scheduled');
  }

  pausePeriodicSyncs() {
    if (this.fullSyncTimer) {
      clearInterval(this.fullSyncTimer);
      this.fullSyncTimer = null;
    }
    if (this.incrementalSyncTimer) {
      clearInterval(this.incrementalSyncTimer);
      this.incrementalSyncTimer = null;
    }

    logger.info('⏸️ Certificate sync timers paused');
  }

  recordSyncError(operation, error) {
    this.syncErrors.push({
      operation,
      error: error.message,
      timestamp: new Date(),
      stack: error.stack
    });

    // Keep only last 100 errors
    if (this.syncErrors.length > 100) {
      this.syncErrors = this.syncErrors.slice(-100);
    }
  }

  // Status and Health
  getStatus() {
    return {
      syncInProgress: this.syncInProgress,
      lastFullSync: this.lastFullSync,
      syncErrors: this.syncErrors.length,
      recentErrors: this.syncErrors.slice(-10),
      timersActive: !!(this.fullSyncTimer && this.incrementalSyncTimer),
      enterpriseDirectoryConnected: this.enterpriseDirectory.connected
    };
  }

  async stop() {
    logger.info('🛑 Stopping Certificate Directory Sync...');
    
    this.pausePeriodicSyncs();
    this.syncInProgress = false;
    
    logger.info('✅ Certificate Directory Sync stopped');
  }
}

module.exports = CertificateDirectorySync;