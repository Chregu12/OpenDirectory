const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

class MobileIntegrationService {
  constructor(licenseService) {
    this.licenseService = licenseService;
    this.mobileServiceConfig = {
      baseUrl: process.env.MOBILE_SERVICE_URL || 'http://mobile-management:3013',
      apiKey: process.env.MOBILE_API_KEY || '',
      syncInterval: parseInt(process.env.MOBILE_SYNC_INTERVAL) || 300000, // 5 minutes
      timeout: parseInt(process.env.MOBILE_TIMEOUT) || 30000 // 30 seconds
    };
    
    this.syncHistory = new Map();
    this.mobileLicenseCache = new Map();
    this.lastSyncStatus = null;
    
    this.startMobileSync();
  }

  startMobileSync() {
    // Initial sync
    this.performFullSync();
    
    // Regular sync interval
    setInterval(() => {
      this.performIncrementalSync();
    }, this.mobileServiceConfig.syncInterval);

    this.licenseService.logger.info('Mobile integration service started', {
      baseUrl: this.mobileServiceConfig.baseUrl,
      syncInterval: this.mobileServiceConfig.syncInterval
    });
  }

  async performFullSync() {
    const syncId = uuidv4();
    const sync = {
      id: syncId,
      type: 'full',
      startedAt: new Date().toISOString(),
      completedAt: null,
      status: 'running',
      results: {
        licensesSynced: 0,
        licensesCreated: 0,
        licensesUpdated: 0,
        usageRecordsSynced: 0,
        errors: []
      }
    };

    this.syncHistory.set(syncId, sync);

    try {
      this.licenseService.logger.info('Starting full mobile sync', { syncId });

      // Sync mobile licenses
      const licenseResults = await this.syncMobileLicenses();
      sync.results.licensesSynced = licenseResults.synced;
      sync.results.licensesCreated = licenseResults.created;
      sync.results.licensesUpdated = licenseResults.updated;

      // Sync mobile usage data
      const usageResults = await this.syncMobileUsage();
      sync.results.usageRecordsSynced = usageResults.synced;

      // Sync mobile compliance data
      await this.syncMobileCompliance();

      sync.status = 'completed';
      sync.completedAt = new Date().toISOString();
      
      this.lastSyncStatus = 'success';
      this.licenseService.logger.info('Full mobile sync completed', {
        syncId,
        results: sync.results
      });

    } catch (error) {
      sync.status = 'failed';
      sync.error = error.message;
      sync.completedAt = new Date().toISOString();
      
      this.lastSyncStatus = 'failed';
      this.licenseService.logger.error('Full mobile sync failed', {
        syncId,
        error: error.message
      });
      
      sync.results.errors.push({
        stage: 'full_sync',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }

    this.syncHistory.set(syncId, sync);
    return sync;
  }

  async performIncrementalSync() {
    const syncId = uuidv4();
    const sync = {
      id: syncId,
      type: 'incremental',
      startedAt: new Date().toISOString(),
      completedAt: null,
      status: 'running',
      results: {
        licensesSynced: 0,
        usageRecordsSynced: 0,
        errors: []
      }
    };

    this.syncHistory.set(syncId, sync);

    try {
      // Get latest changes since last sync
      const lastSyncTime = this.getLastSuccessfulSyncTime();
      
      // Sync recent license changes
      const licenseResults = await this.syncRecentLicenseChanges(lastSyncTime);
      sync.results.licensesSynced = licenseResults.synced;

      // Sync recent usage data
      const usageResults = await this.syncRecentUsage(lastSyncTime);
      sync.results.usageRecordsSynced = usageResults.synced;

      sync.status = 'completed';
      sync.completedAt = new Date().toISOString();
      
      this.lastSyncStatus = 'success';

    } catch (error) {
      sync.status = 'failed';
      sync.error = error.message;
      sync.completedAt = new Date().toISOString();
      
      this.lastSyncStatus = 'failed';
      this.licenseService.logger.error('Incremental mobile sync failed', {
        syncId,
        error: error.message
      });
    }

    this.syncHistory.set(syncId, sync);
    return sync;
  }

  async syncMobileLicenses() {
    try {
      // Fetch mobile app licenses from MAM service
      const response = await this.makeApiRequest('GET', '/api/mam/licenses');
      const mobileLicenses = response.data || [];

      let synced = 0;
      let created = 0;
      let updated = 0;

      for (const mobileLicense of mobileLicenses) {
        try {
          const result = await this.processMobileLicense(mobileLicense);
          if (result.action === 'created') {
            created++;
          } else if (result.action === 'updated') {
            updated++;
          }
          synced++;
        } catch (error) {
          this.licenseService.logger.error('Failed to process mobile license', {
            mobileLicenseId: mobileLicense.id,
            error: error.message
          });
        }
      }

      return { synced, created, updated };

    } catch (error) {
      this.licenseService.logger.error('Failed to sync mobile licenses', {
        error: error.message
      });
      throw error;
    }
  }

  async processMobileLicense(mobileLicense) {
    // Find existing license by mobile license ID
    const existingLicense = Array.from(this.licenseService.licenses.values())
      .find(license => 
        license.externalId === mobileLicense.id && 
        license.source === 'mobile'
      );

    const licenseData = {
      name: mobileLicense.appName || `Mobile App License`,
      description: `Mobile license for ${mobileLicense.appName || 'Unknown App'}`,
      vendorId: this.getOrCreateMobileVendor(mobileLicense),
      softwareId: await this.getOrCreateMobileSoftware(mobileLicense),
      type: 'per_device',
      externalId: mobileLicense.id,
      source: 'mobile',
      status: this.mapMobileLicenseStatus(mobileLicense.status),
      quantity: mobileLicense.totalSeats || 1,
      cost: mobileLicense.cost || 0,
      currency: mobileLicense.currency || 'USD',
      purchaseDate: mobileLicense.purchaseDate || mobileLicense.createdAt,
      expiryDate: mobileLicense.expiryDate || null,
      terms: {
        concurrent: false,
        maxUsers: mobileLicense.totalSeats || 1,
        allowedPlatforms: [mobileLicense.platform || 'mobile'],
        transferable: false
      },
      compliance: {
        requiresActivation: false,
        requiresRegistration: true,
        allowsRemoteAccess: true,
        geoRestrictions: [],
        usageReporting: true
      },
      mobileData: {
        appId: mobileLicense.appId,
        platform: mobileLicense.platform,
        version: mobileLicense.version,
        packageName: mobileLicense.packageName,
        bundleId: mobileLicense.bundleId,
        category: mobileLicense.category,
        isManaged: mobileLicense.isManaged,
        deploymentType: mobileLicense.deploymentType,
        lastSynced: new Date().toISOString()
      }
    };

    if (existingLicense) {
      // Update existing license
      const updatedLicense = {
        ...existingLicense,
        ...licenseData,
        id: existingLicense.id,
        updatedAt: new Date().toISOString()
      };

      this.licenseService.licenses.set(existingLicense.id, updatedLicense);
      this.mobileLicenseCache.set(mobileLicense.id, updatedLicense);

      return { action: 'updated', license: updatedLicense };

    } else {
      // Create new license
      const licenseId = uuidv4();
      const newLicense = {
        ...licenseData,
        id: licenseId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: 'mobile-sync'
      };

      this.licenseService.licenses.set(licenseId, newLicense);
      this.mobileLicenseCache.set(mobileLicense.id, newLicense);

      // Log audit event
      this.licenseService.logAuditEvent('mobile_license_created', {
        licenseId,
        mobileLicenseId: mobileLicense.id,
        appName: mobileLicense.appName
      });

      return { action: 'created', license: newLicense };
    }
  }

  async syncMobileUsage() {
    try {
      // Fetch mobile usage data from MAM service
      const response = await this.makeApiRequest('GET', '/api/mam/analytics/usage-data', {
        since: this.getLastSuccessfulSyncTime()
      });
      const usageData = response.data || [];

      let synced = 0;

      for (const usage of usageData) {
        try {
          await this.processMobileUsage(usage);
          synced++;
        } catch (error) {
          this.licenseService.logger.error('Failed to process mobile usage', {
            usageId: usage.id,
            error: error.message
          });
        }
      }

      return { synced };

    } catch (error) {
      this.licenseService.logger.error('Failed to sync mobile usage', {
        error: error.message
      });
      throw error;
    }
  }

  async processMobileUsage(mobileUsage) {
    // Find corresponding license
    const mobileLicense = this.mobileLicenseCache.get(mobileUsage.licenseId) ||
      Array.from(this.licenseService.licenses.values())
        .find(license => license.externalId === mobileUsage.licenseId);

    if (!mobileLicense) {
      this.licenseService.logger.warn('Mobile usage without corresponding license', {
        mobileLicenseId: mobileUsage.licenseId
      });
      return;
    }

    // Create usage record in license management format
    const usageRecord = {
      id: uuidv4(),
      licenseId: mobileLicense.id,
      userId: mobileUsage.userId,
      deviceId: mobileUsage.deviceId,
      action: this.mapMobileUsageAction(mobileUsage.action),
      timestamp: mobileUsage.timestamp,
      metadata: {
        source: 'mobile',
        mobileUsageId: mobileUsage.id,
        appVersion: mobileUsage.appVersion,
        platform: mobileUsage.platform,
        deviceModel: mobileUsage.deviceModel,
        osVersion: mobileUsage.osVersion,
        sessionDuration: mobileUsage.duration || 0,
        features: mobileUsage.features || [],
        location: mobileUsage.location || ''
      },
      duration: mobileUsage.duration || 0,
      features: mobileUsage.features || [],
      location: mobileUsage.location || '',
      ipAddress: mobileUsage.ipAddress || '',
      userAgent: `${mobileUsage.platform || 'Mobile'}/${mobileUsage.appVersion || '1.0'}`
    };

    // Store usage record
    if (!this.licenseService.usage.has(mobileLicense.id)) {
      this.licenseService.usage.set(mobileLicense.id, []);
    }
    this.licenseService.usage.get(mobileLicense.id).push(usageRecord);

    // Update license usage statistics
    this.licenseService.updateLicenseUsageStats(mobileLicense, usageRecord);

    // Check for compliance violations
    this.licenseService.checkUsageCompliance(mobileLicense, usageRecord);

    return usageRecord;
  }

  async syncMobileCompliance() {
    try {
      // Fetch mobile compliance data
      const response = await this.makeApiRequest('GET', '/api/mam/compliance/violations');
      const violations = response.data || [];

      for (const violation of violations) {
        await this.processMobileComplianceViolation(violation);
      }

    } catch (error) {
      this.licenseService.logger.error('Failed to sync mobile compliance', {
        error: error.message
      });
      // Don't throw error for compliance sync failures
    }
  }

  async processMobileComplianceViolation(mobileViolation) {
    // Find corresponding license
    const mobileLicense = Array.from(this.licenseService.licenses.values())
      .find(license => license.externalId === mobileViolation.appId);

    if (!mobileLicense) {
      return;
    }

    // Create compliance violation in license management format
    const violationId = uuidv4();
    const violation = {
      id: violationId,
      licenseId: mobileLicense.id,
      type: this.mapMobileViolationType(mobileViolation.type),
      severity: this.mapMobileViolationSeverity(mobileViolation.severity),
      details: {
        source: 'mobile',
        mobileViolationId: mobileViolation.id,
        deviceId: mobileViolation.deviceId,
        userId: mobileViolation.userId,
        description: mobileViolation.description,
        recommendation: mobileViolation.recommendation,
        ...mobileViolation.details
      },
      status: 'open',
      detectedAt: mobileViolation.detectedAt || new Date().toISOString(),
      resolvedAt: null,
      resolvedBy: null,
      resolution: null
    };

    this.licenseService.violations.set(violationId, violation);

    // Create alert for critical violations
    if (violation.severity === 'critical') {
      this.licenseService.createAlert(mobileLicense.id, violation);
    }
  }

  async syncRecentLicenseChanges(since) {
    try {
      const response = await this.makeApiRequest('GET', '/api/mam/licenses', {
        modifiedSince: since
      });
      const recentLicenses = response.data || [];

      let synced = 0;
      for (const license of recentLicenses) {
        await this.processMobileLicense(license);
        synced++;
      }

      return { synced };

    } catch (error) {
      this.licenseService.logger.error('Failed to sync recent license changes', {
        error: error.message,
        since
      });
      throw error;
    }
  }

  async syncRecentUsage(since) {
    try {
      const response = await this.makeApiRequest('GET', '/api/mam/analytics/usage-data', {
        since: since
      });
      const recentUsage = response.data || [];

      let synced = 0;
      for (const usage of recentUsage) {
        await this.processMobileUsage(usage);
        synced++;
      }

      return { synced };

    } catch (error) {
      this.licenseService.logger.error('Failed to sync recent usage', {
        error: error.message,
        since
      });
      throw error;
    }
  }

  // Mobile-specific license management operations
  async assignMobileLicense(mobileLicenseId, deviceId, userId) {
    try {
      const response = await this.makeApiRequest('POST', `/api/mam/licenses/${mobileLicenseId}/assign`, {
        deviceId,
        userId,
        assignedBy: 'license-management-service'
      });

      // Update local license data
      const license = this.findLicenseByMobileId(mobileLicenseId);
      if (license) {
        // Track assignment in license management
        await this.licenseService.assignLicense(license.id, { userId, deviceId });
      }

      return response.data;

    } catch (error) {
      this.licenseService.logger.error('Failed to assign mobile license', {
        mobileLicenseId,
        deviceId,
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async revokeMobileLicense(mobileLicenseId, deviceId, userId) {
    try {
      const response = await this.makeApiRequest('POST', `/api/mam/licenses/${mobileLicenseId}/revoke`, {
        deviceId,
        userId,
        revokedBy: 'license-management-service'
      });

      // Update local license data
      const license = this.findLicenseByMobileId(mobileLicenseId);
      if (license) {
        // Track revocation in license management
        await this.licenseService.revokeLicense(license.id, { userId, deviceId });
      }

      return response.data;

    } catch (error) {
      this.licenseService.logger.error('Failed to revoke mobile license', {
        mobileLicenseId,
        deviceId,
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async getMobileLicenseUsage(mobileLicenseId, options = {}) {
    try {
      const response = await this.makeApiRequest('GET', `/api/mam/licenses/${mobileLicenseId}/usage`, {
        timeframe: options.timeframe || '7d',
        detailed: options.detailed || false
      });

      return response.data;

    } catch (error) {
      this.licenseService.logger.error('Failed to get mobile license usage', {
        mobileLicenseId,
        error: error.message
      });
      throw error;
    }
  }

  async getMobileComplianceStatus() {
    try {
      const response = await this.makeApiRequest('GET', '/api/mam/compliance/overview');
      
      return {
        totalMobileLicenses: response.data.totalLicenses || 0,
        compliantLicenses: response.data.compliantLicenses || 0,
        violations: response.data.violations || 0,
        lastUpdated: new Date().toISOString(),
        details: response.data
      };

    } catch (error) {
      this.licenseService.logger.error('Failed to get mobile compliance status', {
        error: error.message
      });
      throw error;
    }
  }

  async pushLicenseDataToMobile(licenseId) {
    const license = this.licenseService.licenses.get(licenseId);
    if (!license || license.source === 'mobile') {
      return; // Don't push mobile-sourced licenses back to mobile service
    }

    // Convert license to mobile format
    const mobileFormat = this.convertToMobileFormat(license);

    try {
      const response = await this.makeApiRequest('POST', '/api/mam/licenses/external', mobileFormat);
      
      // Update license with mobile reference
      license.mobileData = license.mobileData || {};
      license.mobileData.externalId = response.data.id;
      license.mobileData.lastPushed = new Date().toISOString();
      
      this.licenseService.licenses.set(licenseId, license);

      return response.data;

    } catch (error) {
      this.licenseService.logger.error('Failed to push license to mobile service', {
        licenseId,
        error: error.message
      });
      throw error;
    }
  }

  // Helper Methods
  async makeApiRequest(method, endpoint, data = null, params = {}) {
    const config = {
      method,
      url: `${this.mobileServiceConfig.baseUrl}${endpoint}`,
      timeout: this.mobileServiceConfig.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpenDirectory-LicenseManagement/1.0'
      }
    };

    if (this.mobileServiceConfig.apiKey) {
      config.headers['X-API-Key'] = this.mobileServiceConfig.apiKey;
    }

    if (data) {
      config.data = data;
    }

    if (Object.keys(params).length > 0) {
      config.params = params;
    }

    try {
      const response = await axios(config);
      return response.data;
    } catch (error) {
      if (error.response) {
        // API returned error response
        throw new Error(`Mobile API error: ${error.response.status} - ${error.response.data?.error || error.response.statusText}`);
      } else if (error.request) {
        // Network error
        throw new Error(`Mobile API network error: ${error.message}`);
      } else {
        // Other error
        throw error;
      }
    }
  }

  getOrCreateMobileVendor(mobileLicense) {
    // Check if mobile vendor already exists
    for (const [vendorId, vendor] of this.licenseService.vendors) {
      if (vendor.name === 'Mobile Apps' || vendor.id === 'mobile_vendor') {
        return vendorId;
      }
    }

    // Create mobile vendor
    const vendorId = 'mobile_vendor';
    const vendor = {
      id: vendorId,
      name: 'Mobile Apps',
      description: 'Mobile application publisher',
      website: '',
      supportContact: {
        email: '',
        phone: ''
      },
      products: ['Mobile Applications'],
      licenseTypes: ['per_device'],
      createdBy: 'mobile-sync'
    };

    this.licenseService.vendors.set(vendorId, vendor);
    return vendorId;
  }

  async getOrCreateMobileSoftware(mobileLicense) {
    const appName = mobileLicense.appName || 'Unknown Mobile App';
    
    // Check if software already exists
    for (const [softwareId, software] of this.licenseService.software) {
      if (software.name === appName && software.category === 'mobile') {
        return softwareId;
      }
    }

    // Create new software entry
    const softwareId = uuidv4();
    const software = {
      id: softwareId,
      name: appName,
      description: mobileLicense.description || `Mobile application: ${appName}`,
      category: 'mobile',
      vendor: 'mobile_vendor',
      version: mobileLicense.version || '1.0.0',
      platform: mobileLicense.platform || 'mobile',
      packageName: mobileLicense.packageName || '',
      bundleId: mobileLicense.bundleId || '',
      createdAt: new Date().toISOString(),
      createdBy: 'mobile-sync'
    };

    this.licenseService.software.set(softwareId, software);
    return softwareId;
  }

  mapMobileLicenseStatus(mobileStatus) {
    const statusMap = {
      'active': 'active',
      'inactive': 'inactive',
      'suspended': 'suspended',
      'expired': 'expired',
      'pending': 'pending'
    };

    return statusMap[mobileStatus] || 'active';
  }

  mapMobileUsageAction(mobileAction) {
    const actionMap = {
      'app_start': 'start',
      'app_stop': 'stop',
      'app_background': 'pause',
      'app_foreground': 'resume',
      'feature_access': 'feature_access',
      'heartbeat': 'heartbeat'
    };

    return actionMap[mobileAction] || 'heartbeat';
  }

  mapMobileViolationType(mobileType) {
    const typeMap = {
      'unauthorized_device': 'unauthorized_platform',
      'license_expired': 'expired',
      'usage_exceeded': 'overusage',
      'geo_violation': 'geo_restriction',
      'policy_violation': 'policy_violation'
    };

    return typeMap[mobileType] || 'policy_violation';
  }

  mapMobileViolationSeverity(mobileSeverity) {
    const severityMap = {
      'critical': 'critical',
      'high': 'high', 
      'medium': 'medium',
      'low': 'low',
      'info': 'low'
    };

    return severityMap[mobileSeverity] || 'medium';
  }

  findLicenseByMobileId(mobileLicenseId) {
    return Array.from(this.licenseService.licenses.values())
      .find(license => license.externalId === mobileLicenseId && license.source === 'mobile');
  }

  convertToMobileFormat(license) {
    return {
      name: license.name,
      description: license.description,
      appName: license.name,
      platform: license.terms?.allowedPlatforms?.[0] || 'mobile',
      totalSeats: license.quantity || 1,
      cost: license.cost || 0,
      currency: license.currency || 'USD',
      expiryDate: license.expiryDate,
      status: license.status,
      source: 'license-management',
      externalId: license.id,
      metadata: {
        licenseType: license.type,
        vendor: license.vendorId,
        syncedAt: new Date().toISOString()
      }
    };
  }

  getLastSuccessfulSyncTime() {
    // Find the last successful sync
    const successfulSyncs = Array.from(this.syncHistory.values())
      .filter(sync => sync.status === 'completed')
      .sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt));

    if (successfulSyncs.length > 0) {
      return successfulSyncs[0].startedAt;
    }

    // Default to 24 hours ago if no previous sync
    return moment().subtract(24, 'hours').toISOString();
  }

  // Public API Methods
  async triggerManualSync() {
    this.licenseService.logger.info('Manual mobile sync triggered');
    return await this.performFullSync();
  }

  async getSyncStatus() {
    const recentSyncs = Array.from(this.syncHistory.values())
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
      .slice(0, 10);

    const lastSync = recentSyncs[0];
    
    return {
      lastSyncStatus: this.lastSyncStatus,
      lastSync: lastSync ? {
        id: lastSync.id,
        type: lastSync.type,
        status: lastSync.status,
        startedAt: lastSync.startedAt,
        completedAt: lastSync.completedAt,
        results: lastSync.results
      } : null,
      nextSyncIn: this.mobileServiceConfig.syncInterval,
      recentSyncs: recentSyncs.map(sync => ({
        id: sync.id,
        type: sync.type,
        status: sync.status,
        startedAt: sync.startedAt,
        completedAt: sync.completedAt
      })),
      configuration: {
        baseUrl: this.mobileServiceConfig.baseUrl,
        syncInterval: this.mobileServiceConfig.syncInterval,
        timeout: this.mobileServiceConfig.timeout
      }
    };
  }

  async getMobileLicenseMetrics() {
    const mobileLicenses = Array.from(this.licenseService.licenses.values())
      .filter(license => license.source === 'mobile');

    const metrics = {
      total: mobileLicenses.length,
      byStatus: {},
      byPlatform: {},
      totalCost: 0,
      utilizationRate: 0
    };

    mobileLicenses.forEach(license => {
      // By status
      metrics.byStatus[license.status] = (metrics.byStatus[license.status] || 0) + 1;
      
      // By platform
      const platform = license.mobileData?.platform || 'unknown';
      metrics.byPlatform[platform] = (metrics.byPlatform[platform] || 0) + 1;
      
      // Total cost
      metrics.totalCost += license.cost || 0;
      
      // Utilization
      const usage = this.licenseService.calculateLicenseUsage(license.id);
      metrics.utilizationRate += usage.utilizationRate;
    });

    if (mobileLicenses.length > 0) {
      metrics.utilizationRate = metrics.utilizationRate / mobileLicenses.length;
    }

    return metrics;
  }

  async testConnection() {
    try {
      const response = await this.makeApiRequest('GET', '/health');
      return {
        status: 'connected',
        mobileServiceVersion: response.version || 'unknown',
        responseTime: Date.now() // Would need to measure actual response time
      };
    } catch (error) {
      return {
        status: 'disconnected',
        error: error.message
      };
    }
  }
}

module.exports = MobileIntegrationService;