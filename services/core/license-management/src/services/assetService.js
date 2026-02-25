const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const axios = require('axios');

class AssetService {
  constructor(licenseService) {
    this.licenseService = licenseService;
    this.discoveryAgents = new Map();
    this.assetTypes = new Map();
    this.lifecycleStages = new Map();
    this.initializeAssetTypes();
    this.initializeLifecycleStages();
  }

  initializeAssetTypes() {
    // Software Assets
    this.assetTypes.set('software_license', {
      id: 'software_license',
      name: 'Software License',
      category: 'software',
      attributes: ['license_key', 'version', 'installation_path', 'user_count'],
      discoveryMethods: ['registry_scan', 'file_scan', 'network_scan']
    });

    this.assetTypes.set('installed_software', {
      id: 'installed_software',
      name: 'Installed Software',
      category: 'software',
      attributes: ['version', 'install_date', 'size', 'publisher'],
      discoveryMethods: ['registry_scan', 'wmi_query', 'package_manager']
    });

    // Hardware Assets
    this.assetTypes.set('physical_device', {
      id: 'physical_device',
      name: 'Physical Device',
      category: 'hardware',
      attributes: ['serial_number', 'model', 'manufacturer', 'specs'],
      discoveryMethods: ['network_discovery', 'snmp_scan', 'agent_reporting']
    });

    this.assetTypes.set('virtual_machine', {
      id: 'virtual_machine',
      name: 'Virtual Machine',
      category: 'virtual',
      attributes: ['hypervisor', 'allocated_resources', 'guest_os'],
      discoveryMethods: ['hypervisor_api', 'agent_reporting']
    });

    // Cloud Assets
    this.assetTypes.set('cloud_instance', {
      id: 'cloud_instance',
      name: 'Cloud Instance',
      category: 'cloud',
      attributes: ['instance_type', 'region', 'cost_per_hour', 'provider'],
      discoveryMethods: ['cloud_api', 'billing_api']
    });

    // Mobile Assets
    this.assetTypes.set('mobile_device', {
      id: 'mobile_device',
      name: 'Mobile Device',
      category: 'mobile',
      attributes: ['device_type', 'os_version', 'imei', 'carrier'],
      discoveryMethods: ['mdm_api', 'enrollment_data']
    });
  }

  initializeLifecycleStages() {
    this.lifecycleStages.set('planning', {
      id: 'planning',
      name: 'Planning',
      description: 'Asset requirement planning and approval',
      order: 1,
      activities: ['needs_assessment', 'budget_approval', 'vendor_selection']
    });

    this.lifecycleStages.set('procurement', {
      id: 'procurement',
      name: 'Procurement',
      description: 'Asset acquisition and purchasing',
      order: 2,
      activities: ['purchase_order', 'contract_negotiation', 'delivery']
    });

    this.lifecycleStages.set('deployment', {
      id: 'deployment',
      name: 'Deployment',
      description: 'Asset installation and configuration',
      order: 3,
      activities: ['installation', 'configuration', 'testing', 'user_training']
    });

    this.lifecycleStages.set('active', {
      id: 'active',
      name: 'Active',
      description: 'Asset in production use',
      order: 4,
      activities: ['monitoring', 'maintenance', 'support', 'optimization']
    });

    this.lifecycleStages.set('maintenance', {
      id: 'maintenance',
      name: 'Maintenance',
      description: 'Scheduled maintenance and updates',
      order: 5,
      activities: ['updates', 'patches', 'performance_tuning']
    });

    this.lifecycleStages.set('retirement', {
      id: 'retirement',
      name: 'Retirement',
      description: 'Asset end-of-life and disposal',
      order: 6,
      activities: ['data_backup', 'decommissioning', 'disposal', 'documentation']
    });
  }

  async startAssetDiscovery(options = {}) {
    const discoveryId = uuidv4();
    const discovery = {
      id: discoveryId,
      type: options.discoveryType || 'comprehensive',
      scope: options.scope || 'all',
      startedAt: new Date().toISOString(),
      completedAt: null,
      status: 'running',
      progress: 0,
      results: {
        discovered: 0,
        updated: 0,
        errors: 0
      },
      settings: {
        includeHardware: options.includeHardware !== false,
        includeSoftware: options.includeSoftware !== false,
        includeCloud: options.includeCloud !== false,
        includeMobile: options.includeMobile !== false,
        discoveryMethods: options.discoveryMethods || ['network_scan', 'registry_scan', 'api_query'],
        targetNetworks: options.targetNetworks || [],
        credentials: options.credentials || {}
      }
    };

    try {
      // Store discovery job
      this.licenseService.reports.set(`discovery_${discoveryId}`, discovery);

      // Start discovery process
      await this.performAssetDiscovery(discoveryId);

      return discovery;

    } catch (error) {
      discovery.status = 'failed';
      discovery.error = error.message;
      discovery.completedAt = new Date().toISOString();
      
      this.licenseService.logger.error('Asset discovery failed', {
        discoveryId,
        error: error.message
      });

      return discovery;
    }
  }

  async performAssetDiscovery(discoveryId) {
    const discovery = this.licenseService.reports.get(`discovery_${discoveryId}`);
    if (!discovery) return;

    try {
      const discoveryMethods = discovery.settings.discoveryMethods;
      let totalAssets = 0;

      // Network Discovery
      if (discoveryMethods.includes('network_scan')) {
        const networkAssets = await this.performNetworkDiscovery(discovery.settings);
        totalAssets += await this.processDiscoveredAssets(networkAssets, 'network');
        discovery.progress = 25;
        this.updateDiscoveryProgress(discoveryId, discovery);
      }

      // Software Registry Scan
      if (discoveryMethods.includes('registry_scan')) {
        const softwareAssets = await this.performSoftwareDiscovery(discovery.settings);
        totalAssets += await this.processDiscoveredAssets(softwareAssets, 'software');
        discovery.progress = 50;
        this.updateDiscoveryProgress(discoveryId, discovery);
      }

      // Cloud Assets Discovery
      if (discoveryMethods.includes('cloud_api')) {
        const cloudAssets = await this.performCloudDiscovery(discovery.settings);
        totalAssets += await this.processDiscoveredAssets(cloudAssets, 'cloud');
        discovery.progress = 75;
        this.updateDiscoveryProgress(discoveryId, discovery);
      }

      // Mobile Assets Discovery
      if (discoveryMethods.includes('mobile_mdm')) {
        const mobileAssets = await this.performMobileDiscovery(discovery.settings);
        totalAssets += await this.processDiscoveredAssets(mobileAssets, 'mobile');
        discovery.progress = 90;
        this.updateDiscoveryProgress(discoveryId, discovery);
      }

      // License Reconciliation
      await this.reconcileWithLicenses();
      discovery.progress = 100;

      discovery.status = 'completed';
      discovery.completedAt = new Date().toISOString();
      discovery.results.discovered = totalAssets;

      // Generate discovery report
      const report = this.generateDiscoveryReport(discovery);
      this.licenseService.reports.set(`discovery_report_${discoveryId}`, report);

      // Broadcast completion
      this.licenseService.broadcastToSubscribers('discovery_completed', {
        discoveryId,
        summary: discovery.results,
        reportId: report.id
      });

      this.licenseService.logger.info('Asset discovery completed', {
        discoveryId,
        discoveredAssets: totalAssets
      });

    } catch (error) {
      discovery.status = 'failed';
      discovery.error = error.message;
      discovery.completedAt = new Date().toISOString();
      
      this.licenseService.logger.error('Asset discovery failed', {
        discoveryId,
        error: error.message
      });
    }

    this.licenseService.reports.set(`discovery_${discoveryId}`, discovery);
  }

  async performNetworkDiscovery(settings) {
    // Mock network discovery - in reality would use SNMP, ping sweeps, etc.
    const discoveredAssets = [];
    const networks = settings.targetNetworks || ['192.168.1.0/24'];

    for (const network of networks) {
      // Simulate network scanning
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Generate mock discovered devices
      for (let i = 1; i <= 50; i++) {
        discoveredAssets.push({
          type: 'physical_device',
          identifier: `${network.split('/')[0].replace(/\.\d+$/, '')}.${i}`,
          attributes: {
            ip_address: `${network.split('/')[0].replace(/\.\d+$/, '')}.${i}`,
            hostname: `device-${i}.local`,
            mac_address: this.generateMacAddress(),
            device_type: this.randomDeviceType(),
            manufacturer: this.randomManufacturer(),
            os: this.randomOS(),
            last_seen: new Date().toISOString(),
            discovery_method: 'network_scan'
          }
        });
      }
    }

    return discoveredAssets;
  }

  async performSoftwareDiscovery(settings) {
    // Mock software discovery - in reality would scan registries, file systems, etc.
    const discoveredAssets = [];
    const commonSoftware = [
      'Microsoft Office', 'Adobe Acrobat', 'AutoCAD', 'Photoshop', 'Visual Studio',
      'Chrome', 'Firefox', 'Notepad++', 'WinRAR', 'Spotify'
    ];

    // Simulate software discovery across devices
    for (let deviceId = 1; deviceId <= 100; deviceId++) {
      const installedSoftware = commonSoftware
        .filter(() => Math.random() > 0.3) // Random subset
        .map(software => ({
          type: 'installed_software',
          identifier: `${software.toLowerCase().replace(/\s+/g, '_')}_${deviceId}`,
          attributes: {
            name: software,
            version: this.randomVersion(),
            publisher: this.getPublisher(software),
            install_date: moment().subtract(Math.random() * 365, 'days').toISOString(),
            install_path: `C:\\Program Files\\${software}`,
            size_bytes: Math.floor(Math.random() * 1000000000), // Random size
            device_id: `device-${deviceId}`,
            discovery_method: 'registry_scan'
          }
        }));

      discoveredAssets.push(...installedSoftware);
    }

    return discoveredAssets;
  }

  async performCloudDiscovery(settings) {
    // Mock cloud discovery - in reality would use cloud provider APIs
    const discoveredAssets = [];
    const cloudProviders = ['AWS', 'Azure', 'GCP'];
    const instanceTypes = ['t2.micro', 't2.small', 't2.medium', 'm5.large', 'c5.xlarge'];

    cloudProviders.forEach(provider => {
      for (let i = 1; i <= 20; i++) {
        discoveredAssets.push({
          type: 'cloud_instance',
          identifier: `${provider.toLowerCase()}-instance-${i}`,
          attributes: {
            provider: provider,
            instance_id: `i-${Math.random().toString(36).substr(2, 9)}`,
            instance_type: instanceTypes[Math.floor(Math.random() * instanceTypes.length)],
            region: `${provider.toLowerCase()}-region-1`,
            state: 'running',
            launch_time: moment().subtract(Math.random() * 30, 'days').toISOString(),
            cost_per_hour: (Math.random() * 2).toFixed(4),
            tags: {
              Environment: Math.random() > 0.5 ? 'Production' : 'Development',
              Project: `Project-${Math.floor(Math.random() * 10)}`
            },
            discovery_method: 'cloud_api'
          }
        });
      }
    });

    return discoveredAssets;
  }

  async performMobileDiscovery(settings) {
    // Mock mobile discovery - in reality would use MDM APIs
    const discoveredAssets = [];
    
    try {
      // Integrate with mobile management service
      const response = await axios.get(`${this.licenseService.config.mobileManagementServiceUrl}/api/mam/devices`);
      const mobileDevices = response.data.data || [];

      mobileDevices.forEach(device => {
        discoveredAssets.push({
          type: 'mobile_device',
          identifier: device.deviceId || uuidv4(),
          attributes: {
            device_name: device.deviceName,
            platform: device.platform,
            os_version: device.osVersion,
            model: device.model,
            serial_number: device.serialNumber,
            imei: device.imei,
            enrollment_date: device.enrolledAt,
            last_checkin: device.lastSeen,
            compliance_status: device.complianceStatus,
            discovery_method: 'mobile_mdm'
          }
        });
      });
    } catch (error) {
      this.licenseService.logger.warn('Mobile discovery failed', { error: error.message });
    }

    return discoveredAssets;
  }

  async processDiscoveredAssets(discoveredAssets, category) {
    let processedCount = 0;

    for (const discoveredAsset of discoveredAssets) {
      try {
        const existingAsset = this.findExistingAsset(discoveredAsset);
        
        if (existingAsset) {
          // Update existing asset
          await this.updateAsset(existingAsset.id, {
            ...discoveredAsset.attributes,
            lastDiscovered: new Date().toISOString(),
            discoveryMethod: discoveredAsset.attributes.discovery_method
          });
        } else {
          // Create new asset
          await this.createAsset({
            name: this.generateAssetName(discoveredAsset),
            type: discoveredAsset.type,
            category: category,
            identifier: discoveredAsset.identifier,
            status: 'discovered',
            lifecycleStage: 'active',
            attributes: discoveredAsset.attributes,
            discoveredAt: new Date().toISOString(),
            discoveryMethod: discoveredAsset.attributes.discovery_method
          });
        }
        
        processedCount++;
      } catch (error) {
        this.licenseService.logger.error('Failed to process discovered asset', {
          identifier: discoveredAsset.identifier,
          error: error.message
        });
      }
    }

    return processedCount;
  }

  async createAsset(assetData) {
    const assetId = uuidv4();
    const asset = {
      id: assetId,
      name: assetData.name,
      description: assetData.description || '',
      type: assetData.type,
      category: assetData.category,
      identifier: assetData.identifier,
      status: assetData.status || 'active',
      lifecycleStage: assetData.lifecycleStage || 'active',
      attributes: assetData.attributes || {},
      tags: assetData.tags || [],
      owner: assetData.owner || '',
      department: assetData.department || '',
      location: assetData.location || '',
      cost: assetData.cost || 0,
      acquisitionDate: assetData.acquisitionDate || new Date().toISOString(),
      warrantyExpiry: assetData.warrantyExpiry || null,
      maintenanceSchedule: assetData.maintenanceSchedule || null,
      relatedLicenses: [],
      relatedAssets: [],
      discoveredAt: assetData.discoveredAt || new Date().toISOString(),
      discoveryMethod: assetData.discoveryMethod || 'manual',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: assetData.createdBy || 'asset-discovery'
    };

    this.licenseService.assetInventory.set(assetId, asset);

    // Log audit event
    this.licenseService.logAuditEvent('asset_created', {
      assetId,
      assetName: asset.name,
      type: asset.type,
      discoveryMethod: asset.discoveryMethod
    });

    return asset;
  }

  async updateAsset(assetId, updateData) {
    const asset = this.licenseService.assetInventory.get(assetId);
    if (!asset) {
      throw new Error('Asset not found');
    }

    const updatedAsset = {
      ...asset,
      ...updateData,
      id: assetId,
      updatedAt: new Date().toISOString()
    };

    this.licenseService.assetInventory.set(assetId, updatedAsset);

    // Log audit event
    this.licenseService.logAuditEvent('asset_updated', {
      assetId,
      assetName: updatedAsset.name,
      changes: updateData
    });

    return updatedAsset;
  }

  async retireAsset(assetId, retirementData) {
    const asset = this.licenseService.assetInventory.get(assetId);
    if (!asset) {
      throw new Error('Asset not found');
    }

    const retirementId = uuidv4();
    const retirement = {
      id: retirementId,
      assetId,
      reason: retirementData.reason || 'end_of_life',
      retiredBy: retirementData.retiredBy || 'system',
      retiredAt: new Date().toISOString(),
      disposalMethod: retirementData.disposalMethod || 'standard',
      dataWiped: retirementData.dataWiped || false,
      certificateOfDestruction: retirementData.certificateOfDestruction || null,
      replacementAsset: retirementData.replacementAsset || null,
      notes: retirementData.notes || ''
    };

    // Update asset status
    asset.status = 'retired';
    asset.lifecycleStage = 'retirement';
    asset.retiredAt = new Date().toISOString();
    asset.retirement = retirement;
    asset.updatedAt = new Date().toISOString();

    this.licenseService.assetInventory.set(assetId, asset);

    // Log audit event
    this.licenseService.logAuditEvent('asset_retired', {
      assetId,
      assetName: asset.name,
      retirementId,
      reason: retirement.reason
    });

    return { asset, retirement };
  }

  async reconcileWithLicenses() {
    this.licenseService.logger.info('Starting license-asset reconciliation');

    const softwareAssets = Array.from(this.licenseService.assetInventory.values())
      .filter(asset => asset.type === 'installed_software');

    for (const asset of softwareAssets) {
      // Find matching licenses
      const matchingLicenses = this.findMatchingLicenses(asset);
      
      if (matchingLicenses.length > 0) {
        // Link asset to licenses
        asset.relatedLicenses = matchingLicenses.map(license => ({
          licenseId: license.id,
          licenseName: license.name,
          linkType: 'installation',
          linkedAt: new Date().toISOString()
        }));

        // Update license with asset information
        matchingLicenses.forEach(license => {
          if (!license.linkedAssets) {
            license.linkedAssets = [];
          }
          
          if (!license.linkedAssets.some(link => link.assetId === asset.id)) {
            license.linkedAssets.push({
              assetId: asset.id,
              assetName: asset.name,
              linkType: 'installation',
              linkedAt: new Date().toISOString()
            });
          }

          this.licenseService.licenses.set(license.id, license);
        });

        this.licenseService.assetInventory.set(asset.id, asset);
      }
    }

    this.licenseService.logger.info('License-asset reconciliation completed');
  }

  findMatchingLicenses(asset) {
    const matchingLicenses = [];
    const assetName = asset.attributes.name?.toLowerCase() || '';

    for (const [licenseId, license] of this.licenseService.licenses) {
      const licenseName = license.name.toLowerCase();
      const software = this.licenseService.software.get(license.softwareId);
      const softwareName = software?.name.toLowerCase() || '';

      // Check for name matches
      if (assetName.includes(licenseName) || 
          licenseName.includes(assetName) ||
          assetName.includes(softwareName) ||
          softwareName.includes(assetName)) {
        matchingLicenses.push(license);
      }

      // Check for publisher/vendor matches
      const assetPublisher = asset.attributes.publisher?.toLowerCase() || '';
      const vendor = this.licenseService.vendors.get(license.vendorId);
      const vendorName = vendor?.name.toLowerCase() || '';

      if (assetPublisher && vendorName && 
          (assetPublisher.includes(vendorName) || vendorName.includes(assetPublisher))) {
        matchingLicenses.push(license);
      }
    }

    // Remove duplicates
    return matchingLicenses.filter((license, index, self) => 
      index === self.findIndex(l => l.id === license.id)
    );
  }

  findExistingAsset(discoveredAsset) {
    // Look for existing asset by identifier or other unique attributes
    for (const [assetId, asset] of this.licenseService.assetInventory) {
      if (asset.identifier === discoveredAsset.identifier) {
        return asset;
      }

      // Additional matching logic for different asset types
      if (discoveredAsset.type === 'physical_device' && asset.type === 'physical_device') {
        const discoveredMac = discoveredAsset.attributes.mac_address;
        const assetMac = asset.attributes.mac_address;
        if (discoveredMac && assetMac && discoveredMac === assetMac) {
          return asset;
        }
      }

      if (discoveredAsset.type === 'installed_software' && asset.type === 'installed_software') {
        const discoveredName = discoveredAsset.attributes.name;
        const discoveredDevice = discoveredAsset.attributes.device_id;
        const assetName = asset.attributes.name;
        const assetDevice = asset.attributes.device_id;
        
        if (discoveredName === assetName && discoveredDevice === assetDevice) {
          return asset;
        }
      }
    }

    return null;
  }

  generateAssetName(discoveredAsset) {
    const attributes = discoveredAsset.attributes;
    
    switch (discoveredAsset.type) {
      case 'physical_device':
        return attributes.hostname || attributes.ip_address || `Device-${discoveredAsset.identifier}`;
      case 'installed_software':
        return `${attributes.name} on ${attributes.device_id}`;
      case 'cloud_instance':
        return `${attributes.provider} ${attributes.instance_type} (${attributes.instance_id})`;
      case 'mobile_device':
        return attributes.device_name || `Mobile Device ${discoveredAsset.identifier}`;
      default:
        return `Asset ${discoveredAsset.identifier}`;
    }
  }

  updateDiscoveryProgress(discoveryId, discovery) {
    this.licenseService.reports.set(`discovery_${discoveryId}`, discovery);
    
    // Broadcast progress update
    this.licenseService.broadcastToSubscribers('discovery_progress', {
      discoveryId,
      progress: discovery.progress,
      status: discovery.status
    });
  }

  generateDiscoveryReport(discovery) {
    const reportId = uuidv4();
    const report = {
      id: reportId,
      type: 'asset_discovery_report',
      discoveryId: discovery.id,
      title: `Asset Discovery Report - ${moment().format('YYYY-MM-DD')}`,
      generatedAt: new Date().toISOString(),
      summary: {
        discoveryType: discovery.type,
        duration: moment(discovery.completedAt).diff(moment(discovery.startedAt), 'minutes'),
        totalDiscovered: discovery.results.discovered,
        discoveryMethods: discovery.settings.discoveryMethods,
        scope: discovery.settings.scope
      },
      assetBreakdown: this.generateAssetBreakdown(),
      licenseReconciliation: this.generateReconciliationSummary(),
      recommendations: this.generateDiscoveryRecommendations(),
      nextSteps: this.generateNextSteps()
    };

    return report;
  }

  generateAssetBreakdown() {
    const breakdown = {
      byType: {},
      byCategory: {},
      byStatus: {},
      byLifecycleStage: {}
    };

    for (const [assetId, asset] of this.licenseService.assetInventory) {
      // By type
      breakdown.byType[asset.type] = (breakdown.byType[asset.type] || 0) + 1;
      
      // By category
      breakdown.byCategory[asset.category] = (breakdown.byCategory[asset.category] || 0) + 1;
      
      // By status
      breakdown.byStatus[asset.status] = (breakdown.byStatus[asset.status] || 0) + 1;
      
      // By lifecycle stage
      breakdown.byLifecycleStage[asset.lifecycleStage] = (breakdown.byLifecycleStage[asset.lifecycleStage] || 0) + 1;
    }

    return breakdown;
  }

  generateReconciliationSummary() {
    const linkedAssets = Array.from(this.licenseService.assetInventory.values())
      .filter(asset => asset.relatedLicenses && asset.relatedLicenses.length > 0);

    const unlinkedAssets = Array.from(this.licenseService.assetInventory.values())
      .filter(asset => asset.type === 'installed_software' && 
                       (!asset.relatedLicenses || asset.relatedLicenses.length === 0));

    return {
      totalSoftwareAssets: Array.from(this.licenseService.assetInventory.values())
        .filter(asset => asset.type === 'installed_software').length,
      linkedToLicenses: linkedAssets.length,
      unlicensedSoftware: unlinkedAssets.length,
      reconciliationRate: linkedAssets.length / (linkedAssets.length + unlinkedAssets.length) * 100 || 0
    };
  }

  generateDiscoveryRecommendations() {
    const recommendations = [];

    // Check for unlicensed software
    const unlicensedSoftware = Array.from(this.licenseService.assetInventory.values())
      .filter(asset => asset.type === 'installed_software' && 
                       (!asset.relatedLicenses || asset.relatedLicenses.length === 0));

    if (unlicensedSoftware.length > 0) {
      recommendations.push({
        priority: 'high',
        category: 'compliance',
        title: 'Review Unlicensed Software',
        description: `${unlicensedSoftware.length} software installations found without associated licenses`,
        action: 'Review and obtain licenses for business-critical unlicensed software'
      });
    }

    // Check for outdated assets
    const outdatedAssets = Array.from(this.licenseService.assetInventory.values())
      .filter(asset => {
        const lastUpdate = moment(asset.updatedAt);
        return moment().diff(lastUpdate, 'days') > 90;
      });

    if (outdatedAssets.length > 0) {
      recommendations.push({
        priority: 'medium',
        category: 'maintenance',
        title: 'Update Asset Information',
        description: `${outdatedAssets.length} assets have outdated information`,
        action: 'Schedule regular asset discovery to keep information current'
      });
    }

    return recommendations;
  }

  generateNextSteps() {
    return [
      {
        step: 1,
        title: 'Review Discovery Results',
        description: 'Validate discovered assets and update any incorrect information',
        timeframe: '1-2 weeks'
      },
      {
        step: 2,
        title: 'Address Compliance Issues',
        description: 'Obtain licenses for any unlicensed software installations',
        timeframe: '2-4 weeks'
      },
      {
        step: 3,
        title: 'Establish Regular Discovery',
        description: 'Schedule automated discovery to run monthly',
        timeframe: '1 week'
      },
      {
        step: 4,
        title: 'Asset Lifecycle Management',
        description: 'Implement formal asset lifecycle processes',
        timeframe: '4-8 weeks'
      }
    ];
  }

  // Helper methods for mock data generation
  generateMacAddress() {
    return 'XX:XX:XX:XX:XX:XX'.replace(/X/g, () => 
      '0123456789ABCDEF'.charAt(Math.floor(Math.random() * 16))
    );
  }

  randomDeviceType() {
    const types = ['Desktop', 'Laptop', 'Server', 'Workstation', 'Tablet'];
    return types[Math.floor(Math.random() * types.length)];
  }

  randomManufacturer() {
    const manufacturers = ['Dell', 'HP', 'Lenovo', 'Apple', 'Microsoft', 'ASUS'];
    return manufacturers[Math.floor(Math.random() * manufacturers.length)];
  }

  randomOS() {
    const osTypes = ['Windows 10', 'Windows 11', 'macOS', 'Ubuntu', 'CentOS'];
    return osTypes[Math.floor(Math.random() * osTypes.length)];
  }

  randomVersion() {
    const major = Math.floor(Math.random() * 10) + 1;
    const minor = Math.floor(Math.random() * 10);
    const patch = Math.floor(Math.random() * 100);
    return `${major}.${minor}.${patch}`;
  }

  getPublisher(software) {
    const publisherMap = {
      'Microsoft Office': 'Microsoft Corporation',
      'Adobe Acrobat': 'Adobe Inc.',
      'AutoCAD': 'Autodesk, Inc.',
      'Photoshop': 'Adobe Inc.',
      'Visual Studio': 'Microsoft Corporation',
      'Chrome': 'Google LLC',
      'Firefox': 'Mozilla Corporation',
      'Notepad++': 'Notepad++ Team',
      'WinRAR': 'RARLAB',
      'Spotify': 'Spotify AB'
    };

    return publisherMap[software] || 'Unknown Publisher';
  }

  // Asset lifecycle management methods
  async progressAssetLifecycle(assetId, newStage, notes = '') {
    const asset = this.licenseService.assetInventory.get(assetId);
    if (!asset) {
      throw new Error('Asset not found');
    }

    const currentStage = this.lifecycleStages.get(asset.lifecycleStage);
    const targetStage = this.lifecycleStages.get(newStage);

    if (!targetStage) {
      throw new Error('Invalid lifecycle stage');
    }

    // Create lifecycle event
    const lifecycleEvent = {
      id: uuidv4(),
      assetId,
      fromStage: asset.lifecycleStage,
      toStage: newStage,
      timestamp: new Date().toISOString(),
      notes,
      performedBy: 'system' // In reality would be current user
    };

    // Update asset
    asset.lifecycleStage = newStage;
    asset.lifecycleHistory = asset.lifecycleHistory || [];
    asset.lifecycleHistory.push(lifecycleEvent);
    asset.updatedAt = new Date().toISOString();

    this.licenseService.assetInventory.set(assetId, asset);

    // Log audit event
    this.licenseService.logAuditEvent('asset_lifecycle_changed', {
      assetId,
      assetName: asset.name,
      fromStage: lifecycleEvent.fromStage,
      toStage: newStage,
      notes
    });

    return { asset, lifecycleEvent };
  }

  async scheduleAssetMaintenance(assetId, maintenanceData) {
    const asset = this.licenseService.assetInventory.get(assetId);
    if (!asset) {
      throw new Error('Asset not found');
    }

    const maintenanceId = uuidv4();
    const maintenance = {
      id: maintenanceId,
      assetId,
      type: maintenanceData.type || 'routine',
      scheduledDate: maintenanceData.scheduledDate,
      description: maintenanceData.description || '',
      assignedTo: maintenanceData.assignedTo || '',
      status: 'scheduled',
      estimatedDuration: maintenanceData.estimatedDuration || 60, // minutes
      priority: maintenanceData.priority || 'medium',
      createdAt: new Date().toISOString(),
      createdBy: maintenanceData.createdBy || 'system'
    };

    // Update asset maintenance schedule
    if (!asset.maintenanceSchedule) {
      asset.maintenanceSchedule = [];
    }
    asset.maintenanceSchedule.push(maintenance);
    asset.updatedAt = new Date().toISOString();

    this.licenseService.assetInventory.set(assetId, asset);

    // Log audit event
    this.licenseService.logAuditEvent('asset_maintenance_scheduled', {
      assetId,
      assetName: asset.name,
      maintenanceId,
      scheduledDate: maintenance.scheduledDate
    });

    return maintenance;
  }

  async getAssetMetrics() {
    const assets = Array.from(this.licenseService.assetInventory.values());
    
    return {
      total: assets.length,
      byType: this.groupBy(assets, 'type'),
      byStatus: this.groupBy(assets, 'status'),
      byLifecycleStage: this.groupBy(assets, 'lifecycleStage'),
      averageAge: this.calculateAverageAge(assets),
      maintenanceDue: this.countMaintenanceDue(assets),
      warrantyExpiring: this.countWarrantyExpiring(assets, 90)
    };
  }

  groupBy(array, key) {
    return array.reduce((groups, item) => {
      const group = item[key] || 'unknown';
      groups[group] = (groups[group] || 0) + 1;
      return groups;
    }, {});
  }

  calculateAverageAge(assets) {
    const agesInDays = assets
      .filter(asset => asset.acquisitionDate)
      .map(asset => moment().diff(moment(asset.acquisitionDate), 'days'));
    
    return agesInDays.length > 0 ? 
      Math.round(agesInDays.reduce((sum, age) => sum + age, 0) / agesInDays.length) : 0;
  }

  countMaintenanceDue(assets) {
    return assets.filter(asset => {
      if (!asset.maintenanceSchedule) return false;
      
      return asset.maintenanceSchedule.some(maintenance => 
        maintenance.status === 'scheduled' && 
        moment(maintenance.scheduledDate).isBefore(moment().add(7, 'days'))
      );
    }).length;
  }

  countWarrantyExpiring(assets, days) {
    const cutoffDate = moment().add(days, 'days');
    
    return assets.filter(asset => 
      asset.warrantyExpiry && 
      moment(asset.warrantyExpiry).isBefore(cutoffDate) &&
      moment(asset.warrantyExpiry).isAfter(moment())
    ).length;
  }
}

module.exports = AssetService;