const axios = require('axios');
const EventEmitter = require('events');
const logger = require('./logger');

class ServiceDiscovery extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      interval: options.interval || 30000,
      timeout: options.timeout || 5000,
      retries: options.retries || 3,
      ports: options.ports || [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3011, 3012, 3013, 3014],
      healthPath: options.healthPath || '/health',
      ...options
    };
    
    this.discoveredServices = new Map();
    this.scanning = false;
    this.scanInterval = null;
  }
  
  start() {
    logger.info('🔍 Starting service discovery', {
      interval: this.options.interval,
      ports: this.options.ports.length,
      timeout: this.options.timeout
    });
    
    // Initial scan
    this.scan();
    
    // Periodic scanning
    this.scanInterval = setInterval(() => {
      this.scan();
    }, this.options.interval);
    
    this.emit('started');
  }
  
  stop() {
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
    
    logger.info('🛑 Service discovery stopped');
    this.emit('stopped');
  }
  
  async scan() {
    if (this.scanning) {
      logger.debug('🔍 Discovery scan already in progress, skipping');
      return;
    }
    
    this.scanning = true;
    
    try {
      const discoveryPromises = this.options.ports.map(port => 
        this.discoverServiceOnPort(port)
      );
      
      const results = await Promise.allSettled(discoveryPromises);
      
      const newServices = results
        .filter(result => result.status === 'fulfilled' && result.value)
        .map(result => result.value);
      
      await this.processDiscoveredServices(newServices);
      
      logger.debug(`🎯 Service discovery scan completed`, {
        scanned: this.options.ports.length,
        discovered: newServices.length,
        total: this.discoveredServices.size
      });
      
    } catch (error) {
      logger.error('❌ Service discovery scan failed:', error);
      this.emit('error', error);
    } finally {
      this.scanning = false;
    }
  }
  
  async discoverServiceOnPort(port) {
    const maxRetries = this.options.retries;
    let attempt = 0;
    
    while (attempt < maxRetries) {
      try {
        const response = await axios.get(`http://localhost:${port}${this.options.healthPath}`, {
          timeout: this.options.timeout,
          headers: {
            'User-Agent': 'OpenDirectory-Gateway-Discovery/2.0'
          }
        });
        
        if (response.data && response.data.service) {
          const service = this.parseServiceInfo(response.data, port);
          
          if (this.validateService(service)) {
            return service;
          } else {
            logger.warn(`⚠️ Invalid service info from port ${port}`, service);
          }
        }
        
        break;
        
      } catch (error) {
        attempt++;
        
        if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
          // Service not running, no need to retry
          break;
        }
        
        if (attempt < maxRetries) {
          logger.debug(`🔄 Retrying discovery on port ${port}, attempt ${attempt + 1}`);
          await this.delay(1000 * attempt); // Exponential backoff
        }
      }
    }
    
    return null;
  }
  
  parseServiceInfo(healthData, port) {
    const service = {
      id: this.sanitizeServiceId(healthData.service),
      name: healthData.service,
      host: 'localhost',
      port: port,
      path: '',
      version: healthData.version || '1.0.0',
      status: 'healthy',
      lastSeen: new Date().toISOString(),
      discoveredAt: new Date().toISOString(),
      metadata: {
        uptime: healthData.uptime,
        environment: healthData.environment || 'unknown',
        capabilities: healthData.capabilities || [],
        pid: healthData.pid,
        memory: healthData.memory,
        components: healthData.components || {},
        websocket: healthData.websocket,
        ...this.extractAdditionalMetadata(healthData)
      }
    };
    
    // Determine service path based on service type
    service.path = this.determineServicePath(service);
    
    return service;
  }
  
  sanitizeServiceId(serviceId) {
    // Convert service names to consistent IDs
    return serviceId
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }
  
  determineServicePath(service) {
    // Map service types to their common path prefixes
    const pathMappings = {
      'authentication-service': '/api/auth',
      'auth-service': '/api/auth',
      'auth': '/api/auth',
      'device-service': '/api/devices',
      'device-management': '/api/devices',
      'network-infrastructure': '/api/network',
      'network-service': '/api/network',
      'monitoring-service': '/api/monitoring',
      'user-service': '/api/users',
      'admin-service': '/api/admin',
      'notification-service': '/api/notifications',
      'file-service': '/api/files',
      'backup-service': '/api/backup',
      // Mobile Management Services
      'ios-management-service': '/api/mobile/ios',
      'ios-management': '/api/mobile/ios',
      'android-enterprise-service': '/api/mobile/android',
      'android-enterprise': '/api/mobile/android',
      'mobile-app-management-service': '/api/mobile/mam',
      'mobile-app-management': '/api/mobile/mam',
      'mam': '/api/mobile/mam',
      'mobile-threat-defense-service': '/api/mobile/mtd',
      'mobile-threat-defense': '/api/mobile/mtd',
      'mtd': '/api/mobile/mtd'
    };
    
    const servicePath = pathMappings[service.id] || pathMappings[service.name];
    return servicePath || '';
  }
  
  extractAdditionalMetadata(healthData) {
    const metadata = {};
    
    // Extract service-specific metadata
    if (healthData.services) {
      metadata.serviceStatus = healthData.services;
    }
    
    if (healthData.database) {
      metadata.database = healthData.database;
    }
    
    if (healthData.redis) {
      metadata.redis = healthData.redis;
    }
    
    if (healthData.features) {
      metadata.features = healthData.features;
    }
    
    return metadata;
  }
  
  validateService(service) {
    // Basic validation
    if (!service.id || !service.name || !service.host || !service.port) {
      return false;
    }
    
    // Port validation
    if (service.port < 1 || service.port > 65535) {
      return false;
    }
    
    // Service ID validation (must be valid for URL paths)
    if (!/^[a-z0-9-]+$/.test(service.id)) {
      return false;
    }
    
    return true;
  }
  
  async processDiscoveredServices(newServices) {
    const currentTime = new Date().toISOString();
    const activeServiceIds = new Set();
    
    // Process new and updated services
    for (const service of newServices) {
      activeServiceIds.add(service.id);
      
      const existing = this.discoveredServices.get(service.id);
      
      if (!existing) {
        // New service discovered
        this.discoveredServices.set(service.id, service);
        logger.info(`✨ New service discovered: ${service.name} on port ${service.port}`, {
          serviceId: service.id,
          version: service.version,
          capabilities: service.metadata.capabilities?.length || 0
        });
        this.emit('serviceDiscovered', service);
        
      } else {
        // Update existing service
        const updated = {
          ...existing,
          ...service,
          lastSeen: currentTime,
          metadata: {
            ...existing.metadata,
            ...service.metadata
          }
        };
        
        this.discoveredServices.set(service.id, updated);
        
        // Check for significant changes
        if (this.hasSignificantChanges(existing, updated)) {
          logger.info(`🔄 Service updated: ${service.name}`, {
            serviceId: service.id,
            changes: this.getChanges(existing, updated)
          });
          this.emit('serviceUpdated', updated, existing);
        }
      }
    }
    
    // Check for services that are no longer responding
    const staleTimeout = 5 * 60 * 1000; // 5 minutes
    const staleServices = [];
    
    for (const [serviceId, service] of this.discoveredServices) {
      if (!activeServiceIds.has(serviceId)) {
        const lastSeenTime = new Date(service.lastSeen);
        const timeSinceLastSeen = Date.now() - lastSeenTime.getTime();
        
        if (timeSinceLastSeen > staleTimeout) {
          staleServices.push(serviceId);
        }
      }
    }
    
    // Remove stale services
    for (const serviceId of staleServices) {
      const service = this.discoveredServices.get(serviceId);
      this.discoveredServices.delete(serviceId);
      
      logger.warn(`🗑️ Service removed (stale): ${service.name}`, {
        serviceId,
        lastSeen: service.lastSeen,
        staleFor: Math.round((Date.now() - new Date(service.lastSeen).getTime()) / 1000) + 's'
      });
      
      this.emit('serviceRemoved', service);
    }
  }
  
  hasSignificantChanges(old, updated) {
    const significantFields = ['version', 'port', 'path', 'status'];
    
    return significantFields.some(field => old[field] !== updated[field]) ||
           JSON.stringify(old.metadata.capabilities) !== JSON.stringify(updated.metadata.capabilities);
  }
  
  getChanges(old, updated) {
    const changes = {};
    
    ['version', 'port', 'path', 'status'].forEach(field => {
      if (old[field] !== updated[field]) {
        changes[field] = { from: old[field], to: updated[field] };
      }
    });
    
    if (JSON.stringify(old.metadata.capabilities) !== JSON.stringify(updated.metadata.capabilities)) {
      changes.capabilities = {
        from: old.metadata.capabilities,
        to: updated.metadata.capabilities
      };
    }
    
    return changes;
  }
  
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  getServices() {
    return Array.from(this.discoveredServices.values());
  }
  
  getService(serviceId) {
    return this.discoveredServices.get(serviceId);
  }
  
  getServicesByCapability(capability) {
    return this.getServices().filter(service =>
      service.metadata.capabilities?.includes(capability)
    );
  }
  
  getHealthyServices() {
    return this.getServices().filter(service => service.status === 'healthy');
  }
  
  getServiceCount() {
    return this.discoveredServices.size;
  }
  
  getDiscoveryStats() {
    const services = this.getServices();
    const now = Date.now();
    
    return {
      total: services.length,
      healthy: services.filter(s => s.status === 'healthy').length,
      versions: [...new Set(services.map(s => s.version))],
      environments: [...new Set(services.map(s => s.metadata.environment))],
      capabilities: [...new Set(services.flatMap(s => s.metadata.capabilities || []))],
      averageUptime: services.reduce((acc, s) => acc + (s.metadata.uptime || 0), 0) / services.length,
      oldestService: Math.min(...services.map(s => new Date(s.discoveredAt).getTime())),
      newestService: Math.max(...services.map(s => new Date(s.discoveredAt).getTime())),
      portDistribution: services.reduce((acc, s) => {
        acc[s.port] = (acc[s.port] || 0) + 1;
        return acc;
      }, {})
    };
  }
  
  // Manual service registration (for external services)
  registerExternalService(serviceInfo) {
    const service = {
      ...serviceInfo,
      discoveredAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      external: true
    };
    
    if (!this.validateService(service)) {
      throw new Error('Invalid service information');
    }
    
    this.discoveredServices.set(service.id, service);
    
    logger.info(`📝 External service registered: ${service.name}`, {
      serviceId: service.id,
      host: service.host,
      port: service.port
    });
    
    this.emit('serviceDiscovered', service);
    return service;
  }
  
  unregisterService(serviceId) {
    const service = this.discoveredServices.get(serviceId);
    
    if (service) {
      this.discoveredServices.delete(serviceId);
      
      logger.info(`🗑️ Service unregistered: ${service.name}`, {
        serviceId
      });
      
      this.emit('serviceRemoved', service);
      return true;
    }
    
    return false;
  }
}

module.exports = ServiceDiscovery;