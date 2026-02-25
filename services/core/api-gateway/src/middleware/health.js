const axios = require('axios');
const logger = require('../config/logger');

class HealthCheckMiddleware {
  constructor() {
    this.serviceHealthCache = new Map();
    this.cacheTimeout = 30000; // 30 seconds
    
    // Define all services to monitor
    this.services = [
      { name: 'authentication-service', url: 'http://authentication-service:3001/health', critical: true },
      { name: 'configuration-service', url: 'http://configuration-service:3002/health', critical: true },
      { name: 'device-service', url: 'http://device-service:3003/health', critical: false },
      { name: 'policy-service', url: 'http://policy-service:3004/health', critical: false },
      { name: 'integration-service', url: 'http://integration-service:3005/health', critical: false },
      { name: 'printer-service', url: 'http://printer-service:3006/health', critical: false },
      { name: 'network-infrastructure', url: 'http://network-infrastructure:3007/api/health', critical: false },
      { name: 'security-suite', url: 'http://security-suite:3008/health', critical: false },
      { name: 'monitoring-analytics', url: 'http://monitoring-analytics:3009/health', critical: false },
      { name: 'policy-compliance', url: 'http://policy-compliance:3010/health', critical: false },
      { name: 'backup-disaster', url: 'http://backup-disaster:3011/health', critical: false },
      { name: 'automation-workflows', url: 'http://automation-workflows:3012/health', critical: false },
      { name: 'container-orchestration', url: 'http://container-orchestration:3013/health', critical: false },
      { name: 'enterprise-integrations', url: 'http://enterprise-integrations:3014/health', critical: false },
      { name: 'ai-intelligence', url: 'http://ai-intelligence:3015/health', critical: false },
      { name: 'notification-service', url: 'http://notification-service:3016/health', critical: false },
      { name: 'deployment-service', url: 'http://deployment-service:3017/health', critical: false },
      { name: 'identity-service', url: 'http://identity-service:3001/health', critical: false },
      { name: 'lldap', url: 'http://lldap:17170/health', critical: false },
      { name: 'prometheus', url: 'http://prometheus:9090/-/healthy', critical: false },
      { name: 'grafana', url: 'http://grafana:3000/api/health', critical: false },
    ];
    
    // Start periodic health checks
    this.startHealthChecks();
  }

  middleware() {
    return async (req, res, next) => {
      // Basic health check endpoint
      if (req.path === '/health') {
        return this.handleBasicHealth(req, res);
      }
      
      // Detailed health check
      if (req.path === '/health/detailed') {
        return this.handleDetailedHealth(req, res);
      }
      
      // Service-specific health check
      if (req.path.startsWith('/health/service/')) {
        const serviceName = req.path.replace('/health/service/', '');
        return this.handleServiceHealth(serviceName, req, res);
      }
      
      // Liveness probe (for Kubernetes)
      if (req.path === '/health/live') {
        return res.status(200).json({ status: 'alive' });
      }
      
      // Readiness probe (for Kubernetes)
      if (req.path === '/health/ready') {
        return this.handleReadiness(req, res);
      }
      
      next();
    };
  }

  async handleBasicHealth(req, res) {
    const health = await this.getOverallHealth();
    const status = health.status === 'healthy' ? 200 : 503;
    
    res.status(status).json({
      status: health.status,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: health.summary
    });
  }

  async handleDetailedHealth(req, res) {
    const health = await this.getDetailedHealth();
    const status = health.status === 'healthy' ? 200 : 503;
    
    res.status(status).json(health);
  }

  async handleServiceHealth(serviceName, req, res) {
    const service = this.services.find(s => s.name === serviceName);
    
    if (!service) {
      return res.status(404).json({
        error: 'Service not found',
        service: serviceName
      });
    }
    
    const health = await this.checkServiceHealth(service);
    const status = health.status === 'healthy' ? 200 : 503;
    
    res.status(status).json({
      service: serviceName,
      ...health,
      timestamp: new Date().toISOString()
    });
  }

  async handleReadiness(req, res) {
    const health = await this.getOverallHealth();
    
    // Check if critical services are healthy
    const criticalHealthy = health.criticalServices.every(s => s.status === 'healthy');
    
    if (criticalHealthy) {
      res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(503).json({
        status: 'not ready',
        reason: 'Critical services unhealthy',
        services: health.criticalServices.filter(s => s.status !== 'healthy'),
        timestamp: new Date().toISOString()
      });
    }
  }

  async getOverallHealth() {
    const results = await this.checkAllServices();
    
    const healthy = results.filter(r => r.status === 'healthy').length;
    const unhealthy = results.filter(r => r.status === 'unhealthy').length;
    const unknown = results.filter(r => r.status === 'unknown').length;
    
    const criticalServices = results.filter(r => r.critical);
    const criticalHealthy = criticalServices.every(s => s.status === 'healthy');
    
    let overallStatus = 'healthy';
    if (!criticalHealthy) {
      overallStatus = 'critical';
    } else if (unhealthy > 0) {
      overallStatus = 'degraded';
    } else if (unknown > results.length / 2) {
      overallStatus = 'unknown';
    }
    
    return {
      status: overallStatus,
      summary: {
        total: results.length,
        healthy,
        unhealthy,
        unknown
      },
      criticalServices,
      services: results
    };
  }

  async getDetailedHealth() {
    const results = await this.checkAllServices();
    
    const categorized = {
      core: [],
      modules: [],
      infrastructure: [],
      external: []
    };
    
    results.forEach(service => {
      if (service.name.includes('authentication') || service.name.includes('configuration')) {
        categorized.core.push(service);
      } else if (service.name.includes('lldap') || service.name.includes('prometheus') || service.name.includes('grafana')) {
        categorized.external.push(service);
      } else if (service.name.includes('postgres') || service.name.includes('redis') || service.name.includes('mongo')) {
        categorized.infrastructure.push(service);
      } else {
        categorized.modules.push(service);
      }
    });
    
    const health = await this.getOverallHealth();
    
    return {
      ...health,
      gateway: {
        version: require('../../package.json').version,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage()
      },
      categorized,
      lastCheck: new Date().toISOString()
    };
  }

  async checkAllServices() {
    const results = [];
    
    for (const service of this.services) {
      const cached = this.getCachedHealth(service.name);
      
      if (cached) {
        results.push(cached);
      } else {
        const health = await this.checkServiceHealth(service);
        results.push(health);
      }
    }
    
    return results;
  }

  async checkServiceHealth(service) {
    try {
      const response = await axios.get(service.url, {
        timeout: 5000,
        validateStatus: () => true
      });
      
      const health = {
        name: service.name,
        status: response.status === 200 ? 'healthy' : 'unhealthy',
        statusCode: response.status,
        responseTime: response.headers['x-response-time'] || null,
        critical: service.critical,
        details: response.data,
        lastCheck: new Date().toISOString()
      };
      
      this.cacheHealth(service.name, health);
      return health;
      
    } catch (error) {
      const health = {
        name: service.name,
        status: 'unknown',
        critical: service.critical,
        error: error.message,
        lastCheck: new Date().toISOString()
      };
      
      this.cacheHealth(service.name, health);
      return health;
    }
  }

  getCachedHealth(serviceName) {
    const cached = this.serviceHealthCache.get(serviceName);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.health;
    }
    
    return null;
  }

  cacheHealth(serviceName, health) {
    this.serviceHealthCache.set(serviceName, {
      health,
      timestamp: Date.now()
    });
  }

  startHealthChecks() {
    // Periodic health checks every 30 seconds
    setInterval(async () => {
      logger.debug('Running periodic health checks');
      await this.checkAllServices();
    }, 30000);
    
    // Initial check
    this.checkAllServices();
  }

  // API for getting service registry
  getServiceRegistry() {
    return this.services.map(s => ({
      name: s.name,
      url: s.url,
      critical: s.critical
    }));
  }

  // Add a new service to monitor
  addService(name, url, critical = false) {
    const existing = this.services.find(s => s.name === name);
    if (!existing) {
      this.services.push({ name, url, critical });
      logger.info(`Added health check for service: ${name}`);
    }
  }

  // Remove a service from monitoring
  removeService(name) {
    const index = this.services.findIndex(s => s.name === name);
    if (index !== -1) {
      this.services.splice(index, 1);
      this.serviceHealthCache.delete(name);
      logger.info(`Removed health check for service: ${name}`);
    }
  }
}

// Create singleton instance
const healthCheck = new HealthCheckMiddleware();

// Export middleware and utility functions
module.exports = healthCheck.middleware();
module.exports.getOverallHealth = healthCheck.getOverallHealth.bind(healthCheck);
module.exports.getDetailedHealth = healthCheck.getDetailedHealth.bind(healthCheck);
module.exports.getServiceRegistry = healthCheck.getServiceRegistry.bind(healthCheck);
module.exports.addService = healthCheck.addService.bind(healthCheck);
module.exports.removeService = healthCheck.removeService.bind(healthCheck);