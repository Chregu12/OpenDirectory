const axios = require('axios');
const ioredis = require('ioredis');
const winston = require('winston');

// Simple logger for registrar
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.colorize(),
    winston.format.printf(({ level, message, timestamp }) => {
      return `${timestamp} [REGISTRAR] [${level}]: ${message}`;
    })
  ),
  transports: [new winston.transports.Console()]
});

class ServiceRegistrar {
  constructor() {
    this.redis = new ioredis({
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3
    });
    
    this.gatewayHost = process.env.GATEWAY_HOST || 'localhost';
    this.gatewayPort = process.env.GATEWAY_PORT || 3000;
    
    // Parse discovery targets
    const targets = process.env.DISCOVERY_TARGETS || 'localhost:3001,localhost:3002,localhost:3003';
    this.discoveryTargets = targets.split(',').map(target => {
      const [host, port] = target.split(':');
      return { host: host.trim(), port: parseInt(port.trim()) };
    });
    
    this.registeredServices = new Set();
    this.scanInterval = null;
  }
  
  async start() {
    logger.info('🚀 Service Registrar starting...');
    
    // Wait for Redis connection
    await this.waitForRedis();
    
    // Wait for Gateway
    await this.waitForGateway();
    
    // Start discovery
    await this.startDiscovery();
    
    logger.info('✅ Service Registrar started successfully');
  }
  
  async waitForRedis() {
    logger.info('⏳ Waiting for Redis connection...');
    
    while (true) {
      try {
        await this.redis.ping();
        logger.info('✅ Redis connected');
        break;
      } catch (error) {
        logger.warn('❌ Redis not ready, retrying in 2s...');
        await this.delay(2000);
      }
    }
  }
  
  async waitForGateway() {
    logger.info('⏳ Waiting for API Gateway...');
    
    while (true) {
      try {
        const response = await axios.get(`http://${this.gatewayHost}:${this.gatewayPort}/health`, {
          timeout: 3000
        });
        
        if (response.status === 200) {
          logger.info('✅ API Gateway ready');
          break;
        }
      } catch (error) {
        logger.warn('❌ Gateway not ready, retrying in 3s...');
        await this.delay(3000);
      }
    }
  }
  
  async startDiscovery() {
    logger.info('🔍 Starting service discovery...', {
      targets: this.discoveryTargets.length,
      interval: '30s'
    });
    
    // Initial discovery
    await this.discoverServices();
    
    // Periodic discovery
    this.scanInterval = setInterval(() => {
      this.discoverServices();
    }, 30000);
  }
  
  async discoverServices() {
    logger.info('🔍 Scanning for services...');
    
    const discoveryPromises = this.discoveryTargets.map(target => 
      this.checkService(target.host, target.port)
    );
    
    const results = await Promise.allSettled(discoveryPromises);
    
    let discovered = 0;
    let registered = 0;
    
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        discovered++;
        
        const service = result.value;
        const serviceKey = `${service.id}:${service.host}:${service.port}`;
        
        if (!this.registeredServices.has(serviceKey)) {
          const success = await this.registerWithGateway(service);
          if (success) {
            this.registeredServices.add(serviceKey);
            registered++;
            
            logger.info(`✨ Registered new service: ${service.name}`, {
              id: service.id,
              host: service.host,
              port: service.port,
              version: service.version
            });
          }
        }
      }
    }
    
    logger.info(`🎯 Discovery completed`, {
      targets: this.discoveryTargets.length,
      discovered,
      registered,
      totalRegistered: this.registeredServices.size
    });
  }
  
  async checkService(host, port) {
    try {
      const response = await axios.get(`http://${host}:${port}/health`, {
        timeout: 5000,
        headers: {
          'User-Agent': 'OpenDirectory-Service-Registrar/1.0'
        }
      });
      
      if (response.data && response.data.service) {
        return {
          id: this.sanitizeServiceId(response.data.service),
          name: response.data.service,
          host: host,
          port: port,
          path: this.generateServicePath(response.data.service),
          version: response.data.version || '1.0.0',
          metadata: {
            uptime: response.data.uptime,
            environment: response.data.environment || 'unknown',
            capabilities: response.data.capabilities || [],
            registrar: 'external',
            discoveredBy: 'service-registrar',
            discoveredAt: new Date().toISOString()
          }
        };
      }
    } catch (error) {
      // Service not available or not responding correctly
      return null;
    }
    
    return null;
  }
  
  sanitizeServiceId(serviceName) {
    return serviceName
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }
  
  generateServicePath(serviceName) {
    const pathMappings = {
      'authentication-service': '/api/auth',
      'auth-service': '/api/auth',
      'device-service': '/api/devices',
      'device-management': '/api/devices',
      'network-infrastructure': '/api/network',
      'network-service': '/api/network',
      'monitoring-service': '/api/monitoring',
      'user-service': '/api/users',
      'notification-service': '/api/notifications',
      'file-service': '/api/files'
    };
    
    const serviceId = this.sanitizeServiceId(serviceName);
    return pathMappings[serviceId] || pathMappings[serviceName] || '';
  }
  
  async registerWithGateway(service) {
    try {
      const response = await axios.post(
        `http://${this.gatewayHost}:${this.gatewayPort}/gateway/register`,
        service,
        {
          timeout: 10000,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'OpenDirectory-Service-Registrar/1.0'
          }
        }
      );
      
      return response.status === 200 && response.data.success;
    } catch (error) {
      logger.error(`❌ Failed to register service ${service.name}:`, {
        error: error.message,
        service: service.id
      });
      return false;
    }
  }
  
  async publishServiceEvent(event, data) {
    try {
      await this.redis.publish(`service:${event}`, JSON.stringify(data));
    } catch (error) {
      logger.error(`❌ Failed to publish ${event} event:`, error.message);
    }
  }
  
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  async stop() {
    logger.info('🛑 Stopping Service Registrar...');
    
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
    
    if (this.redis) {
      await this.redis.quit();
    }
    
    logger.info('✅ Service Registrar stopped');
  }
}

// Graceful shutdown
const registrar = new ServiceRegistrar();

process.on('SIGTERM', async () => {
  logger.info('📨 SIGTERM received');
  await registrar.stop();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('📨 SIGINT received');
  await registrar.stop();
  process.exit(0);
});

// Start the registrar
registrar.start().catch(error => {
  logger.error('💥 Failed to start Service Registrar:', error);
  process.exit(1);
});

module.exports = ServiceRegistrar;