const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');
const WebSocket = require('ws');
const http = require('http');

const logger = require('./config/logger');
const serviceDiscovery = require('./discovery/serviceDiscovery');
const authMiddleware = require('./middleware/auth');
const routingMiddleware = require('./middleware/routing');
const configManager = require('./config/configManager');
const healthCheck = require('./middleware/health');

class APIGateway {
  constructor() {
    this.app = express();
    this.server = null;
    this.wsServer = null;
    this.services = new Map();
    this.config = configManager.getConfig();
    
    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    this.initializeServiceDiscovery();
  }

  initializeMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS configuration - Allow frontend and authenticated API access
    this.app.use(cors({
      origin: function (origin, callback) {
        // Allow frontend origins
        const allowedOrigins = [
          'http://localhost:3000',              // Local development frontend
          'http://localhost:3001',              // Alternative dev port
          'http://127.0.0.1:3000',             // Alternative localhost
          'https://app.opendirectory.local'     // Production frontend domain
        ];
        
        // Allow requests with no origin (Postman, curl, mobile apps, etc.)
        // These will need proper authentication via API keys
        if (!origin) {
          return callback(null, true);
        }
        
        // Allow any origin in development mode
        if (process.env.NODE_ENV === 'development') {
          return callback(null, true);
        }
        
        // Check if origin is in allowed list
        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          // For production, require proper authentication for unknown origins
          callback(null, true); // Allow but will be caught by auth middleware
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
      allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Requested-With',
        'X-API-Key',
        'X-Service-Auth',
        'X-Service-Name',
        'X-Client-Type'
      ],
      exposedHeaders: ['X-Total-Count', 'X-Response-Time', 'X-Rate-Limit-Remaining'],
    }));

    // Dynamic rate limiting based on authentication type
    this.app.use((req, res, next) => {
      const limiter = this.getRateLimiter(req);
      limiter(req, res, next);
    });

    // Logging
    this.app.use(morgan('combined', {
      stream: { write: (message) => logger.info(message.trim()) }
    }));

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging and client type detection
    this.app.use((req, res, next) => {
      const origin = req.headers.origin;
      const userAgent = req.headers['user-agent'] || '';
      const apiKey = req.headers['x-api-key'];
      
      // Detect client type for better logging
      if (apiKey) {
        req.clientType = 'api-client';
      } else if (!origin) {
        req.clientType = 'direct-client'; // Postman, curl, etc.
      } else if (origin.includes('localhost:3000') || origin.includes('app.opendirectory')) {
        req.clientType = 'frontend';
      } else {
        req.clientType = 'external';
      }
      
      // Log requests for monitoring
      logger.debug(`${req.clientType} request: ${req.method} ${req.path}`, {
        origin: origin || 'none',
        userAgent: userAgent.substring(0, 50),
        hasApiKey: !!apiKey
      });
      
      next();
    });

    // Custom middleware
    this.app.use(authMiddleware);
    this.app.use(routingMiddleware);
  }

  initializeWebSocket() {
    this.server = http.createServer(this.app);
    
    this.wsServer = new WebSocket.Server({ 
      server: this.server,
      path: '/ws'
    });

    this.wsServer.on('connection', (ws, req) => {
      logger.info(`WebSocket connection established from ${req.socket.remoteAddress}`);
      
      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data);
          this.handleWebSocketMessage(ws, message);
        } catch (error) {
          logger.error('WebSocket message error:', error);
          ws.send(JSON.stringify({ error: 'Invalid message format' }));
        }
      });

      ws.on('close', () => {
        logger.info('WebSocket connection closed');
      });

      ws.on('error', (error) => {
        logger.error('WebSocket error:', error);
      });

      // Send initial connection confirmation
      ws.send(JSON.stringify({ 
        type: 'connection', 
        status: 'connected',
        gateway: 'OpenDirectory API Gateway'
      }));
    });
  }

  initializeRoutes() {
    // Health check endpoints (public)
    this.app.get('/health', healthCheck);
    this.app.get('/health/detailed', this.getDetailedHealth.bind(this));
    this.app.get('/health/*', healthCheck);

    // API Documentation (public)
    this.app.get('/docs', this.getApiDocs.bind(this));
    this.app.get('/api-docs', this.getApiDocs.bind(this));
    this.app.get('/docs/openapi.json', this.getOpenApiSpec.bind(this));

    // Gateway info endpoints (public)
    this.app.get('/api/gateway/info', this.getGatewayInfo.bind(this));
    this.app.get('/api/gateway/routes', this.getGatewayRoutes.bind(this));

    // Service endpoints (public read access)
    this.app.get('/api/services', this.getServices.bind(this));
    this.app.get('/api/services/:serviceId/health', this.getServiceHealth.bind(this));

    // Configuration endpoints (public read, auth required for write)
    this.app.get('/api/config/modules', this.getModuleConfiguration.bind(this));
    this.app.post('/api/config/modules/:moduleId', this.updateModuleConfiguration.bind(this));

    // API Key management (admin only)
    this.app.get('/api/admin/keys', authMiddleware.requireAdmin(), this.getApiKeys.bind(this));
    this.app.post('/api/admin/keys', authMiddleware.requireAdmin(), this.createApiKey.bind(this));
    this.app.delete('/api/admin/keys/:keyId', authMiddleware.requireAdmin(), this.deleteApiKey.bind(this));

    // Dynamic proxy setup for enabled modules
    this.setupDynamicProxies();

    // Catch-all for undefined routes
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Route not found',
        path: req.originalUrl,
        method: req.method,
        availableEndpoints: this.getAvailableEndpoints(),
        docs: '/docs',
        timestamp: new Date().toISOString()
      });
    });

    // Error handling middleware
    this.app.use(this.errorHandler.bind(this));
  }

  setupDynamicProxies() {
    const enabledModules = configManager.getEnabledModules();
    const connectedServices = [];

    // Core services (always enabled)
    this.setupServiceProxy('authentication', 'http://authentication-service:3001', '/api/auth');
    this.setupServiceProxy('configuration', 'http://configuration-service:3002', '/api/config');
    connectedServices.push('authentication', 'configuration');

    // Health service (if exists)
    this.setupServiceProxy('health', 'http://health-service:3020', '/api/health');
    connectedServices.push('health');

    // Module-based proxies - ALL available modules
    if (enabledModules.includes('network-infrastructure')) {
      this.setupServiceProxy('network', 'http://network-infrastructure:3007', '/api/network');
      connectedServices.push('network-infrastructure');
    }

    if (enabledModules.includes('security-suite')) {
      this.setupServiceProxy('security', 'http://security-suite:3008', '/api/security');
      connectedServices.push('security-suite');
    }

    if (enabledModules.includes('printer-service')) {
      this.setupServiceProxy('printer', 'http://printer-service:3006', '/api/printer');
      this.setupServiceProxy('printers', 'http://printer-service:3006', '/api/printers'); // Alternative route
      connectedServices.push('printer-service');
    }

    if (enabledModules.includes('monitoring-analytics')) {
      this.setupServiceProxy('monitoring', 'http://monitoring-analytics:3009', '/api/monitoring');
      this.setupServiceProxy('analytics', 'http://monitoring-analytics:3009', '/api/analytics');
      connectedServices.push('monitoring-analytics');
    }

    if (enabledModules.includes('device-management')) {
      this.setupServiceProxy('devices', 'http://device-service:3003', '/api/devices');
      this.setupServiceProxy('device', 'http://device-service:3003', '/api/device'); // Singular route
      connectedServices.push('device-management');
    }

    if (enabledModules.includes('policy-compliance')) {
      this.setupServiceProxy('policy', 'http://policy-compliance:3010', '/api/policy');
      this.setupServiceProxy('compliance', 'http://policy-compliance:3010', '/api/compliance');
      connectedServices.push('policy-compliance');
    }

    if (enabledModules.includes('backup-disaster')) {
      this.setupServiceProxy('backup', 'http://backup-disaster:3011', '/api/backup');
      this.setupServiceProxy('disaster-recovery', 'http://backup-disaster:3011', '/api/dr');
      connectedServices.push('backup-disaster');
    }

    if (enabledModules.includes('automation-workflows')) {
      this.setupServiceProxy('automation', 'http://automation-workflows:3012', '/api/automation');
      this.setupServiceProxy('workflows', 'http://automation-workflows:3012', '/api/workflows');
      connectedServices.push('automation-workflows');
    }

    if (enabledModules.includes('container-orchestration')) {
      this.setupServiceProxy('containers', 'http://container-orchestration:3013', '/api/containers');
      this.setupServiceProxy('kubernetes', 'http://container-orchestration:3013', '/api/k8s');
      this.setupServiceProxy('docker', 'http://container-orchestration:3013', '/api/docker');
      connectedServices.push('container-orchestration');
    }

    if (enabledModules.includes('enterprise-integrations')) {
      this.setupServiceProxy('integrations', 'http://enterprise-integrations:3014', '/api/integrations');
      this.setupServiceProxy('erp', 'http://enterprise-integrations:3014', '/api/erp');
      this.setupServiceProxy('sap', 'http://enterprise-integrations:3014', '/api/sap');
      this.setupServiceProxy('o365', 'http://enterprise-integrations:3014', '/api/o365');
      connectedServices.push('enterprise-integrations');
    }

    if (enabledModules.includes('ai-intelligence')) {
      this.setupServiceProxy('ai', 'http://ai-intelligence:3015', '/api/ai');
      this.setupServiceProxy('ml', 'http://ai-intelligence:3015', '/api/ml');
      this.setupServiceProxy('predictions', 'http://ai-intelligence:3015', '/api/predictions');
      connectedServices.push('ai-intelligence');
    }

    // Legacy API Backend (if still needed)
    if (enabledModules.includes('api-backend')) {
      this.setupServiceProxy('legacy', 'http://api-backend:8081', '/api/legacy');
      connectedServices.push('api-backend');
    }

    // Integration Service (for external services)
    if (enabledModules.includes('integration-service')) {
      this.setupServiceProxy('external', 'http://integration-service:3005', '/api/external');
      this.setupServiceProxy('lldap', 'http://integration-service:3005', '/api/lldap');
      this.setupServiceProxy('grafana', 'http://integration-service:3005', '/api/grafana');
      this.setupServiceProxy('prometheus', 'http://integration-service:3005', '/api/prometheus');
      this.setupServiceProxy('vault', 'http://integration-service:3005', '/api/vault');
      connectedServices.push('integration-service');
    }

    // Identity and Policy services from core
    if (enabledModules.includes('identity-service')) {
      this.setupServiceProxy('identity', 'http://identity-service:3001', '/api/identity');
      this.setupServiceProxy('users', 'http://identity-service:3001', '/api/users');
      this.setupServiceProxy('groups', 'http://identity-service:3001', '/api/groups');
      connectedServices.push('identity-service');
    }

    if (enabledModules.includes('policy-service')) {
      this.setupServiceProxy('policies', 'http://policy-service:3004', '/api/policies');
      connectedServices.push('policy-service');
    }

    // Notification Service
    if (enabledModules.includes('notification-service')) {
      this.setupServiceProxy('notifications', 'http://notification-service:3016', '/api/notifications');
      this.setupServiceProxy('alerts', 'http://notification-service:3016', '/api/alerts');
      connectedServices.push('notification-service');
    }

    // Deployment Service
    if (enabledModules.includes('deployment-service')) {
      this.setupServiceProxy('deployment', 'http://deployment-service:3017', '/api/deployment');
      this.setupServiceProxy('apps', 'http://deployment-service:3017', '/api/apps');
      connectedServices.push('deployment-service');
    }

    // License Management Service
    if (enabledModules.includes('license-management')) {
      this.setupServiceProxy('license', 'http://license-management:3018', '/api/license');
      this.setupServiceProxy('licenses', 'http://license-management:3018', '/api/license'); // Alternative route
      connectedServices.push('license-management');
    }

    logger.info(`✅ API Gateway configured with ${connectedServices.length} services`);
    logger.info(`📋 Connected services: ${connectedServices.join(', ')}`);
    logger.info(`🔌 Enabled modules: ${enabledModules.join(', ') || 'none'}`);
  }

  setupServiceProxy(serviceName, target, pathPrefix) {
    const proxyOptions = {
      target,
      changeOrigin: true,
      pathRewrite: {
        [`^${pathPrefix}`]: '/api'
      },
      onError: (err, req, res) => {
        logger.error(`Proxy error for ${serviceName}:`, err);
        res.status(503).json({
          error: 'Service temporarily unavailable',
          service: serviceName,
          timestamp: new Date().toISOString()
        });
      },
      onProxyReq: (proxyReq, req, res) => {
        logger.debug(`Proxying ${req.method} ${req.url} to ${serviceName}`);
      },
      onProxyRes: (proxyRes, req, res) => {
        logger.debug(`Response from ${serviceName}: ${proxyRes.statusCode}`);
      }
    };

    const proxy = createProxyMiddleware(proxyOptions);
    this.app.use(pathPrefix, proxy);

    // Register service
    this.services.set(serviceName, {
      name: serviceName,
      target,
      pathPrefix,
      status: 'active',
      lastCheck: new Date().toISOString()
    });

    logger.info(`Registered proxy: ${pathPrefix} -> ${target}`);
  }

  initializeServiceDiscovery() {
    serviceDiscovery.start();
    
    // Update service registry periodically
    setInterval(async () => {
      await this.updateServiceRegistry();
    }, 30000); // Every 30 seconds
  }

  async updateServiceRegistry() {
    for (const [serviceName, serviceInfo] of this.services) {
      try {
        const response = await fetch(`${serviceInfo.target}/health`, {
          timeout: 5000
        });
        
        this.services.set(serviceName, {
          ...serviceInfo,
          status: response.ok ? 'healthy' : 'unhealthy',
          lastCheck: new Date().toISOString()
        });
      } catch (error) {
        this.services.set(serviceName, {
          ...serviceInfo,
          status: 'unavailable',
          lastCheck: new Date().toISOString(),
          error: error.message
        });
      }
    }
  }

  handleWebSocketMessage(ws, message) {
    const { type, data } = message;

    switch (type) {
      case 'subscribe':
        // Subscribe to service updates
        ws.subscriptions = ws.subscriptions || [];
        if (data.service && !ws.subscriptions.includes(data.service)) {
          ws.subscriptions.push(data.service);
        }
        break;

      case 'unsubscribe':
        // Unsubscribe from service updates
        if (ws.subscriptions && data.service) {
          ws.subscriptions = ws.subscriptions.filter(s => s !== data.service);
        }
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;

      default:
        ws.send(JSON.stringify({ error: `Unknown message type: ${type}` }));
    }
  }

  async getDetailedHealth(req, res) {
    const services = Array.from(this.services.values());
    const overallStatus = services.every(s => s.status === 'healthy') ? 'healthy' : 'degraded';

    res.json({
      status: overallStatus,
      timestamp: new Date().toISOString(),
      gateway: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: require('../package.json').version
      },
      services,
      modules: configManager.getEnabledModules()
    });
  }

  getServices(req, res) {
    res.json(Array.from(this.services.values()));
  }

  async getServiceHealth(req, res) {
    const { serviceId } = req.params;
    const service = this.services.get(serviceId);

    if (!service) {
      return res.status(404).json({ error: 'Service not found' });
    }

    try {
      const response = await fetch(`${service.target}/health`);
      const healthData = await response.json();

      res.json({
        service: serviceId,
        status: response.ok ? 'healthy' : 'unhealthy',
        details: healthData,
        lastCheck: new Date().toISOString()
      });
    } catch (error) {
      res.status(503).json({
        service: serviceId,
        status: 'unavailable',
        error: error.message,
        lastCheck: new Date().toISOString()
      });
    }
  }

  getModuleConfiguration(req, res) {
    res.json(configManager.getModuleConfiguration());
  }

  async updateModuleConfiguration(req, res) {
    const { moduleId } = req.params;
    const { enabled, config } = req.body;

    try {
      await configManager.updateModuleConfiguration(moduleId, { enabled, config });
      
      // Restart proxies if needed
      if (enabled) {
        this.setupDynamicProxies();
      }

      res.json({ 
        success: true, 
        message: `Module ${moduleId} ${enabled ? 'enabled' : 'disabled'}` 
      });
    } catch (error) {
      res.status(400).json({ 
        error: error.message 
      });
    }
  }

  errorHandler(error, req, res, next) {
    logger.error('Gateway error:', error);

    res.status(error.status || 500).json({
      error: error.message || 'Internal server error',
      path: req.originalUrl,
      method: req.method,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
  }

  getRateLimiter(req) {
    const hasApiKey = req.headers['x-api-key'];
    const isFromFrontend = req.clientType === 'frontend';
    
    if (hasApiKey) {
      // API clients get higher rate limits
      return rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5000, // 5000 requests per 15 minutes
        message: 'API rate limit exceeded',
        standardHeaders: true,
      });
    } else if (isFromFrontend) {
      // Frontend gets normal rate limits
      return rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 1000, // 1000 requests per 15 minutes
        message: 'Rate limit exceeded',
        standardHeaders: true,
      });
    } else {
      // Direct clients (Postman, etc.) get lower rate limits without auth
      return rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // 100 requests per 15 minutes
        message: 'Rate limit exceeded. Consider using API authentication for higher limits.',
        standardHeaders: true,
      });
    }
  }

  getApiDocs(req, res) {
    res.json({
      name: 'OpenDirectory API Gateway',
      version: '1.0.0',
      description: 'Central API Gateway for OpenDirectory services',
      endpoints: {
        public: {
          health: '/health',
          'health-detailed': '/health/detailed',
          'gateway-info': '/api/gateway/info',
          'gateway-routes': '/api/gateway/routes',
          services: '/api/services',
          'module-config': '/api/config/modules',
          documentation: '/docs'
        },
        authenticated: {
          'all-service-endpoints': '/api/*',
          'module-management': 'POST /api/config/modules/:moduleId'
        },
        admin: {
          'api-key-management': '/api/admin/keys'
        }
      },
      authentication: {
        types: ['JWT Bearer Token', 'API Key (X-API-Key header)'],
        'api-key-example': 'X-API-Key: your-api-key-here',
        'jwt-example': 'Authorization: Bearer your-jwt-token-here'
      },
      'rate-limits': {
        'frontend-clients': '1000 requests per 15 minutes',
        'api-clients': '5000 requests per 15 minutes',
        'unauthenticated': '100 requests per 15 minutes'
      }
    });
  }

  getOpenApiSpec(req, res) {
    const spec = {
      openapi: '3.0.0',
      info: {
        title: 'OpenDirectory API Gateway',
        version: '1.0.0',
        description: 'Central API Gateway for OpenDirectory services'
      },
      servers: [
        { url: 'http://localhost:8080', description: 'Development server' }
      ],
      components: {
        securitySchemes: {
          BearerAuth: {
            type: 'http',
            scheme: 'bearer'
          },
          ApiKeyAuth: {
            type: 'apiKey',
            in: 'header',
            name: 'X-API-Key'
          }
        }
      },
      paths: {
        '/health': {
          get: {
            summary: 'Health check',
            responses: { '200': { description: 'Service is healthy' } }
          }
        },
        '/api/services': {
          get: {
            summary: 'List all services',
            responses: { '200': { description: 'List of services' } }
          }
        }
      }
    };
    res.json(spec);
  }

  getGatewayInfo(req, res) {
    res.json({
      name: 'OpenDirectory API Gateway',
      version: require('../package.json').version,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV || 'development',
      'enabled-modules': configManager.getEnabledModules(),
      'total-services': this.services.size,
      timestamp: new Date().toISOString()
    });
  }

  getGatewayRoutes(req, res) {
    const routes = [];
    
    // Add static routes
    routes.push(
      { path: '/health', method: 'GET', auth: 'public' },
      { path: '/api/services', method: 'GET', auth: 'public' },
      { path: '/api/config/modules', method: 'GET', auth: 'public' },
      { path: '/docs', method: 'GET', auth: 'public' }
    );
    
    // Add dynamic proxy routes
    for (const [serviceName, serviceInfo] of this.services) {
      routes.push({
        path: serviceInfo.pathPrefix,
        target: serviceInfo.target,
        service: serviceName,
        auth: 'required'
      });
    }
    
    res.json(routes);
  }

  getApiKeys(req, res) {
    // This would normally query a database
    res.json([
      { id: '1', name: 'Development Key', permissions: ['read'], created: '2024-01-01' },
      { id: '2', name: 'Testing Key', permissions: ['read', 'write'], created: '2024-01-01' }
    ]);
  }

  createApiKey(req, res) {
    const { name, permissions } = req.body;
    // This would normally create in database
    res.json({
      id: Date.now().toString(),
      name,
      permissions,
      key: 'generated-api-key-' + Math.random().toString(36).substr(2),
      created: new Date().toISOString()
    });
  }

  deleteApiKey(req, res) {
    const { keyId } = req.params;
    // This would normally delete from database
    res.json({ message: `API key ${keyId} deleted` });
  }

  getAvailableEndpoints() {
    return [
      '/health', '/api/services', '/api/config/modules', '/docs'
    ];
  }

  start(port = process.env.PORT || 8080) {
    this.server.listen(port, () => {
      logger.info(`🚀 OpenDirectory API Gateway started on port ${port}`);
      logger.info(`📊 Health check available at: http://localhost:${port}/health`);
      logger.info(`📚 API documentation available at: http://localhost:${port}/docs`);
      logger.info(`🔌 WebSocket server available at: ws://localhost:${port}/ws`);
      logger.info(`📋 Enabled modules: ${configManager.getEnabledModules().join(', ')}`);
      logger.info(`🔑 API access: Use X-API-Key header for external clients`);
    });
  }

  stop() {
    if (this.server) {
      this.server.close(() => {
        logger.info('API Gateway stopped');
      });
    }
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully');
  process.exit(0);
});

// Start the gateway
const gateway = new APIGateway();
gateway.start();

module.exports = APIGateway;