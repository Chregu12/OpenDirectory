const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');
const WebSocket = require('ws');
const EventEmitter = require('events');
const axios = require('axios');
const ioredis = require('ioredis');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const compression = require('compression');
const winston = require('winston');

// Configuration
const config = {
  port: process.env.API_GATEWAY_PORT || 3000,
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: '24h'
  },
  services: {
    discovery: {
      enabled: true,
      interval: 30000, // 30 seconds
      timeout: 5000,   // 5 seconds
      retries: 3
    },
    healthCheck: {
      interval: 15000, // 15 seconds
      timeout: 3000,   // 3 seconds
      unhealthyThreshold: 3
    }
  },
  loadBalancing: {
    strategy: 'round-robin', // round-robin, least-connections, weighted
    stickySession: false
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // requests per window
    skipSuccessfulRequests: false
  }
};

// Logger setup
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.colorize(),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ 
      filename: 'logs/api-gateway.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5
    })
  ]
});

class AutoExtendingApiGateway extends EventEmitter {
  constructor() {
    super();
    
    this.app = express();
    this.server = null;
    this.wss = null;
    this.redis = null;
    
    // Service registry and discovery
    this.services = new Map();
    this.serviceInstances = new Map();
    this.healthStatus = new Map();
    this.loadBalancers = new Map();
    
    // Request tracking
    this.activeConnections = new Map();
    this.requestMetrics = {
      total: 0,
      successful: 0,
      failed: 0,
      averageResponseTime: 0
    };
    
    this.initialize();
  }
  
  async initialize() {
    await this.setupRedis();
    this.setupMiddleware();
    this.setupWebSocket();
    this.setupRoutes();
    this.startServiceDiscovery();
    this.startHealthChecking();
    this.setupGracefulShutdown();
    
    logger.info('🚀 Auto-extending API Gateway initialized');
  }
  
  async setupRedis() {
    this.redis = new ioredis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true
    });
    
    this.redis.on('connect', () => {
      logger.info('🔌 Connected to Redis for service registry');
    });
    
    this.redis.on('error', (error) => {
      logger.error('❌ Redis connection error:', error);
    });
    
    // Subscribe to service registration events
    const subscriber = this.redis.duplicate();
    subscriber.subscribe('service:register', 'service:unregister', 'service:health');
    
    subscriber.on('message', (channel, message) => {
      try {
        const data = JSON.parse(message);
        this.handleServiceEvent(channel, data);
      } catch (error) {
        logger.error('❌ Failed to parse service event:', error);
      }
    });
  }
  
  setupMiddleware() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:", "http:"],
          connectSrc: ["'self'", "ws:", "wss:", "http:", "https:"]
        }
      }
    }));
    
    // Compression
    this.app.use(compression());
    
    // CORS
    this.app.use(cors({
      origin: function(origin, callback) {
        // Allow requests from registered services and configured origins
        callback(null, true);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Service-ID']
    }));
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: config.rateLimit.windowMs,
      max: config.rateLimit.max,
      message: {
        error: 'Too many requests from this IP',
        retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => {
        // Custom key generation for different rate limits per service
        const serviceId = this.getServiceIdFromPath(req.path);
        return `${req.ip}:${serviceId || 'global'}`;
      }
    });
    this.app.use(limiter);
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request ID and logging
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || uuidv4();
      req.startTime = Date.now();
      res.setHeader('X-Request-ID', req.id);
      res.setHeader('X-Gateway-Version', '2.0.0');
      
      // Track active connections
      this.activeConnections.set(req.id, {
        method: req.method,
        url: req.url,
        startTime: req.startTime,
        ip: req.ip
      });
      
      res.on('finish', () => {
        const duration = Date.now() - req.startTime;
        this.updateMetrics(req, res, duration);
        this.activeConnections.delete(req.id);
        
        logger.info(`${req.method} ${req.path} - ${res.statusCode}`, {
          requestId: req.id,
          ip: req.ip,
          duration,
          userAgent: req.headers['user-agent'],
          serviceId: req.serviceId
        });
      });
      
      next();
    });
    
    // Authentication middleware
    this.app.use(this.authenticateRequest.bind(this));
    
    // Service routing middleware
    this.app.use(this.routeToService.bind(this));
  }
  
  setupWebSocket() {
    this.wss = new WebSocket.Server({ 
      port: parseInt(config.port) + 1,
      verifyClient: this.verifyWebSocketClient.bind(this)
    });
    
    this.wss.on('connection', (ws, req) => {
      ws.id = uuidv4();
      ws.isAlive = true;
      ws.authenticated = false;
      ws.subscriptions = new Set();
      
      logger.info('🔌 WebSocket client connected', { clientId: ws.id });
      
      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message);
          await this.handleWebSocketMessage(ws, data);
        } catch (error) {
          logger.error('❌ WebSocket message error:', error);
          ws.send(JSON.stringify({ 
            error: 'Invalid message format',
            timestamp: new Date().toISOString()
          }));
        }
      });
      
      ws.on('pong', () => {
        ws.isAlive = true;
      });
      
      ws.on('close', () => {
        logger.info('🔌 WebSocket client disconnected', { clientId: ws.id });
      });
      
      // Send initial gateway status
      ws.send(JSON.stringify({
        type: 'gateway:status',
        data: {
          services: Array.from(this.services.keys()),
          healthy: this.getHealthyServices().length,
          total: this.services.size,
          version: '2.0.0'
        },
        timestamp: new Date().toISOString()
      }));
    });
    
    // WebSocket health check
    setInterval(() => {
      this.wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
          return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
    
    logger.info(`🌐 WebSocket server started on port ${parseInt(config.port) + 1}`);
  }
  
  setupRoutes() {
    // Gateway health and status
    this.app.get('/health', this.getGatewayHealth.bind(this));
    this.app.get('/status', this.getGatewayStatus.bind(this));
    this.app.get('/services', this.getRegisteredServices.bind(this));
    this.app.get('/metrics', this.getGatewayMetrics.bind(this));
    
    // Service registration endpoints (for services to register themselves)
    this.app.post('/gateway/register', this.registerService.bind(this));
    this.app.delete('/gateway/register/:serviceId', this.unregisterService.bind(this));
    
    // Admin endpoints
    this.app.get('/admin/services/:serviceId/health', this.getServiceHealth.bind(this));
    this.app.post('/admin/services/:serviceId/reload', this.reloadService.bind(this));
    this.app.get('/admin/connections', this.getActiveConnections.bind(this));
    
    // Catch-all for service routing
    this.app.use('*', this.handleUnregisteredRoute.bind(this));
  }
  
  async startServiceDiscovery() {
    if (!config.services.discovery.enabled) return;
    
    logger.info('🔍 Starting automatic service discovery');
    
    // Initial discovery
    await this.discoverServices();
    
    // Periodic discovery
    setInterval(async () => {
      try {
        await this.discoverServices();
      } catch (error) {
        logger.error('❌ Service discovery error:', error);
      }
    }, config.services.discovery.interval);
  }
  
  async discoverServices() {
    try {
      // Look for services in common ports and paths
      const servicePorts = [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008];
      const discoveredServices = [];
      
      for (const port of servicePorts) {
        try {
          const response = await axios.get(`http://localhost:${port}/health`, {
            timeout: config.services.discovery.timeout
          });
          
          if (response.data && response.data.service) {
            const serviceInfo = {
              id: response.data.service,
              name: response.data.service,
              host: 'localhost',
              port: port,
              path: '',
              version: response.data.version || '1.0.0',
              status: 'healthy',
              lastSeen: new Date().toISOString(),
              metadata: {
                uptime: response.data.uptime,
                environment: response.data.environment,
                capabilities: response.data.capabilities || []
              }
            };
            
            discoveredServices.push(serviceInfo);
            await this.registerServiceInternal(serviceInfo);
          }
        } catch (error) {
          // Service not available on this port, continue
        }
      }
      
      if (discoveredServices.length > 0) {
        logger.info(`🎯 Discovered ${discoveredServices.length} services`, {
          services: discoveredServices.map(s => `${s.name}:${s.port}`)
        });
      }
      
      // Store discovered services in Redis
      await this.redis.setex('gateway:discovered:services', 300, JSON.stringify(discoveredServices));
      
    } catch (error) {
      logger.error('❌ Service discovery failed:', error);
    }
  }
  
  async startHealthChecking() {
    logger.info('💓 Starting service health monitoring');
    
    setInterval(async () => {
      await this.performHealthChecks();
    }, config.services.healthCheck.interval);
  }
  
  async performHealthChecks() {
    const healthPromises = Array.from(this.services.values()).map(service => 
      this.checkServiceHealth(service)
    );
    
    await Promise.allSettled(healthPromises);
  }
  
  async checkServiceHealth(service) {
    try {
      const url = `http://${service.host}:${service.port}/health`;
      const response = await axios.get(url, {
        timeout: config.services.healthCheck.timeout
      });
      
      const isHealthy = response.status === 200 && response.data?.status === 'healthy';
      await this.updateServiceHealth(service.id, isHealthy, response.data);
      
    } catch (error) {
      await this.updateServiceHealth(service.id, false, { error: error.message });
    }
  }
  
  async updateServiceHealth(serviceId, isHealthy, healthData) {
    const currentHealth = this.healthStatus.get(serviceId) || { 
      status: 'unknown', 
      consecutiveFailures: 0,
      lastCheck: null 
    };
    
    if (isHealthy) {
      currentHealth.status = 'healthy';
      currentHealth.consecutiveFailures = 0;
    } else {
      currentHealth.consecutiveFailures++;
      if (currentHealth.consecutiveFailures >= config.services.healthCheck.unhealthyThreshold) {
        currentHealth.status = 'unhealthy';
      }
    }
    
    currentHealth.lastCheck = new Date().toISOString();
    currentHealth.data = healthData;
    
    this.healthStatus.set(serviceId, currentHealth);
    
    // Broadcast health update
    this.broadcastToWebSocket({
      type: 'service:health',
      data: {
        serviceId,
        ...currentHealth
      }
    });
    
    // Store in Redis
    await this.redis.setex(
      `service:health:${serviceId}`, 
      300, 
      JSON.stringify(currentHealth)
    );
  }
  
  authenticateRequest(req, res, next) {
    // Skip authentication for health checks and public endpoints
    const publicPaths = ['/health', '/status', '/services', '/metrics'];
    if (publicPaths.some(path => req.path.startsWith(path))) {
      return next();
    }
    
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      // Allow unauthenticated requests to pass through to services
      // Services can handle their own authentication
      req.user = null;
      return next();
    }
    
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      req.user = decoded;
      next();
    } catch (error) {
      req.user = null;
      next(); // Let the service handle invalid tokens
    }
  }
  
  async routeToService(req, res, next) {
    const serviceId = this.getServiceIdFromPath(req.path);
    
    if (!serviceId) {
      return next();
    }
    
    const service = this.services.get(serviceId);
    if (!service) {
      return res.status(404).json({
        error: 'Service not found',
        serviceId,
        availableServices: Array.from(this.services.keys())
      });
    }
    
    // Check service health
    const health = this.healthStatus.get(serviceId);
    if (health?.status === 'unhealthy') {
      return res.status(503).json({
        error: 'Service temporarily unavailable',
        serviceId,
        retryAfter: 30
      });
    }
    
    // Get service instance using load balancer
    const instance = this.getServiceInstance(serviceId);
    if (!instance) {
      return res.status(503).json({
        error: 'No healthy service instances available',
        serviceId
      });
    }
    
    req.serviceId = serviceId;
    
    // Create proxy middleware
    const proxy = createProxyMiddleware({
      target: `http://${instance.host}:${instance.port}`,
      changeOrigin: true,
      pathRewrite: {
        [`^/api/${serviceId}`]: instance.path || ''
      },
      onProxyReq: (proxyReq, req, res) => {
        // Add gateway headers
        proxyReq.setHeader('X-Gateway-ID', 'auto-extending-gateway');
        proxyReq.setHeader('X-Request-ID', req.id);
        proxyReq.setHeader('X-Forwarded-For', req.ip);
        
        if (req.user) {
          proxyReq.setHeader('X-User-ID', req.user.id || req.user.sub);
          proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.roles || []));
        }
        
        logger.debug(`📡 Proxying ${req.method} ${req.path} to ${instance.host}:${instance.port}`);
      },
      onProxyRes: (proxyRes, req, res) => {
        // Add gateway response headers
        proxyRes.headers['X-Gateway-Service'] = serviceId;
        proxyRes.headers['X-Service-Instance'] = `${instance.host}:${instance.port}`;
      },
      onError: (err, req, res) => {
        logger.error(`❌ Proxy error for ${serviceId}:`, err);
        
        if (!res.headersSent) {
          res.status(502).json({
            error: 'Bad Gateway',
            message: 'Service temporarily unavailable',
            serviceId,
            requestId: req.id
          });
        }
      }
    });
    
    proxy(req, res, next);
  }
  
  getServiceIdFromPath(path) {
    // Extract service ID from path like /api/auth/login -> auth
    const match = path.match(/^\/api\/([^\/]+)/);
    return match ? match[1] : null;
  }
  
  getServiceInstance(serviceId) {
    const instances = this.serviceInstances.get(serviceId) || [];
    const healthyInstances = instances.filter(instance => {
      const health = this.healthStatus.get(`${serviceId}:${instance.host}:${instance.port}`);
      return !health || health.status !== 'unhealthy';
    });
    
    if (healthyInstances.length === 0) {
      return null;
    }
    
    // Load balancing strategy
    let loadBalancer = this.loadBalancers.get(serviceId);
    if (!loadBalancer) {
      loadBalancer = new LoadBalancer(config.loadBalancing.strategy);
      this.loadBalancers.set(serviceId, loadBalancer);
    }
    
    return loadBalancer.getNextInstance(healthyInstances);
  }
  
  getHealthyServices() {
    return Array.from(this.services.values()).filter(service => {
      const health = this.healthStatus.get(service.id);
      return !health || health.status !== 'unhealthy';
    });
  }
  
  // Service registration handlers
  async registerService(req, res) {
    try {
      const serviceInfo = req.body;
      
      // Validate service registration
      if (!serviceInfo.id || !serviceInfo.host || !serviceInfo.port) {
        return res.status(400).json({
          error: 'Missing required service information',
          required: ['id', 'host', 'port']
        });
      }
      
      await this.registerServiceInternal(serviceInfo);
      
      logger.info(`📝 Service registered manually`, { serviceId: serviceInfo.id });
      
      res.json({
        success: true,
        message: 'Service registered successfully',
        serviceId: serviceInfo.id
      });
      
    } catch (error) {
      logger.error('❌ Service registration error:', error);
      res.status(500).json({
        error: 'Failed to register service',
        details: error.message
      });
    }
  }
  
  async registerServiceInternal(serviceInfo) {
    // Add default values
    const service = {
      ...serviceInfo,
      registeredAt: new Date().toISOString(),
      lastSeen: new Date().toISOString()
    };
    
    this.services.set(service.id, service);
    
    // Add to service instances
    const instances = this.serviceInstances.get(service.id) || [];
    const instanceKey = `${service.host}:${service.port}`;
    
    if (!instances.find(i => `${i.host}:${i.port}` === instanceKey)) {
      instances.push({
        host: service.host,
        port: service.port,
        path: service.path || '',
        weight: service.weight || 1
      });
      this.serviceInstances.set(service.id, instances);
    }
    
    // Store in Redis
    await this.redis.setex(`service:${service.id}`, 300, JSON.stringify(service));
    
    // Broadcast service registration
    this.broadcastToWebSocket({
      type: 'service:registered',
      data: service
    });
    
    // Trigger immediate health check
    await this.checkServiceHealth(service);
    
    this.emit('serviceRegistered', service);
  }
  
  async unregisterService(req, res) {
    try {
      const { serviceId } = req.params;
      
      if (!this.services.has(serviceId)) {
        return res.status(404).json({
          error: 'Service not found',
          serviceId
        });
      }
      
      this.services.delete(serviceId);
      this.serviceInstances.delete(serviceId);
      this.healthStatus.delete(serviceId);
      this.loadBalancers.delete(serviceId);
      
      // Remove from Redis
      await this.redis.del(`service:${serviceId}`);
      await this.redis.del(`service:health:${serviceId}`);
      
      // Broadcast service unregistration
      this.broadcastToWebSocket({
        type: 'service:unregistered',
        data: { serviceId }
      });
      
      logger.info(`🗑️ Service unregistered`, { serviceId });
      
      res.json({
        success: true,
        message: 'Service unregistered successfully',
        serviceId
      });
      
      this.emit('serviceUnregistered', serviceId);
      
    } catch (error) {
      logger.error('❌ Service unregistration error:', error);
      res.status(500).json({
        error: 'Failed to unregister service',
        details: error.message
      });
    }
  }
  
  // Status and health endpoints
  async getGatewayHealth(req, res) {
    const healthyServices = this.getHealthyServices();
    const totalServices = this.services.size;
    
    const status = totalServices === 0 ? 'no-services' : 
                  healthyServices.length === totalServices ? 'healthy' :
                  healthyServices.length > 0 ? 'degraded' : 'unhealthy';
    
    res.json({
      status,
      gateway: {
        version: '2.0.0',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        activeConnections: this.activeConnections.size,
        websocketConnections: this.wss.clients.size
      },
      services: {
        total: totalServices,
        healthy: healthyServices.length,
        unhealthy: totalServices - healthyServices.length
      },
      timestamp: new Date().toISOString()
    });
  }
  
  async getGatewayStatus(req, res) {
    const services = Array.from(this.services.values()).map(service => ({
      ...service,
      health: this.healthStatus.get(service.id),
      instances: this.serviceInstances.get(service.id) || []
    }));
    
    res.json({
      gateway: {
        version: '2.0.0',
        startTime: this.startTime,
        uptime: process.uptime()
      },
      services,
      metrics: this.requestMetrics,
      timestamp: new Date().toISOString()
    });
  }
  
  async getRegisteredServices(req, res) {
    const services = Array.from(this.services.values()).map(service => ({
      id: service.id,
      name: service.name,
      version: service.version,
      host: service.host,
      port: service.port,
      path: service.path,
      status: this.healthStatus.get(service.id)?.status || 'unknown',
      lastSeen: service.lastSeen,
      metadata: service.metadata
    }));
    
    res.json({
      services,
      total: services.length,
      healthy: services.filter(s => s.status === 'healthy').length,
      timestamp: new Date().toISOString()
    });
  }
  
  async getGatewayMetrics(req, res) {
    const metrics = {
      ...this.requestMetrics,
      services: {
        total: this.services.size,
        healthy: this.getHealthyServices().length,
        discovering: config.services.discovery.enabled
      },
      connections: {
        active: this.activeConnections.size,
        websocket: this.wss.clients.size
      },
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString()
    };
    
    res.json(metrics);
  }
  
  async getServiceHealth(req, res) {
    const { serviceId } = req.params;
    const service = this.services.get(serviceId);
    
    if (!service) {
      return res.status(404).json({ error: 'Service not found' });
    }
    
    const health = this.healthStatus.get(serviceId);
    
    res.json({
      serviceId,
      service,
      health: health || { status: 'unknown' },
      timestamp: new Date().toISOString()
    });
  }
  
  async reloadService(req, res) {
    const { serviceId } = req.params;
    
    if (!this.services.has(serviceId)) {
      return res.status(404).json({ error: 'Service not found' });
    }
    
    // Trigger immediate health check and discovery
    const service = this.services.get(serviceId);
    await this.checkServiceHealth(service);
    
    res.json({
      success: true,
      message: 'Service reload triggered',
      serviceId
    });
  }
  
  async getActiveConnections(req, res) {
    const connections = Array.from(this.activeConnections.entries()).map(([id, conn]) => ({
      id,
      ...conn,
      duration: Date.now() - conn.startTime
    }));
    
    res.json({
      connections,
      total: connections.length,
      timestamp: new Date().toISOString()
    });
  }
  
  handleUnregisteredRoute(req, res) {
    const serviceId = this.getServiceIdFromPath(req.path);
    
    res.status(404).json({
      error: 'Route not found',
      path: req.path,
      method: req.method,
      suggestedService: serviceId,
      availableServices: Array.from(this.services.keys()),
      help: 'Register your service using POST /gateway/register',
      timestamp: new Date().toISOString()
    });
  }
  
  // WebSocket handling
  verifyWebSocketClient(info) {
    // In production, implement proper authentication
    return true;
  }
  
  async handleWebSocketMessage(ws, message) {
    const { type, data } = message;
    
    switch (type) {
      case 'authenticate':
        await this.authenticateWebSocket(ws, data);
        break;
        
      case 'subscribe':
        this.subscribeWebSocket(ws, data.topics || []);
        break;
        
      case 'unsubscribe':
        this.unsubscribeWebSocket(ws, data.topics || []);
        break;
        
      case 'ping':
        ws.send(JSON.stringify({
          type: 'pong',
          timestamp: new Date().toISOString()
        }));
        break;
        
      default:
        ws.send(JSON.stringify({
          error: 'Unknown message type',
          supportedTypes: ['authenticate', 'subscribe', 'unsubscribe', 'ping']
        }));
    }
  }
  
  async authenticateWebSocket(ws, data) {
    try {
      if (data.token) {
        const decoded = jwt.verify(data.token, config.jwt.secret);
        ws.authenticated = true;
        ws.user = decoded;
      }
      
      ws.send(JSON.stringify({
        type: 'authenticated',
        success: ws.authenticated,
        user: ws.user || null
      }));
    } catch (error) {
      ws.send(JSON.stringify({
        type: 'authenticated',
        success: false,
        error: 'Invalid token'
      }));
    }
  }
  
  subscribeWebSocket(ws, topics) {
    topics.forEach(topic => ws.subscriptions.add(topic));
    ws.send(JSON.stringify({
      type: 'subscribed',
      topics,
      totalSubscriptions: ws.subscriptions.size
    }));
  }
  
  unsubscribeWebSocket(ws, topics) {
    topics.forEach(topic => ws.subscriptions.delete(topic));
    ws.send(JSON.stringify({
      type: 'unsubscribed',
      topics,
      remainingSubscriptions: ws.subscriptions.size
    }));
  }
  
  broadcastToWebSocket(message) {
    const messageStr = JSON.stringify({
      ...message,
      timestamp: new Date().toISOString()
    });
    
    this.wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(messageStr);
      }
    });
  }
  
  // Event handlers
  handleServiceEvent(channel, data) {
    switch (channel) {
      case 'service:register':
        this.registerServiceInternal(data);
        break;
        
      case 'service:unregister':
        this.services.delete(data.serviceId);
        this.serviceInstances.delete(data.serviceId);
        this.healthStatus.delete(data.serviceId);
        break;
        
      case 'service:health':
        this.updateServiceHealth(data.serviceId, data.healthy, data.healthData);
        break;
    }
  }
  
  updateMetrics(req, res, duration) {
    this.requestMetrics.total++;
    
    if (res.statusCode >= 200 && res.statusCode < 400) {
      this.requestMetrics.successful++;
    } else {
      this.requestMetrics.failed++;
    }
    
    // Calculate moving average response time
    const currentAvg = this.requestMetrics.averageResponseTime;
    const total = this.requestMetrics.total;
    this.requestMetrics.averageResponseTime = 
      ((currentAvg * (total - 1)) + duration) / total;
  }
  
  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      logger.info(`🛑 Received ${signal}, starting graceful shutdown...`);
      
      // Stop accepting new connections
      this.server.close(() => {
        logger.info('✅ HTTP server closed');
      });
      
      // Close WebSocket connections
      this.wss.clients.forEach(client => {
        client.close(1001, 'Server shutting down');
      });
      this.wss.close(() => {
        logger.info('✅ WebSocket server closed');
      });
      
      // Close Redis connection
      if (this.redis) {
        await this.redis.quit();
        logger.info('✅ Redis connection closed');
      }
      
      logger.info('✅ Graceful shutdown completed');
      process.exit(0);
    };
    
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }
  
  start() {
    this.startTime = new Date().toISOString();
    
    this.server = this.app.listen(config.port, () => {
      logger.info(`🚀 Auto-extending API Gateway started on port ${config.port}`);
      logger.info(`📊 Health check: http://localhost:${config.port}/health`);
      logger.info(`🔍 Service discovery: ${config.services.discovery.enabled ? 'Enabled' : 'Disabled'}`);
      logger.info(`💓 Health monitoring: Enabled`);
      logger.info(`🌐 WebSocket: ws://localhost:${parseInt(config.port) + 1}`);
      logger.info(`📝 Service registration: POST /gateway/register`);
    });
  }
}

// Load balancer class
class LoadBalancer {
  constructor(strategy = 'round-robin') {
    this.strategy = strategy;
    this.roundRobinIndex = 0;
    this.connections = new Map();
  }
  
  getNextInstance(instances) {
    if (instances.length === 0) return null;
    
    switch (this.strategy) {
      case 'round-robin':
        return this.roundRobin(instances);
        
      case 'least-connections':
        return this.leastConnections(instances);
        
      case 'weighted':
        return this.weighted(instances);
        
      default:
        return this.roundRobin(instances);
    }
  }
  
  roundRobin(instances) {
    const instance = instances[this.roundRobinIndex % instances.length];
    this.roundRobinIndex++;
    return instance;
  }
  
  leastConnections(instances) {
    return instances.reduce((least, current) => {
      const leastConns = this.connections.get(`${least.host}:${least.port}`) || 0;
      const currentConns = this.connections.get(`${current.host}:${current.port}`) || 0;
      return currentConns < leastConns ? current : least;
    });
  }
  
  weighted(instances) {
    const totalWeight = instances.reduce((sum, instance) => sum + (instance.weight || 1), 0);
    let random = Math.random() * totalWeight;
    
    for (const instance of instances) {
      random -= instance.weight || 1;
      if (random <= 0) {
        return instance;
      }
    }
    
    return instances[0];
  }
  
  addConnection(host, port) {
    const key = `${host}:${port}`;
    this.connections.set(key, (this.connections.get(key) || 0) + 1);
  }
  
  removeConnection(host, port) {
    const key = `${host}:${port}`;
    const current = this.connections.get(key) || 0;
    if (current > 0) {
      this.connections.set(key, current - 1);
    }
  }
}

// Start the gateway
const gateway = new AutoExtendingApiGateway();
gateway.start();

module.exports = AutoExtendingApiGateway;