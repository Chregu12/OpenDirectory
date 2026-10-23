const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const createProxyMiddleware = require('./middleware/proxy');
const WebSocket = require('ws');
const http = require('http');
const { gatewayAccess, getGatewayPermissions } = require('./middleware/gatewayAccess');
const { Pool } = require('pg');

const pgPool = new Pool({
  ...(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL } : {}),
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || process.env.POSTGRES_DB || 'api_gateway',
  user: process.env.DB_USER || process.env.POSTGRES_USER || 'postgres',
  password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || '',
  max: 5,
  connectionTimeoutMillis: 3000,
});

let apiGwDbReady = false;
const databaseReady = pgPool.query('SELECT 1').then(async () => {
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      key_hash VARCHAR(512) NOT NULL UNIQUE,
      permissions JSONB NOT NULL DEFAULT '["read"]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used TIMESTAMPTZ,
      active BOOLEAN DEFAULT TRUE
    )
  `);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS webhooks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(255) NOT NULL,
      url TEXT NOT NULL,
      events TEXT[] DEFAULT '{}',
      secret_hash VARCHAR(512),
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_triggered TIMESTAMPTZ,
      delivery_count INTEGER DEFAULT 0,
      failure_count INTEGER DEFAULT 0
    )
  `);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
      event_type VARCHAR(100),
      payload JSONB,
      response_status INTEGER,
      delivered_at TIMESTAMPTZ DEFAULT NOW(),
      success BOOLEAN DEFAULT false
    )
  `);
  apiGwDbReady = true;
}).catch(() => {});

const logger = require('./config/logger');

// ─── RabbitMQ Event Bus ───────────────────────────────────────────────────────
const EventBusClient = (() => {
  try { return require('@opendirectory/grpc-event-bus').EventBusClient; }
  catch (_) { return require('../../../../packages/grpc-event-bus/src').EventBusClient; }
})();
const _bus = new EventBusClient({ source: 'api-gateway' });
async function connectBus() { await _bus.connect(); }
function publish(routingKey, payload) { _bus.publish(routingKey, payload).catch(() => {}); }

const serviceDiscovery = require('./discovery/serviceDiscovery');
const authMiddleware = require('./middleware/auth');
const routingMiddleware = require('./middleware/routing');
const configManager = require('./config/configManager');
const healthCheck = require('./middleware/health');

class APIGateway {
  constructor({ authentication = authMiddleware, discover = true, enabledModules } = {}) {
    this.authentication = typeof authentication === 'function' ? { middleware: authentication, authenticate: authentication.authenticate } : authentication;
    this.enabledModules = enabledModules;
    this.app = express();
    this.server = null;
    this.wsServer = null;
    this.services = new Map();
    this.config = configManager.getConfig();

    // Pre-create rate limiters at init time (express-rate-limit v7 requirement)
    this.apiClientLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5000,
      message: 'API rate limit exceeded',
      standardHeaders: true,
    });
    this.frontendLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 1000,
      message: 'Rate limit exceeded',
      standardHeaders: true,
    });
    this.defaultLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      message: 'Rate limit exceeded. Consider using API authentication for higher limits.',
      standardHeaders: true,
    });

    this.initializeMiddleware();
    this.initializeWebSocket();
    this.initializeRoutes();
    if (discover) this.initializeServiceDiscovery();
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

    // CORS configuration
    const allowedOrigins = process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
      : ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000'];

    this.app.use((_req, res, next) => { res.vary('Origin'); next(); });
    this.app.use(cors({
      origin: function (origin, callback) {
        if (origin === undefined) return callback(null, false);

        if (origin && origin !== 'null' && allowedOrigins.includes(origin)) {
          return callback(null, true);
        }

        return callback(Object.assign(new Error('Browser origin not allowed by CORS policy'), { status: 403 }), false);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'If-Match',
        'X-Requested-With',
        'X-API-Key',
        'X-Service-Auth',
        'X-Service-Name',
        'X-Client-Type'
      ],
      exposedHeaders: ['ETag', 'X-Total-Count', 'X-Response-Time', 'X-Rate-Limit-Remaining'],
    }));

    // Dynamic rate limiting based on authentication type


    // Logging
    morgan.token('safe-path', req => req.path);
    this.app.use(morgan(':method :safe-path :status :response-time ms', {
      stream: { write: (message) => logger.info(message.trim()) }
    }));

    // Body parsing
    this.app.use(['/api/gateway', '/api/admin', '/api/config/modules'], express.json({ limit: '256kb' }));
    this.app.use(['/api/gateway', '/api/admin', '/api/config/modules'], express.urlencoded({ extended: false, limit: '256kb' }));

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
    this.app.use(this.apiClientLimiter);
    this.app.use(this.authentication.middleware);
    this.app.use((req, res, next) => {
      const limiter = this.getRateLimiter(req);
      limiter(req, res, next);
    });
    this.app.use(routingMiddleware);
    this.app.use(gatewayAccess(path => [...this.services.values()].filter(service => path === service.pathPrefix || path.startsWith(`${service.pathPrefix}/`))
      .sort((first, second) => second.pathPrefix.length - first.pathPrefix.length)[0]));
  }

  initializeWebSocket() {
    this.server = http.createServer(this.app);
    this.wsServer = new WebSocket.Server({ noServer: true, maxPayload: 16384 });
    let pending = 0;
    this.server.on('upgrade', async (req, socket, head) => {
      socket.on('error', () => socket.destroy());
      const reject = status => { if (!socket.destroyed) socket.end('HTTP/1.1 ' + status + ' ' + http.STATUS_CODES[status] + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); };
      if (req.url !== '/ws') return reject(404);
      if (pending >= 8 || this.wsServer.clients.size >= 32) return reject(503);
      const origin = req.headers.origin;
      const allowed = (process.env.CORS_ORIGIN || 'http://localhost:3000,http://localhost:3001').split(',').map(value => value.trim());
      if (origin && !allowed.includes(origin)) return reject(403);
      pending++;
      socket.setTimeout(6000, () => socket.destroy());
      try {
        req.user = await this.authentication.authenticate(req);
        if (!getGatewayPermissions(req.user).includes('gateway.events.read')) return reject(403);
        if (socket.destroyed) return;
        socket.setTimeout(0);
        this.wsServer.handleUpgrade(req, socket, head, ws => this.wsServer.emit('connection', ws, req));
      } catch (error) { reject(error.status || 503); }
      finally { pending--; }
    });
    this.wsServer.on('connection', (ws, req) => {
      ws.principal = req.user;
      let processing = false;
      const expiry = setTimeout(() => ws.close(4401, 'Access token expired'), Math.min(2147483647, Math.max(1, req.user.exp * 1000 - Date.now())));
      expiry.unref();
      let checking = false;
      const stateCheck = setInterval(async () => {
        if (checking || ws.readyState !== WebSocket.OPEN) return;
        checking = true;
        try {
          const principal = await this.authentication.authenticate(req);
          if (!getGatewayPermissions(principal).includes('gateway.events.read')) return ws.close(4403, 'Permission required');
          ws.principal = principal;
        } catch (error) { ws.close(error.status === 503 ? 1013 : 4401, 'Access token state unavailable or revoked'); }
        finally { checking = false; }
      }, 5000);
      stateCheck.unref();
      ws.on('message', async data => {
        if (processing) return ws.close(4408, 'Message rate exceeded');
        processing = true;
        try {
          const principal = await this.authentication.authenticate(req);
          if (!getGatewayPermissions(principal).includes('gateway.events.read')) return ws.close(4403, 'Permission required');
          ws.principal = principal;
          this.handleWebSocketMessage(ws, JSON.parse(data.toString()));
        } catch { ws.close(4401, 'Invalid message or access token'); }
        finally { processing = false; }
      });
      ws.on('close', () => { clearTimeout(expiry); clearInterval(stateCheck); });
      ws.on('error', () => ws.terminate());
      ws.send(JSON.stringify({ type: 'connection', status: 'connected', gateway: 'OpenDirectory API Gateway' }));
    });
  }

  initializeRoutes() {
    this.app.get('/api/gateway/access', (req, res) => res.set('Cache-Control', 'no-store').json({ subject: req.user.sub, permissions: getGatewayPermissions(req.user),
      keyIssuanceEnabled: false, websocketAuthentication: 'bearer-header' }));
    // Health check endpoints (public)
    this.app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'api-gateway' }));
    this.app.get('/health/live', (_req, res) => res.json({ status: 'ok', service: 'api-gateway' }));
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
    this.app.get('/api/admin/keys', this.getApiKeys.bind(this));
    this.app.post('/api/admin/keys', this.createApiKey.bind(this));
    this.app.delete('/api/admin/keys/:keyId', this.deleteApiKey.bind(this));

    // Public API key / webhook management endpoints (used by frontend)
    this.app.get('/api/gateway/api-keys', this.getApiKeys.bind(this));
    this.app.post('/api/gateway/api-keys', this.createApiKey.bind(this));
    this.app.delete('/api/gateway/api-keys/:keyId', this.deleteApiKey.bind(this));

    // Webhook management
    this.app.get('/api/gateway/webhooks', this.getWebhooks.bind(this));
    this.app.post('/api/gateway/webhooks', this.createWebhook.bind(this));
    this.app.put('/api/gateway/webhooks/:webhookId', this.updateWebhook.bind(this));
    this.app.delete('/api/gateway/webhooks/:webhookId', this.deleteWebhook.bind(this));
    this.app.post('/api/gateway/webhooks/:webhookId/test', this.testWebhook.bind(this));
    this.app.get('/api/gateway/webhooks/:webhookId/deliveries', this.getWebhookDeliveries.bind(this));

    // RabbitMQ audit logging for API requests
    this.app.use((req, res, next) => {
      res.on('finish', () => {
        if (req.path !== '/health' && req.path !== '/metrics') {
          publish('api.request', { method: req.method, path: req.path, status: res.statusCode, ip: req.ip });
        }
      });
      next();
    });

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
    const enabledModules = this.enabledModules || configManager.getEnabledModules();
    const connectedServices = [];

    // least-privilege service: resource/level permission matrix
    // (/api/permissions/*) and its own JIT elevation flow
    // (/api/pim/elevation/*) — see
    // services/core/least-privilege/src/index.js for why /api/pim/elevation
    // is a distinct prefix from bare /api/pim/*: authentication-service owns
    // bare /api/pim/* for a different capability (role-based PIM tied to a
    // directory group; see routes/pim.js there), and least-privilege's
    // resource/level JIT elevation is not the same feature reimplemented —
    // it operates on this service's own permission matrix, not directory
    // roles/groups, and has an incompatible request shape. These two proxy
    // registrations MUST come before the generic 'pim' registration below
    // (bare /api/pim -> authentication-service), or Express/
    // http-proxy-middleware's registration-order matching would let the
    // generic /api/pim rule claim /api/pim/elevation/* requests first and
    // silently shadow this service — same reasoning as the /api/config/domain
    // special case a few lines down. Mounted directly (not via
    // setupServiceProxy) because that helper's generic `pathPrefix -> '/api'`
    // rewrite would strip 'permissions' / 'pim/elevation' from the path —
    // wrong here, since least-privilege's own routes are the full paths (no
    // rewrite needed, forwarded as-is).
    this.app.use('/api/pim/elevation', createProxyMiddleware({
      target: 'http://least-privilege:3011',
      changeOrigin: true,
      onError: (err, req, res) => {
        logger.error('Proxy error for pim-elevation:', err);
        res.status(503).json({
          error: 'Service temporarily unavailable',
          service: 'pim-elevation',
          timestamp: new Date().toISOString()
        });
      },
    }));
    this.services.set('pim-elevation', {
      name: 'pim-elevation',
      target: 'http://least-privilege:3011',
      pathPrefix: '/api/pim/elevation',
      status: 'active',
      lastCheck: new Date().toISOString()
    });

    this.app.use('/api/permissions', createProxyMiddleware({
      target: 'http://least-privilege:3011',
      changeOrigin: true,
      onError: (err, req, res) => {
        logger.error('Proxy error for least-privilege:', err);
        res.status(503).json({
          error: 'Service temporarily unavailable',
          service: 'least-privilege',
          timestamp: new Date().toISOString()
        });
      },
    }));
    this.services.set('least-privilege', {
      name: 'least-privilege',
      target: 'http://least-privilege:3011',
      pathPrefix: '/api/permissions',
      status: 'active',
      lastCheck: new Date().toISOString()
    });

    // Core services (always enabled)
    this.setupServiceProxy('authentication', 'http://authentication-service', '/api/auth');
    this.setupServiceProxy('pim', 'http://authentication-service', '/api/pim');

    // /api/config/domain is owned by authentication-service (see
    // src/routes/directory.js there — restored alongside PIM/OUs/service-
    // accounts), NOT configuration-service. It must be registered BEFORE the
    // generic '/api/config' -> configuration-service proxy below so this
    // more specific rule wins (Express/http-proxy-middleware matches
    // registration order; whichever proxy claims the request first handles
    // it fully). Unlike setupServiceProxy()'s other registrations, this is
    // mounted directly (not through that helper) because its generic
    // `pathPrefix -> '/api'` rewrite convention would collapse
    // '/api/config/domain' down to bare '/api' — wrong here, since
    // authentication-service's own route is the full '/api/config/domain'
    // path (no rewrite needed, forwarded as-is).
    this.app.use('/api/config/domain', createProxyMiddleware({
      target: 'http://authentication-service',
      changeOrigin: true,
      onError: (err, req, res) => {
        logger.error('Proxy error for config-domain:', err);
        res.status(503).json({
          error: 'Service temporarily unavailable',
          service: 'config-domain',
          timestamp: new Date().toISOString()
        });
      },
    }));
    this.services.set('config-domain', {
      name: 'config-domain',
      target: 'http://authentication-service',
      pathPrefix: '/api/config/domain',
      status: 'active',
      lastCheck: new Date().toISOString()
    });

    this.setupServiceProxy('configuration', 'http://configuration-service', '/api/config');
    connectedServices.push('authentication', 'pim', 'pim-elevation', 'least-privilege', 'config-domain', 'configuration');

    // Health service (if exists)
    this.setupServiceProxy('health', 'http://health-service', '/api/health');
    connectedServices.push('health');

    // Module-based proxies - ALL available modules
    if (enabledModules.includes('network-infrastructure')) {
      this.setupServiceProxy('network', 'http://network-infrastructure', '/api/network');
      connectedServices.push('network-infrastructure');
    }

    if (enabledModules.includes('security-suite')) {
      this.setupServiceProxy('security', 'http://security-suite', '/api/security');
      connectedServices.push('security-suite');
    }

    if (enabledModules.includes('printer-service')) {
      this.setupServiceProxy('printer', 'http://printer-service', '/api/printer');
      this.setupServiceProxy('printers', 'http://printer-service', '/api/printers'); // Alternative route
      connectedServices.push('printer-service');
    }

    if (enabledModules.includes('monitoring-analytics')) {
      this.setupServiceProxy('monitoring', 'http://monitoring-analytics', '/api/monitoring');
      this.setupServiceProxy('analytics', 'http://monitoring-analytics', '/api/analytics');
      connectedServices.push('monitoring-analytics');
    }

    if (enabledModules.includes('device-management')) {
      const inventoryTarget=process.env.DEVICE_SERVICE_URL || 'http://device-service:3003';
      this.app.use('/api/devices',require('./middleware/deviceInventoryProxy').deviceInventoryReceiver(inventoryTarget),createProxyMiddleware({target:inventoryTarget,changeOrigin:true}));
      this.services.set('devices',{name:'devices',target:inventoryTarget,pathPrefix:'/api/devices',status:'active',lastCheck:new Date().toISOString()});
      connectedServices.push('device-management');
    }

    if (enabledModules.includes('policy-compliance')) {
      this.setupServiceProxy('policy', 'http://policy-compliance', '/api/policy');
      this.setupServiceProxy('compliance', 'http://policy-compliance', '/api/compliance');
      connectedServices.push('policy-compliance');
    }

    if (enabledModules.includes('backup-disaster')) {
      this.setupServiceProxy('backup', 'http://backup-disaster', '/api/backup');
      this.setupServiceProxy('disaster-recovery', 'http://backup-disaster', '/api/dr');
      connectedServices.push('backup-disaster');
    }

    if (enabledModules.includes('automation-workflows')) {
      this.setupServiceProxy('automation', 'http://automation-workflows', '/api/automation');
      this.setupServiceProxy('workflows', 'http://automation-workflows', '/api/workflows');
      connectedServices.push('automation-workflows');
    }

    if (enabledModules.includes('container-orchestration')) {
      this.setupServiceProxy('containers', 'http://container-orchestration', '/api/containers');
      this.setupServiceProxy('kubernetes', 'http://container-orchestration', '/api/k8s');
      this.setupServiceProxy('docker', 'http://container-orchestration', '/api/docker');
      connectedServices.push('container-orchestration');
    }

    if (enabledModules.includes('enterprise-integrations')) {
      this.setupServiceProxy('integrations', 'http://enterprise-integrations', '/api/integrations');
      this.setupServiceProxy('erp', 'http://enterprise-integrations', '/api/erp');
      this.setupServiceProxy('sap', 'http://enterprise-integrations', '/api/sap');
      this.setupServiceProxy('o365', 'http://enterprise-integrations', '/api/o365');
      connectedServices.push('enterprise-integrations');
    }

    if (enabledModules.includes('ai-intelligence')) {
      this.setupServiceProxy('ai', 'http://ai-intelligence', '/api/ai');
      this.setupServiceProxy('ml', 'http://ai-intelligence', '/api/ml');
      this.setupServiceProxy('predictions', 'http://ai-intelligence', '/api/predictions');
      connectedServices.push('ai-intelligence');
    }

    // Legacy API Backend (if still needed)
    if (enabledModules.includes('api-backend')) {
      this.setupServiceProxy('legacy', 'http://api-backend', '/api/legacy');
      connectedServices.push('api-backend');
    }

    // Integration Service (for external services)
    if (enabledModules.includes('integration-service')) {
      this.setupServiceProxy('external', 'http://integration-service', '/api/external');
      this.setupServiceProxy('lldap', 'http://integration-service', '/api/lldap');
      this.setupServiceProxy('grafana', 'http://integration-service', '/api/grafana');
      this.setupServiceProxy('prometheus', 'http://integration-service', '/api/prometheus');
      this.setupServiceProxy('vault', 'http://integration-service', '/api/vault');
      connectedServices.push('integration-service');
    }

    // Identity and Policy services from core
    if (enabledModules.includes('identity-service')) {
      const companyAppTarget=process.env.OAUTH_PROVIDER_URL||'http://oauth-provider:3010';
      this.app.use('/api/clients/company',createProxyMiddleware({target:companyAppTarget,changeOrigin:true}));
      this.services.set('company-apps',{name:'company-apps',target:companyAppTarget,pathPrefix:'/api/clients/company',status:'active',lastCheck:new Date().toISOString()});
      const membershipReviewTarget=process.env.IDENTITY_SERVICE_URL||'http://identity-service:3001';
      this.app.use('/api/identity/license-sources',createProxyMiddleware({target:membershipReviewTarget,changeOrigin:true}));
      this.services.set('license-source-grants',{name:'license-source-grants',target:membershipReviewTarget,pathPrefix:'/api/identity/license-sources',status:'active',lastCheck:new Date().toISOString()});
      this.app.use('/api/identity/membership-reviews',createProxyMiddleware({target:membershipReviewTarget,changeOrigin:true}));
      this.services.set('membership-reviews',{name:'membership-reviews',target:membershipReviewTarget,pathPrefix:'/api/identity/membership-reviews',status:'active',lastCheck:new Date().toISOString()});
      for (const [name,pathPrefix] of [['identity','/api/identity'],['users','/api/users'],['groups','/api/groups'],['ous','/api/ous']]) {
        this.app.use(pathPrefix,createProxyMiddleware({target:membershipReviewTarget,changeOrigin:true}));
        this.services.set(name,{name,target:membershipReviewTarget,pathPrefix,status:'active',lastCheck:new Date().toISOString()});
      }
      this.app.use('/api/license-groups', createProxyMiddleware({ target: process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', changeOrigin: true }));
      this.app.use('/api/license-users', createProxyMiddleware({ target: process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', changeOrigin: true }));
      this.app.use('/api/license-reviewers', createProxyMiddleware({ target: process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', changeOrigin: true }));
      this.app.use('/api/license-delegates', createProxyMiddleware({ target: process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', changeOrigin: true }));
      this.app.use('/api/license-activation-reviewers', createProxyMiddleware({ target: process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', changeOrigin: true }));
      this.app.use('/api/license-scope-reviewers', createProxyMiddleware({ target: process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', changeOrigin: true }));
      connectedServices.push('identity-service');
    }

    if (enabledModules.includes('quick-actions')) {
      const target = process.env.QUICK_ACTIONS_URL || 'http://quick-actions:3950';
      this.app.use('/api/quick', createProxyMiddleware({ target, changeOrigin: true }));
      this.services.set('quick-actions', { name: 'quick-actions', target, pathPrefix: '/api/quick', status: 'active', lastCheck: new Date().toISOString() });
      connectedServices.push('quick-actions');
    }

    if (enabledModules.includes('policy-service')) {
      const licenseTarget = process.env.POLICY_SERVICE_URL || 'http://policy-service:3004';
      for (const name of ['policies', 'blueprints', 'company-blueprints', 'company-blueprint-assignments', 'gpo', 'update-rings']) {
        const pathPrefix = '/api/' + name;
        this.app.use(pathPrefix, createProxyMiddleware({ target: licenseTarget, changeOrigin: true }));
        this.services.set(name, { name, target: licenseTarget, pathPrefix, status: 'active', lastCheck: new Date().toISOString() });
      }
      this.app.use('/api/licenses', createProxyMiddleware({ target: licenseTarget, changeOrigin: true }));
      this.services.set('licenses', { name: 'licenses', target: licenseTarget, pathPrefix: '/api/licenses', status: 'active', lastCheck: new Date().toISOString() });
      connectedServices.push('policy-service');
    }

    // Notification Service
    if (enabledModules.includes('notification-service')) {
      this.setupServiceProxy('notifications', 'http://notification-service', '/api/notifications');
      this.setupServiceProxy('alerts', 'http://notification-service', '/api/alerts');
      connectedServices.push('notification-service');
    }

    // Deployment Service
    if (enabledModules.includes('deployment-service')) {
      this.setupServiceProxy('deployment', 'http://deployment-service', '/api/deployment');
      this.setupServiceProxy('apps', 'http://deployment-service', '/api/apps');
      connectedServices.push('deployment-service');
    }

    // License Management Service
    if (enabledModules.includes('license-management')) {
      const licenseAdapterTarget = process.env.LICENSE_ADAPTER_URL || 'http://license-management:3018';
      this.app.use('/api/license', createProxyMiddleware({ target: licenseAdapterTarget, changeOrigin: true }));
      this.services.set('license', { name: 'license', target: licenseAdapterTarget, pathPrefix: '/api/license', status: 'active', lastCheck: new Date().toISOString() });
      connectedServices.push('license-management');
    }

    // Certificate Authority service (always enabled)
    this.app.use('/api/ca', createProxyMiddleware({ target: 'http://certificate-authority', changeOrigin: true, pathRewrite: { '^/api/ca': '/ca' } }));
    connectedServices.push('certificate-authority');

    // Kerberos KDC REST API (always enabled)
    this.app.use('/api/kerberos', createProxyMiddleware({ target: 'http://kerberos-kdc', changeOrigin: true }));
    connectedServices.push('kerberos-kdc');

    // Apple MDM server (always enabled — enrollment, APNs push, command delivery)
    this.app.use('/api/mdm', createProxyMiddleware({ target: 'http://apple-mdm', changeOrigin: true }));
    this.app.use('/mdm', createProxyMiddleware({ target: 'http://apple-mdm', changeOrigin: true }));
    connectedServices.push('apple-mdm');

    // Intelligence Services (always enabled - core platform value)
    this.setupServiceProxy('graph', 'http://graph-explorer', '/api/graph');
    this.setupServiceProxy('graph-explorer', 'http://graph-explorer', '/api/graph-explorer');
    connectedServices.push('graph-explorer');

    this.setupServiceProxy('simulator', 'http://policy-simulator', '/api/simulator');
    this.setupServiceProxy('drift', 'http://policy-simulator', '/api/drift');
    this.setupServiceProxy('timeline', 'http://policy-simulator', '/api/timeline');
    connectedServices.push('policy-simulator');

    this.setupServiceProxy('scanner', 'http://security-scanner', '/api/scanner');
    this.setupServiceProxy('security-scan', 'http://security-scanner', '/api/security-scan');
    connectedServices.push('security-scanner');

    this.setupServiceProxy('lifecycle', 'http://device-lifecycle', '/api/lifecycle');
    this.setupServiceProxy('device-lifecycle', 'http://device-lifecycle', '/api/device-lifecycle');
    connectedServices.push('device-lifecycle');

    this.setupServiceProxy('remediation', 'http://auto-remediation', '/api/remediation');
    this.setupServiceProxy('auto-remediation', 'http://auto-remediation', '/api/auto-remediation');
    connectedServices.push('auto-remediation');

    this.setupServiceProxy('antivirus', 'http://antivirus-protection', '/api/antivirus');
    this.setupServiceProxy('clamav', 'http://antivirus-protection', '/api/clamav');
    connectedServices.push('antivirus-protection');

    // App Store
    this.setupServiceProxy('appstore', 'http://app-store', '/api/appstore');
    connectedServices.push('app-store');

    // Notification / Alerting service
    this.setupServiceProxy('notification', 'http://notification-service', '/api/notification');
    connectedServices.push('notification-service');

    // Backup service
    this.setupServiceProxy('backup-jobs', 'http://backup-service', '/api/backup');
    connectedServices.push('backup-service');

    // MDM (Apple MDM)
    this.setupServiceProxy('mdm', 'http://apple-mdm', '/api/mdm');
    connectedServices.push('apple-mdm');

    // Certificate Authority
    this.setupServiceProxy('ca', 'http://certificate-authority', '/api/ca');
    this.setupServiceProxy('certificates', 'http://certificate-authority', '/api/certificates');
    connectedServices.push('certificate-authority');

    // Conditional Access
    this.setupServiceProxy('conditional-access', 'http://conditional-access', '/api/conditional-access');
    connectedServices.push('conditional-access');

    logger.info(`API Gateway configured with ${connectedServices.length} services`);
    logger.info(`Connected services: ${connectedServices.join(', ')}`);
    logger.info(`Enabled modules: ${enabledModules.join(', ') || 'none'}`);
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
    healthCheck.start?.();
    serviceDiscovery.start();
    
    // Update service registry periodically
    this.discoveryTimer = setInterval(async () => {
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
        if (getGatewayPermissions(ws.principal).includes('gateway.status.read') && typeof data?.service === 'string' && this.services.has(data.service) && ws.subscriptions.length < 32 && !ws.subscriptions.includes(data.service)) {
          ws.subscriptions.push(data.service);
        }
        ws.send(JSON.stringify({ type: 'subscription', accepted: ws.subscriptions.includes(data?.service) }));
        break;

      case 'unsubscribe':
        // Unsubscribe from service updates
        if (ws.subscriptions && typeof data?.service === 'string') {
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
    const modules = configManager.getModuleConfiguration();
    res.json(Object.fromEntries(Object.entries(modules).map(([name, value]) => [name, { enabled: value.enabled, port: value.port, features: value.features }])));
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
    return req.auth ? this.frontendLimiter : this.defaultLimiter;
  }

  getApiDocs(req, res) {
    res.json({
      name: 'OpenDirectory API Gateway',
      version: '1.0.0',
      description: 'Central API Gateway for OpenDirectory services',
      endpoints: {
        public: {
          health: '/health',
          documentation: '/docs'
        },
        protected: {
          'health-detailed': '/health/detailed',
          'gateway-info': '/api/gateway/info',
          'gateway-routes': '/api/gateway/routes',
          services: '/api/services',
          'module-config': '/api/config/modules'
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
        types: ['OIDC Bearer access token'],
        'jwt-example': 'Authorization: Bearer your-jwt-token-here'
      },
      'rate-limits': {
        'all-client-ingress': '5000 requests per 15 minutes',
        'authenticated': '1000 requests per 15 minutes',
        'public': '100 requests per 15 minutes'
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
          }
        }
      },
      security: [{ BearerAuth: [] }],
      paths: {
        '/health': {
          get: {
            summary: 'Health check',
            security: [],
            responses: { '200': { description: 'Service is healthy' } }
          }
        },
        '/api/services': {
          get: {
            summary: 'List all services',
            description: 'Requires the server-issued gateway.status.read permission',
            responses: { '200': { description: 'List of services' }, '401': { description: 'Bearer access token required' }, '403': { description: 'Permission required' } }
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
      { path: '/api/services', method: 'GET', auth: 'required', permission: 'gateway.status.read' },
      { path: '/api/config/modules', method: 'GET', auth: 'required', permission: 'gateway.config.read' },
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

  async getApiKeys(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway credential metadata storage unavailable' });
    try {
      const result = await pgPool.query('SELECT id,name,permissions,created_at AS created,last_used,active FROM api_keys ORDER BY created_at DESC');
      res.json(result.rows.map(row => ({ ...row, credentialStatus: 'retired' })));
    } catch { res.status(503).json({ error: 'Gateway credential metadata storage unavailable' }); }
  }

  async createApiKey(req, res) {
    res.status(410).json({ error: 'Legacy gateway API keys are retired; use authorized OAuth application credentials', replacement: 'oauth-client-registration' });
  }

  async deleteApiKey(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway credential metadata storage unavailable' });
    try {
      const result = await pgPool.query('UPDATE api_keys SET active=false WHERE id=$1 RETURNING id', [req.params.keyId]);
      if (!result.rows.length) return res.status(404).json({ error: 'Legacy key record not found' });
      res.json({ id: req.params.keyId, active: false });
    } catch { res.status(503).json({ error: 'Gateway credential metadata storage unavailable' }); }
  }

  async getWebhooks(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway webhook storage unavailable' });
    try {
      const result = await pgPool.query('SELECT id, name, url, events, active, created_at, last_triggered, delivery_count, failure_count FROM webhooks ORDER BY created_at DESC');
      return res.json(result.rows);
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
  }

  async createWebhook(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway webhook storage unavailable' });
    if (req.body.secret) return res.status(422).json({ error: 'Signed webhook delivery is not implemented; do not submit a signing secret' });
    if (req.body.url !== undefined) {
      try {
        const target = new URL(req.body.url);
        if (target.protocol !== 'https:' || target.username || target.password || target.hash) throw new Error('Invalid URL');
      } catch { return res.status(400).json({ error: 'A credential-free HTTPS webhook URL is required' }); }
    }
    const { name, url, events } = req.body;
    if (!name || !url) return res.status(400).json({ error: 'name and url are required' });
    const crypto = require('crypto');
    try {
      const result = await pgPool.query(
        'INSERT INTO webhooks(id, name, url, events, active) VALUES($1,$2,$3,$4,true) RETURNING id, name, url, events, active, created_at, last_triggered, delivery_count, failure_count',
        [crypto.randomUUID(), name, url, events || []]
      );
      return res.status(201).json(result.rows[0]);
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
  }

  async updateWebhook(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway webhook storage unavailable' });
    if (req.body.secret) return res.status(422).json({ error: 'Signed webhook delivery is not implemented; do not submit a signing secret' });
    if (req.body.url !== undefined) {
      try {
        const target = new URL(req.body.url);
        if (target.protocol !== 'https:' || target.username || target.password || target.hash) throw new Error('Invalid URL');
      } catch { return res.status(400).json({ error: 'A credential-free HTTPS webhook URL is required' }); }
    }
    const { webhookId } = req.params;
    const { name, url, events, active } = req.body;
    try {
      const updates = [];
      const values = [];
      let index = 1;
      if (name !== undefined) { updates.push(`name=$${index++}`); values.push(name); }
      if (url !== undefined) { updates.push(`url=$${index++}`); values.push(url); }
      if (events !== undefined) { updates.push(`events=$${index++}`); values.push(events); }
      if (active !== undefined) { updates.push(`active=$${index++}`); values.push(active); }
      if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
      values.push(webhookId);
      const result = await pgPool.query(`UPDATE webhooks SET ${updates.join(',')} WHERE id=$${index} RETURNING id, name, url, events, active, created_at, last_triggered, delivery_count, failure_count`, values);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Webhook not found' });
      return res.json(result.rows[0]);
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
  }

  async deleteWebhook(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway webhook storage unavailable' });
    const { webhookId } = req.params;
    try {
      await pgPool.query('DELETE FROM webhooks WHERE id=$1', [webhookId]);
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
    res.status(204).send();
  }

  async testWebhook(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway webhook storage unavailable' });
    const { webhookId } = req.params;
    let webhook = null;
    try {
      const result = await pgPool.query('SELECT id, url FROM webhooks WHERE id=$1', [webhookId]);
      if (result.rows.length > 0) webhook = result.rows[0];
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
    if (!webhook) return res.status(404).json({ error: 'Webhook not found' });

    let target;
    try {
      target = new URL(webhook.url);
      const allowed = (process.env.GATEWAY_WEBHOOK_ALLOWED_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean);
      if (target.protocol !== 'https:' || target.username || target.password || target.hash || !allowed.includes(target.origin)) throw new Error('Not approved');
    } catch { return res.status(403).json({ error: 'Webhook destination is not approved by deployment egress policy' }); }

    const testPayload = {
      event: 'test',
      timestamp: new Date().toISOString(),
      data: { message: 'This is a test delivery from OpenDirectory API Gateway' },
    };

    let responseStatus = null;
    let success = false;
    try {
      const resp = await fetch(target, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: { 'Content-Type': 'application/json', 'X-OpenDirectory-Event': 'test', 'X-OpenDirectory-Delivery': 'unsigned-test' },
        body: JSON.stringify(testPayload),
      });
      await resp.body?.cancel();
      responseStatus = resp.status;
      success = resp.ok;
    } catch (err) {
      responseStatus = 0;
      success = false;
    }

    try {
      const result = await pgPool.query(
        'INSERT INTO webhook_deliveries(webhook_id, event_type, payload, response_status, success) VALUES($1,$2,$3,$4,$5) RETURNING id, webhook_id, event_type, response_status, delivered_at, success',
        [webhookId, 'test', testPayload, responseStatus, success]
      );
      await pgPool.query('UPDATE webhooks SET delivery_count=delivery_count+1, failure_count=failure_count+$2, last_triggered=NOW() WHERE id=$1', [webhookId, success ? 0 : 1]);
      res.json({ success, responseStatus, delivery: result.rows[0] });
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
  }

  async getWebhookDeliveries(req, res) {
    if (!apiGwDbReady) return res.status(503).json({ error: 'Gateway webhook storage unavailable' });
    const { webhookId } = req.params;
    try {
      const result = await pgPool.query(
        'SELECT id, webhook_id, event_type, response_status, delivered_at, success FROM webhook_deliveries WHERE webhook_id=$1 ORDER BY delivered_at DESC LIMIT 50',
        [webhookId]
      );
      return res.json(result.rows);
    } catch { return res.status(503).json({ error: 'Gateway webhook storage unavailable' }); }
  }

  getAvailableEndpoints() {
    return [
      '/health', '/api/services', '/api/config/modules', '/docs'
    ];
  }

  start(port = process.env.PORT || 8080) {
    connectBus();
    this.server.listen(port, () => {
      logger.info(`🚀 OpenDirectory API Gateway started on port ${port}`);
      logger.info(`📊 Health check available at: http://localhost:${port}/health`);
      logger.info(`📚 API documentation available at: http://localhost:${port}/docs`);
      logger.info(`🔌 WebSocket server available at: ws://localhost:${port}/ws`);
      logger.info(`📋 Enabled modules: ${configManager.getEnabledModules().join(', ')}`);
      logger.info('API access requires issuer-verified OIDC bearer access tokens');
    });
  }

  stop() {
    healthCheck.stop?.();
    clearInterval(this.discoveryTimer);
    this.wsServer?.clients.forEach(client => client.terminate());
    this.wsServer?.close();
    if (this.server) {
      this.server.close(() => {
        logger.info('API Gateway stopped');
      });
    }
  }
}

if (require.main === module) {
  const gateway = new APIGateway();
  gateway.start();
  const shutdown = () => {
    gateway.stop();
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}
module.exports = APIGateway;
module.exports.databaseReady = databaseReady;
module.exports.closeDatabase = () => pgPool.end();
