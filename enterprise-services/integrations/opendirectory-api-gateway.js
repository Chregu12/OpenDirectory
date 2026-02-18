/**
 * OpenDirectory API Gateway & Data Router
 * Unified API gateway with routing, transformation, caching, and monitoring
 */

const EventEmitter = require('events');
const crypto = require('crypto');

/**
 * API Gateway - Central hub for all enterprise integrations
 */
class APIGateway extends EventEmitter {
    constructor(config) {
        super();
        this.config = {
            port: config.port || 8080,
            rateLimiting: {
                enabled: true,
                defaultLimit: 1000,
                windowMs: 60000,
                ...config.rateLimiting
            },
            authentication: {
                enabled: true,
                methods: ['jwt', 'apikey', 'oauth'],
                ...config.authentication
            },
            caching: {
                enabled: true,
                defaultTTL: 300,
                maxSize: 1000,
                ...config.caching
            },
            monitoring: {
                enabled: true,
                metricsInterval: 60000,
                ...config.monitoring
            },
            ...config
        };
        
        this.router = new DataRouter(this.config.routing);
        this.rateLimiter = new RateLimiter(this.config.rateLimiting);
        this.authManager = new AuthenticationManager(this.config.authentication);
        this.cache = new ResponseCache(this.config.caching);
        this.validator = new DataValidator();
        this.transformer = new DataTransformer();
        this.monitor = new APIMonitor(this.config.monitoring);
        this.versionManager = new APIVersionManager();
        
        this.routes = new Map();
        this.middleware = [];
        this.connectors = new Map();
        
        this.setupDefaultRoutes();
        this.setupDefaultMiddleware();
    }

    async start() {
        try {
            await this.router.initialize();
            await this.monitor.start();
            
            this.emit('gateway:started', { 
                port: this.config.port,
                timestamp: new Date().toISOString()
            });
            
            console.log(`API Gateway started on port ${this.config.port}`);
            return true;
        } catch (error) {
            this.emit('gateway:error', { error, phase: 'startup' });
            throw error;
        }
    }

    async stop() {
        await this.monitor.stop();
        this.emit('gateway:stopped', { timestamp: new Date().toISOString() });
        console.log('API Gateway stopped');
    }

    registerConnector(name, connector) {
        this.connectors.set(name, connector);
        this.setupConnectorRoutes(name, connector);
        console.log(`Registered connector: ${name}`);
    }

    setupConnectorRoutes(connectorName, connector) {
        // Dynamic route generation for each connector
        const routes = [
            {
                path: `/api/v1/${connectorName}/sync`,
                method: 'POST',
                handler: async (req, res) => {
                    return await this.handleConnectorOperation(connectorName, 'sync', req.body, req);
                }
            },
            {
                path: `/api/v1/${connectorName}/query`,
                method: 'GET',
                handler: async (req, res) => {
                    return await this.handleConnectorOperation(connectorName, 'query', req.query, req);
                }
            },
            {
                path: `/api/v1/${connectorName}/health`,
                method: 'GET',
                handler: async (req, res) => {
                    return await this.handleConnectorOperation(connectorName, 'health', {}, req);
                }
            }
        ];
        
        routes.forEach(route => this.registerRoute(route));
    }

    registerRoute(routeConfig) {
        const routeKey = `${routeConfig.method}:${routeConfig.path}`;
        this.routes.set(routeKey, routeConfig);
    }

    async handleRequest(method, path, headers, body, query) {
        const startTime = Date.now();
        const requestId = this.generateRequestId();
        
        try {
            // Apply middleware
            const context = {
                requestId,
                method,
                path,
                headers,
                body,
                query,
                startTime,
                user: null,
                rateLimitInfo: null
            };
            
            await this.applyMiddleware(context);
            
            // Route request
            const response = await this.routeRequest(context);
            
            // Log metrics
            const duration = Date.now() - startTime;
            this.monitor.recordRequest({
                requestId,
                method,
                path,
                duration,
                status: 'success',
                user: context.user?.id
            });
            
            return {
                status: 200,
                headers: {
                    'X-Request-ID': requestId,
                    'X-Response-Time': `${duration}ms`,
                    'Content-Type': 'application/json'
                },
                body: response
            };
            
        } catch (error) {
            const duration = Date.now() - startTime;
            this.monitor.recordRequest({
                requestId,
                method,
                path,
                duration,
                status: 'error',
                error: error.message
            });
            
            this.emit('gateway:request:error', {
                requestId,
                method,
                path,
                error: error.message,
                duration
            });
            
            return {
                status: error.statusCode || 500,
                headers: {
                    'X-Request-ID': requestId,
                    'Content-Type': 'application/json'
                },
                body: {
                    error: error.message,
                    requestId,
                    timestamp: new Date().toISOString()
                }
            };
        }
    }

    async applyMiddleware(context) {
        for (const middleware of this.middleware) {
            await middleware(context);
        }
    }

    async routeRequest(context) {
        const routeKey = `${context.method}:${context.path}`;
        const route = this.routes.get(routeKey);
        
        if (!route) {
            // Try pattern matching for dynamic routes
            const matchedRoute = this.findMatchingRoute(context.method, context.path);
            if (matchedRoute) {
                context.pathParams = this.extractPathParams(matchedRoute.path, context.path);
                return await matchedRoute.handler(context);
            }
            
            throw new APIError('Route not found', 404);
        }
        
        return await route.handler(context);
    }

    findMatchingRoute(method, path) {
        for (const [routeKey, route] of this.routes) {
            const [routeMethod, routePath] = routeKey.split(':');
            if (routeMethod === method && this.matchesPattern(routePath, path)) {
                return route;
            }
        }
        return null;
    }

    matchesPattern(pattern, path) {
        const patternParts = pattern.split('/');
        const pathParts = path.split('/');
        
        if (patternParts.length !== pathParts.length) return false;
        
        return patternParts.every((part, index) => {
            return part.startsWith(':') || part === pathParts[index];
        });
    }

    extractPathParams(pattern, path) {
        const patternParts = pattern.split('/');
        const pathParts = path.split('/');
        const params = {};
        
        patternParts.forEach((part, index) => {
            if (part.startsWith(':')) {
                const paramName = part.substring(1);
                params[paramName] = pathParts[index];
            }
        });
        
        return params;
    }

    async handleConnectorOperation(connectorName, operation, data, context) {
        const connector = this.connectors.get(connectorName);
        if (!connector) {
            throw new APIError(`Connector not found: ${connectorName}`, 404);
        }
        
        // Check cache first
        if (operation === 'query' || operation === 'health') {
            const cacheKey = this.cache.generateKey(connectorName, operation, data);
            const cachedResponse = await this.cache.get(cacheKey);
            if (cachedResponse) {
                return cachedResponse;
            }
        }
        
        // Execute operation
        const result = await connector.executeOperation(operation, data);
        
        // Cache response if applicable
        if (operation === 'query' || operation === 'health') {
            const cacheKey = this.cache.generateKey(connectorName, operation, data);
            await this.cache.set(cacheKey, result);
        }
        
        return result;
    }

    setupDefaultRoutes() {
        // Health check endpoint
        this.registerRoute({
            path: '/health',
            method: 'GET',
            handler: async (context) => {
                return {
                    status: 'healthy',
                    timestamp: new Date().toISOString(),
                    version: this.config.version || '1.0.0',
                    uptime: process.uptime(),
                    connectors: Array.from(this.connectors.keys())
                };
            }
        });
        
        // Metrics endpoint
        this.registerRoute({
            path: '/metrics',
            method: 'GET',
            handler: async (context) => {
                return await this.monitor.getMetrics();
            }
        });
        
        // Connectors status endpoint
        this.registerRoute({
            path: '/api/v1/connectors/status',
            method: 'GET',
            handler: async (context) => {
                const status = {};
                for (const [name, connector] of this.connectors) {
                    status[name] = connector.getHealthStatus();
                }
                return status;
            }
        });
        
        // Data transformation endpoint
        this.registerRoute({
            path: '/api/v1/transform',
            method: 'POST',
            handler: async (context) => {
                const { sourceFormat, targetFormat, data, mapping } = context.body;
                return await this.transformer.transform(data, sourceFormat, targetFormat, mapping);
            }
        });
    }

    setupDefaultMiddleware() {
        // Authentication middleware
        this.middleware.push(async (context) => {
            if (this.config.authentication.enabled && !this.isPublicRoute(context.path)) {
                context.user = await this.authManager.authenticate(context.headers);
            }
        });
        
        // Rate limiting middleware
        this.middleware.push(async (context) => {
            if (this.config.rateLimiting.enabled) {
                const identifier = context.user?.id || context.headers['x-forwarded-for'] || 'anonymous';
                const rateLimitResult = await this.rateLimiter.checkLimit(identifier);
                
                if (!rateLimitResult.allowed) {
                    throw new APIError('Rate limit exceeded', 429, {
                        retryAfter: rateLimitResult.resetTime
                    });
                }
                
                context.rateLimitInfo = rateLimitResult;
            }
        });
        
        // Request validation middleware
        this.middleware.push(async (context) => {
            if (context.method === 'POST' || context.method === 'PUT') {
                await this.validator.validateRequest(context.body, context.path);
            }
        });
        
        // Logging middleware
        this.middleware.push(async (context) => {
            console.log(`${context.method} ${context.path} - ${context.requestId} - ${context.user?.id || 'anonymous'}`);
        });
    }

    isPublicRoute(path) {
        const publicRoutes = ['/health', '/api/docs', '/api/v1/auth/login'];
        return publicRoutes.some(route => path.startsWith(route));
    }

    generateRequestId() {
        return crypto.randomUUID();
    }

    getStats() {
        return {
            uptime: process.uptime(),
            totalRoutes: this.routes.size,
            connectors: this.connectors.size,
            middleware: this.middleware.length,
            cacheStats: this.cache.getStats(),
            rateLimitStats: this.rateLimiter.getStats(),
            monitoringStats: this.monitor.getStats()
        };
    }
}

/**
 * Data Router - Handles request routing and transformation
 */
class DataRouter {
    constructor(config) {
        this.config = config || {};
        this.routingRules = new Map();
        this.loadBalancers = new Map();
        this.circuitBreakers = new Map();
    }

    async initialize() {
        // Initialize routing rules and load balancers
        console.log('Data Router initialized');
    }

    addRoutingRule(pattern, targets, options = {}) {
        this.routingRules.set(pattern, {
            targets,
            strategy: options.strategy || 'round-robin',
            healthCheck: options.healthCheck || false,
            timeout: options.timeout || 30000,
            retries: options.retries || 3
        });
        
        if (targets.length > 1) {
            this.loadBalancers.set(pattern, new LoadBalancer(targets, options.strategy));
        }
    }

    async route(request) {
        const rule = this.findMatchingRule(request.path);
        if (!rule) {
            throw new Error('No routing rule found for path: ' + request.path);
        }
        
        let target;
        if (this.loadBalancers.has(rule.pattern)) {
            target = await this.loadBalancers.get(rule.pattern).getNextTarget();
        } else {
            target = rule.targets[0];
        }
        
        const circuitBreaker = this.getCircuitBreaker(target);
        
        return await circuitBreaker.execute(async () => {
            return await this.forwardRequest(request, target, rule);
        });
    }

    findMatchingRule(path) {
        for (const [pattern, rule] of this.routingRules) {
            if (this.matchesPattern(pattern, path)) {
                return { pattern, ...rule };
            }
        }
        return null;
    }

    matchesPattern(pattern, path) {
        // Simple pattern matching - can be enhanced with regex
        return path.startsWith(pattern) || pattern === '*';
    }

    async forwardRequest(request, target, rule) {
        // Simulate request forwarding
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
        
        return {
            target,
            response: { status: 'forwarded', timestamp: new Date().toISOString() },
            latency: Math.random() * 100
        };
    }

    getCircuitBreaker(target) {
        if (!this.circuitBreakers.has(target)) {
            this.circuitBreakers.set(target, new CircuitBreaker(target, {
                failureThreshold: 5,
                timeout: 60000,
                monitoringPeriod: 10000
            }));
        }
        return this.circuitBreakers.get(target);
    }
}

/**
 * Rate Limiter - Advanced rate limiting with multiple strategies
 */
class RateLimiter {
    constructor(config) {
        this.config = config;
        this.limits = new Map();
        this.buckets = new Map();
        this.slidingWindows = new Map();
    }

    async checkLimit(identifier, limit = null, window = null) {
        const effectiveLimit = limit || this.config.defaultLimit;
        const effectiveWindow = window || this.config.windowMs;
        
        const key = `${identifier}:${effectiveLimit}:${effectiveWindow}`;
        
        switch (this.config.strategy || 'token-bucket') {
            case 'token-bucket':
                return this.checkTokenBucket(key, effectiveLimit, effectiveWindow);
            case 'sliding-window':
                return this.checkSlidingWindow(key, effectiveLimit, effectiveWindow);
            case 'fixed-window':
                return this.checkFixedWindow(key, effectiveLimit, effectiveWindow);
            default:
                return this.checkTokenBucket(key, effectiveLimit, effectiveWindow);
        }
    }

    checkTokenBucket(key, limit, window) {
        const now = Date.now();
        let bucket = this.buckets.get(key);
        
        if (!bucket) {
            bucket = {
                tokens: limit,
                lastRefill: now,
                limit,
                refillRate: limit / window
            };
            this.buckets.set(key, bucket);
        }
        
        // Refill tokens based on time elapsed
        const timePassed = now - bucket.lastRefill;
        const tokensToAdd = Math.floor(timePassed * bucket.refillRate);
        bucket.tokens = Math.min(bucket.limit, bucket.tokens + tokensToAdd);
        bucket.lastRefill = now;
        
        if (bucket.tokens >= 1) {
            bucket.tokens--;
            return {
                allowed: true,
                remaining: bucket.tokens,
                resetTime: null
            };
        }
        
        return {
            allowed: false,
            remaining: 0,
            resetTime: Math.ceil((1 / bucket.refillRate) - (timePassed % (1 / bucket.refillRate)))
        };
    }

    checkSlidingWindow(key, limit, window) {
        const now = Date.now();
        let windowData = this.slidingWindows.get(key);
        
        if (!windowData) {
            windowData = { requests: [], limit, window };
            this.slidingWindows.set(key, windowData);
        }
        
        // Remove old requests outside the window
        windowData.requests = windowData.requests.filter(
            requestTime => now - requestTime < window
        );
        
        if (windowData.requests.length < limit) {
            windowData.requests.push(now);
            return {
                allowed: true,
                remaining: limit - windowData.requests.length,
                resetTime: windowData.requests.length > 0 ? 
                    window - (now - windowData.requests[0]) : null
            };
        }
        
        const oldestRequest = Math.min(...windowData.requests);
        return {
            allowed: false,
            remaining: 0,
            resetTime: window - (now - oldestRequest)
        };
    }

    checkFixedWindow(key, limit, window) {
        const now = Date.now();
        const windowStart = Math.floor(now / window) * window;
        const windowKey = `${key}:${windowStart}`;
        
        let windowCount = this.limits.get(windowKey) || 0;
        
        if (windowCount < limit) {
            this.limits.set(windowKey, windowCount + 1);
            
            // Clean up old windows
            setTimeout(() => this.limits.delete(windowKey), window * 2);
            
            return {
                allowed: true,
                remaining: limit - windowCount - 1,
                resetTime: window - (now - windowStart)
            };
        }
        
        return {
            allowed: false,
            remaining: 0,
            resetTime: window - (now - windowStart)
        };
    }

    getStats() {
        return {
            bucketsCount: this.buckets.size,
            windowsCount: this.slidingWindows.size,
            limitsCount: this.limits.size,
            strategy: this.config.strategy || 'token-bucket'
        };
    }
}

/**
 * Authentication Manager - Multi-method authentication
 */
class AuthenticationManager {
    constructor(config) {
        this.config = config;
        this.authMethods = new Map();
        this.tokens = new Map();
        this.sessions = new Map();
        
        this.setupAuthMethods();
    }

    setupAuthMethods() {
        if (this.config.methods.includes('jwt')) {
            this.authMethods.set('jwt', this.authenticateJWT.bind(this));
        }
        
        if (this.config.methods.includes('apikey')) {
            this.authMethods.set('apikey', this.authenticateAPIKey.bind(this));
        }
        
        if (this.config.methods.includes('oauth')) {
            this.authMethods.set('oauth', this.authenticateOAuth.bind(this));
        }
        
        if (this.config.methods.includes('basic')) {
            this.authMethods.set('basic', this.authenticateBasic.bind(this));
        }
    }

    async authenticate(headers) {
        const authHeader = headers.authorization || headers.Authorization;
        const apiKey = headers['x-api-key'] || headers['X-API-Key'];
        
        if (authHeader) {
            const [type, credential] = authHeader.split(' ');
            
            switch (type.toLowerCase()) {
                case 'bearer':
                    return await this.authenticateBearer(credential);
                case 'basic':
                    return await this.authenticateBasic(credential);
                default:
                    throw new APIError('Unsupported authentication type', 401);
            }
        }
        
        if (apiKey) {
            return await this.authenticateAPIKey(apiKey);
        }
        
        throw new APIError('No authentication provided', 401);
    }

    async authenticateBearer(token) {
        // Try JWT first
        if (this.authMethods.has('jwt')) {
            try {
                return await this.authenticateJWT(token);
            } catch (error) {
                // Fall through to OAuth
            }
        }
        
        // Try OAuth
        if (this.authMethods.has('oauth')) {
            return await this.authenticateOAuth(token);
        }
        
        throw new APIError('Invalid bearer token', 401);
    }

    async authenticateJWT(token) {
        // Simplified JWT validation - in production use proper JWT library
        const payload = this.decodeJWT(token);
        
        if (payload.exp && payload.exp < Date.now() / 1000) {
            throw new APIError('Token expired', 401);
        }
        
        return {
            id: payload.sub || payload.userId,
            username: payload.username,
            roles: payload.roles || [],
            permissions: payload.permissions || [],
            method: 'jwt'
        };
    }

    async authenticateAPIKey(apiKey) {
        // In production, verify against database
        const validKeys = this.config.apiKeys || [];
        const keyInfo = validKeys.find(key => key.key === apiKey);
        
        if (!keyInfo) {
            throw new APIError('Invalid API key', 401);
        }
        
        if (keyInfo.expires && keyInfo.expires < Date.now()) {
            throw new APIError('API key expired', 401);
        }
        
        return {
            id: keyInfo.userId,
            username: keyInfo.name,
            roles: keyInfo.roles || [],
            permissions: keyInfo.permissions || [],
            method: 'apikey'
        };
    }

    async authenticateOAuth(token) {
        // Simulate OAuth token validation
        await new Promise(resolve => setTimeout(resolve, 100));
        
        if (token.startsWith('oauth_')) {
            return {
                id: token.split('_')[1],
                username: 'oauth_user',
                roles: ['user'],
                permissions: ['read'],
                method: 'oauth'
            };
        }
        
        throw new APIError('Invalid OAuth token', 401);
    }

    async authenticateBasic(credentials) {
        const decoded = Buffer.from(credentials, 'base64').toString('utf-8');
        const [username, password] = decoded.split(':');
        
        // In production, verify against user database
        if (username === 'admin' && password === 'password') {
            return {
                id: 'admin',
                username: 'admin',
                roles: ['admin'],
                permissions: ['*'],
                method: 'basic'
            };
        }
        
        throw new APIError('Invalid credentials', 401);
    }

    decodeJWT(token) {
        // Simplified JWT decoding - use proper library in production
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new APIError('Invalid JWT format', 401);
        }
        
        const payload = Buffer.from(parts[1], 'base64').toString('utf-8');
        return JSON.parse(payload);
    }
}

/**
 * Response Cache - Intelligent caching with TTL and invalidation
 */
class ResponseCache {
    constructor(config) {
        this.config = config;
        this.cache = new Map();
        this.ttlTimers = new Map();
        this.stats = {
            hits: 0,
            misses: 0,
            sets: 0,
            deletes: 0
        };
    }

    generateKey(connector, operation, data) {
        const keyData = {
            connector,
            operation,
            dataHash: this.hashObject(data)
        };
        return crypto.createHash('md5').update(JSON.stringify(keyData)).digest('hex');
    }

    async get(key) {
        if (this.cache.has(key)) {
            const entry = this.cache.get(key);
            if (entry.expires > Date.now()) {
                this.stats.hits++;
                return entry.data;
            } else {
                this.delete(key);
            }
        }
        
        this.stats.misses++;
        return null;
    }

    async set(key, data, ttl = null) {
        const effectiveTTL = ttl || this.config.defaultTTL * 1000;
        const expires = Date.now() + effectiveTTL;
        
        // Check cache size limit
        if (this.cache.size >= this.config.maxSize) {
            this.evictOldest();
        }
        
        this.cache.set(key, {
            data,
            expires,
            created: Date.now()
        });
        
        // Set TTL timer
        const timer = setTimeout(() => {
            this.delete(key);
        }, effectiveTTL);
        
        this.ttlTimers.set(key, timer);
        this.stats.sets++;
    }

    delete(key) {
        if (this.cache.has(key)) {
            this.cache.delete(key);
            this.stats.deletes++;
        }
        
        if (this.ttlTimers.has(key)) {
            clearTimeout(this.ttlTimers.get(key));
            this.ttlTimers.delete(key);
        }
    }

    evictOldest() {
        let oldestKey = null;
        let oldestTime = Date.now();
        
        for (const [key, entry] of this.cache) {
            if (entry.created < oldestTime) {
                oldestTime = entry.created;
                oldestKey = key;
            }
        }
        
        if (oldestKey) {
            this.delete(oldestKey);
        }
    }

    invalidatePattern(pattern) {
        const keysToDelete = [];
        
        for (const key of this.cache.keys()) {
            if (key.includes(pattern)) {
                keysToDelete.push(key);
            }
        }
        
        keysToDelete.forEach(key => this.delete(key));
    }

    hashObject(obj) {
        const str = JSON.stringify(obj, Object.keys(obj).sort());
        return crypto.createHash('md5').update(str).digest('hex');
    }

    getStats() {
        return {
            ...this.stats,
            size: this.cache.size,
            hitRate: this.stats.hits / (this.stats.hits + this.stats.misses) || 0
        };
    }
}

/**
 * Data Validator - Request and response validation
 */
class DataValidator {
    constructor() {
        this.schemas = new Map();
    }

    registerSchema(path, schema) {
        this.schemas.set(path, schema);
    }

    async validateRequest(data, path) {
        const schema = this.schemas.get(path);
        if (!schema) return true;
        
        return this.validate(data, schema);
    }

    validate(data, schema) {
        if (schema.required) {
            for (const field of schema.required) {
                if (!data.hasOwnProperty(field)) {
                    throw new APIError(`Missing required field: ${field}`, 400);
                }
            }
        }
        
        if (schema.properties) {
            for (const [field, fieldSchema] of Object.entries(schema.properties)) {
                if (data.hasOwnProperty(field)) {
                    this.validateField(data[field], fieldSchema, field);
                }
            }
        }
        
        return true;
    }

    validateField(value, schema, fieldName) {
        if (schema.type && typeof value !== schema.type) {
            throw new APIError(`Invalid type for field ${fieldName}: expected ${schema.type}`, 400);
        }
        
        if (schema.minLength && value.length < schema.minLength) {
            throw new APIError(`Field ${fieldName} is too short`, 400);
        }
        
        if (schema.maxLength && value.length > schema.maxLength) {
            throw new APIError(`Field ${fieldName} is too long`, 400);
        }
        
        if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
            throw new APIError(`Field ${fieldName} does not match pattern`, 400);
        }
    }
}

/**
 * Data Transformer - Format transformation and mapping
 */
class DataTransformer {
    constructor() {
        this.transformations = new Map();
        this.mappings = new Map();
    }

    registerTransformation(name, transformer) {
        this.transformations.set(name, transformer);
    }

    registerMapping(name, mapping) {
        this.mappings.set(name, mapping);
    }

    async transform(data, sourceFormat, targetFormat, mapping = null) {
        let transformedData = data;
        
        // Apply mapping if provided
        if (mapping) {
            transformedData = this.applyMapping(transformedData, mapping);
        }
        
        // Apply format transformation
        const transformationKey = `${sourceFormat}_to_${targetFormat}`;
        if (this.transformations.has(transformationKey)) {
            const transformer = this.transformations.get(transformationKey);
            transformedData = await transformer(transformedData);
        }
        
        return transformedData;
    }

    applyMapping(data, mapping) {
        const mapped = {};
        
        for (const [sourceField, targetField] of Object.entries(mapping)) {
            if (data.hasOwnProperty(sourceField)) {
                mapped[targetField] = data[sourceField];
            }
        }
        
        return mapped;
    }
}

/**
 * API Monitor - Comprehensive monitoring and analytics
 */
class APIMonitor {
    constructor(config) {
        this.config = config;
        this.metrics = {
            requests: {
                total: 0,
                success: 0,
                error: 0,
                avgResponseTime: 0
            },
            endpoints: new Map(),
            users: new Map(),
            errors: []
        };
        
        this.isRunning = false;
        this.intervalId = null;
    }

    async start() {
        this.isRunning = true;
        
        if (this.config.metricsInterval) {
            this.intervalId = setInterval(() => {
                this.generateReport();
            }, this.config.metricsInterval);
        }
        
        console.log('API Monitor started');
    }

    async stop() {
        this.isRunning = false;
        
        if (this.intervalId) {
            clearInterval(this.intervalId);
        }
        
        console.log('API Monitor stopped');
    }

    recordRequest(requestInfo) {
        // Update global metrics
        this.metrics.requests.total++;
        
        if (requestInfo.status === 'success') {
            this.metrics.requests.success++;
        } else {
            this.metrics.requests.error++;
            this.metrics.errors.push({
                timestamp: Date.now(),
                error: requestInfo.error,
                path: requestInfo.path,
                method: requestInfo.method
            });
            
            // Keep only last 100 errors
            if (this.metrics.errors.length > 100) {
                this.metrics.errors = this.metrics.errors.slice(-100);
            }
        }
        
        // Update average response time
        const totalTime = this.metrics.requests.avgResponseTime * (this.metrics.requests.total - 1);
        this.metrics.requests.avgResponseTime = (totalTime + requestInfo.duration) / this.metrics.requests.total;
        
        // Update endpoint metrics
        const endpointKey = `${requestInfo.method} ${requestInfo.path}`;
        if (!this.metrics.endpoints.has(endpointKey)) {
            this.metrics.endpoints.set(endpointKey, {
                requests: 0,
                success: 0,
                error: 0,
                avgResponseTime: 0
            });
        }
        
        const endpoint = this.metrics.endpoints.get(endpointKey);
        endpoint.requests++;
        
        if (requestInfo.status === 'success') {
            endpoint.success++;
        } else {
            endpoint.error++;
        }
        
        const endpointTotalTime = endpoint.avgResponseTime * (endpoint.requests - 1);
        endpoint.avgResponseTime = (endpointTotalTime + requestInfo.duration) / endpoint.requests;
        
        // Update user metrics
        if (requestInfo.user) {
            if (!this.metrics.users.has(requestInfo.user)) {
                this.metrics.users.set(requestInfo.user, {
                    requests: 0,
                    lastActivity: Date.now()
                });
            }
            
            const user = this.metrics.users.get(requestInfo.user);
            user.requests++;
            user.lastActivity = Date.now();
        }
    }

    async getMetrics() {
        return {
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            requests: this.metrics.requests,
            endpoints: Object.fromEntries(this.metrics.endpoints),
            users: Object.fromEntries(this.metrics.users),
            recentErrors: this.metrics.errors.slice(-10),
            memory: process.memoryUsage(),
            system: {
                platform: process.platform,
                nodeVersion: process.version,
                pid: process.pid
            }
        };
    }

    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            summary: {
                totalRequests: this.metrics.requests.total,
                successRate: (this.metrics.requests.success / this.metrics.requests.total * 100).toFixed(2) + '%',
                errorRate: (this.metrics.requests.error / this.metrics.requests.total * 100).toFixed(2) + '%',
                avgResponseTime: Math.round(this.metrics.requests.avgResponseTime) + 'ms'
            },
            topEndpoints: this.getTopEndpoints(),
            activeUsers: this.metrics.users.size,
            recentErrors: this.metrics.errors.slice(-5).length
        };
        
        console.log('=== API Gateway Report ===');
        console.log(JSON.stringify(report, null, 2));
    }

    getTopEndpoints(limit = 5) {
        return Array.from(this.metrics.endpoints.entries())
            .sort(([,a], [,b]) => b.requests - a.requests)
            .slice(0, limit)
            .map(([endpoint, stats]) => ({
                endpoint,
                requests: stats.requests,
                avgResponseTime: Math.round(stats.avgResponseTime) + 'ms'
            }));
    }

    getStats() {
        return {
            isRunning: this.isRunning,
            totalRequests: this.metrics.requests.total,
            endpoints: this.metrics.endpoints.size,
            users: this.metrics.users.size,
            errors: this.metrics.errors.length
        };
    }
}

/**
 * API Version Manager - Handles API versioning
 */
class APIVersionManager {
    constructor() {
        this.versions = new Map();
        this.currentVersion = '1.0.0';
    }

    addVersion(version, routes) {
        this.versions.set(version, routes);
    }

    getVersionedRoute(version, path) {
        const versionRoutes = this.versions.get(version);
        return versionRoutes ? versionRoutes.get(path) : null;
    }

    extractVersion(path) {
        const versionMatch = path.match(/^\/api\/v(\d+(?:\.\d+)*)/);
        return versionMatch ? versionMatch[1] : this.currentVersion;
    }
}

/**
 * Load Balancer - Distributes requests across multiple targets
 */
class LoadBalancer {
    constructor(targets, strategy = 'round-robin') {
        this.targets = targets.map(target => ({
            ...target,
            healthy: true,
            connections: 0,
            responseTime: 0
        }));
        this.strategy = strategy;
        this.currentIndex = 0;
    }

    async getNextTarget() {
        const healthyTargets = this.targets.filter(target => target.healthy);
        
        if (healthyTargets.length === 0) {
            throw new Error('No healthy targets available');
        }
        
        switch (this.strategy) {
            case 'round-robin':
                return this.getRoundRobinTarget(healthyTargets);
            case 'least-connections':
                return this.getLeastConnectionsTarget(healthyTargets);
            case 'fastest-response':
                return this.getFastestResponseTarget(healthyTargets);
            default:
                return this.getRoundRobinTarget(healthyTargets);
        }
    }

    getRoundRobinTarget(targets) {
        const target = targets[this.currentIndex % targets.length];
        this.currentIndex++;
        return target;
    }

    getLeastConnectionsTarget(targets) {
        return targets.reduce((least, current) => 
            current.connections < least.connections ? current : least
        );
    }

    getFastestResponseTarget(targets) {
        return targets.reduce((fastest, current) => 
            current.responseTime < fastest.responseTime ? current : fastest
        );
    }

    updateTargetHealth(target, healthy) {
        const targetIndex = this.targets.findIndex(t => t.url === target.url);
        if (targetIndex !== -1) {
            this.targets[targetIndex].healthy = healthy;
        }
    }

    updateTargetStats(target, stats) {
        const targetIndex = this.targets.findIndex(t => t.url === target.url);
        if (targetIndex !== -1) {
            Object.assign(this.targets[targetIndex], stats);
        }
    }
}

/**
 * Circuit Breaker - Prevents cascading failures
 */
class CircuitBreaker {
    constructor(name, options = {}) {
        this.name = name;
        this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
        this.failureCount = 0;
        this.successCount = 0;
        this.lastFailureTime = null;
        this.nextAttempt = Date.now();
        
        this.options = {
            failureThreshold: options.failureThreshold || 5,
            timeout: options.timeout || 60000,
            monitoringPeriod: options.monitoringPeriod || 10000,
            ...options
        };
        
        this.resetTimeout = null;
    }

    async execute(operation) {
        if (this.state === 'OPEN') {
            if (Date.now() < this.nextAttempt) {
                throw new Error(`Circuit breaker ${this.name} is OPEN`);
            }
            this.state = 'HALF_OPEN';
        }
        
        try {
            const result = await operation();
            this.onSuccess();
            return result;
        } catch (error) {
            this.onFailure();
            throw error;
        }
    }

    onSuccess() {
        this.failureCount = 0;
        
        if (this.state === 'HALF_OPEN') {
            this.state = 'CLOSED';
            this.clearResetTimeout();
        }
    }

    onFailure() {
        this.failureCount++;
        this.lastFailureTime = Date.now();
        
        if (this.failureCount >= this.options.failureThreshold) {
            this.state = 'OPEN';
            this.nextAttempt = Date.now() + this.options.timeout;
            this.scheduleReset();
        }
    }

    scheduleReset() {
        this.clearResetTimeout();
        
        this.resetTimeout = setTimeout(() => {
            this.state = 'HALF_OPEN';
        }, this.options.timeout);
    }

    clearResetTimeout() {
        if (this.resetTimeout) {
            clearTimeout(this.resetTimeout);
            this.resetTimeout = null;
        }
    }

    getState() {
        return {
            name: this.name,
            state: this.state,
            failureCount: this.failureCount,
            successCount: this.successCount,
            lastFailureTime: this.lastFailureTime,
            nextAttempt: this.nextAttempt
        };
    }
}

/**
 * API Error - Custom error class for API responses
 */
class APIError extends Error {
    constructor(message, statusCode = 500, details = {}) {
        super(message);
        this.name = 'APIError';
        this.statusCode = statusCode;
        this.details = details;
        this.timestamp = new Date().toISOString();
    }

    toJSON() {
        return {
            error: this.message,
            statusCode: this.statusCode,
            details: this.details,
            timestamp: this.timestamp
        };
    }
}

module.exports = {
    APIGateway,
    DataRouter,
    RateLimiter,
    AuthenticationManager,
    ResponseCache,
    DataValidator,
    DataTransformer,
    APIMonitor,
    APIVersionManager,
    LoadBalancer,
    CircuitBreaker,
    APIError
};