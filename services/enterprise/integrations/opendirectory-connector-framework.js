/**
 * OpenDirectory Enterprise Connector Framework
 * Comprehensive enterprise integration foundation for OpenDirectory MDM
 */

const EventEmitter = require('events');
const crypto = require('crypto');

/**
 * Base Connector Class - Foundation for all enterprise connectors
 */
class BaseConnector extends EventEmitter {
    constructor(config) {
        super();
        this.config = {
            name: 'base-connector',
            retryAttempts: 3,
            retryDelay: 1000,
            timeout: 30000,
            rateLimit: { requests: 100, window: 60000 },
            healthCheckInterval: 30000,
            ...config
        };
        
        this.isConnected = false;
        this.connectionPool = new Map();
        this.rateLimiter = new RateLimiter(this.config.rateLimit);
        this.healthMonitor = new HealthMonitor(this);
        this.authManager = new AuthenticationManager(this.config.auth);
        this.dataTransformer = new DataTransformationEngine();
        this.errorHandler = new ErrorHandler(this.config.retryAttempts, this.config.retryDelay);
        
        this.initializeConnector();
    }

    async initializeConnector() {
        try {
            await this.validateConfiguration();
            await this.authenticate();
            this.startHealthMonitoring();
            this.emit('connector:initialized', { name: this.config.name });
        } catch (error) {
            this.emit('connector:error', { error, phase: 'initialization' });
        }
    }

    async validateConfiguration() {
        const required = ['name', 'endpoint', 'auth'];
        for (const field of required) {
            if (!this.config[field]) {
                throw new Error(`Missing required configuration: ${field}`);
            }
        }
    }

    async authenticate() {
        return await this.authManager.authenticate();
    }

    async connect() {
        if (this.isConnected) return true;
        
        try {
            await this.establishConnection();
            this.isConnected = true;
            this.emit('connector:connected', { name: this.config.name });
            return true;
        } catch (error) {
            this.emit('connector:error', { error, phase: 'connection' });
            throw error;
        }
    }

    async disconnect() {
        if (!this.isConnected) return true;
        
        try {
            await this.closeConnections();
            this.isConnected = false;
            this.healthMonitor.stop();
            this.emit('connector:disconnected', { name: this.config.name });
            return true;
        } catch (error) {
            this.emit('connector:error', { error, phase: 'disconnection' });
            throw error;
        }
    }

    async executeOperation(operation, data, options = {}) {
        if (!this.rateLimiter.canProceed()) {
            throw new Error('Rate limit exceeded');
        }

        return await this.errorHandler.executeWithRetry(async () => {
            const transformedData = await this.dataTransformer.transform(data, operation);
            const result = await this.performOperation(operation, transformedData, options);
            return await this.dataTransformer.transformResponse(result, operation);
        });
    }

    async performOperation(operation, data, options) {
        throw new Error('performOperation must be implemented by subclass');
    }

    async establishConnection() {
        throw new Error('establishConnection must be implemented by subclass');
    }

    async closeConnections() {
        this.connectionPool.clear();
    }

    startHealthMonitoring() {
        this.healthMonitor.start();
    }

    getHealthStatus() {
        return {
            name: this.config.name,
            connected: this.isConnected,
            lastHealthCheck: this.healthMonitor.lastCheck,
            connectionPoolSize: this.connectionPool.size,
            rateLimitStatus: this.rateLimiter.getStatus(),
            authStatus: this.authManager.getStatus()
        };
    }
}

/**
 * Authentication Manager - Handles multiple authentication methods
 */
class AuthenticationManager {
    constructor(config) {
        this.config = config;
        this.tokens = new Map();
        this.refreshTimers = new Map();
    }

    async authenticate() {
        switch (this.config.type) {
            case 'oauth2':
                return await this.authenticateOAuth2();
            case 'bearer':
                return await this.authenticateBearer();
            case 'basic':
                return await this.authenticateBasic();
            case 'certificate':
                return await this.authenticateCertificate();
            case 'saml':
                return await this.authenticateSAML();
            default:
                throw new Error(`Unsupported authentication type: ${this.config.type}`);
        }
    }

    async authenticateOAuth2() {
        const tokenResponse = await this.requestOAuth2Token();
        const token = tokenResponse.access_token;
        const expiresIn = tokenResponse.expires_in * 1000;
        
        this.tokens.set('access_token', token);
        this.scheduleTokenRefresh(expiresIn * 0.8); // Refresh at 80% of expiration
        
        return { type: 'Bearer', token };
    }

    async authenticateBearer() {
        const token = this.config.token;
        this.tokens.set('bearer_token', token);
        return { type: 'Bearer', token };
    }

    async authenticateBasic() {
        const credentials = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
        return { type: 'Basic', token: credentials };
    }

    async authenticateCertificate() {
        return {
            type: 'Certificate',
            cert: this.config.cert,
            key: this.config.key,
            ca: this.config.ca
        };
    }

    async authenticateSAML() {
        const samlResponse = await this.processSAMLAuthentication();
        return { type: 'SAML', token: samlResponse.token };
    }

    async requestOAuth2Token() {
        // Implementation for OAuth2 token request
        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'client_credentials',
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                scope: this.config.scope
            })
        });
        
        if (!response.ok) {
            throw new Error(`OAuth2 authentication failed: ${response.statusText}`);
        }
        
        return await response.json();
    }

    scheduleTokenRefresh(delay) {
        const timer = setTimeout(async () => {
            try {
                await this.authenticate();
            } catch (error) {
                console.error('Token refresh failed:', error);
            }
        }, delay);
        
        this.refreshTimers.set('access_token', timer);
    }

    getAuthHeaders() {
        const auth = this.tokens.get('access_token') || this.tokens.get('bearer_token');
        if (auth) {
            return { 'Authorization': `Bearer ${auth}` };
        }
        return {};
    }

    getStatus() {
        return {
            type: this.config.type,
            authenticated: this.tokens.size > 0,
            tokenCount: this.tokens.size,
            hasRefreshTimer: this.refreshTimers.size > 0
        };
    }
}

/**
 * Data Transformation Engine - Handles data mapping and transformation
 */
class DataTransformationEngine {
    constructor() {
        this.transformations = new Map();
        this.fieldMappings = new Map();
        this.validators = new Map();
    }

    registerTransformation(operation, transformer) {
        this.transformations.set(operation, transformer);
    }

    registerFieldMapping(operation, mapping) {
        this.fieldMappings.set(operation, mapping);
    }

    registerValidator(operation, validator) {
        this.validators.set(operation, validator);
    }

    async transform(data, operation) {
        // Apply field mapping
        const mappedData = await this.applyFieldMapping(data, operation);
        
        // Apply custom transformation
        const transformedData = await this.applyTransformation(mappedData, operation);
        
        // Validate transformed data
        await this.validateData(transformedData, operation);
        
        return transformedData;
    }

    async transformResponse(data, operation) {
        const reverseOperation = `${operation}_response`;
        return await this.transform(data, reverseOperation);
    }

    async applyFieldMapping(data, operation) {
        const mapping = this.fieldMappings.get(operation);
        if (!mapping) return data;

        const mapped = {};
        for (const [sourceField, targetField] of Object.entries(mapping)) {
            if (data.hasOwnProperty(sourceField)) {
                mapped[targetField] = data[sourceField];
            }
        }
        
        return { ...data, ...mapped };
    }

    async applyTransformation(data, operation) {
        const transformer = this.transformations.get(operation);
        if (!transformer) return data;

        return await transformer(data);
    }

    async validateData(data, operation) {
        const validator = this.validators.get(operation);
        if (!validator) return true;

        const isValid = await validator(data);
        if (!isValid) {
            throw new Error(`Data validation failed for operation: ${operation}`);
        }
        
        return true;
    }
}

/**
 * Connection Pool Manager - Manages connection pooling for performance
 */
class ConnectionPool {
    constructor(maxConnections = 10, idleTimeout = 300000) {
        this.maxConnections = maxConnections;
        this.idleTimeout = idleTimeout;
        this.pool = [];
        this.activeConnections = new Set();
        this.waitingQueue = [];
    }

    async getConnection() {
        if (this.pool.length > 0) {
            const connection = this.pool.pop();
            this.activeConnections.add(connection);
            return connection;
        }

        if (this.activeConnections.size < this.maxConnections) {
            const connection = await this.createConnection();
            this.activeConnections.add(connection);
            return connection;
        }

        // Wait for available connection
        return new Promise((resolve) => {
            this.waitingQueue.push(resolve);
        });
    }

    releaseConnection(connection) {
        this.activeConnections.delete(connection);
        
        if (this.waitingQueue.length > 0) {
            const resolve = this.waitingQueue.shift();
            this.activeConnections.add(connection);
            resolve(connection);
        } else {
            this.pool.push(connection);
            this.scheduleConnectionCleanup(connection);
        }
    }

    async createConnection() {
        throw new Error('createConnection must be implemented by subclass');
    }

    scheduleConnectionCleanup(connection) {
        setTimeout(() => {
            const index = this.pool.indexOf(connection);
            if (index > -1) {
                this.pool.splice(index, 1);
                this.closeConnection(connection);
            }
        }, this.idleTimeout);
    }

    async closeConnection(connection) {
        // Implementation specific to connection type
    }

    async closeAll() {
        const allConnections = [...this.pool, ...this.activeConnections];
        for (const connection of allConnections) {
            await this.closeConnection(connection);
        }
        this.pool = [];
        this.activeConnections.clear();
    }
}

/**
 * Rate Limiter - Controls request rate per connector
 */
class RateLimiter {
    constructor(config) {
        this.requests = config.requests || 100;
        this.window = config.window || 60000;
        this.requestTimes = [];
    }

    canProceed() {
        const now = Date.now();
        const windowStart = now - this.window;
        
        // Remove old requests outside the window
        this.requestTimes = this.requestTimes.filter(time => time > windowStart);
        
        if (this.requestTimes.length < this.requests) {
            this.requestTimes.push(now);
            return true;
        }
        
        return false;
    }

    getStatus() {
        const now = Date.now();
        const windowStart = now - this.window;
        const currentRequests = this.requestTimes.filter(time => time > windowStart).length;
        
        return {
            currentRequests,
            maxRequests: this.requests,
            windowMs: this.window,
            remaining: Math.max(0, this.requests - currentRequests)
        };
    }

    getRemainingTime() {
        if (this.requestTimes.length < this.requests) return 0;
        
        const oldestRequest = Math.min(...this.requestTimes);
        const resetTime = oldestRequest + this.window;
        
        return Math.max(0, resetTime - Date.now());
    }
}

/**
 * Health Monitor - Monitors connector health and performance
 */
class HealthMonitor {
    constructor(connector) {
        this.connector = connector;
        this.isMonitoring = false;
        this.healthCheckInterval = connector.config.healthCheckInterval;
        this.metrics = {
            uptime: 0,
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            averageResponseTime: 0,
            lastHealthCheck: null,
            connectionErrors: 0
        };
        this.startTime = Date.now();
        this.responseTimeSamples = [];
    }

    start() {
        if (this.isMonitoring) return;
        
        this.isMonitoring = true;
        this.healthCheckTimer = setInterval(async () => {
            await this.performHealthCheck();
        }, this.healthCheckInterval);
    }

    stop() {
        if (!this.isMonitoring) return;
        
        this.isMonitoring = false;
        if (this.healthCheckTimer) {
            clearInterval(this.healthCheckTimer);
        }
    }

    async performHealthCheck() {
        const startTime = Date.now();
        
        try {
            const healthStatus = await this.checkConnectorHealth();
            const responseTime = Date.now() - startTime;
            
            this.updateMetrics(true, responseTime);
            this.metrics.lastHealthCheck = new Date().toISOString();
            
            this.connector.emit('health:check:success', {
                status: healthStatus,
                responseTime,
                metrics: this.metrics
            });
            
        } catch (error) {
            const responseTime = Date.now() - startTime;
            this.updateMetrics(false, responseTime);
            this.metrics.connectionErrors++;
            
            this.connector.emit('health:check:failure', {
                error: error.message,
                responseTime,
                metrics: this.metrics
            });
        }
    }

    async checkConnectorHealth() {
        if (!this.connector.isConnected) {
            throw new Error('Connector is not connected');
        }
        
        // Perform a lightweight health check operation
        return await this.connector.performHealthCheck?.() || { status: 'healthy' };
    }

    updateMetrics(success, responseTime) {
        this.metrics.totalRequests++;
        this.metrics.uptime = Date.now() - this.startTime;
        
        if (success) {
            this.metrics.successfulRequests++;
        } else {
            this.metrics.failedRequests++;
        }
        
        // Calculate average response time
        this.responseTimeSamples.push(responseTime);
        if (this.responseTimeSamples.length > 100) {
            this.responseTimeSamples.shift();
        }
        
        this.metrics.averageResponseTime = 
            this.responseTimeSamples.reduce((sum, time) => sum + time, 0) / 
            this.responseTimeSamples.length;
    }

    getMetrics() {
        return {
            ...this.metrics,
            successRate: this.metrics.totalRequests > 0 ? 
                (this.metrics.successfulRequests / this.metrics.totalRequests) * 100 : 0,
            errorRate: this.metrics.totalRequests > 0 ? 
                (this.metrics.failedRequests / this.metrics.totalRequests) * 100 : 0
        };
    }
}

/**
 * Error Handler - Comprehensive error handling and retry logic
 */
class ErrorHandler {
    constructor(maxRetries = 3, baseDelay = 1000) {
        this.maxRetries = maxRetries;
        this.baseDelay = baseDelay;
        this.retryableErrors = new Set([
            'ECONNRESET',
            'ENOTFOUND',
            'ECONNREFUSED',
            'ETIMEDOUT',
            'SOCKET_TIMEOUT'
        ]);
    }

    async executeWithRetry(operation, context = {}) {
        let lastError;
        
        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                const result = await operation();
                
                if (attempt > 0) {
                    console.log(`Operation succeeded after ${attempt} retries`);
                }
                
                return result;
            } catch (error) {
                lastError = error;
                
                if (attempt === this.maxRetries || !this.shouldRetry(error)) {
                    break;
                }
                
                const delay = this.calculateDelay(attempt);
                console.log(`Attempt ${attempt + 1} failed, retrying in ${delay}ms:`, error.message);
                
                await this.sleep(delay);
            }
        }
        
        throw new Error(`Operation failed after ${this.maxRetries + 1} attempts: ${lastError.message}`);
    }

    shouldRetry(error) {
        // Check for specific error codes
        if (this.retryableErrors.has(error.code)) {
            return true;
        }
        
        // Check for HTTP status codes
        if (error.status >= 500 && error.status < 600) {
            return true;
        }
        
        if (error.status === 429) { // Too Many Requests
            return true;
        }
        
        return false;
    }

    calculateDelay(attempt) {
        // Exponential backoff with jitter
        const exponentialDelay = this.baseDelay * Math.pow(2, attempt);
        const jitter = Math.random() * 0.1 * exponentialDelay;
        return Math.floor(exponentialDelay + jitter);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * Configuration Manager - Manages connector configurations
 */
class ConfigurationManager {
    constructor() {
        this.configurations = new Map();
        this.encryptionKey = this.generateEncryptionKey();
    }

    setConfiguration(connectorName, config) {
        const encryptedConfig = this.encryptSensitiveData(config);
        this.configurations.set(connectorName, encryptedConfig);
    }

    getConfiguration(connectorName) {
        const encryptedConfig = this.configurations.get(connectorName);
        if (!encryptedConfig) {
            throw new Error(`Configuration not found for connector: ${connectorName}`);
        }
        
        return this.decryptSensitiveData(encryptedConfig);
    }

    encryptSensitiveData(config) {
        const sensitiveFields = ['password', 'token', 'secret', 'key', 'clientSecret'];
        const encrypted = { ...config };
        
        for (const field of sensitiveFields) {
            if (encrypted[field]) {
                encrypted[field] = this.encrypt(encrypted[field]);
            }
        }
        
        return encrypted;
    }

    decryptSensitiveData(config) {
        const sensitiveFields = ['password', 'token', 'secret', 'key', 'clientSecret'];
        const decrypted = { ...config };
        
        for (const field of sensitiveFields) {
            if (decrypted[field]) {
                decrypted[field] = this.decrypt(decrypted[field]);
            }
        }
        
        return decrypted;
    }

    encrypt(text) {
        const algorithm = 'aes-256-gcm';
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(algorithm, this.encryptionKey);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    }

    decrypt(encryptedText) {
        const algorithm = 'aes-256-gcm';
        const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
        
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const decipher = crypto.createDecipher(algorithm, this.encryptionKey);
        
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }

    generateEncryptionKey() {
        return crypto.randomBytes(32).toString('hex');
    }
}

/**
 * Connector Registry - Manages all enterprise connectors
 */
class ConnectorRegistry {
    constructor() {
        this.connectors = new Map();
        this.configManager = new ConfigurationManager();
    }

    register(name, connectorClass, config) {
        this.configManager.setConfiguration(name, config);
        const connectorConfig = this.configManager.getConfiguration(name);
        const connector = new connectorClass(connectorConfig);
        
        this.connectors.set(name, connector);
        
        // Set up event listeners
        connector.on('connector:error', (data) => {
            console.error(`Connector ${name} error:`, data.error.message);
        });
        
        connector.on('connector:connected', () => {
            console.log(`Connector ${name} connected successfully`);
        });
        
        connector.on('connector:disconnected', () => {
            console.log(`Connector ${name} disconnected`);
        });
        
        return connector;
    }

    get(name) {
        const connector = this.connectors.get(name);
        if (!connector) {
            throw new Error(`Connector not found: ${name}`);
        }
        return connector;
    }

    async connectAll() {
        const results = [];
        for (const [name, connector] of this.connectors) {
            try {
                await connector.connect();
                results.push({ name, status: 'connected' });
            } catch (error) {
                results.push({ name, status: 'failed', error: error.message });
            }
        }
        return results;
    }

    async disconnectAll() {
        const results = [];
        for (const [name, connector] of this.connectors) {
            try {
                await connector.disconnect();
                results.push({ name, status: 'disconnected' });
            } catch (error) {
                results.push({ name, status: 'failed', error: error.message });
            }
        }
        return results;
    }

    getHealthStatus() {
        const status = {};
        for (const [name, connector] of this.connectors) {
            status[name] = connector.getHealthStatus();
        }
        return status;
    }

    list() {
        return Array.from(this.connectors.keys());
    }
}

module.exports = {
    BaseConnector,
    AuthenticationManager,
    DataTransformationEngine,
    ConnectionPool,
    RateLimiter,
    HealthMonitor,
    ErrorHandler,
    ConfigurationManager,
    ConnectorRegistry
};