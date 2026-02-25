const crypto = require('crypto');
const logger = require('../utils/logger').logger;

/**
 * Audit middleware factory
 * Automatically logs API requests and responses for compliance and security monitoring
 */
const auditMiddleware = (auditLogger) => {
    return (req, res, next) => {
        // Skip audit logging for health checks and non-sensitive endpoints
        const skipAuditPaths = ['/health', '/metrics'];
        if (skipAuditPaths.some(path => req.path === path)) {
            return next();
        }

        // Generate unique request ID for correlation
        req.requestId = req.requestId || generateRequestId();

        // Capture request start time for performance tracking
        req.auditStartTime = Date.now();

        // Extract request information
        const requestInfo = extractRequestInfo(req);

        // Log request initiation
        auditLogger.log('api_request_initiated', {
            requestId: req.requestId,
            method: req.method,
            path: req.path,
            query: sanitizeQueryParams(req.query),
            headers: sanitizeHeaders(req.headers),
            body: sanitizeRequestBody(req.body),
            userAgent: req.get('User-Agent'),
            contentLength: req.get('Content-Length'),
            timestamp: new Date().toISOString()
        }, {
            ipAddress: requestInfo.ipAddress,
            userAgent: requestInfo.userAgent,
            userId: requestInfo.userId,
            tenantId: requestInfo.tenantId,
            sessionId: requestInfo.sessionId,
            requestId: req.requestId
        });

        // Capture original response methods
        const originalSend = res.send;
        const originalJson = res.json;
        const originalEnd = res.end;

        let responseBody = null;
        let responseSent = false;

        // Override response methods to capture response data
        res.send = function(body) {
            if (!responseSent) {
                responseBody = body;
                logApiResponse(req, res, responseBody, auditLogger);
                responseSent = true;
            }
            return originalSend.call(this, body);
        };

        res.json = function(obj) {
            if (!responseSent) {
                responseBody = obj;
                logApiResponse(req, res, responseBody, auditLogger);
                responseSent = true;
            }
            return originalJson.call(this, obj);
        };

        res.end = function(chunk, encoding) {
            if (!responseSent) {
                if (chunk) {
                    responseBody = chunk;
                }
                logApiResponse(req, res, responseBody, auditLogger);
                responseSent = true;
            }
            return originalEnd.call(this, chunk, encoding);
        };

        // Handle response finish event as fallback
        res.on('finish', () => {
            if (!responseSent) {
                logApiResponse(req, res, responseBody, auditLogger);
                responseSent = true;
            }
        });

        // Add request ID to response headers
        res.set('X-Request-ID', req.requestId);

        next();
    };
};

/**
 * Log API response with audit information
 */
const logApiResponse = (req, res, responseBody, auditLogger) => {
    try {
        const duration = Date.now() - req.auditStartTime;
        const requestInfo = extractRequestInfo(req);
        
        const responseInfo = {
            requestId: req.requestId,
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            duration,
            responseSize: getResponseSize(res, responseBody),
            headers: sanitizeResponseHeaders(res.getHeaders()),
            body: sanitizeResponseBody(responseBody, res.statusCode),
            timestamp: new Date().toISOString()
        };

        // Determine event type based on status code and method
        const eventType = getAuditEventType(req.method, req.path, res.statusCode);

        // Log the response
        auditLogger.log(eventType, responseInfo, {
            ipAddress: requestInfo.ipAddress,
            userAgent: requestInfo.userAgent,
            userId: requestInfo.userId,
            tenantId: requestInfo.tenantId,
            sessionId: requestInfo.sessionId,
            requestId: req.requestId
        });

        // Log performance metrics for slow requests
        if (duration > 5000) { // 5 seconds
            auditLogger.log('api_slow_response', {
                requestId: req.requestId,
                method: req.method,
                path: req.path,
                duration,
                threshold: 5000,
                timestamp: new Date().toISOString()
            }, {
                userId: requestInfo.userId,
                tenantId: requestInfo.tenantId,
                requestId: req.requestId
            });
        }

        // Log error responses with additional detail
        if (res.statusCode >= 400) {
            auditLogger.log('api_error_response', {
                requestId: req.requestId,
                method: req.method,
                path: req.path,
                statusCode: res.statusCode,
                errorBody: sanitizeResponseBody(responseBody, res.statusCode),
                userAgent: req.get('User-Agent'),
                referer: req.get('Referer'),
                timestamp: new Date().toISOString()
            }, {
                ipAddress: requestInfo.ipAddress,
                userId: requestInfo.userId,
                tenantId: requestInfo.tenantId,
                requestId: req.requestId
            });
        }

        // Log sensitive operations with enhanced detail
        if (isSensitiveOperation(req.method, req.path)) {
            auditLogger.log('sensitive_operation_executed', {
                requestId: req.requestId,
                operation: `${req.method} ${req.path}`,
                statusCode: res.statusCode,
                inputData: sanitizeRequestBody(req.body),
                queryParams: sanitizeQueryParams(req.query),
                success: res.statusCode < 400,
                timestamp: new Date().toISOString()
            }, {
                ipAddress: requestInfo.ipAddress,
                userId: requestInfo.userId,
                tenantId: requestInfo.tenantId,
                requestId: req.requestId
            });
        }

    } catch (error) {
        logger.error('Error in audit response logging:', error);
    }
};

/**
 * Generate unique request ID
 */
const generateRequestId = () => {
    return crypto.randomBytes(16).toString('hex');
};

/**
 * Extract request information
 */
const extractRequestInfo = (req) => {
    return {
        ipAddress: getClientIP(req),
        userAgent: req.get('User-Agent'),
        userId: req.user?.id || null,
        tenantId: req.tenantId || req.user?.tenantId || null,
        sessionId: req.user?.sessionId || null
    };
};

/**
 * Get client IP address from request
 */
const getClientIP = (req) => {
    return req.headers['x-forwarded-for'] ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress ||
           req.ip ||
           'unknown';
};

/**
 * Determine audit event type based on request characteristics
 */
const getAuditEventType = (method, path, statusCode) => {
    // Authentication related
    if (path.includes('/auth') || path.includes('/login') || path.includes('/logout')) {
        if (statusCode < 400) {
            return 'authentication_success';
        } else {
            return 'authentication_failure';
        }
    }

    // User management
    if (path.includes('/users')) {
        return 'user_management_operation';
    }

    // Device management
    if (path.includes('/devices')) {
        return 'device_management_operation';
    }

    // Policy management
    if (path.includes('/policies') || path.includes('/update-rings')) {
        return 'policy_management_operation';
    }

    // Remote actions
    if (path.includes('/remote-actions')) {
        return 'remote_action_operation';
    }

    // Terms of use
    if (path.includes('/terms')) {
        return 'terms_of_use_operation';
    }

    // Tenant management
    if (path.includes('/tenants')) {
        return 'tenant_management_operation';
    }

    // Data operations
    if (method === 'DELETE') {
        return 'data_deletion_operation';
    } else if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        return 'data_modification_operation';
    } else if (method === 'GET') {
        return 'data_access_operation';
    }

    return 'api_operation';
};

/**
 * Check if operation is sensitive and requires enhanced logging
 */
const isSensitiveOperation = (method, path) => {
    const sensitivePatterns = [
        '/auth',
        '/login',
        '/logout',
        '/password',
        '/users',
        '/admin',
        '/tenants',
        '/remote-actions',
        '/wipe',
        '/lock',
        '/policies',
        '/terms',
        '/compliance'
    ];

    const isDeleteOperation = method === 'DELETE';
    const isSensitivePath = sensitivePatterns.some(pattern => path.includes(pattern));

    return isDeleteOperation || isSensitivePath;
};

/**
 * Sanitize query parameters for logging
 */
const sanitizeQueryParams = (query) => {
    if (!query || typeof query !== 'object') {
        return query;
    }

    const sensitiveParams = ['password', 'token', 'key', 'secret', 'apikey', 'api_key'];
    const sanitized = { ...query };

    for (const [key, value] of Object.entries(sanitized)) {
        if (sensitiveParams.some(param => key.toLowerCase().includes(param))) {
            sanitized[key] = '[REDACTED]';
        }
    }

    return sanitized;
};

/**
 * Sanitize request headers for logging
 */
const sanitizeHeaders = (headers) => {
    if (!headers || typeof headers !== 'object') {
        return headers;
    }

    const sensitiveHeaders = [
        'authorization',
        'cookie',
        'x-api-key',
        'x-auth-token',
        'x-access-token'
    ];

    const sanitized = { ...headers };

    for (const [key, value] of Object.entries(sanitized)) {
        if (sensitiveHeaders.some(header => key.toLowerCase().includes(header))) {
            sanitized[key] = '[REDACTED]';
        }
    }

    return sanitized;
};

/**
 * Sanitize response headers for logging
 */
const sanitizeResponseHeaders = (headers) => {
    if (!headers || typeof headers !== 'object') {
        return headers;
    }

    const sensitiveHeaders = ['set-cookie', 'x-auth-token'];
    const sanitized = { ...headers };

    for (const [key, value] of Object.entries(sanitized)) {
        if (sensitiveHeaders.some(header => key.toLowerCase().includes(header))) {
            sanitized[key] = '[REDACTED]';
        }
    }

    return sanitized;
};

/**
 * Sanitize request body for logging
 */
const sanitizeRequestBody = (body, maxSize = 1024) => {
    if (!body) {
        return null;
    }

    try {
        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        
        // Truncate large bodies
        const truncatedBody = bodyStr.length > maxSize ? 
            bodyStr.substring(0, maxSize) + '...[TRUNCATED]' : 
            bodyStr;

        // Parse and sanitize if JSON
        if (typeof body === 'object') {
            const sanitized = sanitizeSensitiveFields({ ...body });
            const sanitizedStr = JSON.stringify(sanitized);
            return sanitizedStr.length > maxSize ? 
                sanitizedStr.substring(0, maxSize) + '...[TRUNCATED]' : 
                sanitized;
        }

        return truncatedBody;
    } catch (error) {
        return '[BODY_PARSING_ERROR]';
    }
};

/**
 * Sanitize response body for logging
 */
const sanitizeResponseBody = (body, statusCode, maxSize = 1024) => {
    // Don't log response bodies for successful operations (to reduce log volume)
    // Only log for errors and sensitive operations
    if (statusCode < 400) {
        return '[SUCCESS_RESPONSE]';
    }

    if (!body) {
        return null;
    }

    try {
        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        
        // Truncate large bodies
        const truncatedBody = bodyStr.length > maxSize ? 
            bodyStr.substring(0, maxSize) + '...[TRUNCATED]' : 
            bodyStr;

        // Parse and sanitize if JSON
        if (typeof body === 'object') {
            const sanitized = sanitizeSensitiveFields({ ...body });
            const sanitizedStr = JSON.stringify(sanitized);
            return sanitizedStr.length > maxSize ? 
                sanitizedStr.substring(0, maxSize) + '...[TRUNCATED]' : 
                sanitized;
        }

        return truncatedBody;
    } catch (error) {
        return '[RESPONSE_PARSING_ERROR]';
    }
};

/**
 * Sanitize sensitive fields from objects
 */
const sanitizeSensitiveFields = (obj) => {
    if (!obj || typeof obj !== 'object') {
        return obj;
    }

    const sensitiveFields = [
        'password',
        'secret',
        'key',
        'token',
        'credential',
        'api_key',
        'apikey',
        'private_key',
        'certificate',
        'passphrase',
        'pin',
        'ssn',
        'social_security_number',
        'credit_card',
        'card_number'
    ];

    const sanitized = Array.isArray(obj) ? [...obj] : { ...obj };

    for (const [key, value] of Object.entries(sanitized)) {
        const lowerKey = key.toLowerCase();
        
        if (sensitiveFields.some(field => lowerKey.includes(field))) {
            sanitized[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeSensitiveFields(value);
        }
    }

    return sanitized;
};

/**
 * Get response size in bytes
 */
const getResponseSize = (res, body) => {
    const contentLength = res.get('Content-Length');
    if (contentLength) {
        return parseInt(contentLength);
    }

    if (body) {
        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        return Buffer.byteLength(bodyStr, 'utf8');
    }

    return 0;
};

/**
 * Middleware for logging specific audit events
 */
const logAuditEvent = (eventType, getData) => {
    return (req, res, next) => {
        const auditLogger = req.app.locals.auditLogger;
        if (auditLogger && typeof getData === 'function') {
            const data = getData(req, res);
            const requestInfo = extractRequestInfo(req);
            
            auditLogger.log(eventType, data, {
                ipAddress: requestInfo.ipAddress,
                userId: requestInfo.userId,
                tenantId: requestInfo.tenantId,
                requestId: req.requestId
            });
        }
        next();
    };
};

module.exports = {
    auditMiddleware,
    logAuditEvent
};