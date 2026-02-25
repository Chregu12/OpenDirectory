/**
 * Audit Middleware
 * Automatically logs HTTP requests and responses
 */

const auditMiddleware = (auditLogger) => {
    return (req, res, next) => {
        // Capture request start time
        const startTime = Date.now();
        
        // Store original response methods
        const originalSend = res.send;
        const originalJson = res.json;
        
        // Override response methods to capture response data
        res.send = function(data) {
            res.responseData = data;
            return originalSend.call(this, data);
        };
        
        res.json = function(data) {
            res.responseData = data;
            return originalJson.call(this, data);
        };
        
        // Log request completion
        res.on('finish', async () => {
            const duration = Date.now() - startTime;
            
            // Extract relevant request information
            const auditData = {
                method: req.method,
                url: req.url,
                path: req.path,
                query: req.query,
                userAgent: req.get('User-Agent'),
                ip: req.ip,
                userId: req.user?.id,
                deviceId: req.headers['x-device-id'],
                appId: req.headers['x-app-id'],
                statusCode: res.statusCode,
                duration,
                timestamp: new Date(startTime)
            };
            
            // Determine event type based on status code
            let eventType = 'HTTP_REQUEST';
            if (res.statusCode >= 400) {
                eventType = 'HTTP_REQUEST_ERROR';
            } else if (res.statusCode >= 200 && res.statusCode < 300) {
                eventType = 'HTTP_REQUEST_SUCCESS';
            }
            
            // Don't log health check requests unless they fail
            if (req.path === '/health' && res.statusCode < 400) {
                return;
            }
            
            // Don't log sensitive data
            const sanitizedBody = sanitizeRequestBody(req.body);
            if (Object.keys(sanitizedBody).length > 0) {
                auditData.requestBody = sanitizedBody;
            }
            
            // Log authentication failures as security events
            if (res.statusCode === 401 || res.statusCode === 403) {
                await auditLogger.logEvent(
                    'security',
                    'AUTHENTICATION_FAILED',
                    auditData
                );
            } else {
                await auditLogger.logEvent(
                    'system',
                    eventType,
                    auditData
                );
            }
        });
        
        next();
    };
};

/**
 * Sanitize request body to remove sensitive information
 */
function sanitizeRequestBody(body) {
    if (!body || typeof body !== 'object') {
        return {};
    }
    
    const sensitiveFields = [
        'password',
        'secret',
        'token',
        'key',
        'credential',
        'authorization',
        'recoveryKey',
        'privateKey'
    ];
    
    const sanitized = {};
    
    for (const [key, value] of Object.entries(body)) {
        const lowercaseKey = key.toLowerCase();
        
        // Check if field is sensitive
        const isSensitive = sensitiveFields.some(field => 
            lowercaseKey.includes(field)
        );
        
        if (isSensitive) {
            sanitized[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
            // Recursively sanitize nested objects
            sanitized[key] = sanitizeRequestBody(value);
        } else {
            sanitized[key] = value;
        }
    }
    
    return sanitized;
}

module.exports = auditMiddleware;