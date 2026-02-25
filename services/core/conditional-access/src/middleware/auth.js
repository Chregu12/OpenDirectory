/**
 * Authentication Middleware for Conditional Access Service
 */

const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * JWT Authentication Middleware
 */
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({
            success: false,
            error: 'Authorization header missing'
        });
    }
    
    const token = authHeader.split(' ')[1]; // Bearer <token>
    
    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Token missing'
        });
    }
    
    try {
        const decoded = jwt.verify(token, config.security.jwtSecret);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            error: 'Invalid or expired token'
        });
    }
};

/**
 * API Key Authentication Middleware
 */
const authenticateAPIKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({
            success: false,
            error: 'API key missing'
        });
    }
    
    // In production, validate against API key store
    // For now, use environment variable
    const validAPIKey = process.env.CONDITIONAL_ACCESS_API_KEY || 'default-api-key';
    
    if (apiKey !== validAPIKey) {
        return res.status(403).json({
            success: false,
            error: 'Invalid API key'
        });
    }
    
    // Set service user context
    req.user = {
        id: 'service-account',
        type: 'service',
        roles: ['SERVICE_ACCOUNT'],
        permissions: ['*']
    };
    
    next();
};

/**
 * Role-based Authorization Middleware
 */
const requireRole = (requiredRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'User not authenticated'
            });
        }
        
        const userRoles = req.user.roles || [];
        const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));
        
        if (!hasRequiredRole) {
            return res.status(403).json({
                success: false,
                error: 'Insufficient permissions'
            });
        }
        
        next();
    };
};

/**
 * Permission-based Authorization Middleware
 */
const requirePermission = (requiredPermissions) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'User not authenticated'
            });
        }
        
        const userPermissions = req.user.permissions || [];
        
        // Service accounts with wildcard permission
        if (userPermissions.includes('*')) {
            return next();
        }
        
        const hasRequiredPermission = requiredPermissions.some(permission => 
            userPermissions.includes(permission)
        );
        
        if (!hasRequiredPermission) {
            return res.status(403).json({
                success: false,
                error: 'Insufficient permissions'
            });
        }
        
        next();
    };
};

/**
 * Combined Authentication Middleware (JWT or API Key)
 */
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey) {
        // Use API key authentication
        return authenticateAPIKey(req, res, next);
    } else if (authHeader) {
        // Use JWT authentication
        return authenticateJWT(req, res, next);
    } else {
        return res.status(401).json({
            success: false,
            error: 'Authentication required'
        });
    }
};

/**
 * Device Context Validation Middleware
 */
const validateDeviceContext = (req, res, next) => {
    const deviceId = req.headers['x-device-id'];
    const userAgent = req.headers['user-agent'];
    
    if (!deviceId) {
        return res.status(400).json({
            success: false,
            error: 'Device ID required'
        });
    }
    
    if (!userAgent) {
        return res.status(400).json({
            success: false,
            error: 'User Agent required'
        });
    }
    
    // Add device context to request
    req.deviceContext = {
        deviceId,
        userAgent,
        ip: req.ip,
        timestamp: new Date()
    };
    
    next();
};

/**
 * Request Validation Middleware
 */
const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        
        if (error) {
            return res.status(400).json({
                success: false,
                error: error.details[0].message
            });
        }
        
        next();
    };
};

/**
 * Service-to-Service Authentication
 */
const authenticateService = (allowedServices = []) => {
    return (req, res, next) => {
        const serviceToken = req.headers['x-service-token'];
        const serviceName = req.headers['x-service-name'];
        
        if (!serviceToken || !serviceName) {
            return res.status(401).json({
                success: false,
                error: 'Service authentication required'
            });
        }
        
        // Validate service token (in production, use proper service registry)
        const expectedToken = process.env[`${serviceName.toUpperCase()}_SERVICE_TOKEN`];
        
        if (!expectedToken || serviceToken !== expectedToken) {
            return res.status(403).json({
                success: false,
                error: 'Invalid service token'
            });
        }
        
        // Check if service is allowed
        if (allowedServices.length > 0 && !allowedServices.includes(serviceName)) {
            return res.status(403).json({
                success: false,
                error: 'Service not authorized'
            });
        }
        
        req.service = {
            name: serviceName,
            type: 'service'
        };
        
        next();
    };
};

module.exports = {
    authenticate,
    authenticateJWT,
    authenticateAPIKey,
    authenticateService,
    requireRole,
    requirePermission,
    validateDeviceContext,
    validateRequest
};