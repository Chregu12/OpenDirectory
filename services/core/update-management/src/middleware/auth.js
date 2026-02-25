const jwt = require('jsonwebtoken');
const config = require('../config');
const logger = require('../utils/logger').logger;

/**
 * Authentication middleware
 * Verifies JWT tokens and extracts user information
 */
const authMiddleware = (req, res, next) => {
    try {
        // Skip authentication for health checks and public endpoints
        const publicEndpoints = ['/health', '/metrics', '/api/v1/docs'];
        if (publicEndpoints.some(endpoint => req.path.startsWith(endpoint))) {
            return next();
        }

        // Extract token from Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Missing or invalid Authorization header',
                timestamp: new Date().toISOString()
            });
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix

        // Verify JWT token
        const decoded = jwt.verify(token, config.auth.jwtSecret);

        // Extract user information from token
        req.user = {
            id: decoded.sub || decoded.userId,
            username: decoded.username,
            email: decoded.email,
            roles: decoded.roles || [],
            tenantId: decoded.tenantId,
            permissions: decoded.permissions || [],
            sessionId: decoded.sessionId,
            iat: decoded.iat,
            exp: decoded.exp
        };

        // Check token expiration
        const now = Math.floor(Date.now() / 1000);
        if (decoded.exp && decoded.exp < now) {
            return res.status(401).json({
                error: 'Token expired',
                message: 'The provided token has expired',
                timestamp: new Date().toISOString()
            });
        }

        // Set tenant context
        if (req.user.tenantId) {
            req.tenantId = req.user.tenantId;
        }

        // Log successful authentication
        logger.debug('User authenticated', {
            userId: req.user.id,
            username: req.user.username,
            tenantId: req.user.tenantId,
            roles: req.user.roles,
            path: req.path,
            method: req.method
        });

        next();

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                error: 'Invalid token',
                message: 'The provided token is invalid',
                timestamp: new Date().toISOString()
            });
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expired',
                message: 'The provided token has expired',
                timestamp: new Date().toISOString()
            });
        } else {
            logger.error('Authentication error:', error);
            return res.status(500).json({
                error: 'Authentication error',
                message: 'An error occurred during authentication',
                timestamp: new Date().toISOString()
            });
        }
    }
};

/**
 * Authorization middleware factory
 * Checks if user has required roles or permissions
 */
const requireRole = (...requiredRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'User not authenticated',
                timestamp: new Date().toISOString()
            });
        }

        const userRoles = req.user.roles || [];
        const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

        if (!hasRequiredRole) {
            logger.warn('Authorization failed', {
                userId: req.user.id,
                username: req.user.username,
                userRoles,
                requiredRoles,
                path: req.path,
                method: req.method
            });

            return res.status(403).json({
                error: 'Insufficient permissions',
                message: `Required roles: ${requiredRoles.join(', ')}`,
                timestamp: new Date().toISOString()
            });
        }

        next();
    };
};

/**
 * Permission-based authorization middleware
 */
const requirePermission = (...requiredPermissions) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'User not authenticated',
                timestamp: new Date().toISOString()
            });
        }

        const userPermissions = req.user.permissions || [];
        const hasRequiredPermission = requiredPermissions.some(permission => 
            userPermissions.includes(permission)
        );

        if (!hasRequiredPermission) {
            logger.warn('Permission check failed', {
                userId: req.user.id,
                username: req.user.username,
                userPermissions,
                requiredPermissions,
                path: req.path,
                method: req.method
            });

            return res.status(403).json({
                error: 'Insufficient permissions',
                message: `Required permissions: ${requiredPermissions.join(', ')}`,
                timestamp: new Date().toISOString()
            });
        }

        next();
    };
};

/**
 * Tenant-specific authorization
 * Ensures user can only access resources from their tenant
 */
const requireTenantAccess = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'User not authenticated',
            timestamp: new Date().toISOString()
        });
    }

    // Extract tenant ID from request (URL parameter, body, or query)
    const requestedTenantId = req.params.tenantId || 
                             req.body.tenantId || 
                             req.query.tenantId ||
                             req.headers['x-tenant-id'];

    // If no tenant ID in request, use user's tenant
    if (!requestedTenantId) {
        req.tenantId = req.user.tenantId;
        return next();
    }

    // Check if user has access to requested tenant
    const userTenantId = req.user.tenantId;
    const userRoles = req.user.roles || [];

    // Super admins can access any tenant
    if (userRoles.includes('super-admin')) {
        req.tenantId = requestedTenantId;
        return next();
    }

    // Regular users can only access their own tenant
    if (userTenantId !== requestedTenantId) {
        logger.warn('Tenant access denied', {
            userId: req.user.id,
            username: req.user.username,
            userTenantId,
            requestedTenantId,
            path: req.path,
            method: req.method
        });

        return res.status(403).json({
            error: 'Tenant access denied',
            message: 'You do not have access to the requested tenant',
            timestamp: new Date().toISOString()
        });
    }

    req.tenantId = requestedTenantId;
    next();
};

/**
 * Admin-only middleware
 */
const requireAdmin = requireRole('admin', 'super-admin');

/**
 * Super admin-only middleware
 */
const requireSuperAdmin = requireRole('super-admin');

/**
 * Optional authentication middleware
 * Extracts user info if token is present but doesn't require it
 */
const optionalAuth = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next();
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, config.auth.jwtSecret);

        req.user = {
            id: decoded.sub || decoded.userId,
            username: decoded.username,
            email: decoded.email,
            roles: decoded.roles || [],
            tenantId: decoded.tenantId,
            permissions: decoded.permissions || []
        };

        if (req.user.tenantId) {
            req.tenantId = req.user.tenantId;
        }

    } catch (error) {
        // Ignore authentication errors for optional auth
        logger.debug('Optional authentication failed:', error.message);
    }

    next();
};

/**
 * API Key authentication middleware
 */
const apiKeyAuth = (req, res, next) => {
    if (!config.security.api.enableApiKey) {
        return next();
    }

    const apiKeyHeader = config.security.api.apiKeyHeader;
    const apiKey = req.headers[apiKeyHeader.toLowerCase()];

    if (!apiKey) {
        return res.status(401).json({
            error: 'API key required',
            message: `Missing ${apiKeyHeader} header`,
            timestamp: new Date().toISOString()
        });
    }

    // In a real implementation, you would validate the API key against a database
    // For now, this is a placeholder
    if (!validateApiKey(apiKey)) {
        return res.status(401).json({
            error: 'Invalid API key',
            message: 'The provided API key is invalid',
            timestamp: new Date().toISOString()
        });
    }

    // Set API key context
    req.apiKey = {
        key: apiKey,
        // Additional metadata would be retrieved from database
        permissions: [],
        tenantId: null
    };

    next();
};

/**
 * Validate API key (placeholder implementation)
 */
const validateApiKey = (apiKey) => {
    // This is a placeholder - in production, validate against database
    const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
    return validApiKeys.includes(apiKey);
};

module.exports = {
    authMiddleware,
    requireRole,
    requirePermission,
    requireTenantAccess,
    requireAdmin,
    requireSuperAdmin,
    optionalAuth,
    apiKeyAuth
};