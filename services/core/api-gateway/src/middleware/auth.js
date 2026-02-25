const jwt = require('jsonwebtoken');
const axios = require('axios');
const logger = require('../config/logger');

class AuthenticationMiddleware {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'changeme';
    this.authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://authentication-service:3001';
    this.publicPaths = [
      '/health',
      '/health/*',
      '/api/auth/login',
      '/api/auth/register',
      '/api/config/modules',
      '/api/services',
      '/api/gateway/info',
      '/api/gateway/routes',
      '/docs',
      '/api-docs',
      '/docs/*',
      '/ws'
    ];
    this.cache = new Map(); // Simple in-memory cache for token validation
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  middleware() {
    return async (req, res, next) => {
      try {
        // Skip authentication for public paths
        if (this.isPublicPath(req.path)) {
          return next();
        }

        // Skip authentication for OPTIONS requests
        if (req.method === 'OPTIONS') {
          return next();
        }

        // Check for API Key authentication first
        const apiKey = this.extractApiKey(req);
        if (apiKey) {
          const keyInfo = this.validateApiKey(apiKey);
          if (keyInfo) {
            req.auth = {
              type: 'api-key',
              keyName: keyInfo.name,
              isAdmin: keyInfo.isAdmin || false,
              roles: keyInfo.roles || ['api'],
              permissions: keyInfo.permissions || []
            };
            logger.debug(`API key authenticated: ${keyInfo.name}`);
            return next();
          } else {
            return this.unauthorized(res, 'Invalid API key');
          }
        }

        // Check for JWT token authentication
        const token = this.extractToken(req);
        
        if (!token) {
          return this.unauthorized(res, 'Authentication required - provide JWT token or API key');
        }

        // Check cache first
        const cachedUser = this.getCachedUser(token);
        if (cachedUser) {
          req.user = cachedUser;
          req.auth = {
            type: 'jwt',
            userId: cachedUser.id,
            username: cachedUser.username,
            roles: cachedUser.roles || [],
            permissions: cachedUser.permissions || [],
            isAdmin: cachedUser.roles?.includes('admin') || false
          };
          return next();
        }

        // Validate token
        const user = await this.validateToken(token);
        
        if (!user) {
          return this.unauthorized(res, 'Invalid token');
        }

        // Cache the user info
        this.cacheUser(token, user);
        
        // Add user to request
        req.user = user;
        
        // Add authorization context
        req.auth = {
          type: 'jwt',
          userId: user.id,
          username: user.username,
          roles: user.roles || [],
          permissions: user.permissions || [],
          isAdmin: user.roles?.includes('admin') || false
        };

        logger.debug(`Authenticated user: ${user.username} (${user.id})`);
        next();

      } catch (error) {
        logger.error('Authentication error:', error);
        this.unauthorized(res, 'Authentication failed');
      }
    };
  }

  isPublicPath(path) {
    return this.publicPaths.some(publicPath => {
      if (publicPath.endsWith('*')) {
        return path.startsWith(publicPath.slice(0, -1));
      }
      return path === publicPath || path.startsWith(publicPath + '/');
    });
  }


  extractApiKey(req) {
    // Check X-API-Key header
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      return apiKey;
    }

    // Check query parameter
    if (req.query.api_key) {
      return req.query.api_key;
    }

    return null;
  }

  validateApiKey(apiKey) {
    // In production, this would query a database
    // For now, we'll use environment variables
    const validKeys = {
      // Development keys
      'dev-read-only': {
        name: 'Development Read-Only',
        isAdmin: false,
        roles: ['api', 'read'],
        permissions: ['read']
      },
      'dev-full-access': {
        name: 'Development Full Access',
        isAdmin: false,
        roles: ['api', 'read', 'write'],
        permissions: ['read', 'write']
      },
      'admin-key': {
        name: 'Admin Access',
        isAdmin: true,
        roles: ['api', 'admin'],
        permissions: ['*']
      },
      // Environment-based keys
      [process.env.API_KEY_READ_ONLY]: {
        name: 'Read Only API Key',
        isAdmin: false,
        roles: ['api'],
        permissions: ['read']
      },
      [process.env.API_KEY_FULL]: {
        name: 'Full Access API Key',
        isAdmin: false,
        roles: ['api', 'read', 'write'],
        permissions: ['read', 'write']
      },
      [process.env.API_KEY_ADMIN]: {
        name: 'Admin API Key',
        isAdmin: true,
        roles: ['api', 'admin'],
        permissions: ['*']
      }
    };

    return validKeys[apiKey] || null;
  }

  extractToken(req) {
    // Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Check query parameter
    if (req.query.token) {
      return req.query.token;
    }

    // Check cookies
    if (req.headers.cookie) {
      const cookies = req.headers.cookie.split(';');
      const tokenCookie = cookies.find(cookie => cookie.trim().startsWith('token='));
      if (tokenCookie) {
        return tokenCookie.split('=')[1];
      }
    }

    return null;
  }

  async validateToken(token) {
    try {
      // First, try to verify JWT locally
      const decoded = jwt.verify(token, this.jwtSecret);
      
      // If local verification passes, validate with auth service
      const response = await axios.post(`${this.authServiceUrl}/api/validate`, {
        token
      }, {
        timeout: 5000
      });

      if (response.data.valid) {
        return {
          id: decoded.sub || decoded.userId,
          username: decoded.username,
          email: decoded.email,
          roles: decoded.roles || [],
          permissions: decoded.permissions || [],
          iat: decoded.iat,
          exp: decoded.exp
        };
      }

      return null;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        logger.security('Token expired', { token: token.substring(0, 20) + '...' });
      } else if (error.name === 'JsonWebTokenError') {
        logger.security('Invalid token', { token: token.substring(0, 20) + '...' });
      } else {
        logger.error('Token validation error:', error);
      }
      return null;
    }
  }

  getCachedUser(token) {
    const cacheKey = this.hashToken(token);
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.user;
    }

    // Remove expired cache entry
    if (cached) {
      this.cache.delete(cacheKey);
    }

    return null;
  }

  cacheUser(token, user) {
    const cacheKey = this.hashToken(token);
    this.cache.set(cacheKey, {
      user,
      timestamp: Date.now()
    });
  }

  hashToken(token) {
    // Simple hash for cache key (don't store full token)
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  unauthorized(res, message) {
    res.status(401).json({
      error: 'Unauthorized',
      message,
      timestamp: new Date().toISOString()
    });
  }

  // Role-based authorization middleware
  requireRole(roles) {
    return (req, res, next) => {
      if (!req.auth) {
        return this.unauthorized(res, 'Authentication required');
      }

      const userRoles = req.auth.roles || [];
      const hasRole = roles.some(role => userRoles.includes(role));

      if (!hasRole) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Insufficient permissions',
          requiredRoles: roles,
          userRoles
        });
      }

      next();
    };
  }

  // Permission-based authorization middleware
  requirePermission(permissions) {
    return (req, res, next) => {
      if (!req.auth) {
        return this.unauthorized(res, 'Authentication required');
      }

      const userPermissions = req.auth.permissions || [];
      const hasPermission = permissions.some(permission => 
        userPermissions.includes(permission)
      );

      if (!hasPermission && !req.auth.isAdmin) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Insufficient permissions',
          requiredPermissions: permissions,
          userPermissions
        });
      }

      next();
    };
  }

  // Admin-only middleware
  requireAdmin() {
    return (req, res, next) => {
      if (!req.auth || !req.auth.isAdmin) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Admin access required'
        });
      }
      next();
    };
  }

  // Clear token cache (useful for logout)
  clearCache(token) {
    if (token) {
      const cacheKey = this.hashToken(token);
      this.cache.delete(cacheKey);
    }
  }

  // Periodic cache cleanup
  startCacheCleanup() {
    setInterval(() => {
      const now = Date.now();
      for (const [key, value] of this.cache.entries()) {
        if (now - value.timestamp > this.cacheTimeout) {
          this.cache.delete(key);
        }
      }
    }, this.cacheTimeout);
  }
}

// Create singleton instance
const authMiddleware = new AuthenticationMiddleware();

// Start cache cleanup
authMiddleware.startCacheCleanup();

// Export middleware and utility functions
module.exports = authMiddleware.middleware();
module.exports.requireRole = authMiddleware.requireRole.bind(authMiddleware);
module.exports.requirePermission = authMiddleware.requirePermission.bind(authMiddleware);
module.exports.requireAdmin = authMiddleware.requireAdmin.bind(authMiddleware);
module.exports.clearCache = authMiddleware.clearCache.bind(authMiddleware);