/**
 * OpenDirectory Enterprise Directory Service Logger
 * Comprehensive logging for Active Directory replacement service
 */

const winston = require('winston');
const path = require('path');
const config = require('../config');

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
  })
);

// Create logs directory
const logDir = './data/logs';
require('fs').mkdirSync(logDir, { recursive: true });

// Create main logger
const logger = winston.createLogger({
  level: config.logging.level,
  format: logFormat,
  defaultMeta: { service: 'enterprise-directory' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: config.server.environment === 'development' ? consoleFormat : logFormat,
      level: 'debug'
    }),

    // General application logs
    new winston.transports.File({
      filename: path.join(logDir, 'enterprise-directory.log'),
      maxsize: config.logging.maxSize || '100m',
      maxFiles: config.logging.maxFiles || 10,
      tailable: true
    }),

    // Error logs
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      maxsize: '100m',
      maxFiles: 5,
      tailable: true
    })
  ]
});

// Audit logger for compliance and security
const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        type: 'audit',
        message,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'audit.log'),
      maxsize: '100m',
      maxFiles: 10,
      tailable: true
    })
  ]
});

// Security logger for authentication and authorization events
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        type: 'security',
        message,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'security.log'),
      maxsize: '100m',
      maxFiles: 15,
      tailable: true
    })
  ]
});

// Performance logger for monitoring
const performanceLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'performance.log'),
      maxsize: '50m',
      maxFiles: 5,
      tailable: true
    })
  ]
});

// LDAP operation logger
const ldapLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        component: 'ldap',
        message,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'ldap.log'),
      maxsize: '50m',
      maxFiles: 5,
      tailable: true
    })
  ]
});

// Kerberos logger
const kerberosLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        component: 'kerberos',
        message,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'kerberos.log'),
      maxsize: '50m',
      maxFiles: 5,
      tailable: true
    })
  ]
});

// Group Policy logger
const policyLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        component: 'group-policy',
        message,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'group-policy.log'),
      maxsize: '50m',
      maxFiles: 5,
      tailable: true
    })
  ]
});

// DNS logger
const dnsLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        component: 'dns',
        message,
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'dns.log'),
      maxsize: '25m',
      maxFiles: 3,
      tailable: true
    })
  ]
});

// Helper functions for structured logging
const logHelpers = {
  // Authentication events
  logAuthSuccess: (username, method, clientIP, details = {}) => {
    securityLogger.info('Authentication successful', {
      username,
      method,
      clientIP,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  logAuthFailure: (username, method, clientIP, reason, details = {}) => {
    securityLogger.warn('Authentication failed', {
      username,
      method,
      clientIP,
      reason,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Authorization events
  logAuthzSuccess: (username, resource, action, details = {}) => {
    auditLogger.info('Authorization granted', {
      username,
      resource,
      action,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  logAuthzFailure: (username, resource, action, reason, details = {}) => {
    securityLogger.warn('Authorization denied', {
      username,
      resource,
      action,
      reason,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Admin actions
  logAdminAction: (adminUser, action, target, details = {}) => {
    auditLogger.info('Administrative action', {
      adminUser,
      action,
      target,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // LDAP operations
  logLDAPOperation: (operation, baseDN, filter, clientIP, username, success = true, details = {}) => {
    ldapLogger.info(`LDAP ${operation}`, {
      operation,
      baseDN,
      filter,
      clientIP,
      username,
      success,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Kerberos events
  logKerberosEvent: (event, principal, clientIP, success = true, details = {}) => {
    kerberosLogger.info(`Kerberos ${event}`, {
      event,
      principal,
      clientIP,
      success,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Group Policy events
  logPolicyEvent: (event, target, policy, username, details = {}) => {
    policyLogger.info(`Group Policy ${event}`, {
      event,
      target,
      policy,
      username,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // DNS events
  logDNSQuery: (query, type, clientIP, response, details = {}) => {
    dnsLogger.info('DNS query', {
      query,
      type,
      clientIP,
      response,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Performance tracking
  logPerformance: (operation, duration, details = {}) => {
    performanceLogger.info('Performance metric', {
      operation,
      duration,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Error logging with context
  logError: (error, context = {}) => {
    logger.error('Application error', {
      error: error.message,
      stack: error.stack,
      context,
      timestamp: new Date().toISOString()
    });
  }
};

// Add performance tracking middleware
const performanceMiddleware = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logHelpers.logPerformance(`${req.method} ${req.path}`, duration, {
      statusCode: res.statusCode,
      userAgent: req.headers['user-agent'],
      clientIP: req.ip
    });
  });
  
  next();
};

module.exports = {
  logger,
  auditLogger,
  securityLogger,
  performanceLogger,
  ldapLogger,
  kerberosLogger,
  policyLogger,
  dnsLogger,
  logHelpers,
  performanceMiddleware
};