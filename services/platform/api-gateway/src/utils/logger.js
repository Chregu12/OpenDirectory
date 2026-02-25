const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize(),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    let logMessage = `${timestamp} [${level}]: ${message}`;
    
    if (Object.keys(meta).length > 0) {
      // Pretty print metadata for console
      const metaStr = JSON.stringify(meta, null, 2);
      logMessage += `\n${metaStr}`;
    }
    
    return logMessage;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create the logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: fileFormat,
  defaultMeta: {
    service: 'api-gateway',
    version: '2.0.0'
  },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: consoleFormat,
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug'
    }),
    
    // File transport for all logs
    new DailyRotateFile({
      filename: path.join(logsDir, 'api-gateway-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      format: fileFormat
    }),
    
    // File transport for error logs only
    new DailyRotateFile({
      filename: path.join(logsDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: '20m',
      maxFiles: '30d',
      format: fileFormat
    }),
    
    // File transport for access logs (requests)
    new DailyRotateFile({
      filename: path.join(logsDir, 'access-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'http',
      maxSize: '50m',
      maxFiles: '7d',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, message, ...meta }) => {
          return JSON.stringify({
            timestamp,
            type: 'access',
            message,
            ...meta
          });
        })
      )
    })
  ],
  
  // Handle exceptions and rejections
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'exceptions.log')
    })
  ],
  
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'rejections.log')
    })
  ]
});

// Add custom logging methods
logger.access = (message, meta = {}) => {
  logger.log('http', message, meta);
};

logger.security = (message, meta = {}) => {
  logger.warn(`🔒 SECURITY: ${message}`, {
    ...meta,
    type: 'security',
    timestamp: new Date().toISOString()
  });
};

logger.performance = (message, meta = {}) => {
  logger.info(`⚡ PERFORMANCE: ${message}`, {
    ...meta,
    type: 'performance'
  });
};

logger.discovery = (message, meta = {}) => {
  logger.info(`🔍 DISCOVERY: ${message}`, {
    ...meta,
    type: 'discovery'
  });
};

logger.gateway = (message, meta = {}) => {
  logger.info(`🚪 GATEWAY: ${message}`, {
    ...meta,
    type: 'gateway'
  });
};

// Create a request logger middleware
logger.createRequestLogger = () => {
  return (req, res, next) => {
    const startTime = Date.now();
    const originalSend = res.send;
    
    res.send = function(data) {
      const duration = Date.now() - startTime;
      const contentLength = Buffer.byteLength(data || '', 'utf8');
      
      logger.access(`${req.method} ${req.originalUrl}`, {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        duration,
        contentLength,
        userAgent: req.headers['user-agent'],
        ip: req.ip || req.connection.remoteAddress,
        requestId: req.id,
        serviceId: req.serviceId,
        referer: req.headers.referer
      });
      
      return originalSend.call(this, data);
    };
    
    next();
  };
};

// Error logging helper
logger.logError = (error, context = {}) => {
  logger.error(error.message, {
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code
    },
    ...context,
    timestamp: new Date().toISOString()
  });
};

// Performance logging helper
logger.logPerformance = (operation, duration, metadata = {}) => {
  const level = duration > 5000 ? 'warn' : duration > 1000 ? 'info' : 'debug';
  
  logger[level](`Performance: ${operation} took ${duration}ms`, {
    operation,
    duration,
    slow: duration > 1000,
    verySlow: duration > 5000,
    ...metadata
  });
};

// Service discovery logging helpers
logger.serviceDiscovered = (service) => {
  logger.discovery(`Service discovered: ${service.name}`, {
    serviceId: service.id,
    port: service.port,
    version: service.version,
    capabilities: service.metadata?.capabilities || []
  });
};

logger.serviceRemoved = (service) => {
  logger.discovery(`Service removed: ${service.name}`, {
    serviceId: service.id,
    port: service.port,
    reason: 'unreachable'
  });
};

logger.serviceHealthChanged = (serviceId, oldStatus, newStatus) => {
  const level = newStatus === 'healthy' ? 'info' : 'warn';
  logger[level](`Service health changed: ${serviceId}`, {
    serviceId,
    oldStatus,
    newStatus,
    timestamp: new Date().toISOString()
  });
};

// Structured logging for different log levels
logger.trace = (message, meta = {}) => logger.log('silly', message, meta);
logger.verbose = (message, meta = {}) => logger.log('verbose', message, meta);

// Export the configured logger
module.exports = logger;