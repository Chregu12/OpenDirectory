const winston = require('winston');
const path = require('path');

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize(),
  winston.format.printf(({ level, message, timestamp, stack }) => {
    return `${timestamp} [${level}] ${stack || message}`;
  })
);

// Create logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'api-gateway' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: logFormat
    }),

    // File transport for errors
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIR || '/tmp', 'api-gateway-error.log'),
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),

    // File transport for all logs
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIR || '/tmp', 'api-gateway.log'),
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ],

  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIR || '/tmp', 'api-gateway-exceptions.log')
    })
  ],

  // Handle unhandled rejections
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIR || '/tmp', 'api-gateway-rejections.log')
    })
  ]
});

// Add custom log methods
logger.request = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`, {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
  });

  next();
};

logger.security = (event, details) => {
  logger.warn(`Security Event: ${event}`, {
    event,
    ...details,
    timestamp: new Date().toISOString()
  });
};

logger.performance = (operation, duration, metadata = {}) => {
  logger.info(`Performance: ${operation} took ${duration}ms`, {
    operation,
    duration,
    ...metadata
  });
};

module.exports = logger;