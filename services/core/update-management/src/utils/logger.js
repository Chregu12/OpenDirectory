const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({
        format: 'HH:mm:ss'
    }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let msg = `${timestamp} [${level}]: ${message}`;
        if (Object.keys(meta).length > 0) {
            msg += ' ' + JSON.stringify(meta);
        }
        return msg;
    })
);

// Create the logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: {
        service: 'update-management',
        version: require('../../package.json').version || '1.0.0'
    },
    transports: [
        // Error log file
        new DailyRotateFile({
            filename: path.join(logsDir, 'error-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            maxSize: '20m',
            maxFiles: '14d',
            zippedArchive: true
        }),

        // Combined log file
        new DailyRotateFile({
            filename: path.join(logsDir, 'combined-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            zippedArchive: true
        }),

        // Audit log file for security events
        new DailyRotateFile({
            filename: path.join(logsDir, 'audit-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'info',
            maxSize: '50m',
            maxFiles: '365d', // Keep audit logs for 1 year
            zippedArchive: true,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        })
    ],
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

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: consoleFormat,
        level: process.env.LOG_LEVEL || 'debug'
    }));
}

// Add production-specific transports
if (process.env.NODE_ENV === 'production') {
    // Add syslog transport for production environments
    // logger.add(new winston.transports.Syslog({
    //     level: 'info',
    //     facility: 'local0'
    // }));

    // Add external log aggregation service
    // Example: Elasticsearch, LogDNA, Splunk, etc.
    if (process.env.ELASTICSEARCH_URL) {
        const { ElasticsearchTransport } = require('winston-elasticsearch');
        logger.add(new ElasticsearchTransport({
            level: 'info',
            clientOpts: {
                node: process.env.ELASTICSEARCH_URL,
                auth: {
                    username: process.env.ELASTICSEARCH_USERNAME,
                    password: process.env.ELASTICSEARCH_PASSWORD
                }
            },
            index: 'opendirectory-update-management',
            indexPrefix: 'opendirectory',
            indexSuffixPattern: 'YYYY.MM.DD'
        }));
    }
}

// Create specialized loggers for different use cases
const createChildLogger = (module) => {
    return logger.child({ module });
};

// Audit logger for security and compliance events
const auditLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: {
        service: 'update-management',
        type: 'audit'
    },
    transports: [
        new DailyRotateFile({
            filename: path.join(logsDir, 'audit-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '50m',
            maxFiles: '2555d', // Keep audit logs for 7 years for compliance
            zippedArchive: true
        })
    ]
});

// Performance logger for monitoring and optimization
const performanceLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: {
        service: 'update-management',
        type: 'performance'
    },
    transports: [
        new DailyRotateFile({
            filename: path.join(logsDir, 'performance-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            zippedArchive: true
        })
    ]
});

// Helper functions for structured logging
const logRequest = (req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = {
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            duration,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            userId: req.user?.id,
            tenantId: req.tenantId,
            requestId: req.id
        };

        if (res.statusCode >= 400) {
            logger.warn('HTTP Error Response', logData);
        } else {
            logger.info('HTTP Request', logData);
        }

        // Log performance metrics
        performanceLogger.info('HTTP Performance', {
            ...logData,
            timestamp: new Date().toISOString()
        });
    });

    next();
};

const logError = (error, req = null) => {
    const errorData = {
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
    };

    if (req) {
        errorData.request = {
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            userId: req.user?.id,
            tenantId: req.tenantId
        };
    }

    logger.error('Application Error', errorData);
};

const logAuditEvent = (event, data, user = null) => {
    const auditData = {
        event,
        data,
        user: user ? {
            id: user.id,
            username: user.username,
            email: user.email
        } : null,
        timestamp: new Date().toISOString(),
        ip: data.ip || null,
        userAgent: data.userAgent || null,
        tenantId: data.tenantId || null
    };

    auditLogger.info('Audit Event', auditData);
};

const logPerformanceMetric = (metric, value, tags = {}) => {
    performanceLogger.info('Performance Metric', {
        metric,
        value,
        tags,
        timestamp: new Date().toISOString()
    });
};

// Export logger and helper functions
module.exports = {
    logger,
    createChildLogger,
    auditLogger,
    performanceLogger,
    logRequest,
    logError,
    logAuditEvent,
    logPerformanceMetric
};

// For backward compatibility, export logger as default
module.exports.default = logger;