'use strict';

const winston = require('winston');
require('winston-daily-rotate-file');

const logLevel = process.env.LOG_LEVEL || 'info';

const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'audit-service' },
  transports: [
    new winston.transports.Console({
      format: process.env.NODE_ENV === 'production'
        ? winston.format.json()
        : winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
    }),
  ],
});

if (process.env.LOG_FILE_ENABLED === 'true') {
  logger.add(new winston.transports.DailyRotateFile({
    filename: 'logs/audit-service-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '100m',
    maxFiles: '90d',
  }));

  logger.add(new winston.transports.DailyRotateFile({
    filename: 'logs/audit-service-error-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    level: 'error',
    zippedArchive: true,
    maxSize: '50m',
    maxFiles: '180d',
  }));
}

module.exports = logger;
