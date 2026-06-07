'use strict';

const winston = require('winston');

const { combine, timestamp, errors, json, colorize, simple } = winston.format;

const isProduction = process.env.NODE_ENV === 'production';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug'),
  format: combine(
    timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    errors({ stack: true }),
    json()
  ),
  defaultMeta: { service: 'monitoring-service' },
  transports: [
    new winston.transports.Console({
      format: isProduction
        ? combine(timestamp(), json())
        : combine(colorize(), simple()),
    }),
  ],
});

// Convenience wrapper so callers can do logger.info('msg', { key: val }) or
// logger.info('msg', errorObj) and both work correctly.
const wrap = (level) => (message, ...args) => {
  if (args.length === 0) {
    logger[level](message);
    return;
  }
  const [first, ...rest] = args;
  if (first && typeof first === 'object' && !(first instanceof Error)) {
    logger[level](message, { ...first, ...(rest[0] || {}) });
  } else {
    logger[level](message, { meta: first });
  }
};

module.exports = {
  error: wrap('error'),
  warn: wrap('warn'),
  info: wrap('info'),
  debug: wrap('debug'),
  http: wrap('http'),
  // Expose the underlying winston logger for stream usage
  stream: {
    write: (message) => logger.http(message.trim()),
  },
};
