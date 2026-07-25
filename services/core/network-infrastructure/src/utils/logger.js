'use strict';

// Was missing from the repo entirely — src/index.js has always required
// './utils/logger' and './utils/config', but neither file existed, so this
// service could never actually `require()` successfully (see also
// ./config.js). Not part of the auth work; added as the minimum plumbing
// needed to make the service loadable/testable at all.

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
  ],
  // Don't let logging itself throw/crash the process on a bad log call.
  exitOnError: false,
});

module.exports = logger;
