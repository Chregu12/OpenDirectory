'use strict';

// Was missing from the repo entirely — see ./logger.js for the same note.
// Values below match the defaults that were already hardcoded inline at
// each `config.x || <default>` call site in src/index.js; this just gives
// them a single, env-var-configurable home.

const environment = process.env.NODE_ENV || 'development';

module.exports = {
  environment,

  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || undefined,
  },

  cors: {
    allowedOrigins: process.env.CORS_ALLOWED_ORIGINS
      ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
      : ['http://localhost:3000'],
  },

  // WEBSOCKET_PORT is new (not previously configurable — the port was
  // hardcoded to 8081). Lets the e2e test suite bind to an OS-assigned free
  // port (0) instead of colliding with a real instance or other test runs.
  websocket: {
    port: parseInt(process.env.WEBSOCKET_PORT || '8081', 10),
  },

  cluster: {
    maxWorkers: parseInt(process.env.CLUSTER_MAX_WORKERS || '4', 10),
  },
};
