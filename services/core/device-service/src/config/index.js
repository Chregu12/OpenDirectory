'use strict';

module.exports = {
  environment: process.env.NODE_ENV || 'development',
  version: process.env.npm_package_version || '1.0.0',

  cors: {
    origins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',')
  },

  compliance: {
    scanInterval: parseInt(process.env.COMPLIANCE_SCAN_INTERVAL) || 300000 // 5 min
  },

  security: {
    threatScanInterval: parseInt(process.env.THREAT_SCAN_INTERVAL) || 60000 // 1 min
  },

  certificates: {
    renewalCheckInterval: parseInt(process.env.CERT_RENEWAL_INTERVAL) || 3600000 // 1 hr
  },

  analytics: {
    aggregationInterval: parseInt(process.env.ANALYTICS_INTERVAL) || 60000 // 1 min
  },

  mdm: {
    // Optional MDM push endpoint. If set, remote actions will attempt an HTTP push.
    pushUrl: process.env.MDM_PUSH_URL || null,
    pushToken: process.env.MDM_PUSH_TOKEN || null
  },

  database: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/device-management'
  },

  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  }
};
