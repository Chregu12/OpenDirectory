'use strict';

// ---------------------------------------------------------------------------
// Central configuration — all values come from environment variables with
// sensible defaults so the service works out-of-the-box without any .env file.
// ---------------------------------------------------------------------------

const env = (key, defaultValue) => process.env[key] ?? defaultValue;
const envInt = (key, defaultValue) => parseInt(process.env[key] ?? String(defaultValue), 10);

module.exports = {
  // Service identity
  version: env('SERVICE_VERSION', '1.0.0'),
  environment: env('NODE_ENV', 'development'),

  // HTTP / WebSocket server
  port: envInt('PORT', 3009),

  // CORS
  cors: {
    origins: (env('CORS_ORIGINS', 'http://localhost:3000,http://localhost:3001'))
      .split(',')
      .map((s) => s.trim()),
  },

  // PostgreSQL (optional; services fall back to in-memory when not configured)
  database: {
    host: env('DB_HOST', 'localhost'),
    port: envInt('DB_PORT', 5432),
    name: env('DB_NAME', 'monitoring'),
    user: env('DB_USER', 'postgres'),
    password: env('DB_PASSWORD', ''),
    ssl: env('DB_SSL', 'false') === 'true',
    poolMin: envInt('DB_POOL_MIN', 2),
    poolMax: envInt('DB_POOL_MAX', 10),
  },

  // Redis (optional)
  redis: {
    host: env('REDIS_HOST', 'localhost'),
    port: envInt('REDIS_PORT', 6379),
    password: env('REDIS_PASSWORD', ''),
    db: envInt('REDIS_DB', 0),
  },

  // Time-series retention (milliseconds)
  timeSeries: {
    defaultRetentionMs: envInt('TS_RETENTION_MS', 7 * 24 * 60 * 60 * 1000), // 7 days
    cleanupIntervalMs: envInt('TS_CLEANUP_INTERVAL_MS', 60 * 60 * 1000),     // 1 hour
  },

  // Real-time broadcasting
  realTime: {
    metricsInterval: envInt('REALTIME_METRICS_INTERVAL_MS', 5000), // 5 s
  },

  // Anomaly detection
  anomalyDetection: {
    interval: envInt('ANOMALY_DETECTION_INTERVAL_MS', 60000), // 1 min
    sensitivitySigma: parseFloat(env('ANOMALY_SENSITIVITY_SIGMA', '3')),
  },

  // Predictive analytics
  predictiveAnalytics: {
    interval: envInt('PREDICTIVE_ANALYTICS_INTERVAL_MS', 5 * 60 * 1000), // 5 min
  },

  // SLA monitoring
  sla: {
    checkInterval: envInt('SLA_CHECK_INTERVAL_MS', 60000), // 1 min
  },

  // Logging
  logging: {
    level: env('LOG_LEVEL', 'info'),
    cleanupInterval: envInt('LOG_CLEANUP_INTERVAL_MS', 24 * 60 * 60 * 1000), // 24 h
    retentionDays: envInt('LOG_RETENTION_DAYS', 30),
  },

  // Cost analysis
  costAnalysis: {
    reportInterval: envInt('COST_REPORT_INTERVAL_MS', 60 * 60 * 1000), // 1 h
    currency: env('COST_CURRENCY', 'USD'),
  },

  // Notification channels
  notifications: {
    email: {
      host: env('SMTP_HOST', 'localhost'),
      port: envInt('SMTP_PORT', 587),
      secure: env('SMTP_SECURE', 'false') === 'true',
      user: env('SMTP_USER', ''),
      password: env('SMTP_PASSWORD', ''),
      from: env('SMTP_FROM', 'monitoring@opendirectory.local'),
    },
    slack: {
      defaultWebhookUrl: env('SLACK_WEBHOOK_URL', ''),
    },
  },

  // Internal service URLs used by the health-checker
  services: {
    authService: env('AUTH_SERVICE_URL', 'http://authentication-service'),
    userService: env('USER_SERVICE_URL', 'http://identity-service'),
    deviceService: env('DEVICE_SERVICE_URL', 'http://device-service'),
    policyService: env('POLICY_SERVICE_URL', 'http://policy-service'),
    apiGateway: env('API_GATEWAY_URL', 'http://api-gateway'),
  },
};
