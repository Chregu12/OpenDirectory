'use strict';

require('dotenv').config();

const config = {
  environment: process.env.NODE_ENV || 'development',

  server: {
    port: parseInt(process.env.PORT, 10) || 3001,
    host: process.env.HOST || '0.0.0.0',
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'changeme-jwt-secret-at-least-32-chars!!',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    tempExpiresIn: process.env.JWT_TEMP_EXPIRES_IN || '5m',
    resetExpiresIn: process.env.JWT_RESET_EXPIRES_IN || '1h',
    issuer: process.env.JWT_ISSUER || 'opendirectory',
    audience: process.env.JWT_AUDIENCE || 'opendirectory-clients',
  },

  session: {
    secret: process.env.SESSION_SECRET || 'changeme-session-secret-32-chars!!',
    maxAge: parseInt(process.env.SESSION_MAX_AGE, 10) || 24 * 60 * 60 * 1000, // 24h
    ttl: parseInt(process.env.SESSION_TTL, 10) || 86400, // seconds for Redis
  },

  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    password: process.env.REDIS_PASSWORD || undefined,
    db: parseInt(process.env.REDIS_DB, 10) || 0,
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'auth:',
  },

  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    name: process.env.DB_NAME || 'opendirectory',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    ssl: process.env.DB_SSL === 'true',
    poolMin: parseInt(process.env.DB_POOL_MIN, 10) || 2,
    poolMax: parseInt(process.env.DB_POOL_MAX, 10) || 10,
  },

  ldap: {
    url: process.env.LDAP_URL || 'ldap://localhost:389',
    bindDN: process.env.LDAP_BIND_DN || 'cn=admin,dc=example,dc=com',
    bindPassword: process.env.LDAP_BIND_PASSWORD || '',
    searchBase: process.env.LDAP_SEARCH_BASE || 'dc=example,dc=com',
    searchFilter: process.env.LDAP_SEARCH_FILTER || '(uid={{username}})',
    syncNewUsers: process.env.LDAP_SYNC_NEW_USERS === 'true',
  },

  cors: {
    origins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim()),
  },

  zeroTrust: {
    enabled: process.env.ZERO_TRUST_ENABLED !== 'false',
    minTrustScore: parseInt(process.env.ZERO_TRUST_MIN_SCORE, 10) || 30,
  },

  mfa: {
    enabled: process.env.MFA_ENABLED !== 'false',
    issuer: process.env.MFA_ISSUER || 'OpenDirectory',
    recoveryCodeCount: parseInt(process.env.MFA_RECOVERY_CODE_COUNT, 10) || 10,
  },

  frontend: {
    url: process.env.FRONTEND_URL || 'http://localhost:3000',
  },

  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
    suspiciousCountries: (process.env.SUSPICIOUS_COUNTRIES || '').split(',').filter(Boolean),
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH, 10) || 8,
    passwordMaxLength: parseInt(process.env.PASSWORD_MAX_LENGTH, 10) || 128,
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
    lockDuration: parseInt(process.env.LOCK_DURATION_MS, 10) || 15 * 60 * 1000, // 15m
  },

  sso: {
    providers: (process.env.SSO_PROVIDERS || '').split(',').filter(Boolean),
  },

  email: {
    host: process.env.SMTP_HOST || 'localhost',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER || '',
    password: process.env.SMTP_PASSWORD || '',
    from: process.env.EMAIL_FROM || 'noreply@opendirectory.local',
  },
};

module.exports = config;
