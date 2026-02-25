const path = require('path');
const fs = require('fs');

// Load environment-specific configuration
const NODE_ENV = process.env.NODE_ENV || 'development';
const configFile = path.join(__dirname, `${NODE_ENV}.json`);

let envConfig = {};
if (fs.existsSync(configFile)) {
    envConfig = require(configFile);
}

// Base configuration
const config = {
    // Server configuration
    port: process.env.PORT || 3000,
    host: process.env.HOST || '0.0.0.0',
    nodeEnv: NODE_ENV,

    // Service identification
    serviceName: 'update-management',
    version: require('../../package.json').version || '1.0.0',

    // Database configuration
    database: {
        url: process.env.DATABASE_URL || 'postgresql://admin:password@localhost:5432/opendirectory',
        poolSize: parseInt(process.env.DB_POOL_SIZE) || 10,
        connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000,
        idleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT) || 300000,
        ssl: process.env.DB_SSL === 'true',
        retryAttempts: parseInt(process.env.DB_RETRY_ATTEMPTS) || 3,
        retryDelay: parseInt(process.env.DB_RETRY_DELAY) || 1000
    },

    // Redis configuration for caching and sessions
    redis: {
        url: process.env.REDIS_URL || 'redis://localhost:6379',
        ttl: parseInt(process.env.REDIS_TTL) || 3600, // 1 hour default
        keyPrefix: process.env.REDIS_KEY_PREFIX || 'opendirectory:update-mgmt:',
        maxRetries: parseInt(process.env.REDIS_MAX_RETRIES) || 3,
        retryDelayOnFailover: parseInt(process.env.REDIS_RETRY_DELAY) || 1000
    },

    // Authentication and authorization
    auth: {
        jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production',
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
        refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d',
        saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10,
        sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 3600000, // 1 hour
        maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
        lockoutTime: parseInt(process.env.LOCKOUT_TIME) || 900000 // 15 minutes
    },

    // CORS configuration
    cors: {
        allowedOrigins: process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',')
            : ['http://localhost:3000', 'http://localhost:8080'],
        credentials: process.env.CORS_CREDENTIALS === 'true' || true,
        maxAge: parseInt(process.env.CORS_MAX_AGE) || 86400 // 24 hours
    },

    // Rate limiting
    rateLimiting: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 900000, // 15 minutes
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX) || 1000,
        skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESS === 'true',
        skipFailedRequests: process.env.RATE_LIMIT_SKIP_FAILED === 'true'
    },

    // Logging configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        fileRotation: process.env.LOG_FILE_ROTATION === 'true' || true,
        maxFileSize: process.env.LOG_MAX_FILE_SIZE || '20m',
        maxFiles: process.env.LOG_MAX_FILES || '14d',
        auditLogRetention: process.env.AUDIT_LOG_RETENTION || '2555d' // 7 years
    },

    // External service integrations
    integrations: {
        // Microsoft Graph API for Azure AD integration
        microsoftGraph: {
            clientId: process.env.MICROSOFT_CLIENT_ID,
            clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
            tenantId: process.env.MICROSOFT_TENANT_ID,
            scope: process.env.MICROSOFT_SCOPE || 'https://graph.microsoft.com/.default'
        },

        // Apple Business Manager for iOS/macOS
        appleBusiness: {
            orgId: process.env.APPLE_ORG_ID,
            keyId: process.env.APPLE_KEY_ID,
            privateKey: process.env.APPLE_PRIVATE_KEY,
            issuerId: process.env.APPLE_ISSUER_ID
        },

        // Google Workspace for Android Enterprise
        googleWorkspace: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            projectId: process.env.GOOGLE_PROJECT_ID,
            serviceAccountKey: process.env.GOOGLE_SERVICE_ACCOUNT_KEY
        },

        // Webhook endpoints for external integrations
        webhooks: {
            baseUrl: process.env.WEBHOOK_BASE_URL || 'https://api.opendirectory.local',
            secret: process.env.WEBHOOK_SECRET || 'webhook-secret-change-this',
            timeout: parseInt(process.env.WEBHOOK_TIMEOUT) || 30000,
            retryAttempts: parseInt(process.env.WEBHOOK_RETRY_ATTEMPTS) || 3
        }
    },

    // Storage configuration
    storage: {
        type: process.env.STORAGE_TYPE || 'local', // local, s3, azure, gcs
        local: {
            basePath: process.env.STORAGE_LOCAL_PATH || path.join(__dirname, '../../storage')
        },
        s3: {
            region: process.env.AWS_REGION || 'us-east-1',
            bucket: process.env.AWS_S3_BUCKET,
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
            presignedUrlExpiry: parseInt(process.env.S3_PRESIGNED_URL_EXPIRY) || 3600
        },
        azure: {
            accountName: process.env.AZURE_STORAGE_ACCOUNT_NAME,
            accountKey: process.env.AZURE_STORAGE_ACCOUNT_KEY,
            containerName: process.env.AZURE_STORAGE_CONTAINER
        }
    },

    // Email configuration for notifications
    email: {
        provider: process.env.EMAIL_PROVIDER || 'smtp', // smtp, sendgrid, ses
        smtp: {
            host: process.env.SMTP_HOST || 'localhost',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true',
            username: process.env.SMTP_USERNAME,
            password: process.env.SMTP_PASSWORD
        },
        sendgrid: {
            apiKey: process.env.SENDGRID_API_KEY
        },
        aws: {
            region: process.env.AWS_SES_REGION || 'us-east-1',
            accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY
        },
        from: process.env.EMAIL_FROM || 'noreply@opendirectory.local',
        templates: {
            basePath: path.join(__dirname, '../templates/email')
        }
    },

    // Monitoring and observability
    monitoring: {
        enabled: process.env.MONITORING_ENABLED === 'true' || NODE_ENV === 'production',
        metricsPort: parseInt(process.env.METRICS_PORT) || 9090,
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000,
        
        // Prometheus metrics
        prometheus: {
            enabled: process.env.PROMETHEUS_ENABLED === 'true',
            endpoint: process.env.PROMETHEUS_ENDPOINT || '/metrics',
            prefix: process.env.PROMETHEUS_PREFIX || 'opendirectory_update_mgmt_'
        },

        // Application Performance Monitoring
        apm: {
            enabled: process.env.APM_ENABLED === 'true',
            serviceName: process.env.APM_SERVICE_NAME || 'update-management',
            serverUrl: process.env.APM_SERVER_URL,
            secretToken: process.env.APM_SECRET_TOKEN
        }
    },

    // Security configuration
    security: {
        // Encryption settings
        encryption: {
            algorithm: process.env.ENCRYPTION_ALGORITHM || 'aes-256-gcm',
            keyDerivation: process.env.KEY_DERIVATION || 'pbkdf2',
            keyLength: parseInt(process.env.KEY_LENGTH) || 32,
            ivLength: parseInt(process.env.IV_LENGTH) || 16
        },

        // Content Security Policy
        csp: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"]
            }
        },

        // API security
        api: {
            enableApiKey: process.env.API_KEY_ENABLED === 'true',
            apiKeyHeader: process.env.API_KEY_HEADER || 'X-API-Key',
            requireHttps: process.env.REQUIRE_HTTPS === 'true' || NODE_ENV === 'production',
            allowedIpRanges: process.env.ALLOWED_IP_RANGES 
                ? process.env.ALLOWED_IP_RANGES.split(',')
                : []
        }
    },

    // Feature flags
    features: {
        windowsUpdateManagement: process.env.FEATURE_WINDOWS_UPDATES !== 'false',
        macosUpdateManagement: process.env.FEATURE_MACOS_UPDATES !== 'false',
        linuxUpdateManagement: process.env.FEATURE_LINUX_UPDATES !== 'false',
        remoteActions: process.env.FEATURE_REMOTE_ACTIONS !== 'false',
        updateRings: process.env.FEATURE_UPDATE_RINGS !== 'false',
        mobileApplicationManagement: process.env.FEATURE_MAM !== 'false',
        termsOfUseEnforcement: process.env.FEATURE_TERMS_OF_USE !== 'false',
        multiTenantSupport: process.env.FEATURE_MULTI_TENANT !== 'false',
        advancedReporting: process.env.FEATURE_ADVANCED_REPORTING !== 'false',
        apiDocumentation: process.env.FEATURE_API_DOCS !== 'false'
    },

    // Performance tuning
    performance: {
        maxRequestSize: process.env.MAX_REQUEST_SIZE || '10mb',
        compressionLevel: parseInt(process.env.COMPRESSION_LEVEL) || 6,
        keepAliveTimeout: parseInt(process.env.KEEP_ALIVE_TIMEOUT) || 5000,
        headersTimeout: parseInt(process.env.HEADERS_TIMEOUT) || 60000,
        maxHeadersCount: parseInt(process.env.MAX_HEADERS_COUNT) || 2000,
        
        // Caching
        cache: {
            defaultTtl: parseInt(process.env.CACHE_DEFAULT_TTL) || 3600,
            maxKeys: parseInt(process.env.CACHE_MAX_KEYS) || 10000
        }
    },

    // Development and testing
    development: {
        enableDebugLogging: process.env.DEBUG_LOGGING === 'true' || NODE_ENV === 'development',
        enableHotReload: process.env.HOT_RELOAD === 'true',
        mockExternalServices: process.env.MOCK_EXTERNAL_SERVICES === 'true',
        seedTestData: process.env.SEED_TEST_DATA === 'true'
    }
};

// Merge environment-specific configuration
const finalConfig = {
    ...config,
    ...envConfig
};

// Validate required configuration
const validateConfig = () => {
    const required = ['port', 'jwtSecret'];
    const missing = required.filter(key => !getNestedValue(finalConfig, key));
    
    if (missing.length > 0) {
        throw new Error(`Missing required configuration: ${missing.join(', ')}`);
    }

    // Validate JWT secret in production
    if (NODE_ENV === 'production' && finalConfig.auth.jwtSecret === 'your-super-secret-jwt-key-change-this-in-production') {
        throw new Error('JWT_SECRET must be set in production environment');
    }

    // Validate database URL
    if (!finalConfig.database.url) {
        throw new Error('DATABASE_URL must be configured');
    }
};

// Helper function to get nested configuration values
const getNestedValue = (obj, path) => {
    return path.split('.').reduce((current, key) => current && current[key], obj);
};

// Validate configuration on module load
try {
    validateConfig();
} catch (error) {
    console.error('Configuration validation failed:', error.message);
    process.exit(1);
}

// Export configuration
module.exports = finalConfig;

// Helper function to get configuration values with fallback
module.exports.get = (path, fallback = null) => {
    const value = getNestedValue(finalConfig, path);
    return value !== undefined ? value : fallback;
};

// Helper function to check if a feature is enabled
module.exports.isFeatureEnabled = (feature) => {
    return finalConfig.features[feature] === true;
};