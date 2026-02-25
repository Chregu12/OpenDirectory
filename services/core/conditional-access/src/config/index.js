/**
 * Conditional Access Service Configuration
 */

module.exports = {
    // Service configuration
    service: {
        name: 'conditional-access',
        version: '1.0.0',
        port: process.env.PORT || 3007,
        environment: process.env.NODE_ENV || 'development'
    },

    // Database configuration
    database: {
        mongodb: {
            url: process.env.MONGODB_URL || 'mongodb://localhost:27017/conditional-access',
            options: {
                useNewUrlParser: true,
                useUnifiedTopology: true
            }
        },
        redis: {
            host: process.env.REDIS_HOST || 'localhost',
            port: process.env.REDIS_PORT || 6379,
            password: process.env.REDIS_PASSWORD,
            db: process.env.REDIS_DB || 0
        }
    },

    // Security configuration
    security: {
        jwtSecret: process.env.JWT_SECRET || 'conditional-access-secret',
        encryptionKey: process.env.ENCRYPTION_KEY || 'default-encryption-key-change-me',
        sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 8 * 60 * 60 * 1000, // 8 hours
        maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
        lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 15 * 60 * 1000, // 15 minutes
        suspiciousCountries: (process.env.SUSPICIOUS_COUNTRIES || '').split(',').filter(Boolean),
        trustedNetworks: (process.env.TRUSTED_NETWORKS || '').split(',').filter(Boolean)
    },

    // Integration endpoints
    integrations: {
        enterpriseDirectory: {
            url: process.env.ENTERPRISE_DIRECTORY_URL || 'http://localhost:3003',
            apiKey: process.env.ENTERPRISE_DIRECTORY_API_KEY || 'default-api-key'
        },
        identityService: {
            url: process.env.IDENTITY_SERVICE_URL || 'http://localhost:3001',
            apiKey: process.env.IDENTITY_SERVICE_API_KEY || 'default-api-key'
        },
        deviceService: {
            url: process.env.DEVICE_SERVICE_URL || 'http://localhost:3004',
            apiKey: process.env.DEVICE_SERVICE_API_KEY || 'default-api-key'
        },
        notificationService: {
            url: process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:3005',
            apiKey: process.env.NOTIFICATION_SERVICE_API_KEY || 'default-api-key'
        },
        siemService: {
            url: process.env.SIEM_SERVICE_URL,
            apiKey: process.env.SIEM_API_KEY
        }
    },

    // Risk assessment configuration
    riskAssessment: {
        thresholds: {
            allow: parseFloat(process.env.RISK_THRESHOLD_ALLOW) || 0.3,
            requireMfa: parseFloat(process.env.RISK_THRESHOLD_MFA) || 0.5,
            requireStepUp: parseFloat(process.env.RISK_THRESHOLD_STEP_UP) || 0.7,
            block: parseFloat(process.env.RISK_THRESHOLD_BLOCK) || 0.9
        },
        weights: {
            user: parseFloat(process.env.RISK_WEIGHT_USER) || 0.2,
            device: parseFloat(process.env.RISK_WEIGHT_DEVICE) || 0.25,
            network: parseFloat(process.env.RISK_WEIGHT_NETWORK) || 0.2,
            application: parseFloat(process.env.RISK_WEIGHT_APPLICATION) || 0.15,
            behavioral: parseFloat(process.env.RISK_WEIGHT_BEHAVIORAL) || 0.15,
            temporal: parseFloat(process.env.RISK_WEIGHT_TEMPORAL) || 0.05
        }
    },

    // Device compliance configuration
    deviceCompliance: {
        checkInterval: parseInt(process.env.COMPLIANCE_CHECK_INTERVAL) || 60 * 60 * 1000, // 1 hour
        remediationTimeout: parseInt(process.env.REMEDIATION_TIMEOUT) || 24 * 60 * 60 * 1000, // 24 hours
        platforms: {
            windows: {
                minVersion: process.env.WINDOWS_MIN_VERSION || '10.0.19041',
                requiredFeatures: ['bitlocker', 'defender', 'firewall', 'updates']
            },
            macos: {
                minVersion: process.env.MACOS_MIN_VERSION || '12.0.0',
                requiredFeatures: ['filevault', 'firewall', 'gatekeeper', 'updates']
            },
            linux: {
                minVersion: process.env.LINUX_MIN_VERSION || '5.4.0',
                requiredFeatures: ['luks', 'firewall', 'selinux', 'updates']
            }
        }
    },

    // Encryption configuration
    encryption: {
        algorithms: {
            windows: process.env.WINDOWS_ENCRYPTION_ALGORITHM || 'AES-256',
            macos: process.env.MACOS_ENCRYPTION_ALGORITHM || 'AES-256',
            linux: process.env.LINUX_ENCRYPTION_ALGORITHM || 'AES-256'
        },
        keyLength: parseInt(process.env.ENCRYPTION_KEY_LENGTH) || 256,
        recoveryKeyRotationDays: parseInt(process.env.RECOVERY_KEY_ROTATION_DAYS) || 365,
        escrowService: {
            url: process.env.KEY_ESCROW_SERVICE_URL,
            apiKey: process.env.KEY_ESCROW_API_KEY
        }
    },

    // Autopilot deployment configuration
    deployment: {
        profiles: {
            defaultDuration: parseInt(process.env.DEPLOYMENT_DEFAULT_DURATION) || 60, // minutes
            maxDuration: parseInt(process.env.DEPLOYMENT_MAX_DURATION) || 180, // minutes
            retryAttempts: parseInt(process.env.DEPLOYMENT_RETRY_ATTEMPTS) || 3
        },
        repositories: {
            windows: process.env.WINDOWS_PACKAGE_REPO || 'https://packages.opendirectory.local/windows',
            macos: process.env.MACOS_PACKAGE_REPO || 'https://packages.opendirectory.local/macos',
            linux: process.env.LINUX_PACKAGE_REPO || 'https://packages.opendirectory.local/linux'
        }
    },

    // EDR configuration
    edr: {
        agents: {
            heartbeatInterval: parseInt(process.env.EDR_HEARTBEAT_INTERVAL) || 30000, // 30 seconds
            telemetryInterval: parseInt(process.env.EDR_TELEMETRY_INTERVAL) || 60000, // 1 minute
            quarantineTimeout: parseInt(process.env.EDR_QUARANTINE_TIMEOUT) || 24 * 60 * 60 * 1000 // 24 hours
        },
        threatDetection: {
            behaviorAnalysisEnabled: process.env.EDR_BEHAVIOR_ANALYSIS === 'true',
            mlDetectionEnabled: process.env.EDR_ML_DETECTION === 'true',
            signatureUpdatesEnabled: process.env.EDR_SIGNATURE_UPDATES === 'true'
        }
    },

    // PIM configuration
    pim: {
        sessions: {
            maxDuration: parseInt(process.env.PIM_MAX_DURATION) || 8 * 60 * 60 * 1000, // 8 hours
            monitoringEnabled: process.env.PIM_MONITORING_ENABLED === 'true',
            recordingEnabled: process.env.PIM_RECORDING_ENABLED === 'true'
        },
        approvals: {
            timeoutDuration: parseInt(process.env.PIM_APPROVAL_TIMEOUT) || 24 * 60 * 60 * 1000, // 24 hours
            requiredApprovers: parseInt(process.env.PIM_REQUIRED_APPROVERS) || 2
        }
    },

    // Emergency access configuration
    emergencyAccess: {
        maxDuration: parseInt(process.env.EMERGENCY_MAX_DURATION) || 4 * 60 * 60 * 1000, // 4 hours
        requiredApprovals: parseInt(process.env.EMERGENCY_REQUIRED_APPROVALS) || 2,
        monitoringEnabled: process.env.EMERGENCY_MONITORING_ENABLED === 'true',
        notificationChannels: (process.env.EMERGENCY_NOTIFICATION_CHANNELS || 'email,sms').split(',')
    },

    // Audit configuration
    audit: {
        retention: {
            authentication: parseInt(process.env.AUDIT_RETENTION_AUTH) || 2555, // 7 years
            privilegedAccess: parseInt(process.env.AUDIT_RETENTION_PIM) || 3650, // 10 years
            emergencyAccess: parseInt(process.env.AUDIT_RETENTION_EMERGENCY) || 3650, // 10 years
            general: parseInt(process.env.AUDIT_RETENTION_GENERAL) || 2555 // 7 years
        },
        encryption: {
            enabled: process.env.AUDIT_ENCRYPTION_ENABLED === 'true',
            keyRotationDays: parseInt(process.env.AUDIT_KEY_ROTATION_DAYS) || 90
        },
        forwarding: {
            siemEnabled: process.env.AUDIT_SIEM_ENABLED === 'true',
            splunkEnabled: process.env.AUDIT_SPLUNK_ENABLED === 'true',
            elasticsearchEnabled: process.env.AUDIT_ELASTICSEARCH_ENABLED === 'true'
        }
    },

    // Logging configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        format: process.env.LOG_FORMAT || 'json',
        destination: process.env.LOG_DESTINATION || 'file',
        maxFileSize: process.env.LOG_MAX_FILE_SIZE || '10MB',
        maxFiles: parseInt(process.env.LOG_MAX_FILES) || 5
    },

    // Rate limiting configuration
    rateLimiting: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX) || 1000, // 1000 requests per window
        skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESS === 'true'
    },

    // CORS configuration
    cors: {
        origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
        credentials: process.env.CORS_CREDENTIALS === 'true',
        methods: (process.env.CORS_METHODS || 'GET,HEAD,PUT,PATCH,POST,DELETE').split(','),
        allowedHeaders: (process.env.CORS_ALLOWED_HEADERS || 'Content-Type,Authorization,X-Requested-With,X-Device-ID,X-App-ID').split(',')
    },

    // Feature flags
    features: {
        mlRiskAssessment: process.env.FEATURE_ML_RISK_ASSESSMENT === 'true',
        behaviorAnalytics: process.env.FEATURE_BEHAVIOR_ANALYTICS === 'true',
        advancedThreatDetection: process.env.FEATURE_ADVANCED_THREAT_DETECTION === 'true',
        automaticRemediation: process.env.FEATURE_AUTOMATIC_REMEDIATION === 'true',
        realtimeMonitoring: process.env.FEATURE_REALTIME_MONITORING === 'true'
    }
};