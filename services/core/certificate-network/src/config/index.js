/**
 * OpenDirectory Certificate & Network Configuration Service
 * Main Configuration Module
 */

const path = require('path');
require('dotenv').config();

const config = {
    // Server Configuration
    server: {
        port: process.env.PORT || 3010,
        host: process.env.HOST || '0.0.0.0',
        environment: process.env.NODE_ENV || 'development',
        corsOrigin: process.env.CORS_ORIGIN || '*'
    },

    // PKI & Certificate Authority Configuration
    pki: {
        rootCAPath: process.env.ROOT_CA_PATH || '/var/lib/opendirectory/ca/root',
        intermediateCAPath: process.env.INTERMEDIATE_CA_PATH || '/var/lib/opendirectory/ca/intermediate',
        certificateStorePath: process.env.CERT_STORE_PATH || '/var/lib/opendirectory/certificates',
        crlPath: process.env.CRL_PATH || '/var/lib/opendirectory/crl',
        ocspPort: process.env.OCSP_PORT || 8080,
        keySize: parseInt(process.env.PKI_KEY_SIZE) || 2048,
        rootCAValidity: parseInt(process.env.ROOT_CA_VALIDITY) || (365 * 10), // 10 years
        intermediateCAValidity: parseInt(process.env.INTERMEDIATE_CA_VALIDITY) || (365 * 5), // 5 years
        leafCertValidity: parseInt(process.env.LEAF_CERT_VALIDITY) || 365, // 1 year
        crlUpdateInterval: parseInt(process.env.CRL_UPDATE_INTERVAL) || (24 * 60 * 60 * 1000), // 24 hours
        renewalThreshold: parseInt(process.env.RENEWAL_THRESHOLD) || 30, // days
        autoRenewal: process.env.AUTO_RENEWAL === 'true',
        hashAlgorithm: process.env.HASH_ALGORITHM || 'sha256'
    },

    // SCEP Configuration
    scep: {
        enabled: process.env.SCEP_ENABLED === 'true',
        endpoint: process.env.SCEP_ENDPOINT || '/scep',
        challengePassword: process.env.SCEP_CHALLENGE_PASSWORD || 'changeme',
        encryptionAlgorithm: process.env.SCEP_ENCRYPTION || 'des3',
        hashAlgorithm: process.env.SCEP_HASH || 'sha1',
        keyUsage: process.env.SCEP_KEY_USAGE || 'digitalSignature,keyEncipherment'
    },

    // Network Profile Configuration
    network: {
        wifiProfilesPath: process.env.WIFI_PROFILES_PATH || '/var/lib/opendirectory/profiles/wifi',
        vpnProfilesPath: process.env.VPN_PROFILES_PATH || '/var/lib/opendirectory/profiles/vpn',
        emailProfilesPath: process.env.EMAIL_PROFILES_PATH || '/var/lib/opendirectory/profiles/email',
        
        // WiFi Configuration
        wifi: {
            defaultSecurity: process.env.WIFI_DEFAULT_SECURITY || 'WPA2-Enterprise',
            supportedSecurityTypes: ['Open', 'WEP', 'WPA-Personal', 'WPA2-Personal', 'WPA-Enterprise', 'WPA2-Enterprise', 'WPA3-Personal', 'WPA3-Enterprise'],
            eapMethods: ['EAP-TLS', 'EAP-TTLS', 'EAP-PEAP', 'EAP-FAST'],
            autoConnect: process.env.WIFI_AUTO_CONNECT === 'true',
            hidden: process.env.WIFI_HIDDEN === 'true'
        },

        // VPN Configuration
        vpn: {
            supportedTypes: ['OpenVPN', 'IKEv2', 'WireGuard', 'L2TP', 'PPTP'],
            defaultType: process.env.VPN_DEFAULT_TYPE || 'OpenVPN',
            
            // OpenVPN specific
            openvpn: {
                port: parseInt(process.env.OPENVPN_PORT) || 1194,
                protocol: process.env.OPENVPN_PROTOCOL || 'udp',
                compression: process.env.OPENVPN_COMPRESSION || 'lzo',
                cipher: process.env.OPENVPN_CIPHER || 'AES-256-CBC',
                auth: process.env.OPENVPN_AUTH || 'SHA256'
            },

            // IKEv2 specific
            ikev2: {
                serverAddress: process.env.IKEV2_SERVER_ADDRESS,
                remoteId: process.env.IKEV2_REMOTE_ID,
                localId: process.env.IKEV2_LOCAL_ID,
                authenticationMethod: process.env.IKEV2_AUTH_METHOD || 'Certificate'
            },

            // WireGuard specific
            wireguard: {
                port: parseInt(process.env.WIREGUARD_PORT) || 51820,
                dns: process.env.WIREGUARD_DNS || '1.1.1.1,1.0.0.1',
                mtu: parseInt(process.env.WIREGUARD_MTU) || 1420
            }
        },

        // Email Configuration
        email: {
            supportedTypes: ['Exchange', 'IMAP', 'POP3', 'Gmail', 'Outlook'],
            defaultType: process.env.EMAIL_DEFAULT_TYPE || 'Exchange',
            
            // Exchange specific
            exchange: {
                autodiscoverEnabled: process.env.EXCHANGE_AUTODISCOVER === 'true',
                serverUrl: process.env.EXCHANGE_SERVER_URL,
                domain: process.env.EXCHANGE_DOMAIN
            },

            // IMAP specific
            imap: {
                defaultPort: parseInt(process.env.IMAP_DEFAULT_PORT) || 993,
                encryption: process.env.IMAP_ENCRYPTION || 'SSL'
            },

            // SMTP specific
            smtp: {
                defaultPort: parseInt(process.env.SMTP_DEFAULT_PORT) || 587,
                encryption: process.env.SMTP_ENCRYPTION || 'STARTTLS'
            }
        }
    },

    // 802.1X & RADIUS Configuration
    radius: {
        enabled: process.env.RADIUS_ENABLED === 'true',
        serverAddress: process.env.RADIUS_SERVER_ADDRESS,
        authPort: parseInt(process.env.RADIUS_AUTH_PORT) || 1812,
        accountingPort: parseInt(process.env.RADIUS_ACCOUNTING_PORT) || 1813,
        sharedSecret: process.env.RADIUS_SHARED_SECRET,
        timeout: parseInt(process.env.RADIUS_TIMEOUT) || 5000,
        retries: parseInt(process.env.RADIUS_RETRIES) || 3,
        nasIdentifier: process.env.RADIUS_NAS_IDENTIFIER || 'opendirectory-ca',
        
        eapTls: {
            enabled: process.env.EAP_TLS_ENABLED === 'true',
            certificateValidation: process.env.EAP_TLS_CERT_VALIDATION === 'true',
            crlCheck: process.env.EAP_TLS_CRL_CHECK === 'true'
        }
    },

    // Database Configuration
    database: {
        mongodb: {
            url: process.env.MONGODB_URL || 'mongodb://localhost:27017/opendirectory_certificates',
            options: {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                maxPoolSize: 10,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
                bufferMaxEntries: 0
            }
        },
        redis: {
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT) || 6379,
            password: process.env.REDIS_PASSWORD,
            db: parseInt(process.env.REDIS_DB) || 0,
            keyPrefix: 'opendirectory:cert:'
        }
    },

    // Security Configuration
    security: {
        jwtSecret: process.env.JWT_SECRET || 'changeme-in-production',
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
        bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
        rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW) || (15 * 60 * 1000), // 15 minutes
        rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100,
        certificateEncryption: process.env.CERT_ENCRYPTION_ENABLED === 'true',
        encryptionKey: process.env.ENCRYPTION_KEY || process.env.JWT_SECRET
    },

    // Logging Configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        format: process.env.LOG_FORMAT || 'json',
        file: process.env.LOG_FILE || '/var/log/opendirectory/certificate-network.log',
        maxSize: process.env.LOG_MAX_SIZE || '10m',
        maxFiles: parseInt(process.env.LOG_MAX_FILES) || 5,
        enableConsole: process.env.LOG_CONSOLE === 'true' || process.env.NODE_ENV === 'development'
    },

    // Email Notifications
    notifications: {
        enabled: process.env.NOTIFICATIONS_ENABLED === 'true',
        smtp: {
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        },
        from: process.env.EMAIL_FROM || 'noreply@opendirectory.com',
        templates: {
            expirationWarning: process.env.EMAIL_TEMPLATE_EXPIRATION || 'expiration-warning',
            renewalSuccess: process.env.EMAIL_TEMPLATE_RENEWAL_SUCCESS || 'renewal-success',
            renewalFailure: process.env.EMAIL_TEMPLATE_RENEWAL_FAILURE || 'renewal-failure',
            certificateIssued: process.env.EMAIL_TEMPLATE_CERT_ISSUED || 'certificate-issued'
        }
    },

    // Enterprise Directory Integration
    enterpriseDirectory: {
        enabled: process.env.ENTERPRISE_DIRECTORY_ENABLED !== 'false',
        serviceURL: process.env.ENTERPRISE_DIRECTORY_URL || 'http://localhost:3008',
        sharedSecret: process.env.ENTERPRISE_DIRECTORY_SECRET || 'shared-enterprise-secret',
        connectionTimeout: parseInt(process.env.ENTERPRISE_DIRECTORY_TIMEOUT) || 30000,
        retryAttempts: parseInt(process.env.ENTERPRISE_DIRECTORY_RETRY) || 3,
        healthCheckInterval: parseInt(process.env.ENTERPRISE_DIRECTORY_HEALTH_CHECK) || 60000,
        userAttributeMapping: {
            email: process.env.ED_ATTR_EMAIL || 'mail',
            cn: process.env.ED_ATTR_CN || 'cn',
            department: process.env.ED_ATTR_DEPARTMENT || 'department',
            title: process.env.ED_ATTR_TITLE || 'title'
        }
    },

    // Certificate Directory Sync Configuration
    certificateSync: {
        fullSyncInterval: parseInt(process.env.CERT_FULL_SYNC_INTERVAL) || 3600000, // 1 hour
        incrementalSyncInterval: parseInt(process.env.CERT_INCREMENTAL_SYNC_INTERVAL) || 300000, // 5 minutes
        batchSize: parseInt(process.env.CERT_SYNC_BATCH_SIZE) || 100,
        autoEnrollment: {
            enabled: process.env.CERT_AUTO_ENROLLMENT !== 'false',
            renewalThresholdDays: parseInt(process.env.CERT_RENEWAL_THRESHOLD_DAYS) || 30,
            retryAttempts: parseInt(process.env.CERT_ENROLLMENT_RETRY) || 3,
            retryDelay: parseInt(process.env.CERT_ENROLLMENT_RETRY_DELAY) || 60000 // 1 minute
        }
    },

    // Network Profile Directory Sync Configuration
    networkProfileSync: {
        policySyncInterval: parseInt(process.env.NETWORK_POLICY_SYNC_INTERVAL) || 900000, // 15 minutes
        deploymentStatusInterval: parseInt(process.env.NETWORK_DEPLOYMENT_STATUS_INTERVAL) || 300000, // 5 minutes
        maxConcurrentDeployments: parseInt(process.env.MAX_CONCURRENT_DEPLOYMENTS) || 50,
        deploymentRetries: parseInt(process.env.DEPLOYMENT_RETRIES) || 2
    },

    // Mobile Device Management Integration
    mdm: {
        enabled: process.env.MDM_ENABLED === 'true',
        serviceUrl: process.env.MDM_SERVICE_URL || 'http://localhost:3015',
        apiKey: process.env.MDM_API_KEY,
        
        // Platform specific settings
        ios: {
            profilePrefix: process.env.IOS_PROFILE_PREFIX || 'com.opendirectory',
            payloadVersion: parseInt(process.env.IOS_PAYLOAD_VERSION) || 1,
            removeOnDisenroll: process.env.IOS_REMOVE_ON_DISENROLL === 'true'
        },
        
        android: {
            packageName: process.env.ANDROID_PACKAGE_NAME || 'com.opendirectory.certificates',
            minSdkVersion: parseInt(process.env.ANDROID_MIN_SDK) || 21
        },
        
        windows: {
            enrollmentType: process.env.WINDOWS_ENROLLMENT_TYPE || 'Device',
            certificateStore: process.env.WINDOWS_CERT_STORE || 'My'
        }
    },

    // Monitoring & Health Checks
    monitoring: {
        enabled: process.env.MONITORING_ENABLED === 'true',
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || (5 * 60 * 1000), // 5 minutes
        metricsInterval: parseInt(process.env.METRICS_INTERVAL) || (60 * 1000), // 1 minute
        prometheusEnabled: process.env.PROMETHEUS_ENABLED === 'true',
        prometheusPort: parseInt(process.env.PROMETHEUS_PORT) || 9090
    },

    // Feature Flags
    features: {
        autoEnrollment: process.env.FEATURE_AUTO_ENROLLMENT === 'true',
        bulkOperations: process.env.FEATURE_BULK_OPERATIONS === 'true',
        crossCertification: process.env.FEATURE_CROSS_CERTIFICATION === 'true',
        keyEscrow: process.env.FEATURE_KEY_ESCROW === 'true',
        timestamping: process.env.FEATURE_TIMESTAMPING === 'true',
        ocspStapling: process.env.FEATURE_OCSP_STAPLING === 'true'
    },

    // Storage Paths
    storage: {
        base: process.env.STORAGE_BASE_PATH || '/var/lib/opendirectory',
        certificates: process.env.STORAGE_CERTIFICATES_PATH || '/var/lib/opendirectory/certificates',
        profiles: process.env.STORAGE_PROFILES_PATH || '/var/lib/opendirectory/profiles',
        templates: process.env.STORAGE_TEMPLATES_PATH || '/var/lib/opendirectory/templates',
        backups: process.env.STORAGE_BACKUPS_PATH || '/var/lib/opendirectory/backups',
        temp: process.env.STORAGE_TEMP_PATH || '/tmp/opendirectory'
    }
};

module.exports = config;