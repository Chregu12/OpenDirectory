/**
 * OpenDirectory Enterprise Directory Service Configuration
 * Complete Active Directory replacement for Windows, macOS, and Linux
 */

const path = require('path');
require('dotenv').config();

const config = {
  // Server Configuration
  server: {
    port: process.env.PORT || 3008,
    host: process.env.HOST || '0.0.0.0',
    environment: process.env.NODE_ENV || 'development',
    serviceName: 'enterprise-directory',
    version: '1.0.0'
  },

  // Database Configuration
  database: {
    mongodb: {
      url: process.env.MONGODB_URL || 'mongodb://opendirectory:changeme@localhost:27017/enterprise-directory',
      options: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 50,
        minPoolSize: 5,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000
      }
    }
  },

  // Redis Configuration
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD,
    keyPrefix: 'od:enterprise-directory:',
    db: 2
  },

  // Message Queue Configuration
  rabbitmq: {
    url: process.env.RABBITMQ_URL || 'amqp://opendirectory:changeme@localhost:5672',
    exchanges: {
      directory: 'od.enterprise-directory',
      events: 'od.directory-events',
      policies: 'od.group-policies',
      auth: 'od.authentication'
    }
  },

  // Active Directory Replacement Configuration
  activeDirectory: {
    domain: process.env.AD_DOMAIN || 'opendirectory.local',
    netbiosName: process.env.AD_NETBIOS || 'OPENDIRECTORY',
    forestFunctionalLevel: process.env.AD_FOREST_LEVEL || '2016',
    domainFunctionalLevel: process.env.AD_DOMAIN_LEVEL || '2016',
    adminUsername: process.env.AD_ADMIN_USER || 'Administrator',
    adminPassword: process.env.AD_ADMIN_PASSWORD || 'OpenDirectory@2024!',
    baseDN: process.env.AD_BASE_DN || 'DC=opendirectory,DC=local',
    defaultContainer: 'CN=Users,DC=opendirectory,DC=local',
    computerContainer: 'CN=Computers,DC=opendirectory,DC=local'
  },

  // LDAP Configuration
  ldap: {
    port: process.env.LDAP_PORT || 389,
    securePort: process.env.LDAP_SECURE_PORT || 636,
    baseDN: process.env.LDAP_BASE_DN || 'DC=opendirectory,DC=local',
    bindDN: process.env.LDAP_BIND_DN || 'CN=Administrator,CN=Users,DC=opendirectory,DC=local',
    bindPassword: process.env.LDAP_BIND_PASSWORD || 'OpenDirectory@2024!',
    enableSSL: process.env.LDAP_SSL === 'true',
    certificatePath: process.env.LDAP_CERT_PATH || './data/certs/ldap.pem',
    privateKeyPath: process.env.LDAP_KEY_PATH || './data/keys/ldap.key',
    schema: {
      userObjectClass: 'user',
      groupObjectClass: 'group',
      computerObjectClass: 'computer',
      organizationalUnitClass: 'organizationalUnit'
    }
  },

  // Kerberos Configuration
  kerberos: {
    realm: process.env.KRB_REALM || 'OPENDIRECTORY.LOCAL',
    kdcPort: process.env.KRB_KDC_PORT || 88,
    adminPort: process.env.KRB_ADMIN_PORT || 464,
    masterKey: process.env.KRB_MASTER_KEY || 'OpenDirectoryMasterKey@2024',
    ticketLifetime: process.env.KRB_TICKET_LIFETIME || '10h',
    renewableLifetime: process.env.KRB_RENEWABLE_LIFETIME || '7d',
    forwardable: true,
    proxiable: true,
    enabledEncTypes: [
      'aes256-cts-hmac-sha1-96',
      'aes128-cts-hmac-sha1-96',
      'aes256-cts-hmac-sha384-192',
      'aes128-cts-hmac-sha256-128'
    ]
  },

  // Group Policy Management
  groupPolicy: {
    enableWindowsGPO: process.env.ENABLE_WINDOWS_GPO !== 'false',
    enableMacOSProfiles: process.env.ENABLE_MACOS_PROFILES !== 'false',
    enableLinuxPolicies: process.env.ENABLE_LINUX_POLICIES !== 'false',
    policyRefreshInterval: parseInt(process.env.POLICY_REFRESH_INTERVAL) || 90, // minutes
    computerPolicyPath: './data/policies/computer',
    userPolicyPath: './data/policies/user',
    templatePath: './data/policies/templates',
    supportedPlatforms: ['windows', 'macos', 'linux'],
    policyFormats: {
      windows: 'gpo',
      macos: 'plist',
      linux: 'json'
    }
  },

  // Single Sign-On Configuration
  sso: {
    oauth2: {
      enabled: process.env.OAUTH2_ENABLED !== 'false',
      clientId: process.env.OAUTH2_CLIENT_ID || 'opendirectory-sso',
      clientSecret: process.env.OAUTH2_CLIENT_SECRET || 'your-oauth2-client-secret',
      authorizationURL: '/oauth2/authorize',
      tokenURL: '/oauth2/token',
      scope: ['openid', 'profile', 'email', 'groups']
    },
    oidc: {
      enabled: process.env.OIDC_ENABLED !== 'false',
      issuer: process.env.OIDC_ISSUER || 'https://opendirectory.local',
      jwksURL: '/oidc/jwks',
      userInfoURL: '/oidc/userinfo',
      supportedResponseTypes: ['code', 'id_token', 'token'],
      supportedScopes: ['openid', 'profile', 'email', 'groups', 'offline_access']
    },
    saml: {
      enabled: process.env.SAML_ENABLED !== 'false',
      entityId: process.env.SAML_ENTITY_ID || 'opendirectory-saml',
      ssoURL: '/saml/sso',
      sloURL: '/saml/slo',
      certificatePath: process.env.SAML_CERT_PATH || './data/certs/saml.pem',
      privateKeyPath: process.env.SAML_KEY_PATH || './data/keys/saml.key'
    }
  },

  // Certificate Authority Configuration
  pki: {
    enabled: process.env.PKI_ENABLED !== 'false',
    rootCA: {
      commonName: process.env.CA_CN || 'OpenDirectory Root CA',
      organization: process.env.CA_ORG || 'OpenDirectory',
      country: process.env.CA_COUNTRY || 'US',
      validityDays: parseInt(process.env.CA_VALIDITY) || 7300, // 20 years
      keySize: parseInt(process.env.CA_KEY_SIZE) || 4096
    },
    intermediateCAs: {
      ssl: {
        commonName: 'OpenDirectory SSL Intermediate CA',
        validityDays: 3650 // 10 years
      },
      user: {
        commonName: 'OpenDirectory User Certificate CA',
        validityDays: 3650
      },
      computer: {
        commonName: 'OpenDirectory Computer Certificate CA',
        validityDays: 3650
      }
    },
    certificateTemplates: {
      ssl: { validityDays: 365, keySize: 2048 },
      user: { validityDays: 730, keySize: 2048 },
      computer: { validityDays: 730, keySize: 2048 },
      codeSign: { validityDays: 1095, keySize: 2048 }
    },
    crlDistributionInterval: 24, // hours
    ocspEnabled: true
  },

  // Device Join Configuration
  deviceJoin: {
    windows: {
      enabled: process.env.WINDOWS_JOIN_ENABLED !== 'false',
      domainJoinOU: 'CN=Computers,DC=opendirectory,DC=local',
      requireSSL: true,
      allowOfflineDomainJoin: true,
      machineAccountQuota: 10
    },
    macos: {
      enabled: process.env.MACOS_JOIN_ENABLED !== 'false',
      bindingMethod: 'advanced', // basic, advanced, or kerberos
      createMobileAccounts: true,
      enableCachedLogon: true,
      homeDirectoryPath: '/Users'
    },
    linux: {
      enabled: process.env.LINUX_JOIN_ENABLED !== 'false',
      sssdConfig: true,
      createHomeDirectories: true,
      shellAccess: '/bin/bash',
      uidRangeStart: 10000,
      gidRangeStart: 10000
    }
  },

  // DNS Integration
  dns: {
    enabled: process.env.DNS_ENABLED !== 'false',
    port: process.env.DNS_PORT || 53,
    forwardZones: process.env.DNS_FORWARD_ZONES ? process.env.DNS_FORWARD_ZONES.split(',') : ['8.8.8.8', '8.8.4.4'],
    enableDNSSEC: process.env.ENABLE_DNSSEC === 'true',
    dynamicUpdates: true,
    scavenging: {
      enabled: true,
      interval: 168 // hours (1 week)
    }
  },

  // Security Configuration
  security: {
    jwt: {
      secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
      issuer: process.env.JWT_ISSUER || 'opendirectory',
      algorithm: 'RS256'
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      keyDerivation: 'pbkdf2',
      iterations: 100000,
      saltLength: 32
    },
    passwordPolicy: {
      minLength: 8,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      historyCount: 12,
      maxAge: 90, // days
      lockoutThreshold: 5,
      lockoutDuration: 30 // minutes
    },
    mfa: {
      enabled: process.env.MFA_ENABLED !== 'false',
      requiredForAdmins: true,
      methods: ['totp', 'sms', 'email'],
      backupCodes: 10
    }
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    maxSize: '100m',
    maxFiles: 10,
    auditLog: {
      enabled: true,
      retention: 365 // days
    },
    securityLog: {
      enabled: true,
      retention: 365 // days
    }
  },

  // Performance Configuration
  performance: {
    maxConnections: parseInt(process.env.MAX_CONNECTIONS) || 1000,
    connectionTimeout: parseInt(process.env.CONNECTION_TIMEOUT) || 30000,
    cacheEnabled: process.env.CACHE_ENABLED !== 'false',
    cacheTTL: parseInt(process.env.CACHE_TTL) || 300, // seconds
    rateLimiting: {
      enabled: true,
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 1000 // requests per window
    }
  },

  // Integration Configuration
  integration: {
    mobileManagement: {
      enabled: process.env.MOBILE_INTEGRATION_ENABLED !== 'false',
      serviceURL: process.env.MOBILE_SERVICE_URL || 'http://localhost:3009',
      sharedSecret: process.env.MOBILE_SHARED_SECRET || 'shared-mobile-secret'
    },
    licenseManagement: {
      enabled: process.env.LICENSE_INTEGRATION_ENABLED !== 'false',
      serviceURL: process.env.LICENSE_SERVICE_URL || 'http://localhost:3010',
      sharedSecret: process.env.LICENSE_SHARED_SECRET || 'shared-license-secret'
    },
    networkInfrastructure: {
      serviceURL: process.env.NETWORK_SERVICE_URL || 'http://localhost:3007'
    },
    monitoring: {
      prometheus: {
        enabled: process.env.PROMETHEUS_ENABLED !== 'false',
        port: process.env.PROMETHEUS_PORT || 9090
      },
      grafana: {
        enabled: process.env.GRAFANA_ENABLED !== 'false',
        url: process.env.GRAFANA_URL || 'http://localhost:3500'
      }
    }
  },

  // Backup Configuration
  backup: {
    enabled: process.env.BACKUP_ENABLED !== 'false',
    schedule: process.env.BACKUP_SCHEDULE || '0 2 * * *', // Daily at 2 AM
    retention: parseInt(process.env.BACKUP_RETENTION) || 30, // days
    location: process.env.BACKUP_LOCATION || './data/backups',
    encryption: true
  }
};

module.exports = config;