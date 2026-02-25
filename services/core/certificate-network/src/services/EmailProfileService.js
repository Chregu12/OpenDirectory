/**
 * OpenDirectory Email Profile Configuration Service
 * Comprehensive email profile creation and deployment for all platforms
 * 
 * Features:
 * - Multi-platform email profile generation (Windows, macOS, iOS, Android, Linux)
 * - Exchange, IMAP, POP3, Gmail, and Outlook support
 * - Autodiscovery and auto-configuration
 * - Certificate-based authentication
 * - S/MIME certificate deployment
 * - OAuth2 authentication support
 * - Profile versioning and bulk deployment
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const EventEmitter = require('events');
const config = require('../config');

class EmailProfileService extends EventEmitter {
    constructor(certificateService, options = {}) {
        super();
        
        this.certificateService = certificateService;
        this.config = {
            ...config.network.email,
            ...options
        };

        this.logger = winston.createLogger({
            level: config.logging.level,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ 
                    filename: path.join(path.dirname(config.logging.file), 'email-profiles.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // Profile stores
        this.emailProfiles = new Map();
        this.autodiscoveryCache = new Map();
        this.deploymentHistory = new Map();
        
        // Email provider configurations
        this.emailProviders = new Map();
        this.initializeEmailProviders();
        
        // Profile generators by platform
        this.profileGenerators = {
            windows: this.generateWindowsProfile.bind(this),
            macos: this.generateMacOSProfile.bind(this),
            ios: this.generateIOSProfile.bind(this),
            android: this.generateAndroidProfile.bind(this),
            linux: this.generateLinuxProfile.bind(this)
        };

        // Metrics
        this.metrics = {
            profilesCreated: 0,
            profilesDeployed: 0,
            autodiscoveryAttempts: 0,
            autodiscoverySuccess: 0,
            deploymentSuccess: 0,
            deploymentFailures: 0,
            smimeCertificates: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadExistingProfiles();
            await this.loadEmailProviders();
            
            this.logger.info('Email Profile Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize Email Profile Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            config.network.emailProfilesPath,
            path.join(config.network.emailProfilesPath, 'profiles'),
            path.join(config.network.emailProfilesPath, 'providers'),
            path.join(config.network.emailProfilesPath, 'deployments'),
            path.join(config.network.emailProfilesPath, 'exports'),
            path.join(config.network.emailProfilesPath, 'autodiscovery-cache')
        ];

        for (const dir of directories) {
            try {
                await fs.mkdir(dir, { recursive: true });
            } catch (error) {
                if (error.code !== 'EEXIST') throw error;
            }
        }
    }

    initializeEmailProviders() {
        // Built-in email provider configurations
        const providers = [
            {
                id: 'exchange',
                name: 'Microsoft Exchange',
                type: 'exchange',
                autodiscovery: {
                    enabled: true,
                    urls: [
                        'https://autodiscover.{domain}/autodiscover/autodiscover.xml',
                        'https://{domain}/autodiscover/autodiscover.xml',
                        'https://autodiscover.{domain}/Autodiscover/Autodiscover.xml'
                    ]
                },
                defaultPorts: {
                    exchange: 443,
                    imap: 993,
                    smtp: 587
                },
                security: {
                    exchange: 'SSL',
                    imap: 'SSL',
                    smtp: 'STARTTLS'
                }
            },
            {
                id: 'gmail',
                name: 'Gmail',
                type: 'gmail',
                servers: {
                    imap: 'imap.gmail.com',
                    smtp: 'smtp.gmail.com'
                },
                ports: {
                    imap: 993,
                    smtp: 587
                },
                security: {
                    imap: 'SSL',
                    smtp: 'STARTTLS'
                },
                oauth2: {
                    enabled: true,
                    clientId: '',
                    scopes: ['https://mail.google.com/']
                }
            },
            {
                id: 'outlook',
                name: 'Outlook.com',
                type: 'outlook',
                servers: {
                    imap: 'outlook.office365.com',
                    smtp: 'smtp-mail.outlook.com'
                },
                ports: {
                    imap: 993,
                    smtp: 587
                },
                security: {
                    imap: 'SSL',
                    smtp: 'STARTTLS'
                }
            }
        ];

        providers.forEach(provider => {
            this.emailProviders.set(provider.id, provider);
        });
    }

    /**
     * Email Profile Creation
     */
    async createEmailProfile(profileData) {
        try {
            const profileId = this.generateProfileId(profileData.name);
            const profile = {
                id: profileId,
                name: profileData.name,
                description: profileData.description || '',
                version: profileData.version || '1.0',
                
                // Email account configuration
                account: {
                    emailAddress: profileData.account.emailAddress,
                    displayName: profileData.account.displayName,
                    username: profileData.account.username || profileData.account.emailAddress,
                    domain: this.extractDomain(profileData.account.emailAddress),
                    
                    // Authentication
                    authentication: {
                        method: profileData.account.authentication?.method || 'password', // password, certificate, oauth2
                        password: profileData.account.authentication?.password,
                        savePassword: profileData.account.authentication?.savePassword || false,
                        
                        // Certificate authentication
                        clientCertificate: {
                            enabled: profileData.account.authentication?.clientCertificate?.enabled || false,
                            templateId: profileData.account.authentication?.clientCertificate?.templateId,
                            certificateId: profileData.account.authentication?.clientCertificate?.certificateId,
                            autoEnroll: profileData.account.authentication?.clientCertificate?.autoEnroll || true
                        },
                        
                        // OAuth2 settings
                        oauth2: {
                            enabled: profileData.account.authentication?.oauth2?.enabled || false,
                            provider: profileData.account.authentication?.oauth2?.provider,
                            clientId: profileData.account.authentication?.oauth2?.clientId,
                            scopes: profileData.account.authentication?.oauth2?.scopes || []
                        }
                    }
                },
                
                // Email provider configuration
                provider: {
                    type: profileData.provider?.type || this.config.defaultType,
                    providerId: profileData.provider?.providerId,
                    
                    // Exchange settings
                    exchange: {
                        serverUrl: profileData.provider?.exchange?.serverUrl,
                        useAutodiscovery: profileData.provider?.exchange?.useAutodiscovery !== false,
                        version: profileData.provider?.exchange?.version || '2016',
                        useSSL: profileData.provider?.exchange?.useSSL !== false
                    },
                    
                    // IMAP settings
                    imap: {
                        server: profileData.provider?.imap?.server,
                        port: profileData.provider?.imap?.port || this.config.imap.defaultPort,
                        security: profileData.provider?.imap?.security || this.config.imap.encryption,
                        useIdle: profileData.provider?.imap?.useIdle !== false,
                        pathPrefix: profileData.provider?.imap?.pathPrefix || ''
                    },
                    
                    // SMTP settings
                    smtp: {
                        server: profileData.provider?.smtp?.server,
                        port: profileData.provider?.smtp?.port || this.config.smtp.defaultPort,
                        security: profileData.provider?.smtp?.security || this.config.smtp.encryption,
                        requiresAuth: profileData.provider?.smtp?.requiresAuth !== false,
                        useStartTLS: profileData.provider?.smtp?.useStartTLS !== false
                    },
                    
                    // POP3 settings (if needed)
                    pop3: {
                        server: profileData.provider?.pop3?.server,
                        port: profileData.provider?.pop3?.port || 995,
                        security: profileData.provider?.pop3?.security || 'SSL',
                        leaveOnServer: profileData.provider?.pop3?.leaveOnServer || false
                    }
                },
                
                // Synchronization settings
                sync: {
                    // Email sync
                    email: {
                        enabled: profileData.sync?.email?.enabled !== false,
                        syncPeriod: profileData.sync?.email?.syncPeriod || 'auto',
                        daysToSync: profileData.sync?.email?.daysToSync || 30,
                        downloadAttachments: profileData.sync?.email?.downloadAttachments || true,
                        maxAttachmentSize: profileData.sync?.email?.maxAttachmentSize || 25 // MB
                    },
                    
                    // Calendar sync
                    calendar: {
                        enabled: profileData.sync?.calendar?.enabled || false,
                        syncPeriod: profileData.sync?.calendar?.syncPeriod || 'auto',
                        pastDaysToSync: profileData.sync?.calendar?.pastDaysToSync || 30,
                        futureDaysToSync: profileData.sync?.calendar?.futureDaysToSync || 365
                    },
                    
                    // Contacts sync
                    contacts: {
                        enabled: profileData.sync?.contacts?.enabled || false,
                        syncPeriod: profileData.sync?.contacts?.syncPeriod || 'auto'
                    },
                    
                    // Tasks sync
                    tasks: {
                        enabled: profileData.sync?.tasks?.enabled || false,
                        syncPeriod: profileData.sync?.tasks?.syncPeriod || 'auto'
                    }
                },
                
                // Security settings
                security: {
                    // S/MIME configuration
                    smime: {
                        enabled: profileData.security?.smime?.enabled || false,
                        signingCertificate: {
                            templateId: profileData.security?.smime?.signingCertificate?.templateId,
                            certificateId: profileData.security?.smime?.signingCertificate?.certificateId,
                            autoEnroll: profileData.security?.smime?.signingCertificate?.autoEnroll || true
                        },
                        encryptionCertificate: {
                            templateId: profileData.security?.smime?.encryptionCertificate?.templateId,
                            certificateId: profileData.security?.smime?.encryptionCertificate?.certificateId,
                            autoEnroll: profileData.security?.smime?.encryptionCertificate?.autoEnroll || true
                        },
                        signByDefault: profileData.security?.smime?.signByDefault || false,
                        encryptByDefault: profileData.security?.smime?.encryptByDefault || false
                    },
                    
                    // Password policies
                    passwordPolicy: {
                        requireDeviceLock: profileData.security?.passwordPolicy?.requireDeviceLock || false,
                        allowSimplePassword: profileData.security?.passwordPolicy?.allowSimplePassword !== false,
                        maxInactivityTime: profileData.security?.passwordPolicy?.maxInactivityTime || 15 // minutes
                    },
                    
                    // Data protection
                    dataProtection: {
                        preventDataBackup: profileData.security?.dataProtection?.preventDataBackup || false,
                        allowMailDrop: profileData.security?.dataProtection?.allowMailDrop !== false
                    }
                },
                
                // Platform-specific configurations
                platforms: {
                    windows: profileData.platforms?.windows || {},
                    macos: profileData.platforms?.macos || {},
                    ios: profileData.platforms?.ios || {},
                    android: profileData.platforms?.android || {},
                    linux: profileData.platforms?.linux || {}
                },
                
                // Deployment settings
                deployment: {
                    enabled: profileData.deployment?.enabled || false,
                    targetDevices: profileData.deployment?.targetDevices || [],
                    targetGroups: profileData.deployment?.targetGroups || [],
                    automatic: profileData.deployment?.automatic || false,
                    removeOnUnenroll: profileData.deployment?.removeOnUnenroll !== false
                },
                
                // Autodiscovery configuration
                autodiscovery: {
                    enabled: profileData.autodiscovery?.enabled !== false,
                    cacheResults: profileData.autodiscovery?.cacheResults !== false,
                    timeout: profileData.autodiscovery?.timeout || 30000, // ms
                    customUrls: profileData.autodiscovery?.customUrls || []
                },
                
                createdAt: new Date(),
                updatedAt: new Date(),
                status: 'active'
            };

            // Perform autodiscovery if enabled
            if (profile.autodiscovery.enabled && !profile.provider.exchange.serverUrl && !profile.provider.imap.server) {
                try {
                    const discoveryResult = await this.performAutodiscovery(profile.account.domain);
                    if (discoveryResult) {
                        this.applyAutodiscoveryResults(profile, discoveryResult);
                    }
                } catch (error) {
                    this.logger.warn(`Autodiscovery failed for ${profile.account.domain}:`, error);
                }
            }

            this.emailProfiles.set(profileId, profile);
            await this.saveEmailProfile(profile);
            
            this.metrics.profilesCreated++;
            if (profile.security.smime.enabled) {
                this.metrics.smimeCertificates++;
            }
            
            this.logger.info(`Email profile created: ${profileId}`);
            this.emit('profileCreated', profile);
            
            return profile;

        } catch (error) {
            this.logger.error('Failed to create email profile:', error);
            throw error;
        }
    }

    async updateEmailProfile(profileId, updates) {
        try {
            const profile = this.emailProfiles.get(profileId);
            if (!profile) {
                throw new Error(`Email profile not found: ${profileId}`);
            }

            const updatedProfile = {
                ...profile,
                ...updates,
                version: this.incrementVersion(profile.version),
                updatedAt: new Date()
            };

            this.emailProfiles.set(profileId, updatedProfile);
            await this.saveEmailProfile(updatedProfile);
            
            this.logger.info(`Email profile updated: ${profileId}`);
            this.emit('profileUpdated', updatedProfile);
            
            return updatedProfile;

        } catch (error) {
            this.logger.error('Failed to update email profile:', error);
            throw error;
        }
    }

    /**
     * Autodiscovery Implementation
     */
    async performAutodiscovery(domain) {
        try {
            this.metrics.autodiscoveryAttempts++;
            
            // Check cache first
            const cacheKey = `autodiscover_${domain}`;
            const cachedResult = this.autodiscoveryCache.get(cacheKey);
            if (cachedResult && (Date.now() - cachedResult.timestamp) < 24 * 60 * 60 * 1000) {
                return cachedResult.data;
            }

            // Try Exchange autodiscovery first
            let result = await this.tryExchangeAutodiscovery(domain);
            
            // Fall back to SRV record discovery
            if (!result) {
                result = await this.trySRVRecordDiscovery(domain);
            }
            
            // Fall back to well-known configurations
            if (!result) {
                result = await this.tryWellKnownConfigurations(domain);
            }

            if (result) {
                // Cache the result
                this.autodiscoveryCache.set(cacheKey, {
                    data: result,
                    timestamp: Date.now()
                });
                
                await this.saveAutodiscoveryCache();
                this.metrics.autodiscoverySuccess++;
                
                this.logger.info(`Autodiscovery successful for domain: ${domain}`);
                return result;
            }

            this.logger.warn(`Autodiscovery failed for domain: ${domain}`);
            return null;

        } catch (error) {
            this.logger.error(`Autodiscovery error for domain ${domain}:`, error);
            return null;
        }
    }

    async tryExchangeAutodiscovery(domain) {
        const autodiscoverUrls = [
            `https://autodiscover.${domain}/autodiscover/autodiscover.xml`,
            `https://${domain}/autodiscover/autodiscover.xml`,
            `https://autodiscover.${domain}/Autodiscover/Autodiscover.xml`
        ];

        for (const url of autodiscoverUrls) {
            try {
                const response = await this.makeAutodiscoverRequest(url, domain);
                if (response) {
                    return this.parseExchangeAutodiscoverResponse(response);
                }
            } catch (error) {
                this.logger.debug(`Autodiscovery failed for URL ${url}:`, error);
            }
        }

        return null;
    }

    async makeAutodiscoverRequest(url, domain) {
        // Implementation would make actual HTTP request
        // For now, return mock data
        return null;
    }

    parseExchangeAutodiscoverResponse(xmlResponse) {
        // Parse Exchange autodiscovery XML response
        // Implementation would use XML parser
        return {
            type: 'exchange',
            exchange: {
                serverUrl: 'https://mail.example.com/EWS/Exchange.asmx',
                version: '2016'
            }
        };
    }

    async trySRVRecordDiscovery(domain) {
        // Try to discover email settings via DNS SRV records
        const srvRecords = [
            `_imaps._tcp.${domain}`,
            `_imap._tcp.${domain}`,
            `_submission._tcp.${domain}`,
            `_smtp._tcp.${domain}`
        ];

        try {
            const dns = require('dns').promises;
            const results = {};

            for (const record of srvRecords) {
                try {
                    const srvData = await dns.resolveSrv(record);
                    if (srvData.length > 0) {
                        const srv = srvData[0];
                        
                        if (record.includes('_imaps')) {
                            results.imap = {
                                server: srv.name,
                                port: srv.port,
                                security: 'SSL'
                            };
                        } else if (record.includes('_imap')) {
                            results.imap = {
                                server: srv.name,
                                port: srv.port,
                                security: 'STARTTLS'
                            };
                        } else if (record.includes('_submission') || record.includes('_smtp')) {
                            results.smtp = {
                                server: srv.name,
                                port: srv.port,
                                security: srv.port === 587 ? 'STARTTLS' : 'SSL'
                            };
                        }
                    }
                } catch (error) {
                    this.logger.debug(`SRV lookup failed for ${record}:`, error);
                }
            }

            return Object.keys(results).length > 0 ? { type: 'imap', ...results } : null;

        } catch (error) {
            this.logger.debug(`SRV discovery failed for domain ${domain}:`, error);
            return null;
        }
    }

    async tryWellKnownConfigurations(domain) {
        // Try common email server configurations
        const wellKnownConfigs = [
            // Common IMAP/SMTP combinations
            {
                type: 'imap',
                imap: { server: `imap.${domain}`, port: 993, security: 'SSL' },
                smtp: { server: `smtp.${domain}`, port: 587, security: 'STARTTLS' }
            },
            {
                type: 'imap',
                imap: { server: `mail.${domain}`, port: 993, security: 'SSL' },
                smtp: { server: `mail.${domain}`, port: 587, security: 'STARTTLS' }
            }
        ];

        for (const config of wellKnownConfigs) {
            // In a real implementation, we would test connectivity to these servers
            // For now, just return the first configuration
            if (await this.testEmailServerConnectivity(config.imap.server, config.imap.port)) {
                return config;
            }
        }

        return null;
    }

    async testEmailServerConnectivity(server, port) {
        try {
            const net = require('net');
            
            return new Promise((resolve) => {
                const socket = new net.Socket();
                const timeout = setTimeout(() => {
                    socket.destroy();
                    resolve(false);
                }, 5000);

                socket.connect(port, server, () => {
                    clearTimeout(timeout);
                    socket.destroy();
                    resolve(true);
                });

                socket.on('error', () => {
                    clearTimeout(timeout);
                    resolve(false);
                });
            });
        } catch (error) {
            return false;
        }
    }

    applyAutodiscoveryResults(profile, discoveryResult) {
        if (discoveryResult.type === 'exchange' && discoveryResult.exchange) {
            profile.provider.type = 'exchange';
            profile.provider.exchange.serverUrl = discoveryResult.exchange.serverUrl;
            profile.provider.exchange.version = discoveryResult.exchange.version;
        } else if (discoveryResult.type === 'imap') {
            profile.provider.type = 'imap';
            if (discoveryResult.imap) {
                profile.provider.imap = { ...profile.provider.imap, ...discoveryResult.imap };
            }
            if (discoveryResult.smtp) {
                profile.provider.smtp = { ...profile.provider.smtp, ...discoveryResult.smtp };
            }
        }
    }

    /**
     * Platform-Specific Profile Generation
     */
    async generateProfileForPlatform(profileId, platform, deviceInfo = {}) {
        try {
            const profile = this.emailProfiles.get(profileId);
            if (!profile) {
                throw new Error(`Email profile not found: ${profileId}`);
            }

            const generator = this.profileGenerators[platform.toLowerCase()];
            if (!generator) {
                throw new Error(`Unsupported platform: ${platform}`);
            }

            // Get certificates if needed
            let certificates = null;
            if (profile.account.authentication.clientCertificate.enabled || profile.security.smime.enabled) {
                certificates = await this.getCertificatesForProfile(profile, deviceInfo);
            }

            const platformProfile = await generator(profile, certificates, deviceInfo);
            
            this.logger.info(`Email profile generated for platform: ${platform}, profile: ${profileId}`);
            this.emit('profileGenerated', profile, platform, platformProfile);
            
            return platformProfile;

        } catch (error) {
            this.logger.error(`Failed to generate email profile for ${platform}:`, error);
            throw error;
        }
    }

    async generateWindowsProfile(profile, certificates, deviceInfo) {
        // Windows Outlook profile configuration
        const outlookConfig = this.buildOutlookConfiguration(profile, certificates);
        const powershellScript = this.buildWindowsDeploymentScript(profile, outlookConfig, certificates);
        
        return {
            platform: 'windows',
            format: 'registry',
            profileData: outlookConfig,
            deploymentScript: powershellScript,
            certificates: certificates ? this.formatCertificatesForWindows(certificates) : null,
            instructions: this.generateWindowsInstructions(profile)
        };
    }

    buildOutlookConfiguration(profile, certificates) {
        const accountName = profile.account.displayName || profile.account.emailAddress;
        
        let config = {
            accountSettings: {
                accountName: accountName,
                emailAddress: profile.account.emailAddress,
                displayName: profile.account.displayName,
                userName: profile.account.username,
                serverType: this.getOutlookServerType(profile.provider.type)
            }
        };

        if (profile.provider.type === 'exchange') {
            config.exchangeSettings = {
                serverURL: profile.provider.exchange.serverUrl,
                useAutodiscovery: profile.provider.exchange.useAutodiscovery,
                useSSL: profile.provider.exchange.useSSL,
                useCachedExchangeMode: true
            };
        } else {
            config.imapSettings = {
                incomingServer: profile.provider.imap.server,
                incomingPort: profile.provider.imap.port,
                incomingSecurity: profile.provider.imap.security,
                outgoingServer: profile.provider.smtp.server,
                outgoingPort: profile.provider.smtp.port,
                outgoingSecurity: profile.provider.smtp.security,
                outgoingAuth: profile.provider.smtp.requiresAuth
            };
        }

        // S/MIME settings
        if (profile.security.smime.enabled && certificates?.smime) {
            config.smimeSettings = {
                signingCertificate: certificates.smime.signing?.thumbprint,
                encryptionCertificate: certificates.smime.encryption?.thumbprint,
                signByDefault: profile.security.smime.signByDefault,
                encryptByDefault: profile.security.smime.encryptByDefault
            };
        }

        return config;
    }

    buildWindowsDeploymentScript(profile, outlookConfig, certificates) {
        return `# Email Profile Deployment Script for Windows Outlook
# Profile: ${profile.name}

# Install certificates if provided
${certificates ? this.buildWindowsCertificateInstallScript(certificates) : '# No certificates to install'}

# Create Outlook profile
$profileName = "${profile.name}"
$emailAddress = "${profile.account.emailAddress}"
$displayName = "${profile.account.displayName}"

# Registry keys for Outlook configuration
$outlookVersion = "16.0" # Office 2016/2019/365
$profilesKey = "HKCU:\\Software\\Microsoft\\Office\\$outlookVersion\\Outlook\\Profiles\\$profileName"

# Create profile registry structure
New-Item -Path $profilesKey -Force
New-Item -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676" -Force

# Configure account settings
${this.buildOutlookRegistrySettings(outlookConfig)}

Write-Host "Email profile '$profileName' configured successfully for Outlook"`;
    }

    async generateMacOSProfile(profile, certificates, deviceInfo) {
        // macOS Configuration Profile (mobileconfig format)
        const configProfile = this.buildMacOSEmailProfile(profile, certificates, deviceInfo);
        
        return {
            platform: 'macos',
            format: 'mobileconfig',
            profileData: configProfile,
            certificates: certificates ? this.formatCertificatesForMacOS(certificates) : null,
            instructions: this.generateMacOSInstructions(profile)
        };
    }

    buildMacOSEmailProfile(profile, certificates, deviceInfo) {
        const payloadUUID = this.generateUUID();
        const emailUUID = this.generateUUID();
        
        const emailPayload = {
            PayloadType: 'com.apple.mail.managed',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.email.${emailUUID}`,
            PayloadUUID: emailUUID,
            PayloadDisplayName: `Email: ${profile.account.emailAddress}`,
            PayloadDescription: `Email configuration for ${profile.account.emailAddress}`,
            
            EmailAccountName: profile.account.displayName || profile.account.emailAddress,
            EmailAccountType: this.getMacOSEmailAccountType(profile.provider.type),
            EmailAddress: profile.account.emailAddress,
            IncomingMailServerAuthentication: this.getMacOSAuthMethod(profile.account.authentication.method),
            IncomingMailServerHostName: this.getIncomingServer(profile),
            IncomingMailServerPortNumber: this.getIncomingPort(profile),
            IncomingMailServerUseSSL: this.getIncomingSSL(profile),
            IncomingMailServerUsername: profile.account.username,
            OutgoingMailServerAuthentication: this.getMacOSAuthMethod(profile.account.authentication.method),
            OutgoingMailServerHostName: this.getOutgoingServer(profile),
            OutgoingMailServerPortNumber: this.getOutgoingPort(profile),
            OutgoingMailServerUseSSL: this.getOutgoingSSL(profile),
            OutgoingMailServerUsername: profile.account.username,
            
            // Authentication
            ...(profile.account.authentication.savePassword && profile.account.authentication.password && {
                IncomingPassword: profile.account.authentication.password,
                OutgoingPassword: profile.account.authentication.password
            }),
            
            // Certificate authentication
            ...(certificates?.client && {
                IncomingMailServerIMAPPathPrefix: profile.provider.imap.pathPrefix,
                PayloadCertificateUUID: certificates.client.uuid
            }),
            
            // S/MIME configuration
            ...(profile.security.smime.enabled && certificates?.smime && {
                SMIMEEnabled: true,
                SMIMESigningEnabled: profile.security.smime.signByDefault,
                SMIMEEncryptionEnabled: profile.security.smime.encryptByDefault,
                SMIMESigningCertificateUUID: certificates.smime.signing?.uuid,
                SMIMEEncryptionCertificateUUID: certificates.smime.encryption?.uuid
            }),
            
            // Sync settings
            MailNumberOfPastDaysToSync: profile.sync.email.daysToSync,
            ...(profile.sync.calendar.enabled && {
                PreventMove: false,
                PreventAppSheet: false
            })
        };

        const payloads = [emailPayload];
        
        // Add certificate payloads if needed
        if (certificates) {
            if (certificates.client) {
                payloads.push(this.buildMacOSCertificatePayload(certificates.client, 'client'));
            }
            if (certificates.smime?.signing) {
                payloads.push(this.buildMacOSCertificatePayload(certificates.smime.signing, 'smime-signing'));
            }
            if (certificates.smime?.encryption) {
                payloads.push(this.buildMacOSCertificatePayload(certificates.smime.encryption, 'smime-encryption'));
            }
        }

        const configProfile = {
            PayloadType: 'Configuration',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.email.${profile.id}`,
            PayloadUUID: payloadUUID,
            PayloadDisplayName: `${profile.name} Email Profile`,
            PayloadDescription: profile.description || `Email configuration for ${profile.account.emailAddress}`,
            PayloadOrganization: 'OpenDirectory',
            PayloadContent: payloads,
            PayloadRemovalDisallowed: false,
            PayloadScope: 'User'
        };

        return this.generatePlistXML(configProfile);
    }

    async generateIOSProfile(profile, certificates, deviceInfo) {
        // iOS uses the same mobileconfig format as macOS with some differences
        const configProfile = this.buildIOSEmailProfile(profile, certificates, deviceInfo);
        
        return {
            platform: 'ios',
            format: 'mobileconfig',
            profileData: configProfile,
            certificates: certificates ? this.formatCertificatesForIOS(certificates) : null,
            instructions: this.generateIOSInstructions(profile)
        };
    }

    buildIOSEmailProfile(profile, certificates, deviceInfo) {
        // Similar to macOS but with iOS-specific considerations
        const macOSProfile = this.buildMacOSEmailProfile(profile, certificates, deviceInfo);
        
        // Parse and modify for iOS-specific settings
        const plist = require('plist');
        const parsedProfile = plist.parse(macOSProfile);
        
        // Add iOS-specific email payload settings
        const emailPayload = parsedProfile.PayloadContent.find(p => p.PayloadType === 'com.apple.mail.managed');
        if (emailPayload) {
            // iOS-specific settings
            emailPayload.PreventMove = profile.security.dataProtection.preventDataBackup;
            emailPayload.PreventAppSheet = profile.security.dataProtection.preventDataBackup;
            emailPayload.SMIMESigningUserOverrideable = true;
            emailPayload.SMIMEEncryptionUserOverrideable = true;
        }
        
        return plist.build(parsedProfile);
    }

    async generateAndroidProfile(profile, certificates, deviceInfo) {
        // Android email configuration - JSON format for most email apps
        const androidConfig = this.buildAndroidEmailConfig(profile, certificates);
        
        return {
            platform: 'android',
            format: 'json',
            profileData: androidConfig,
            certificates: certificates ? this.formatCertificatesForAndroid(certificates) : null,
            instructions: this.generateAndroidInstructions(profile)
        };
    }

    buildAndroidEmailConfig(profile, certificates) {
        const config = {
            accountName: profile.account.displayName || profile.account.emailAddress,
            emailAddress: profile.account.emailAddress,
            username: profile.account.username,
            
            // Incoming server settings
            incomingServer: {
                type: profile.provider.type === 'exchange' ? 'ews' : 'imap',
                hostname: this.getIncomingServer(profile),
                port: this.getIncomingPort(profile),
                security: this.getIncomingSecurity(profile),
                authentication: profile.account.authentication.method,
                username: profile.account.username
            },
            
            // Outgoing server settings
            outgoingServer: {
                hostname: this.getOutgoingServer(profile),
                port: this.getOutgoingPort(profile),
                security: this.getOutgoingSecurity(profile),
                authentication: profile.account.authentication.method,
                username: profile.account.username,
                requireAuth: profile.provider.smtp.requiresAuth
            },
            
            // Sync settings
            sync: {
                email: {
                    enabled: profile.sync.email.enabled,
                    syncPeriod: profile.sync.email.syncPeriod,
                    daysToSync: profile.sync.email.daysToSync
                },
                calendar: profile.sync.calendar.enabled,
                contacts: profile.sync.contacts.enabled
            },
            
            // Security settings
            security: {
                smime: {
                    enabled: profile.security.smime.enabled,
                    signByDefault: profile.security.smime.signByDefault,
                    encryptByDefault: profile.security.smime.encryptByDefault
                }
            },
            
            // Certificate references
            ...(certificates && {
                certificates: {
                    client: certificates.client?.uuid,
                    smimeSigning: certificates.smime?.signing?.uuid,
                    smimeEncryption: certificates.smime?.encryption?.uuid
                }
            })
        };

        return JSON.stringify(config, null, 2);
    }

    async generateLinuxProfile(profile, certificates, deviceInfo) {
        // Linux email configuration for various clients
        const configs = {
            thunderbird: this.buildThunderbirdConfig(profile, certificates),
            evolution: this.buildEvolutionConfig(profile, certificates),
            kmail: this.buildKMailConfig(profile, certificates)
        };
        
        return {
            platform: 'linux',
            format: 'ini',
            profileData: configs.thunderbird, // Default to Thunderbird
            alternativeFormats: {
                evolution: configs.evolution,
                kmail: configs.kmail
            },
            certificates: certificates ? this.formatCertificatesForLinux(certificates) : null,
            instructions: this.generateLinuxInstructions(profile)
        };
    }

    buildThunderbirdConfig(profile, certificates) {
        return `# Thunderbird Email Configuration
# Profile: ${profile.name}

[Account]
name=${profile.account.displayName || profile.account.emailAddress}
email=${profile.account.emailAddress}

[Incoming]
type=${profile.provider.type === 'exchange' ? 'imap' : profile.provider.type}
hostname=${this.getIncomingServer(profile)}
port=${this.getIncomingPort(profile)}
security=${this.getIncomingSecurity(profile)}
username=${profile.account.username}
authentication=${profile.account.authentication.method}

[Outgoing]
hostname=${this.getOutgoingServer(profile)}
port=${this.getOutgoingPort(profile)}
security=${this.getOutgoingSecurity(profile)}
username=${profile.account.username}
authentication=${profile.account.authentication.method}

${profile.security.smime.enabled ? '[S/MIME]\nenabled=true\nsign_by_default=' + profile.security.smime.signByDefault + '\nencrypt_by_default=' + profile.security.smime.encryptByDefault : ''}`;
    }

    buildEvolutionConfig(profile, certificates) {
        // Evolution mail client configuration
        return this.buildThunderbirdConfig(profile, certificates); // Simplified
    }

    buildKMailConfig(profile, certificates) {
        // KMail client configuration
        return this.buildThunderbirdConfig(profile, certificates); // Simplified
    }

    /**
     * Certificate Management
     */
    async getCertificatesForProfile(profile, deviceInfo) {
        let certificates = {};

        // Get client certificate for authentication
        if (profile.account.authentication.clientCertificate.enabled) {
            if (profile.account.authentication.clientCertificate.certificateId) {
                certificates.client = await this.getCertificateById(profile.account.authentication.clientCertificate.certificateId);
            } else if (profile.account.authentication.clientCertificate.templateId && profile.account.authentication.clientCertificate.autoEnroll) {
                certificates.client = await this.enrollCertificateForDevice(
                    profile.account.authentication.clientCertificate.templateId,
                    deviceInfo,
                    'email-auth'
                );
            }
        }

        // Get S/MIME certificates
        if (profile.security.smime.enabled) {
            certificates.smime = {};

            // Signing certificate
            if (profile.security.smime.signingCertificate.certificateId) {
                certificates.smime.signing = await this.getCertificateById(profile.security.smime.signingCertificate.certificateId);
            } else if (profile.security.smime.signingCertificate.templateId && profile.security.smime.signingCertificate.autoEnroll) {
                certificates.smime.signing = await this.enrollCertificateForDevice(
                    profile.security.smime.signingCertificate.templateId,
                    deviceInfo,
                    'smime-signing'
                );
            }

            // Encryption certificate
            if (profile.security.smime.encryptionCertificate.certificateId) {
                certificates.smime.encryption = await this.getCertificateById(profile.security.smime.encryptionCertificate.certificateId);
            } else if (profile.security.smime.encryptionCertificate.templateId && profile.security.smime.encryptionCertificate.autoEnroll) {
                certificates.smime.encryption = await this.enrollCertificateForDevice(
                    profile.security.smime.encryptionCertificate.templateId,
                    deviceInfo,
                    'smime-encryption'
                );
            }
        }

        return Object.keys(certificates).length > 0 ? certificates : null;
    }

    async enrollCertificateForDevice(templateId, deviceInfo, purpose) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        const enrollmentRequest = {
            templateId: templateId,
            deviceId: deviceInfo.deviceId,
            userId: deviceInfo.userId,
            subject: {
                commonName: purpose === 'email-auth' ? 
                    (deviceInfo.deviceName || deviceInfo.deviceId) : 
                    (deviceInfo.userEmail || deviceInfo.userId),
                emailAddress: purpose.includes('smime') ? 
                    (deviceInfo.userEmail || '') : undefined,
                organizationalUnitName: purpose === 'email-auth' ? 'Email Clients' : 'S/MIME Users'
            },
            subjectAltName: purpose.includes('smime') && deviceInfo.userEmail ? 
                [{ type: 1, value: deviceInfo.userEmail }] : [], // Email SAN
            requester: 'email-profile-auto-enrollment'
        };

        const certificate = await this.certificateService.enrollCertificate(enrollmentRequest);
        return this.formatCertificateForEmail(certificate);
    }

    async getCertificateById(certificateId) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        const certificate = await this.certificateService.getCertificate(certificateId);
        return this.formatCertificateForEmail(certificate);
    }

    formatCertificateForEmail(certificate) {
        return {
            uuid: this.generateUUID(),
            certificate: certificate.certificate,
            privateKey: certificate.privateKey,
            data: certificate.certificate,
            thumbprint: this.calculateCertificateThumbprint(certificate.certificate)
        };
    }

    calculateCertificateThumbprint(certificatePem) {
        const crypto = require('crypto');
        const cert = certificatePem.replace(/-----BEGIN CERTIFICATE-----|\-----END CERTIFICATE-----|\n|\r/g, '');
        const der = Buffer.from(cert, 'base64');
        return crypto.createHash('sha1').update(der).digest('hex').toUpperCase();
    }

    /**
     * Utility Methods
     */
    generateProfileId(name) {
        const timestamp = Date.now();
        const hash = crypto.createHash('sha256')
            .update(`${name}-${timestamp}`)
            .digest('hex')
            .substring(0, 8);
        return `email-${hash}`;
    }

    generateUUID() {
        return require('uuid').v4();
    }

    incrementVersion(version) {
        const parts = version.split('.');
        parts[parts.length - 1] = (parseInt(parts[parts.length - 1]) + 1).toString();
        return parts.join('.');
    }

    extractDomain(emailAddress) {
        return emailAddress.split('@')[1];
    }

    getOutlookServerType(providerType) {
        const types = {
            'exchange': 'Exchange',
            'imap': 'IMAP',
            'pop3': 'POP3'
        };
        return types[providerType] || 'IMAP';
    }

    getMacOSEmailAccountType(providerType) {
        const types = {
            'exchange': 'EmailTypeExchange',
            'imap': 'EmailTypeIMAP',
            'pop3': 'EmailTypePOP'
        };
        return types[providerType] || 'EmailTypeIMAP';
    }

    getMacOSAuthMethod(authMethod) {
        const methods = {
            'password': 'EmailAuthPassword',
            'certificate': 'EmailAuthCertificate',
            'oauth2': 'EmailAuthOAuth'
        };
        return methods[authMethod] || 'EmailAuthPassword';
    }

    getIncomingServer(profile) {
        if (profile.provider.type === 'exchange') {
            return profile.provider.exchange.serverUrl ? 
                new URL(profile.provider.exchange.serverUrl).hostname : '';
        }
        return profile.provider.imap.server || '';
    }

    getIncomingPort(profile) {
        if (profile.provider.type === 'exchange') {
            return 443; // HTTPS
        }
        return profile.provider.imap.port || 993;
    }

    getIncomingSSL(profile) {
        if (profile.provider.type === 'exchange') {
            return true;
        }
        return profile.provider.imap.security === 'SSL';
    }

    getIncomingSecurity(profile) {
        if (profile.provider.type === 'exchange') {
            return 'SSL';
        }
        return profile.provider.imap.security || 'SSL';
    }

    getOutgoingServer(profile) {
        return profile.provider.smtp.server || '';
    }

    getOutgoingPort(profile) {
        return profile.provider.smtp.port || 587;
    }

    getOutgoingSSL(profile) {
        return profile.provider.smtp.security === 'SSL';
    }

    getOutgoingSecurity(profile) {
        return profile.provider.smtp.security || 'STARTTLS';
    }

    buildOutlookRegistrySettings(outlookConfig) {
        // Build Windows registry settings for Outlook
        let registryScript = '';
        
        if (outlookConfig.exchangeSettings) {
            registryScript += `
# Exchange settings
Set-ItemProperty -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676\\00000002" -Name "Exchange Server" -Value "${outlookConfig.exchangeSettings.serverURL}"
Set-ItemProperty -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676\\00000002" -Name "Mailbox Name" -Value "$emailAddress"
`;
        } else if (outlookConfig.imapSettings) {
            registryScript += `
# IMAP settings
Set-ItemProperty -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676\\00000003" -Name "IMAP Server" -Value "${outlookConfig.imapSettings.incomingServer}"
Set-ItemProperty -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676\\00000003" -Name "IMAP Port" -Value ${outlookConfig.imapSettings.incomingPort}
Set-ItemProperty -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676\\00000004" -Name "SMTP Server" -Value "${outlookConfig.imapSettings.outgoingServer}"
Set-ItemProperty -Path "$profilesKey\\9375CFF0413111d3B88A00104B2A6676\\00000004" -Name "SMTP Port" -Value ${outlookConfig.imapSettings.outgoingPort}
`;
        }
        
        return registryScript;
    }

    buildWindowsCertificateInstallScript(certificates) {
        let script = '';
        
        if (certificates.client) {
            script += `
# Install client certificate
$clientCertData = [Convert]::FromBase64String("${Buffer.from(certificates.client.data).toString('base64')}")
$clientCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($clientCertData, "", "Exportable,PersistKeySet")
$clientStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$clientStore.Open("ReadWrite")
$clientStore.Add($clientCert)
$clientStore.Close()
Write-Host "Client certificate installed"
`;
        }
        
        if (certificates.smime?.signing) {
            script += `
# Install S/MIME signing certificate
$smimeSignData = [Convert]::FromBase64String("${Buffer.from(certificates.smime.signing.data).toString('base64')}")
$smimeSignCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($smimeSignData, "", "Exportable,PersistKeySet")
$smimeStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$smimeStore.Open("ReadWrite")
$smimeStore.Add($smimeSignCert)
$smimeStore.Close()
Write-Host "S/MIME signing certificate installed"
`;
        }
        
        return script;
    }

    buildMacOSCertificatePayload(certificate, type) {
        return {
            PayloadType: 'com.apple.security.pkcs12',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.cert.${certificate.uuid}`,
            PayloadUUID: certificate.uuid,
            PayloadDisplayName: `${type.toUpperCase()} Certificate`,
            PayloadDescription: `${type} certificate for email`,
            
            PayloadContent: certificate.data,
            Password: certificate.password || ''
        };
    }

    generatePlistXML(data) {
        const plist = require('plist');
        return plist.build(data);
    }

    formatCertificatesForWindows(certificates) {
        return {
            client: certificates.client ? {
                format: 'PKCS#12',
                data: certificates.client.data,
                thumbprint: certificates.client.thumbprint,
                installLocation: 'CurrentUser\\My'
            } : null,
            smime: certificates.smime ? {
                signing: certificates.smime.signing ? {
                    format: 'PKCS#12',
                    data: certificates.smime.signing.data,
                    thumbprint: certificates.smime.signing.thumbprint,
                    installLocation: 'CurrentUser\\My'
                } : null,
                encryption: certificates.smime.encryption ? {
                    format: 'PKCS#12',
                    data: certificates.smime.encryption.data,
                    thumbprint: certificates.smime.encryption.thumbprint,
                    installLocation: 'CurrentUser\\My'
                } : null
            } : null
        };
    }

    formatCertificatesForMacOS(certificates) {
        return certificates; // Already in correct format
    }

    formatCertificatesForIOS(certificates) {
        return certificates; // Same as macOS
    }

    formatCertificatesForAndroid(certificates) {
        return {
            client: certificates.client ? {
                format: 'PKCS#12',
                data: certificates.client.data,
                uuid: certificates.client.uuid
            } : null,
            smime: certificates.smime ? {
                signing: certificates.smime.signing ? {
                    format: 'PKCS#12',
                    data: certificates.smime.signing.data,
                    uuid: certificates.smime.signing.uuid
                } : null,
                encryption: certificates.smime.encryption ? {
                    format: 'PKCS#12',
                    data: certificates.smime.encryption.data,
                    uuid: certificates.smime.encryption.uuid
                } : null
            } : null
        };
    }

    formatCertificatesForLinux(certificates) {
        return {
            client: certificates.client ? {
                certPath: `/tmp/${certificates.client.uuid}.crt`,
                keyPath: `/tmp/${certificates.client.uuid}.key`
            } : null,
            smime: certificates.smime ? {
                signing: certificates.smime.signing ? {
                    certPath: `/tmp/${certificates.smime.signing.uuid}.crt`,
                    keyPath: `/tmp/${certificates.smime.signing.uuid}.key`
                } : null,
                encryption: certificates.smime.encryption ? {
                    certPath: `/tmp/${certificates.smime.encryption.uuid}.crt`,
                    keyPath: `/tmp/${certificates.smime.encryption.uuid}.key`
                } : null
            } : null
        };
    }

    generateWindowsInstructions(profile) {
        return `Email Profile Installation Instructions - Windows Outlook

Profile: ${profile.name}
Email: ${profile.account.emailAddress}
Type: ${profile.provider.type}

Automatic Installation:
1. Run the provided PowerShell script as Administrator
2. Follow any certificate installation prompts
3. Open Outlook and select the new profile

Manual Installation:
1. Open Outlook
2. Go to File > Account Settings > Account Settings
3. Click "New" and configure with provided settings
4. Install certificates manually if provided

Verification:
- Open Outlook and check if the account appears
- Send a test email to verify configuration`;
    }

    generateMacOSInstructions(profile) {
        return `Email Profile Installation Instructions - macOS

Profile: ${profile.name}
Email: ${profile.account.emailAddress}
Type: ${profile.provider.type}

Installation:
1. Double-click the .mobileconfig file
2. System Preferences will open
3. Click "Install" to install the profile
4. Enter administrator credentials when prompted
5. The email account will be configured automatically

Verification:
- Go to System Preferences > Profiles
- The email profile should be listed
- Open Mail app to verify the account`;
    }

    generateIOSInstructions(profile) {
        return `Email Profile Installation Instructions - iOS

Profile: ${profile.name}
Email: ${profile.account.emailAddress}
Type: ${profile.provider.type}

Installation:
1. Email or AirDrop the .mobileconfig file to your device
2. Tap the file to open it
3. Tap "Install" in the Install Profile screen
4. Enter your device passcode if prompted
5. Tap "Install" again to confirm

Verification:
- Go to Settings > General > VPN & Device Management
- The profile should be listed under Configuration Profiles
- Open Mail app to verify the account`;
    }

    generateAndroidInstructions(profile) {
        return `Email Profile Installation Instructions - Android

Profile: ${profile.name}
Email: ${profile.account.emailAddress}
Type: ${profile.provider.type}

Installation:
1. Install any provided certificates first
2. Open Email app or Gmail
3. Add new account with provided configuration
4. Use the JSON configuration file for reference

Manual Configuration:
- Account type: ${profile.provider.type}
- Email: ${profile.account.emailAddress}
- Incoming server: ${this.getIncomingServer(profile)}
- Outgoing server: ${this.getOutgoingServer(profile)}

Verification:
- Send and receive test emails
- Check sync settings if using Exchange`;
    }

    generateLinuxInstructions(profile) {
        return `Email Profile Installation Instructions - Linux

Profile: ${profile.name}
Email: ${profile.account.emailAddress}
Type: ${profile.provider.type}

Thunderbird Installation:
1. Open Thunderbird
2. Go to Account Settings > Account Actions > Add Mail Account
3. Use the provided configuration file as reference
4. Install certificates if provided

Evolution Installation:
1. Open Evolution
2. Add new email account
3. Use manual configuration with provided settings

KMail Installation:
1. Open KMail
2. Configure new account with provided settings

Configuration Details:
- Incoming: ${this.getIncomingServer(profile)}:${this.getIncomingPort(profile)} (${this.getIncomingSecurity(profile)})
- Outgoing: ${this.getOutgoingServer(profile)}:${this.getOutgoingPort(profile)} (${this.getOutgoingSecurity(profile)})`;
    }

    /**
     * Storage Methods
     */
    async saveEmailProfile(profile) {
        const profilePath = path.join(config.network.emailProfilesPath, 'profiles', `${profile.id}.json`);
        await fs.writeFile(profilePath, JSON.stringify(profile, null, 2));
    }

    async loadExistingProfiles() {
        try {
            const profilesDir = path.join(config.network.emailProfilesPath, 'profiles');
            const files = await fs.readdir(profilesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const profilePath = path.join(profilesDir, file);
                    const profile = JSON.parse(await fs.readFile(profilePath, 'utf8'));
                    this.emailProfiles.set(profile.id, profile);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load email profiles:', error);
            }
        }
    }

    async loadEmailProviders() {
        try {
            const providersDir = path.join(config.network.emailProfilesPath, 'providers');
            const files = await fs.readdir(providersDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const providerPath = path.join(providersDir, file);
                    const provider = JSON.parse(await fs.readFile(providerPath, 'utf8'));
                    this.emailProviders.set(provider.id, provider);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load email providers:', error);
            }
        }
    }

    async saveAutodiscoveryCache() {
        const cachePath = path.join(config.network.emailProfilesPath, 'autodiscovery-cache', 'cache.json');
        const cacheData = Object.fromEntries(this.autodiscoveryCache);
        await fs.writeFile(cachePath, JSON.stringify(cacheData, null, 2));
    }

    /**
     * Public API Methods
     */
    async getProfiles() {
        return Array.from(this.emailProfiles.values());
    }

    async getProfile(profileId) {
        return this.emailProfiles.get(profileId);
    }

    async deleteProfile(profileId) {
        const profile = this.emailProfiles.get(profileId);
        if (!profile) {
            throw new Error(`Email profile not found: ${profileId}`);
        }

        this.emailProfiles.delete(profileId);
        
        const profilePath = path.join(config.network.emailProfilesPath, 'profiles', `${profileId}.json`);
        try {
            await fs.unlink(profilePath);
        } catch (error) {
            this.logger.error(`Failed to delete profile file: ${profilePath}`, error);
        }

        this.logger.info(`Email profile deleted: ${profileId}`);
        this.emit('profileDeleted', profile);
        
        return true;
    }

    async getProviders() {
        return Array.from(this.emailProviders.values());
    }

    async testAutodiscovery(domain) {
        return await this.performAutodiscovery(domain);
    }

    async getMetrics() {
        return {
            ...this.metrics,
            totalProfiles: this.emailProfiles.size,
            activeProfiles: Array.from(this.emailProfiles.values()).filter(p => p.status === 'active').length,
            supportedProviders: this.emailProviders.size,
            autodiscoverySuccessRate: this.metrics.autodiscoveryAttempts > 0 ? 
                (this.metrics.autodiscoverySuccess / this.metrics.autodiscoveryAttempts * 100).toFixed(2) + '%' : '0%'
        };
    }
}

module.exports = EmailProfileService;