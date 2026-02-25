/**
 * OpenDirectory WiFi Profile Management Service
 * Comprehensive WiFi profile creation and deployment for all platforms
 * 
 * Features:
 * - Multi-platform WiFi profile generation (Windows, macOS, iOS, Android, Linux)
 * - WPA2-Enterprise, WPA3-Enterprise, and personal network support
 * - 802.1X authentication with certificate-based auth
 * - EAP method configuration (EAP-TLS, EAP-TTLS, EAP-PEAP, EAP-FAST)
 * - Automatic certificate deployment with profiles
 * - Profile versioning and updates
 * - Bulk deployment capabilities
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const EventEmitter = require('events');
const config = require('../config');

class WiFiProfileService extends EventEmitter {
    constructor(certificateService, options = {}) {
        super();
        
        this.certificateService = certificateService;
        this.config = {
            ...config.network.wifi,
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
                    filename: path.join(path.dirname(config.logging.file), 'wifi-profiles.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // Profile stores
        this.wifiProfiles = new Map();
        this.deploymentHistory = new Map();
        
        // Platform-specific profile generators
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
            deploymentSuccess: 0,
            deploymentFailures: 0,
            certificateBasedProfiles: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadExistingProfiles();
            
            this.logger.info('WiFi Profile Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize WiFi Profile Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            config.network.wifiProfilesPath,
            path.join(config.network.wifiProfilesPath, 'profiles'),
            path.join(config.network.wifiProfilesPath, 'deployments'),
            path.join(config.network.wifiProfilesPath, 'templates'),
            path.join(config.network.wifiProfilesPath, 'exports')
        ];

        for (const dir of directories) {
            try {
                await fs.mkdir(dir, { recursive: true });
            } catch (error) {
                if (error.code !== 'EEXIST') throw error;
            }
        }
    }

    /**
     * WiFi Profile Creation
     */
    async createWiFiProfile(profileData) {
        try {
            const profileId = this.generateProfileId(profileData.name);
            const profile = {
                id: profileId,
                name: profileData.name,
                description: profileData.description || '',
                version: profileData.version || '1.0',
                
                // Network configuration
                ssid: profileData.ssid,
                ssidHex: this.stringToHex(profileData.ssid),
                security: profileData.security || this.config.defaultSecurity,
                hidden: profileData.hidden !== undefined ? profileData.hidden : false,
                autoConnect: profileData.autoConnect !== undefined ? profileData.autoConnect : true,
                priority: profileData.priority || 1,
                
                // Security configuration
                authentication: {
                    method: profileData.authentication?.method || 'EAP-TLS',
                    innerMethod: profileData.authentication?.innerMethod, // For tunneled methods
                    
                    // Certificate-based authentication
                    clientCertificate: {
                        enabled: profileData.authentication?.clientCertificate?.enabled || false,
                        templateId: profileData.authentication?.clientCertificate?.templateId,
                        certificateId: profileData.authentication?.clientCertificate?.certificateId,
                        autoEnroll: profileData.authentication?.clientCertificate?.autoEnroll || true
                    },
                    
                    // Username/Password authentication
                    credentials: {
                        username: profileData.authentication?.credentials?.username,
                        password: profileData.authentication?.credentials?.password,
                        domain: profileData.authentication?.credentials?.domain
                    },
                    
                    // Server validation
                    serverValidation: {
                        enabled: profileData.authentication?.serverValidation?.enabled !== false,
                        trustedRootCAs: profileData.authentication?.serverValidation?.trustedRootCAs || [],
                        serverNames: profileData.authentication?.serverValidation?.serverNames || [],
                        validateServerCertificate: profileData.authentication?.serverValidation?.validateServerCertificate !== false
                    }
                },
                
                // Encryption settings
                encryption: {
                    type: profileData.encryption?.type || 'AES',
                    pairwiseCipher: profileData.encryption?.pairwiseCipher || 'CCMP',
                    groupCipher: profileData.encryption?.groupCipher || 'CCMP'
                },
                
                // Platform-specific settings
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
                    rollback: profileData.deployment?.rollback || false
                },
                
                // Advanced settings
                advanced: {
                    fastReconnect: profileData.advanced?.fastReconnect !== false,
                    enablePMKCaching: profileData.advanced?.enablePMKCaching !== false,
                    enablePreAuthentication: profileData.advanced?.enablePreAuthentication !== false,
                    maxAuthFailures: profileData.advanced?.maxAuthFailures || 3,
                    roamingConsortium: profileData.advanced?.roamingConsortium || []
                },
                
                createdAt: new Date(),
                updatedAt: new Date(),
                status: 'active'
            };

            this.wifiProfiles.set(profileId, profile);
            await this.saveWiFiProfile(profile);
            
            this.metrics.profilesCreated++;
            if (profile.authentication.clientCertificate.enabled) {
                this.metrics.certificateBasedProfiles++;
            }
            
            this.logger.info(`WiFi profile created: ${profileId}`);
            this.emit('profileCreated', profile);
            
            return profile;

        } catch (error) {
            this.logger.error('Failed to create WiFi profile:', error);
            throw error;
        }
    }

    async updateWiFiProfile(profileId, updates) {
        try {
            const profile = this.wifiProfiles.get(profileId);
            if (!profile) {
                throw new Error(`WiFi profile not found: ${profileId}`);
            }

            const updatedProfile = {
                ...profile,
                ...updates,
                version: this.incrementVersion(profile.version),
                updatedAt: new Date()
            };

            this.wifiProfiles.set(profileId, updatedProfile);
            await this.saveWiFiProfile(updatedProfile);
            
            this.logger.info(`WiFi profile updated: ${profileId}`);
            this.emit('profileUpdated', updatedProfile);
            
            return updatedProfile;

        } catch (error) {
            this.logger.error('Failed to update WiFi profile:', error);
            throw error;
        }
    }

    /**
     * Platform-Specific Profile Generation
     */
    async generateProfileForPlatform(profileId, platform, deviceInfo = {}) {
        try {
            const profile = this.wifiProfiles.get(profileId);
            if (!profile) {
                throw new Error(`WiFi profile not found: ${profileId}`);
            }

            const generator = this.profileGenerators[platform.toLowerCase()];
            if (!generator) {
                throw new Error(`Unsupported platform: ${platform}`);
            }

            // Get certificates if needed
            let certificates = null;
            if (profile.authentication.clientCertificate.enabled) {
                certificates = await this.getCertificatesForProfile(profile, deviceInfo);
            }

            const platformProfile = await generator(profile, certificates, deviceInfo);
            
            this.logger.info(`WiFi profile generated for platform: ${platform}, profile: ${profileId}`);
            this.emit('profileGenerated', profile, platform, platformProfile);
            
            return platformProfile;

        } catch (error) {
            this.logger.error(`Failed to generate WiFi profile for ${platform}:`, error);
            throw error;
        }
    }

    async generateWindowsProfile(profile, certificates, deviceInfo) {
        // Windows WiFi profile XML format
        const profileXml = this.buildWindowsWiFiXML(profile, certificates);
        
        // PowerShell script for deployment
        const deploymentScript = this.buildWindowsDeploymentScript(profile, profileXml, certificates);
        
        return {
            platform: 'windows',
            format: 'xml',
            profileData: profileXml,
            deploymentScript: deploymentScript,
            certificates: certificates ? this.formatCertificatesForWindows(certificates) : null,
            instructions: this.generateWindowsInstructions(profile)
        };
    }

    buildWindowsWiFiXML(profile, certificates) {
        const eapConfig = this.buildWindowsEAPConfig(profile, certificates);
        
        return `<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>${this.escapeXML(profile.name)}</name>
    <SSIDConfig>
        <SSID>
            <hex>${profile.ssidHex}</hex>
            <name>${this.escapeXML(profile.ssid)}</name>
        </SSID>
        <nonBroadcast>${profile.hidden}</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>${this.getWindowsAuthMethod(profile.security)}</authentication>
                <encryption>${this.getWindowsEncryption(profile.security)}</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            ${eapConfig}
        </security>
    </MSM>
</WLANProfile>`;
    }

    buildWindowsEAPConfig(profile, certificates) {
        switch (profile.authentication.method) {
            case 'EAP-TLS':
                return this.buildWindowsEAPTLSConfig(profile, certificates);
            case 'EAP-TTLS':
                return this.buildWindowsEAPTTLSConfig(profile, certificates);
            case 'EAP-PEAP':
                return this.buildWindowsEAPPEAPConfig(profile, certificates);
            default:
                return this.buildWindowsEAPTLSConfig(profile, certificates);
        }
    }

    buildWindowsEAPTLSConfig(profile, certificates) {
        const serverValidation = profile.authentication.serverValidation;
        
        return `<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
            <authMode>machineOrUser</authMode>
            <EAPConfig>
                <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                    <EapMethod>
                        <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
                        <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                        <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                    </EapMethod>
                    <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                            <Type>13</Type>
                            <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                                <CredentialsSource>
                                    <CertificateStore>
                                        <SimpleCertSelection>true</SimpleCertSelection>
                                    </CertificateStore>
                                </CredentialsSource>
                                <ServerValidation>
                                    <DisableUserPromptForServerValidation>${!serverValidation.enabled}</DisableUserPromptForServerValidation>
                                    <ServerNames>${serverValidation.serverNames.join(';')}</ServerNames>
                                </ServerValidation>
                                <DifferentUsername>${profile.authentication.credentials?.username ? 'true' : 'false'}</DifferentUsername>
                            </EapType>
                        </Eap>
                    </Config>
                </EapHostConfig>
            </EAPConfig>
        </OneX>`;
    }

    buildWindowsEAPTTLSConfig(profile, certificates) {
        // EAP-TTLS configuration for Windows
        return `<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
            <authMode>machineOrUser</authMode>
            <EAPConfig>
                <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                    <EapMethod>
                        <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type>
                    </EapMethod>
                    <Config>
                        <EapTtls>
                            <ServerValidation>
                                <ServerNames>${profile.authentication.serverValidation.serverNames.join(';')}</ServerNames>
                            </ServerValidation>
                            <Phase2Authentication>
                                <InnerEapOptional>false</InnerEapOptional>
                                <InnerMethod>${profile.authentication.innerMethod || 'MSCHAPv2'}</InnerMethod>
                            </Phase2Authentication>
                        </EapTtls>
                    </Config>
                </EapHostConfig>
            </EAPConfig>
        </OneX>`;
    }

    buildWindowsEAPPEAPConfig(profile, certificates) {
        // EAP-PEAP configuration for Windows
        return `<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
            <authMode>machineOrUser</authMode>
            <EAPConfig>
                <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                    <EapMethod>
                        <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
                    </EapMethod>
                    <Config>
                        <EapPeap>
                            <ServerValidation>
                                <ServerNames>${profile.authentication.serverValidation.serverNames.join(';')}</ServerNames>
                            </ServerValidation>
                            <InnerEapOptional>false</InnerEapOptional>
                            <InnerMethod>${profile.authentication.innerMethod || 'MSCHAPv2'}</InnerMethod>
                        </EapPeap>
                    </Config>
                </EapHostConfig>
            </EAPConfig>
        </OneX>`;
    }

    buildWindowsDeploymentScript(profile, profileXml, certificates) {
        return `# WiFi Profile Deployment Script for ${profile.name}
# Generated by OpenDirectory Certificate & Network Service

# Remove existing profile if it exists
try {
    Remove-WiFiProfile -Name "${profile.name}" -ErrorAction SilentlyContinue
} catch {
    Write-Host "No existing profile to remove"
}

# Install certificates if provided
${certificates ? this.buildWindowsCertificateInstallScript(certificates) : '# No certificates to install'}

# Create temporary profile file
$profileXml = @"
${profileXml}
"@

$tempFile = [System.IO.Path]::GetTempFileName() + ".xml"
$profileXml | Out-File -FilePath $tempFile -Encoding UTF8

try {
    # Add WiFi profile
    netsh wlan add profile filename="$tempFile"
    Write-Host "WiFi profile '${profile.name}' installed successfully"
} catch {
    Write-Error "Failed to install WiFi profile: $_"
} finally {
    # Clean up
    Remove-Item $tempFile -ErrorAction SilentlyContinue
}`;
    }

    async generateMacOSProfile(profile, certificates, deviceInfo) {
        // macOS Configuration Profile (mobileconfig format)
        const configProfile = this.buildMacOSConfigurationProfile(profile, certificates, deviceInfo);
        
        return {
            platform: 'macos',
            format: 'mobileconfig',
            profileData: configProfile,
            certificates: certificates ? this.formatCertificatesForMacOS(certificates) : null,
            instructions: this.generateMacOSInstructions(profile)
        };
    }

    buildMacOSConfigurationProfile(profile, certificates, deviceInfo) {
        const payloadUUID = this.generateUUID();
        const wifiUUID = this.generateUUID();
        
        const wifiPayload = {
            PayloadType: 'com.apple.wifi.managed',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.wifi.${wifiUUID}`,
            PayloadUUID: wifiUUID,
            PayloadDisplayName: `WiFi: ${profile.ssid}`,
            PayloadDescription: `WiFi configuration for ${profile.ssid}`,
            
            SSID_STR: profile.ssid,
            HIDDEN_NETWORK: profile.hidden,
            AutoJoin: profile.autoConnect,
            Priority: profile.priority,
            
            EncryptionType: this.getMacOSEncryptionType(profile.security),
            
            // EAP Configuration
            EAPClientConfiguration: this.buildMacOSEAPConfig(profile, certificates),
            
            // Certificate configuration
            ...(certificates && {
                PayloadCertificateUUID: certificates.client?.uuid
            })
        };

        const payloads = [wifiPayload];
        
        // Add certificate payloads if needed
        if (certificates) {
            if (certificates.client) {
                payloads.push(this.buildMacOSCertificatePayload(certificates.client, 'client'));
            }
            if (certificates.ca) {
                payloads.push(this.buildMacOSCertificatePayload(certificates.ca, 'ca'));
            }
        }

        const configProfile = {
            PayloadType: 'Configuration',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.wifi.${profile.id}`,
            PayloadUUID: payloadUUID,
            PayloadDisplayName: `${profile.name} WiFi Profile`,
            PayloadDescription: profile.description || `WiFi configuration for ${profile.ssid}`,
            PayloadOrganization: 'OpenDirectory',
            PayloadContent: payloads,
            PayloadRemovalDisallowed: false,
            PayloadScope: 'System'
        };

        return this.generatePlistXML(configProfile);
    }

    buildMacOSEAPConfig(profile, certificates) {
        const eapConfig = {
            AcceptEAPTypes: [this.getMacOSEAPType(profile.authentication.method)],
            UserName: profile.authentication.credentials?.username || '',
            
            // Server trust settings
            TLSTrustedServerNames: profile.authentication.serverValidation.serverNames || [],
            TLSAllowTrustExceptions: !profile.authentication.serverValidation.validateServerCertificate,
            
            // Certificate-based authentication
            ...(certificates && certificates.client && {
                PayloadCertificateUUID: certificates.client.uuid
            })
        };

        // Add inner method for tunneled EAP
        if (profile.authentication.innerMethod && 
            ['EAP-TTLS', 'EAP-PEAP'].includes(profile.authentication.method)) {
            eapConfig.TTLSInnerAuthentication = this.getMacOSInnerAuthType(profile.authentication.innerMethod);
        }

        return eapConfig;
    }

    buildMacOSCertificatePayload(certificate, type) {
        return {
            PayloadType: 'com.apple.security.pkcs12',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.cert.${certificate.uuid}`,
            PayloadUUID: certificate.uuid,
            PayloadDisplayName: `${type.toUpperCase()} Certificate`,
            PayloadDescription: `${type} certificate for WiFi authentication`,
            
            PayloadContent: certificate.data, // Base64 encoded PKCS#12
            Password: certificate.password || ''
        };
    }

    async generateIOSProfile(profile, certificates, deviceInfo) {
        // iOS uses the same mobileconfig format as macOS
        const configProfile = this.buildIOSConfigurationProfile(profile, certificates, deviceInfo);
        
        return {
            platform: 'ios',
            format: 'mobileconfig',
            profileData: configProfile,
            certificates: certificates ? this.formatCertificatesForIOS(certificates) : null,
            instructions: this.generateIOSInstructions(profile)
        };
    }

    buildIOSConfigurationProfile(profile, certificates, deviceInfo) {
        // Similar to macOS but with iOS-specific considerations
        return this.buildMacOSConfigurationProfile(profile, certificates, deviceInfo);
    }

    async generateAndroidProfile(profile, certificates, deviceInfo) {
        // Android WiFi configuration - multiple formats supported
        const configs = {
            wpaSupplicant: this.buildAndroidWpaSupplicantConfig(profile, certificates),
            json: this.buildAndroidJSONConfig(profile, certificates),
            xml: this.buildAndroidXMLConfig(profile, certificates)
        };
        
        return {
            platform: 'android',
            format: 'json',
            profileData: configs.json,
            alternativeFormats: {
                wpaSupplicant: configs.wpaSupplicant,
                xml: configs.xml
            },
            certificates: certificates ? this.formatCertificatesForAndroid(certificates) : null,
            instructions: this.generateAndroidInstructions(profile)
        };
    }

    buildAndroidWpaSupplicantConfig(profile, certificates) {
        let config = `network={
    ssid="${profile.ssid}"
    ${profile.hidden ? 'scan_ssid=1' : ''}
    key_mgmt=WPA-EAP
    eap=${profile.authentication.method.replace('EAP-', '')}
    proto=RSN
    pairwise=CCMP
    group=CCMP
`;

        // Add authentication details
        if (profile.authentication.method === 'EAP-TLS' && certificates?.client) {
            config += `    client_cert="${certificates.client.path}"\n`;
            config += `    private_key="${certificates.client.keyPath}"\n`;
        }

        if (profile.authentication.credentials?.username) {
            config += `    identity="${profile.authentication.credentials.username}"\n`;
        }

        if (profile.authentication.serverValidation.enabled) {
            config += `    ca_cert="${certificates?.ca?.path || '/system/etc/security/cacerts'}"\n`;
        }

        config += '}';
        return config;
    }

    buildAndroidJSONConfig(profile, certificates) {
        return JSON.stringify({
            ssid: profile.ssid,
            security: profile.security,
            hidden: profile.hidden,
            autoConnect: profile.autoConnect,
            priority: profile.priority,
            
            eap: {
                method: profile.authentication.method,
                phase2: profile.authentication.innerMethod,
                identity: profile.authentication.credentials?.username,
                anonymousIdentity: profile.authentication.credentials?.anonymousIdentity,
                
                clientCertificate: certificates?.client ? {
                    data: certificates.client.data,
                    password: certificates.client.password
                } : null,
                
                caCertificate: certificates?.ca ? {
                    data: certificates.ca.data
                } : null,
                
                serverValidation: {
                    enabled: profile.authentication.serverValidation.enabled,
                    serverNames: profile.authentication.serverValidation.serverNames
                }
            }
        }, null, 2);
    }

    buildAndroidXMLConfig(profile, certificates) {
        // Android Enterprise WiFi configuration XML
        return `<?xml version="1.0" encoding="utf-8"?>
<wifi-configuration>
    <network-name>${this.escapeXML(profile.ssid)}</network-name>
    <ssid>${this.escapeXML(profile.ssid)}</ssid>
    <security-type>${profile.security}</security-type>
    <hidden>${profile.hidden}</hidden>
    <auto-connect>${profile.autoConnect}</auto-connect>
    <priority>${profile.priority}</priority>
    
    <eap-method>${profile.authentication.method}</eap-method>
    ${profile.authentication.innerMethod ? `<phase2-method>${profile.authentication.innerMethod}</phase2-method>` : ''}
    ${profile.authentication.credentials?.username ? `<identity>${this.escapeXML(profile.authentication.credentials.username)}</identity>` : ''}
    
    <server-ca-certificate>${certificates?.ca?.data || ''}</server-ca-certificate>
    <client-certificate>${certificates?.client?.data || ''}</client-certificate>
</wifi-configuration>`;
    }

    async generateLinuxProfile(profile, certificates, deviceInfo) {
        // Linux NetworkManager configuration
        const nmConfig = this.buildNetworkManagerConfig(profile, certificates);
        const wpaConfig = this.buildLinuxWpaSupplicantConfig(profile, certificates);
        
        return {
            platform: 'linux',
            format: 'nmconnection',
            profileData: nmConfig,
            alternativeFormats: {
                wpaSupplicant: wpaConfig
            },
            certificates: certificates ? this.formatCertificatesForLinux(certificates) : null,
            instructions: this.generateLinuxInstructions(profile)
        };
    }

    buildNetworkManagerConfig(profile, certificates) {
        const connectionUuid = this.generateUUID();
        
        return `[connection]
id=${profile.name}
uuid=${connectionUuid}
type=wifi
autoconnect=${profile.autoConnect}
permissions=

[wifi]
ssid=${profile.ssid}
mode=infrastructure
${profile.hidden ? 'hidden=true' : ''}

[wifi-security]
key-mgmt=wpa-eap

[802-1x]
eap=${profile.authentication.method.toLowerCase().replace('eap-', '')};
identity=${profile.authentication.credentials?.username || ''}
${certificates?.client ? `client-cert=${certificates.client.path}` : ''}
${certificates?.client ? `private-key=${certificates.client.keyPath}` : ''}
${certificates?.ca ? `ca-cert=${certificates.ca.path}` : ''}
${profile.authentication.innerMethod ? `phase2-auth=${profile.authentication.innerMethod.toLowerCase()}` : ''}

[ipv4]
method=auto

[ipv6]
addr-gen-mode=stable-privacy
method=auto

[proxy]`;
    }

    buildLinuxWpaSupplicantConfig(profile, certificates) {
        // Similar to Android wpa_supplicant config
        return this.buildAndroidWpaSupplicantConfig(profile, certificates);
    }

    /**
     * Certificate Management for WiFi Profiles
     */
    async getCertificatesForProfile(profile, deviceInfo) {
        if (!profile.authentication.clientCertificate.enabled) {
            return null;
        }

        let certificates = {};

        // Get client certificate
        if (profile.authentication.clientCertificate.certificateId) {
            // Use specific certificate
            certificates.client = await this.getCertificateById(profile.authentication.clientCertificate.certificateId);
        } else if (profile.authentication.clientCertificate.templateId && profile.authentication.clientCertificate.autoEnroll) {
            // Auto-enroll new certificate
            certificates.client = await this.enrollCertificateForDevice(
                profile.authentication.clientCertificate.templateId,
                deviceInfo
            );
        }

        // Get CA certificates for server validation
        if (profile.authentication.serverValidation.trustedRootCAs.length > 0) {
            certificates.ca = await this.getCA Certificates(profile.authentication.serverValidation.trustedRootCAs);
        }

        return certificates;
    }

    async enrollCertificateForDevice(templateId, deviceInfo) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        const enrollmentRequest = {
            templateId: templateId,
            deviceId: deviceInfo.deviceId,
            userId: deviceInfo.userId,
            subject: {
                commonName: deviceInfo.deviceName || deviceInfo.deviceId,
                organizationalUnitName: 'WiFi Clients'
            },
            subjectAltName: deviceInfo.deviceFQDN ? [{ type: 2, value: deviceInfo.deviceFQDN }] : [],
            requester: 'wifi-profile-auto-enrollment'
        };

        const certificate = await this.certificateService.enrollCertificate(enrollmentRequest);
        return this.formatCertificateForWiFi(certificate);
    }

    async getCertificateById(certificateId) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        const certificate = await this.certificateService.getCertificate(certificateId);
        return this.formatCertificateForWiFi(certificate);
    }

    async getCACertificates(caIds) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        const caCerts = [];
        for (const caId of caIds) {
            const ca = await this.certificateService.getCA(caId);
            caCerts.push({
                data: ca.certificate,
                uuid: this.generateUUID(),
                path: `/tmp/${caId}.pem`
            });
        }
        
        return caCerts;
    }

    formatCertificateForWiFi(certificate) {
        return {
            uuid: this.generateUUID(),
            data: certificate.certificate,
            keyData: certificate.privateKey,
            password: '', // Could be generated or provided
            path: `/tmp/${certificate.id}.pem`,
            keyPath: `/tmp/${certificate.id}.key`
        };
    }

    /**
     * Profile Deployment
     */
    async deployProfile(profileId, deploymentOptions = {}) {
        try {
            const profile = this.wifiProfiles.get(profileId);
            if (!profile) {
                throw new Error(`WiFi profile not found: ${profileId}`);
            }

            const deploymentId = this.generateDeploymentId();
            const deployment = {
                id: deploymentId,
                profileId: profileId,
                targetDevices: deploymentOptions.targetDevices || profile.deployment.targetDevices,
                targetGroups: deploymentOptions.targetGroups || profile.deployment.targetGroups,
                platforms: deploymentOptions.platforms || ['windows', 'macos', 'ios', 'android', 'linux'],
                status: 'pending',
                startedAt: new Date(),
                results: []
            };

            this.deploymentHistory.set(deploymentId, deployment);
            
            // Process deployment
            await this.processProfileDeployment(deployment);
            
            this.metrics.profilesDeployed++;
            this.logger.info(`WiFi profile deployment started: ${deploymentId}`);
            this.emit('deploymentStarted', deployment);
            
            return deployment;

        } catch (error) {
            this.logger.error('Failed to deploy WiFi profile:', error);
            throw error;
        }
    }

    async processProfileDeployment(deployment) {
        try {
            deployment.status = 'processing';
            
            // Get target devices (would integrate with device management system)
            const targetDevices = await this.resolveTargetDevices(deployment);
            
            for (const device of targetDevices) {
                try {
                    const platformProfile = await this.generateProfileForPlatform(
                        deployment.profileId,
                        device.platform,
                        device
                    );
                    
                    const result = await this.deployToDevice(device, platformProfile);
                    
                    deployment.results.push({
                        deviceId: device.deviceId,
                        platform: device.platform,
                        success: true,
                        result: result
                    });
                    
                    this.metrics.deploymentSuccess++;
                    
                } catch (error) {
                    deployment.results.push({
                        deviceId: device.deviceId,
                        platform: device.platform,
                        success: false,
                        error: error.message
                    });
                    
                    this.metrics.deploymentFailures++;
                    this.logger.error(`Failed to deploy to device ${device.deviceId}:`, error);
                }
            }
            
            deployment.status = 'completed';
            deployment.completedAt = new Date();
            
            await this.saveDeployment(deployment);
            this.emit('deploymentCompleted', deployment);

        } catch (error) {
            deployment.status = 'failed';
            deployment.error = error.message;
            deployment.completedAt = new Date();
            
            await this.saveDeployment(deployment);
            this.logger.error('Profile deployment failed:', error);
            throw error;
        }
    }

    async resolveTargetDevices(deployment) {
        // This would integrate with device management system
        // For now, return mock devices
        return [
            { deviceId: 'device1', platform: 'windows', deviceName: 'PC-001' },
            { deviceId: 'device2', platform: 'macos', deviceName: 'Mac-001' },
            { deviceId: 'device3', platform: 'ios', deviceName: 'iPhone-001' }
        ];
    }

    async deployToDevice(device, platformProfile) {
        // Integration with MDM or other deployment mechanisms
        if (config.mdm.enabled) {
            return await this.deployViaMDM(device, platformProfile);
        } else {
            return await this.deployViaDownload(device, platformProfile);
        }
    }

    async deployViaMDM(device, platformProfile) {
        // MDM deployment integration
        return {
            method: 'mdm',
            commandId: `cmd-${Date.now()}`,
            status: 'sent'
        };
    }

    async deployViaDownload(device, platformProfile) {
        // Generate download package
        const packageId = this.generatePackageId();
        const packagePath = path.join(config.network.wifiProfilesPath, 'exports', `${packageId}.zip`);
        
        await this.createDeploymentPackage(platformProfile, packagePath);
        
        return {
            method: 'download',
            packageId: packageId,
            downloadUrl: `/api/wifi/download/${packageId}`,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        };
    }

    async createDeploymentPackage(platformProfile, packagePath) {
        const archiver = require('archiver');
        const output = require('fs').createWriteStream(packagePath);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        archive.pipe(output);
        
        // Add profile file
        const profileExtension = this.getProfileFileExtension(platformProfile.platform);
        archive.append(platformProfile.profileData, { name: `wifi-profile.${profileExtension}` });
        
        // Add certificates if present
        if (platformProfile.certificates) {
            if (platformProfile.certificates.client) {
                archive.append(platformProfile.certificates.client.data, { name: 'client-certificate.p12' });
            }
            if (platformProfile.certificates.ca) {
                archive.append(platformProfile.certificates.ca.data, { name: 'ca-certificate.pem' });
            }
        }
        
        // Add deployment script if present
        if (platformProfile.deploymentScript) {
            const scriptExtension = this.getScriptFileExtension(platformProfile.platform);
            archive.append(platformProfile.deploymentScript, { name: `deploy.${scriptExtension}` });
        }
        
        // Add instructions
        archive.append(platformProfile.instructions, { name: 'README.txt' });
        
        await archive.finalize();
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
        return `wifi-${hash}`;
    }

    generateDeploymentId() {
        return `deploy-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generatePackageId() {
        return `pkg-${Date.now()}-${Math.floor(Math.random() * 0xFFFF).toString(16)}`;
    }

    generateUUID() {
        return require('uuid').v4();
    }

    stringToHex(str) {
        return Buffer.from(str, 'utf8').toString('hex').toUpperCase();
    }

    escapeXML(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&apos;');
    }

    incrementVersion(version) {
        const parts = version.split('.');
        parts[parts.length - 1] = (parseInt(parts[parts.length - 1]) + 1).toString();
        return parts.join('.');
    }

    getWindowsAuthMethod(security) {
        const authMethods = {
            'WPA2-Enterprise': 'WPA2',
            'WPA3-Enterprise': 'WPA3',
            'WPA-Enterprise': 'WPA'
        };
        return authMethods[security] || 'WPA2';
    }

    getWindowsEncryption(security) {
        const encryptions = {
            'WPA2-Enterprise': 'AES',
            'WPA3-Enterprise': 'AES',
            'WPA-Enterprise': 'TKIP'
        };
        return encryptions[security] || 'AES';
    }

    getMacOSEncryptionType(security) {
        const types = {
            'WPA2-Enterprise': 'WPA2',
            'WPA3-Enterprise': 'WPA3',
            'WPA-Enterprise': 'WPA'
        };
        return types[security] || 'WPA2';
    }

    getMacOSEAPType(method) {
        const types = {
            'EAP-TLS': 13,
            'EAP-TTLS': 21,
            'EAP-PEAP': 25,
            'EAP-FAST': 43
        };
        return types[method] || 13;
    }

    getMacOSInnerAuthType(method) {
        const types = {
            'MSCHAPv2': 'MSCHAPv2',
            'PAP': 'PAP',
            'CHAP': 'CHAP',
            'EAP-MSCHAPv2': 'EAP-MSCHAPv2'
        };
        return types[method] || 'MSCHAPv2';
    }

    getProfileFileExtension(platform) {
        const extensions = {
            windows: 'xml',
            macos: 'mobileconfig',
            ios: 'mobileconfig',
            android: 'json',
            linux: 'nmconnection'
        };
        return extensions[platform] || 'txt';
    }

    getScriptFileExtension(platform) {
        const extensions = {
            windows: 'ps1',
            macos: 'sh',
            ios: 'sh',
            android: 'sh',
            linux: 'sh'
        };
        return extensions[platform] || 'txt';
    }

    generatePlistXML(data) {
        // Simple plist XML generator
        const plist = require('plist');
        return plist.build(data);
    }

    formatCertificatesForWindows(certificates) {
        return {
            client: certificates.client ? {
                format: 'PKCS#12',
                data: certificates.client.data,
                installLocation: 'CurrentUser\\My'
            } : null,
            ca: certificates.ca ? {
                format: 'PEM',
                data: certificates.ca.data,
                installLocation: 'CurrentUser\\Root'
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
                password: certificates.client.password
            } : null,
            ca: certificates.ca ? {
                format: 'PEM',
                data: certificates.ca.data
            } : null
        };
    }

    formatCertificatesForLinux(certificates) {
        return {
            client: certificates.client ? {
                certPath: certificates.client.path,
                keyPath: certificates.client.keyPath
            } : null,
            ca: certificates.ca ? {
                caPath: certificates.ca.path
            } : null
        };
    }

    buildWindowsCertificateInstallScript(certificates) {
        let script = '';
        
        if (certificates.client) {
            script += `
# Install client certificate
$clientCertData = [Convert]::FromBase64String("${Buffer.from(certificates.client.data).toString('base64')}")
$clientCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($clientCertData, "", "Exportable")
$clientStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$clientStore.Open("ReadWrite")
$clientStore.Add($clientCert)
$clientStore.Close()
Write-Host "Client certificate installed"
`;
        }
        
        if (certificates.ca) {
            script += `
# Install CA certificate
$caCertData = [Convert]::FromBase64String("${Buffer.from(certificates.ca.data).toString('base64')}")
$caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caCertData)
$caStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$caStore.Open("ReadWrite")
$caStore.Add($caCert)
$caStore.Close()
Write-Host "CA certificate installed"
`;
        }
        
        return script;
    }

    generateWindowsInstructions(profile) {
        return `WiFi Profile Installation Instructions - Windows

Profile: ${profile.name}
SSID: ${profile.ssid}
Security: ${profile.security}

Automatic Installation:
1. Run the provided PowerShell script as Administrator
2. Follow any certificate installation prompts
3. The WiFi profile will be installed automatically

Manual Installation:
1. Open Command Prompt as Administrator
2. Run: netsh wlan add profile filename="wifi-profile.xml"
3. Install certificates manually if provided

Verification:
- Run: netsh wlan show profiles
- The profile "${profile.name}" should be listed
- Connect to the WiFi network to test`;
    }

    generateMacOSInstructions(profile) {
        return `WiFi Profile Installation Instructions - macOS

Profile: ${profile.name}
SSID: ${profile.ssid}
Security: ${profile.security}

Installation:
1. Double-click the .mobileconfig file
2. System Preferences will open
3. Click "Install" to install the profile
4. Enter administrator credentials when prompted
5. The WiFi network should appear in available networks

Verification:
- Go to System Preferences > Profiles
- The WiFi profile should be listed
- Go to System Preferences > Network > WiFi
- The network should connect automatically`;
    }

    generateIOSInstructions(profile) {
        return `WiFi Profile Installation Instructions - iOS

Profile: ${profile.name}
SSID: ${profile.ssid}
Security: ${profile.security}

Installation:
1. Email or AirDrop the .mobileconfig file to your device
2. Tap the file to open it
3. Tap "Install" in the Install Profile screen
4. Enter your device passcode if prompted
5. Tap "Install" again to confirm
6. The WiFi network will be configured automatically

Verification:
- Go to Settings > General > VPN & Device Management
- The profile should be listed under Configuration Profiles
- Go to Settings > WiFi
- The network should connect automatically`;
    }

    generateAndroidInstructions(profile) {
        return `WiFi Profile Installation Instructions - Android

Profile: ${profile.name}
SSID: ${profile.ssid}
Security: ${profile.security}

Installation:
1. Install any provided certificates first:
   - Go to Settings > Security > Install from storage
   - Select the certificate files
2. Go to Settings > WiFi
3. Tap "Add network" or "+"
4. Enter the network details from the configuration file
5. Install client certificate if using EAP-TLS

Manual Configuration:
- Network name: ${profile.ssid}
- Security: ${profile.security}
- EAP method: ${profile.authentication.method}
- Phase 2 authentication: ${profile.authentication.innerMethod || 'None'}

Verification:
- The network should appear in WiFi settings
- Connection should be automatic`;
    }

    generateLinuxInstructions(profile) {
        return `WiFi Profile Installation Instructions - Linux

Profile: ${profile.name}
SSID: ${profile.ssid}
Security: ${profile.security}

NetworkManager Installation:
1. Copy the .nmconnection file to /etc/NetworkManager/system-connections/
2. Set correct permissions: sudo chmod 600 /etc/NetworkManager/system-connections/${profile.name}
3. Reload NetworkManager: sudo nmcli connection reload
4. Connect: nmcli connection up "${profile.name}"

wpa_supplicant Installation:
1. Add the network configuration to /etc/wpa_supplicant/wpa_supplicant.conf
2. Restart wpa_supplicant service
3. Connect using your WiFi manager

Certificate Installation:
- Copy certificate files to appropriate locations
- Client cert: /etc/ssl/certs/
- Private key: /etc/ssl/private/
- CA cert: /etc/ssl/certs/

Verification:
- Run: nmcli connection show
- The profile should be listed
- Run: nmcli device wifi list
- The network should be available`;
    }

    /**
     * Storage Methods
     */
    async saveWiFiProfile(profile) {
        const profilePath = path.join(config.network.wifiProfilesPath, 'profiles', `${profile.id}.json`);
        await fs.writeFile(profilePath, JSON.stringify(profile, null, 2));
    }

    async loadExistingProfiles() {
        try {
            const profilesDir = path.join(config.network.wifiProfilesPath, 'profiles');
            const files = await fs.readdir(profilesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const profilePath = path.join(profilesDir, file);
                    const profile = JSON.parse(await fs.readFile(profilePath, 'utf8'));
                    this.wifiProfiles.set(profile.id, profile);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load WiFi profiles:', error);
            }
        }
    }

    async saveDeployment(deployment) {
        const deploymentPath = path.join(config.network.wifiProfilesPath, 'deployments', `${deployment.id}.json`);
        await fs.writeFile(deploymentPath, JSON.stringify(deployment, null, 2));
    }

    /**
     * Public API Methods
     */
    async getProfiles() {
        return Array.from(this.wifiProfiles.values());
    }

    async getProfile(profileId) {
        return this.wifiProfiles.get(profileId);
    }

    async deleteProfile(profileId) {
        const profile = this.wifiProfiles.get(profileId);
        if (!profile) {
            throw new Error(`WiFi profile not found: ${profileId}`);
        }

        this.wifiProfiles.delete(profileId);
        
        // Delete profile file
        const profilePath = path.join(config.network.wifiProfilesPath, 'profiles', `${profileId}.json`);
        try {
            await fs.unlink(profilePath);
        } catch (error) {
            this.logger.error(`Failed to delete profile file: ${profilePath}`, error);
        }

        this.logger.info(`WiFi profile deleted: ${profileId}`);
        this.emit('profileDeleted', profile);
        
        return true;
    }

    async getDeployments() {
        return Array.from(this.deploymentHistory.values());
    }

    async getDeployment(deploymentId) {
        return this.deploymentHistory.get(deploymentId);
    }

    async getMetrics() {
        return {
            ...this.metrics,
            totalProfiles: this.wifiProfiles.size,
            activeProfiles: Array.from(this.wifiProfiles.values()).filter(p => p.status === 'active').length,
            totalDeployments: this.deploymentHistory.size
        };
    }
}

module.exports = WiFiProfileService;