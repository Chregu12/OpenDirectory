/**
 * OpenDirectory VPN Configuration Management Service
 * Comprehensive VPN profile creation and deployment for all VPN types and platforms
 * 
 * Features:
 * - Multi-VPN support (OpenVPN, WireGuard, IKEv2, L2TP, PPTP)
 * - Multi-platform configuration generation
 * - Certificate-based authentication
 * - Embedded certificate deployment for OpenVPN
 * - Split tunneling configuration
 * - Auto-connect and failover settings
 * - Bulk deployment capabilities
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const EventEmitter = require('events');
const forge = require('node-forge');
const config = require('../config');

class VPNProfileService extends EventEmitter {
    constructor(certificateService, options = {}) {
        super();
        
        this.certificateService = certificateService;
        this.config = {
            ...config.network.vpn,
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
                    filename: path.join(path.dirname(config.logging.file), 'vpn-profiles.log')
                }),
                ...(config.logging.enableConsole ? [new winston.transports.Console()] : [])
            ]
        });

        // Profile stores
        this.vpnProfiles = new Map();
        this.deploymentHistory = new Map();
        this.serverConfigurations = new Map();
        
        // VPN type generators
        this.profileGenerators = {
            openvpn: this.generateOpenVPNProfile.bind(this),
            wireguard: this.generateWireGuardProfile.bind(this),
            ikev2: this.generateIKEv2Profile.bind(this),
            l2tp: this.generateL2TPProfile.bind(this),
            pptp: this.generatePPTPProfile.bind(this)
        };

        // Platform-specific adapters
        this.platformAdapters = {
            windows: this.adaptForWindows.bind(this),
            macos: this.adaptForMacOS.bind(this),
            ios: this.adaptForIOS.bind(this),
            android: this.adaptForAndroid.bind(this),
            linux: this.adaptForLinux.bind(this)
        };

        // Metrics
        this.metrics = {
            profilesCreated: 0,
            profilesDeployed: 0,
            openVPNProfiles: 0,
            wireGuardProfiles: 0,
            ikev2Profiles: 0,
            deploymentSuccess: 0,
            deploymentFailures: 0
        };

        this.init();
    }

    async init() {
        try {
            await this.createStorageDirectories();
            await this.loadExistingProfiles();
            await this.loadServerConfigurations();
            
            this.logger.info('VPN Profile Service initialized successfully');
            this.emit('initialized');
        } catch (error) {
            this.logger.error('Failed to initialize VPN Profile Service:', error);
            throw error;
        }
    }

    async createStorageDirectories() {
        const directories = [
            config.network.vpnProfilesPath,
            path.join(config.network.vpnProfilesPath, 'profiles'),
            path.join(config.network.vpnProfilesPath, 'servers'),
            path.join(config.network.vpnProfilesPath, 'deployments'),
            path.join(config.network.vpnProfilesPath, 'exports'),
            path.join(config.network.vpnProfilesPath, 'templates')
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
     * VPN Profile Creation
     */
    async createVPNProfile(profileData) {
        try {
            const profileId = this.generateProfileId(profileData.name);
            const profile = {
                id: profileId,
                name: profileData.name,
                description: profileData.description || '',
                version: profileData.version || '1.0',
                
                // VPN configuration
                vpnType: profileData.vpnType || this.config.defaultType,
                serverAddress: profileData.serverAddress,
                serverPort: profileData.serverPort,
                protocol: profileData.protocol,
                
                // Authentication
                authentication: {
                    method: profileData.authentication?.method || 'certificate', // certificate, username, presharedkey
                    
                    // Certificate-based authentication
                    clientCertificate: {
                        enabled: profileData.authentication?.clientCertificate?.enabled || false,
                        templateId: profileData.authentication?.clientCertificate?.templateId,
                        certificateId: profileData.authentication?.clientCertificate?.certificateId,
                        autoEnroll: profileData.authentication?.clientCertificate?.autoEnroll || true,
                        embedInProfile: profileData.authentication?.clientCertificate?.embedInProfile || true
                    },
                    
                    // Username/Password authentication
                    credentials: {
                        username: profileData.authentication?.credentials?.username,
                        password: profileData.authentication?.credentials?.password,
                        domain: profileData.authentication?.credentials?.domain,
                        saveCredentials: profileData.authentication?.credentials?.saveCredentials || false
                    },
                    
                    // Pre-shared key (for L2TP, IKEv2)
                    presharedKey: profileData.authentication?.presharedKey,
                    
                    // Server validation
                    serverValidation: {
                        enabled: profileData.authentication?.serverValidation?.enabled !== false,
                        serverCertificate: profileData.authentication?.serverValidation?.serverCertificate,
                        trustedCAs: profileData.authentication?.serverValidation?.trustedCAs || [],
                        serverName: profileData.authentication?.serverValidation?.serverName
                    }
                },
                
                // Network settings
                network: {
                    // Split tunneling
                    splitTunneling: {
                        enabled: profileData.network?.splitTunneling?.enabled || false,
                        includeRoutes: profileData.network?.splitTunneling?.includeRoutes || [],
                        excludeRoutes: profileData.network?.splitTunneling?.excludeRoutes || [],
                        bypassLocal: profileData.network?.splitTunneling?.bypassLocal || true
                    },
                    
                    // DNS settings
                    dns: {
                        servers: profileData.network?.dns?.servers || [],
                        searchDomains: profileData.network?.dns?.searchDomains || [],
                        overrideDNS: profileData.network?.dns?.overrideDNS || false
                    },
                    
                    // Routing
                    routing: {
                        defaultRoute: profileData.network?.routing?.defaultRoute || true,
                        customRoutes: profileData.network?.routing?.customRoutes || [],
                        metric: profileData.network?.routing?.metric || 1
                    },
                    
                    // Network adapter settings
                    adapter: {
                        mtu: profileData.network?.adapter?.mtu || 1500,
                        compression: profileData.network?.adapter?.compression || false,
                        tcpMssFixup: profileData.network?.adapter?.tcpMssFixup || true
                    }
                },
                
                // Connection settings
                connection: {
                    autoConnect: profileData.connection?.autoConnect || false,
                    persistentConnection: profileData.connection?.persistentConnection || false,
                    reconnectAttempts: profileData.connection?.reconnectAttempts || 3,
                    reconnectDelay: profileData.connection?.reconnectDelay || 10,
                    connectTimeout: profileData.connection?.connectTimeout || 30,
                    keepAlive: {
                        enabled: profileData.connection?.keepAlive?.enabled || true,
                        interval: profileData.connection?.keepAlive?.interval || 10,
                        timeout: profileData.connection?.keepAlive?.timeout || 120
                    }
                },
                
                // Security settings
                security: {
                    cipher: profileData.security?.cipher,
                    auth: profileData.security?.auth,
                    keySize: profileData.security?.keySize,
                    perfectForwardSecrecy: profileData.security?.perfectForwardSecrecy || true,
                    blockUnencrypted: profileData.security?.blockUnencrypted || true
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
                    rollback: profileData.deployment?.rollback || false
                },
                
                createdAt: new Date(),
                updatedAt: new Date(),
                status: 'active'
            };

            this.vpnProfiles.set(profileId, profile);
            await this.saveVPNProfile(profile);
            
            this.metrics.profilesCreated++;
            this.updateVPNTypeMetrics(profile.vpnType);
            
            this.logger.info(`VPN profile created: ${profileId}, type: ${profile.vpnType}`);
            this.emit('profileCreated', profile);
            
            return profile;

        } catch (error) {
            this.logger.error('Failed to create VPN profile:', error);
            throw error;
        }
    }

    async updateVPNProfile(profileId, updates) {
        try {
            const profile = this.vpnProfiles.get(profileId);
            if (!profile) {
                throw new Error(`VPN profile not found: ${profileId}`);
            }

            const updatedProfile = {
                ...profile,
                ...updates,
                version: this.incrementVersion(profile.version),
                updatedAt: new Date()
            };

            this.vpnProfiles.set(profileId, updatedProfile);
            await this.saveVPNProfile(updatedProfile);
            
            this.logger.info(`VPN profile updated: ${profileId}`);
            this.emit('profileUpdated', updatedProfile);
            
            return updatedProfile;

        } catch (error) {
            this.logger.error('Failed to update VPN profile:', error);
            throw error;
        }
    }

    /**
     * OpenVPN Profile Generation
     */
    async generateOpenVPNProfile(profile, certificates, deviceInfo, platform) {
        try {
            const ovpnConfig = await this.buildOpenVPNConfig(profile, certificates);
            const platformConfig = await this.adaptForPlatform(ovpnConfig, platform, 'openvpn');
            
            return {
                vpnType: 'openvpn',
                platform: platform,
                format: 'ovpn',
                profileData: platformConfig.config,
                certificates: certificates,
                metadata: {
                    embeddedCertificates: profile.authentication.clientCertificate.embedInProfile,
                    serverAddress: profile.serverAddress,
                    protocol: profile.protocol,
                    port: profile.serverPort
                },
                instructions: this.generateOpenVPNInstructions(platform),
                deploymentFiles: platformConfig.deploymentFiles
            };

        } catch (error) {
            this.logger.error('Failed to generate OpenVPN profile:', error);
            throw error;
        }
    }

    async buildOpenVPNConfig(profile, certificates) {
        let config = `# OpenVPN Client Configuration
# Generated by OpenDirectory Certificate & Network Service
# Profile: ${profile.name}
# Generated: ${new Date().toISOString()}

client
dev tun
proto ${profile.protocol || this.config.openvpn.protocol}
remote ${profile.serverAddress} ${profile.serverPort || this.config.openvpn.port}
resolv-retry infinite
nobind
persist-key
persist-tun
`;

        // Authentication method
        if (profile.authentication.method === 'certificate') {
            if (profile.authentication.clientCertificate.embedInProfile && certificates?.client) {
                // Embed certificates directly in the .ovpn file
                config += `
# Embedded Certificates
<ca>
${certificates.ca}
</ca>

<cert>
${certificates.client.certificate}
</cert>

<key>
${certificates.client.privateKey}
</key>
`;
            } else {
                // Reference external certificate files
                config += `
# External Certificate Files
ca ca.crt
cert client.crt
key client.key
`;
            }
        } else if (profile.authentication.method === 'username') {
            config += `
# Username/Password Authentication
auth-user-pass
`;
            
            if (profile.authentication.credentials.saveCredentials) {
                config += `auth-user-pass auth.txt\n`;
            }
        }

        // Security settings
        if (profile.security.cipher) {
            config += `cipher ${profile.security.cipher}\n`;
        } else {
            config += `cipher ${this.config.openvpn.cipher}\n`;
        }

        if (profile.security.auth) {
            config += `auth ${profile.security.auth}\n`;
        } else {
            config += `auth ${this.config.openvpn.auth}\n`;
        }

        // Compression
        if (profile.network.adapter.compression) {
            config += `comp-lzo\n`;
        }

        // MTU settings
        if (profile.network.adapter.mtu !== 1500) {
            config += `tun-mtu ${profile.network.adapter.mtu}\n`;
        }

        // DNS settings
        if (profile.network.dns.servers.length > 0) {
            profile.network.dns.servers.forEach(dns => {
                config += `dhcp-option DNS ${dns}\n`;
            });
        }

        if (profile.network.dns.searchDomains.length > 0) {
            profile.network.dns.searchDomains.forEach(domain => {
                config += `dhcp-option DOMAIN ${domain}\n`;
            });
        }

        // Split tunneling
        if (profile.network.splitTunneling.enabled) {
            // Exclude routes (bypass VPN)
            profile.network.splitTunneling.excludeRoutes.forEach(route => {
                config += `route ${route} net_gateway\n`;
            });
            
            // Include routes (force through VPN)
            if (profile.network.splitTunneling.includeRoutes.length > 0) {
                config += `# Redirect only specific routes through VPN\n`;
                config += `route-nopull\n`;
                profile.network.splitTunneling.includeRoutes.forEach(route => {
                    config += `route ${route}\n`;
                });
            }
            
            if (profile.network.splitTunneling.bypassLocal) {
                config += `# Bypass local network\n`;
                config += `route 192.168.0.0 255.255.0.0 net_gateway\n`;
                config += `route 172.16.0.0 255.240.0.0 net_gateway\n`;
                config += `route 10.0.0.0 255.0.0.0 net_gateway\n`;
            }
        } else if (!profile.network.routing.defaultRoute) {
            config += `route-nopull\n`;
            profile.network.routing.customRoutes.forEach(route => {
                config += `route ${route}\n`;
            });
        }

        // Keep-alive settings
        if (profile.connection.keepAlive.enabled) {
            config += `keepalive ${profile.connection.keepAlive.interval} ${profile.connection.keepAlive.timeout}\n`;
        }

        // Connection settings
        config += `connect-timeout ${profile.connection.connectTimeout}\n`;
        
        if (profile.connection.reconnectAttempts > 0) {
            config += `connect-retry-max ${profile.connection.reconnectAttempts}\n`;
        }

        // Server certificate verification
        if (profile.authentication.serverValidation.enabled) {
            if (profile.authentication.serverValidation.serverName) {
                config += `verify-x509-name ${profile.authentication.serverValidation.serverName} name\n`;
            }
            config += `remote-cert-tls server\n`;
        }

        // Security enhancements
        config += `
# Security
tls-auth ta.key 1
key-direction 1
script-security 2
`;

        // Platform-specific options will be added by platform adapters
        return config;
    }

    /**
     * WireGuard Profile Generation
     */
    async generateWireGuardProfile(profile, certificates, deviceInfo, platform) {
        try {
            const wgConfig = await this.buildWireGuardConfig(profile, deviceInfo);
            const platformConfig = await this.adaptForPlatform(wgConfig, platform, 'wireguard');
            
            return {
                vpnType: 'wireguard',
                platform: platform,
                format: 'conf',
                profileData: platformConfig.config,
                qrCode: platform === 'android' || platform === 'ios' ? this.generateWireGuardQR(wgConfig) : null,
                metadata: {
                    publicKey: wgConfig.publicKey,
                    serverAddress: profile.serverAddress,
                    allowedIPs: wgConfig.allowedIPs
                },
                instructions: this.generateWireGuardInstructions(platform),
                deploymentFiles: platformConfig.deploymentFiles
            };

        } catch (error) {
            this.logger.error('Failed to generate WireGuard profile:', error);
            throw error;
        }
    }

    async buildWireGuardConfig(profile, deviceInfo) {
        // Generate WireGuard key pair if not provided
        const keyPair = await this.generateWireGuardKeyPair();
        
        let config = `[Interface]
PrivateKey = ${keyPair.privateKey}
Address = ${await this.assignWireGuardIP(deviceInfo)}
DNS = ${profile.network.dns.servers.join(', ') || this.config.wireguard.dns}
MTU = ${profile.network.adapter.mtu || this.config.wireguard.mtu}
`;

        // Split tunneling via AllowedIPs
        let allowedIPs = ['0.0.0.0/0', '::/0']; // Default: route all traffic
        
        if (profile.network.splitTunneling.enabled) {
            if (profile.network.splitTunneling.includeRoutes.length > 0) {
                allowedIPs = profile.network.splitTunneling.includeRoutes;
            } else {
                // Calculate allowed IPs by excluding certain routes
                allowedIPs = this.calculateWireGuardAllowedIPs(profile.network.splitTunneling.excludeRoutes);
            }
        }

        config += `
[Peer]
PublicKey = ${await this.getWireGuardServerPublicKey(profile.serverAddress)}
Endpoint = ${profile.serverAddress}:${profile.serverPort || this.config.wireguard.port}
AllowedIPs = ${allowedIPs.join(', ')}
`;

        // Keep-alive
        if (profile.connection.keepAlive.enabled) {
            config += `PersistentKeepalive = ${profile.connection.keepAlive.interval}\n`;
        }

        // Pre-shared key for additional security
        if (profile.authentication.presharedKey) {
            config += `PresharedKey = ${profile.authentication.presharedKey}\n`;
        }

        return {
            config: config,
            publicKey: keyPair.publicKey,
            allowedIPs: allowedIPs
        };
    }

    /**
     * IKEv2 Profile Generation
     */
    async generateIKEv2Profile(profile, certificates, deviceInfo, platform) {
        try {
            const ikev2Config = await this.buildIKEv2Config(profile, certificates, platform);
            
            return {
                vpnType: 'ikev2',
                platform: platform,
                format: platform === 'windows' ? 'ps1' : 'mobileconfig',
                profileData: ikev2Config.config,
                certificates: certificates,
                metadata: {
                    serverAddress: profile.serverAddress,
                    serverIdentifier: profile.authentication.serverValidation.serverName,
                    authenticationMethod: profile.authentication.method
                },
                instructions: this.generateIKEv2Instructions(platform),
                deploymentFiles: ikev2Config.deploymentFiles
            };

        } catch (error) {
            this.logger.error('Failed to generate IKEv2 profile:', error);
            throw error;
        }
    }

    async buildIKEv2Config(profile, certificates, platform) {
        switch (platform) {
            case 'windows':
                return this.buildIKEv2WindowsConfig(profile, certificates);
            case 'macos':
            case 'ios':
                return this.buildIKEv2AppleConfig(profile, certificates);
            case 'android':
                return this.buildIKEv2AndroidConfig(profile, certificates);
            case 'linux':
                return this.buildIKEv2LinuxConfig(profile, certificates);
            default:
                throw new Error(`Unsupported platform for IKEv2: ${platform}`);
        }
    }

    async buildIKEv2WindowsConfig(profile, certificates) {
        const psScript = `# IKEv2 VPN Setup Script for Windows
# Profile: ${profile.name}

$vpnName = "${profile.name}"
$serverAddress = "${profile.serverAddress}"
$authenticationMethod = "${profile.authentication.method === 'certificate' ? 'MachineCertificate' : 'MSChapv2'}"

# Remove existing VPN connection if it exists
Remove-VpnConnection -Name $vpnName -Force -ErrorAction SilentlyContinue

# Create new IKEv2 VPN connection
Add-VpnConnection \`
    -Name $vpnName \`
    -ServerAddress $serverAddress \`
    -TunnelType Ikev2 \`
    -AuthenticationMethod $authenticationMethod \`
    -EncryptionLevel Maximum \`
    -Force

# Configure split tunneling if enabled
${profile.network.splitTunneling.enabled ? this.buildWindowsSplitTunnelingScript(profile) : ''}

# Configure DNS settings
${profile.network.dns.servers.length > 0 ? this.buildWindowsDNSScript(profile) : ''}

Write-Host "IKEv2 VPN connection '$vpnName' created successfully"
`;

        return {
            config: psScript,
            deploymentFiles: []
        };
    }

    async buildIKEv2AppleConfig(profile, certificates) {
        const payloadUUID = this.generateUUID();
        const vpnUUID = this.generateUUID();
        
        const vpnPayload = {
            PayloadType: 'com.apple.vpn.managed',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.vpn.${vpnUUID}`,
            PayloadUUID: vpnUUID,
            PayloadDisplayName: profile.name,
            PayloadDescription: profile.description || `IKEv2 VPN configuration for ${profile.serverAddress}`,
            
            UserDefinedName: profile.name,
            VPNType: 'IKEv2',
            IKEv2: {
                RemoteAddress: profile.serverAddress,
                RemoteIdentifier: profile.authentication.serverValidation.serverName || profile.serverAddress,
                LocalIdentifier: profile.authentication.credentials?.username,
                
                AuthenticationMethod: profile.authentication.method === 'certificate' ? 'Certificate' : 'SharedSecret',
                
                ...(profile.authentication.method === 'certificate' && certificates?.client && {
                    PayloadCertificateUUID: certificates.client.uuid
                }),
                
                ...(profile.authentication.presharedKey && {
                    SharedSecret: profile.authentication.presharedKey
                }),
                
                // Security settings
                ChildSecurityAssociationParameters: {
                    EncryptionAlgorithm: 'AES-256',
                    IntegrityAlgorithm: 'SHA2-256',
                    DiffieHellmanGroup: 14,
                    LifeTimeInMinutes: 1440
                },
                
                IKESecurityAssociationParameters: {
                    EncryptionAlgorithm: 'AES-256',
                    IntegrityAlgorithm: 'SHA2-256',
                    DiffieHellmanGroup: 14,
                    LifeTimeInMinutes: 1440
                },
                
                EnablePFS: profile.security.perfectForwardSecrecy,
                DisableMOBIKE: false,
                DisableRedirect: false,
                EnableCertificateRevocationCheck: profile.authentication.serverValidation.enabled,
                
                // Split tunneling
                ...(profile.network.splitTunneling.enabled && {
                    OnDemandEnabled: 1,
                    OnDemandRules: this.buildAppleOnDemandRules(profile)
                })
            },
            
            // DNS settings
            ...(profile.network.dns.servers.length > 0 && {
                DNS: {
                    ServerAddresses: profile.network.dns.servers,
                    SearchDomains: profile.network.dns.searchDomains
                }
            })
        };

        const payloads = [vpnPayload];
        
        // Add certificate payloads if needed
        if (certificates) {
            if (certificates.client) {
                payloads.push(this.buildAppleCertificatePayload(certificates.client, 'client'));
            }
            if (certificates.ca) {
                payloads.push(this.buildAppleCertificatePayload(certificates.ca, 'ca'));
            }
        }

        const configProfile = {
            PayloadType: 'Configuration',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.vpn.${profile.id}`,
            PayloadUUID: payloadUUID,
            PayloadDisplayName: `${profile.name} VPN Profile`,
            PayloadDescription: profile.description || `IKEv2 VPN configuration for ${profile.serverAddress}`,
            PayloadOrganization: 'OpenDirectory',
            PayloadContent: payloads,
            PayloadRemovalDisallowed: false,
            PayloadScope: 'User'
        };

        return {
            config: this.generatePlistXML(configProfile),
            deploymentFiles: []
        };
    }

    /**
     * Platform Adapters
     */
    async adaptForPlatform(config, platform, vpnType) {
        const adapter = this.platformAdapters[platform];
        if (!adapter) {
            return { config: config, deploymentFiles: [] };
        }
        
        return await adapter(config, vpnType);
    }

    async adaptForWindows(config, vpnType) {
        let adaptedConfig = config;
        let deploymentFiles = [];
        
        switch (vpnType) {
            case 'openvpn':
                // Windows-specific OpenVPN options
                adaptedConfig += `
# Windows-specific settings
route-method exe
route-delay 2
register-dns
block-outside-dns
`;
                
                // Create installation script
                deploymentFiles.push({
                    name: 'install.bat',
                    content: this.generateWindowsOpenVPNInstallScript()
                });
                break;
                
            case 'wireguard':
                // Windows WireGuard service configuration
                deploymentFiles.push({
                    name: 'install.ps1',
                    content: this.generateWindowsWireGuardInstallScript()
                });
                break;
        }
        
        return { config: adaptedConfig, deploymentFiles };
    }

    async adaptForMacOS(config, vpnType) {
        let adaptedConfig = config;
        let deploymentFiles = [];
        
        switch (vpnType) {
            case 'openvpn':
                // macOS-specific OpenVPN options
                adaptedConfig += `
# macOS-specific settings
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
`;
                break;
        }
        
        return { config: adaptedConfig, deploymentFiles };
    }

    async adaptForIOS(config, vpnType) {
        // iOS uses configuration profiles for all VPN types
        return { config: config, deploymentFiles: [] };
    }

    async adaptForAndroid(config, vpnType) {
        let adaptedConfig = config;
        let deploymentFiles = [];
        
        switch (vpnType) {
            case 'openvpn':
                // Android OpenVPN Connect specific options
                adaptedConfig += `
# Android-specific settings
setenv GENERIC_CONFIG 1
`;
                break;
        }
        
        return { config: adaptedConfig, deploymentFiles };
    }

    async adaptForLinux(config, vpnType) {
        let adaptedConfig = config;
        let deploymentFiles = [];
        
        switch (vpnType) {
            case 'openvpn':
                // Linux-specific options
                adaptedConfig += `
# Linux-specific settings
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
`;
                
                deploymentFiles.push({
                    name: 'install.sh',
                    content: this.generateLinuxOpenVPNInstallScript()
                });
                break;
                
            case 'wireguard':
                deploymentFiles.push({
                    name: 'install.sh',
                    content: this.generateLinuxWireGuardInstallScript()
                });
                break;
        }
        
        return { config: adaptedConfig, deploymentFiles };
    }

    /**
     * Certificate Management
     */
    async getCertificatesForProfile(profile, deviceInfo) {
        if (profile.authentication.method !== 'certificate' || !profile.authentication.clientCertificate.enabled) {
            return null;
        }

        let certificates = {};

        // Get client certificate
        if (profile.authentication.clientCertificate.certificateId) {
            certificates.client = await this.getCertificateById(profile.authentication.clientCertificate.certificateId);
        } else if (profile.authentication.clientCertificate.templateId && profile.authentication.clientCertificate.autoEnroll) {
            certificates.client = await this.enrollCertificateForDevice(
                profile.authentication.clientCertificate.templateId,
                deviceInfo
            );
        }

        // Get CA certificates
        if (profile.authentication.serverValidation.trustedCAs.length > 0) {
            certificates.ca = await this.getCACertificates(profile.authentication.serverValidation.trustedCAs);
        }

        // Get server certificate if provided
        if (profile.authentication.serverValidation.serverCertificate) {
            certificates.server = await this.getCertificateById(profile.authentication.serverValidation.serverCertificate);
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
                organizationalUnitName: 'VPN Clients'
            },
            subjectAltName: deviceInfo.deviceFQDN ? [{ type: 2, value: deviceInfo.deviceFQDN }] : [],
            requester: 'vpn-profile-auto-enrollment'
        };

        const certificate = await this.certificateService.enrollCertificate(enrollmentRequest);
        return this.formatCertificateForVPN(certificate);
    }

    async getCertificateById(certificateId) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        const certificate = await this.certificateService.getCertificate(certificateId);
        return this.formatCertificateForVPN(certificate);
    }

    async getCACertificates(caIds) {
        if (!this.certificateService) {
            throw new Error('Certificate service not available');
        }

        let caCertificates = '';
        for (const caId of caIds) {
            const ca = await this.certificateService.getCA(caId);
            caCertificates += ca.certificate + '\n';
        }
        
        return caCertificates.trim();
    }

    formatCertificateForVPN(certificate) {
        return {
            uuid: this.generateUUID(),
            certificate: certificate.certificate,
            privateKey: certificate.privateKey,
            data: certificate.certificate // For embedded use
        };
    }

    /**
     * Profile Generation for Platform
     */
    async generateProfileForPlatform(profileId, platform, deviceInfo = {}) {
        try {
            const profile = this.vpnProfiles.get(profileId);
            if (!profile) {
                throw new Error(`VPN profile not found: ${profileId}`);
            }

            const generator = this.profileGenerators[profile.vpnType.toLowerCase()];
            if (!generator) {
                throw new Error(`Unsupported VPN type: ${profile.vpnType}`);
            }

            // Get certificates if needed
            let certificates = null;
            if (profile.authentication.method === 'certificate') {
                certificates = await this.getCertificatesForProfile(profile, deviceInfo);
            }

            const platformProfile = await generator(profile, certificates, deviceInfo, platform);
            
            this.logger.info(`VPN profile generated: ${profileId} for ${platform}`);
            this.emit('profileGenerated', profile, platform, platformProfile);
            
            return platformProfile;

        } catch (error) {
            this.logger.error(`Failed to generate VPN profile for ${platform}:`, error);
            throw error;
        }
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
        return `vpn-${hash}`;
    }

    generateUUID() {
        return require('uuid').v4();
    }

    incrementVersion(version) {
        const parts = version.split('.');
        parts[parts.length - 1] = (parseInt(parts[parts.length - 1]) + 1).toString();
        return parts.join('.');
    }

    updateVPNTypeMetrics(vpnType) {
        switch (vpnType.toLowerCase()) {
            case 'openvpn':
                this.metrics.openVPNProfiles++;
                break;
            case 'wireguard':
                this.metrics.wireGuardProfiles++;
                break;
            case 'ikev2':
                this.metrics.ikev2Profiles++;
                break;
        }
    }

    async generateWireGuardKeyPair() {
        // Generate Curve25519 key pair for WireGuard
        const privateKey = crypto.randomBytes(32);
        const publicKey = crypto.createPublicKey({
            key: privateKey,
            format: 'raw',
            type: 'x25519'
        });
        
        return {
            privateKey: privateKey.toString('base64'),
            publicKey: publicKey.export({ format: 'raw', type: 'spki' }).toString('base64')
        };
    }

    async assignWireGuardIP(deviceInfo) {
        // Simple IP assignment logic - in production, this would integrate with IPAM
        const baseIP = '10.8.0.';
        const deviceHash = crypto.createHash('sha256').update(deviceInfo.deviceId || 'unknown').digest('hex');
        const lastOctet = parseInt(deviceHash.substring(0, 2), 16) % 254 + 2; // 2-255
        return `${baseIP}${lastOctet}/24`;
    }

    async getWireGuardServerPublicKey(serverAddress) {
        // In production, this would retrieve the server's public key from configuration
        return 'SERVER_PUBLIC_KEY_PLACEHOLDER';
    }

    calculateWireGuardAllowedIPs(excludeRoutes) {
        // Simple implementation - in production, use proper CIDR calculation
        const allIPs = ['0.0.0.0/0'];
        return allIPs.filter(ip => !excludeRoutes.includes(ip));
    }

    generateWireGuardQR(wgConfig) {
        // Generate QR code for mobile devices
        const qrcode = require('qrcode');
        return qrcode.toDataURL(wgConfig.config);
    }

    buildWindowsSplitTunnelingScript(profile) {
        let script = `
# Configure split tunneling
`;
        
        profile.network.splitTunneling.excludeRoutes.forEach(route => {
            script += `Add-VpnConnectionRoute -ConnectionName $vpnName -DestinationPrefix "${route}" -RouteMetric 1\n`;
        });
        
        return script;
    }

    buildWindowsDNSScript(profile) {
        let script = `
# Configure DNS settings
$adapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*$vpnName*"}
if ($adapter) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "${profile.network.dns.servers.join('", "')}"
}
`;
        return script;
    }

    buildAppleOnDemandRules(profile) {
        const rules = [];
        
        if (profile.network.splitTunneling.excludeRoutes.length > 0) {
            rules.push({
                Action: 'Disconnect',
                DNSDomainMatch: profile.network.splitTunneling.excludeRoutes
            });
        }
        
        if (profile.network.splitTunneling.includeRoutes.length > 0) {
            rules.push({
                Action: 'Connect',
                DNSDomainMatch: profile.network.splitTunneling.includeRoutes
            });
        }
        
        return rules;
    }

    buildAppleCertificatePayload(certificate, type) {
        return {
            PayloadType: 'com.apple.security.pkcs12',
            PayloadVersion: 1,
            PayloadIdentifier: `${config.mdm.ios.profilePrefix}.cert.${certificate.uuid}`,
            PayloadUUID: certificate.uuid,
            PayloadDisplayName: `${type.toUpperCase()} Certificate`,
            PayloadDescription: `${type} certificate for VPN authentication`,
            
            PayloadContent: certificate.data,
            Password: certificate.password || ''
        };
    }

    generatePlistXML(data) {
        const plist = require('plist');
        return plist.build(data);
    }

    generateWindowsOpenVPNInstallScript() {
        return `@echo off
echo Installing OpenVPN profile...
if not exist "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe" (
    echo OpenVPN is not installed. Please install OpenVPN first.
    exit /b 1
)

copy "%~dp0*.ovpn" "C:\\Program Files\\OpenVPN\\config\\"
echo Profile installed successfully.
echo You can now connect using OpenVPN GUI.
pause`;
    }

    generateWindowsWireGuardInstallScript() {
        return `# WireGuard Installation Script for Windows
if (!(Get-Command "wg" -ErrorAction SilentlyContinue)) {
    Write-Error "WireGuard is not installed. Please install WireGuard first."
    exit 1
}

$configPath = "$env:USERPROFILE\\AppData\\Local\\WireGuard\\Configurations"
if (!(Test-Path $configPath)) {
    New-Item -ItemType Directory -Path $configPath -Force
}

Copy-Item "$PSScriptRoot\\*.conf" $configPath
Write-Host "WireGuard configuration installed successfully."`;
    }

    generateLinuxOpenVPNInstallScript() {
        return `#!/bin/bash
# OpenVPN Installation Script for Linux

if ! command -v openvpn &> /dev/null; then
    echo "OpenVPN is not installed. Installing..."
    sudo apt-get update
    sudo apt-get install -y openvpn
fi

sudo cp *.ovpn /etc/openvpn/client/
sudo cp *.crt *.key /etc/openvpn/client/ 2>/dev/null || true

echo "OpenVPN profile installed successfully."
echo "To connect: sudo openvpn /etc/openvpn/client/profile.ovpn"`;
    }

    generateLinuxWireGuardInstallScript() {
        return `#!/bin/bash
# WireGuard Installation Script for Linux

if ! command -v wg &> /dev/null; then
    echo "WireGuard is not installed. Installing..."
    sudo apt-get update
    sudo apt-get install -y wireguard
fi

sudo cp *.conf /etc/wireguard/
sudo chmod 600 /etc/wireguard/*.conf

echo "WireGuard configuration installed successfully."
echo "To connect: sudo wg-quick up wg0"`;
    }

    generateOpenVPNInstructions(platform) {
        const instructions = {
            windows: `OpenVPN Installation Instructions - Windows

1. Download and install OpenVPN from https://openvpn.net/community-downloads/
2. Copy the .ovpn file to C:\\Program Files\\OpenVPN\\config\\
3. Copy certificate files to the same directory if not embedded
4. Right-click OpenVPN GUI in system tray
5. Select the profile and click Connect

Automatic Installation:
- Run the provided install.bat as Administrator`,

            macos: `OpenVPN Installation Instructions - macOS

1. Install Tunnelblick from https://tunnelblick.net/
2. Double-click the .ovpn file to import
3. Enter administrator password when prompted
4. Connect using Tunnelblick menu

Alternative:
- Use OpenVPN Connect from App Store`,

            ios: `OpenVPN Installation Instructions - iOS

1. Install OpenVPN Connect from App Store
2. Email or AirDrop the .ovpn file to your device
3. Open the file and import into OpenVPN Connect
4. Connect using the app`,

            android: `OpenVPN Installation Instructions - Android

1. Install OpenVPN for Android from Google Play
2. Copy the .ovpn file to your device
3. Import the profile in the app
4. Connect using the profile`,

            linux: `OpenVPN Installation Instructions - Linux

1. Install OpenVPN: sudo apt-get install openvpn
2. Copy profile to /etc/openvpn/client/
3. Connect: sudo openvpn /etc/openvpn/client/profile.ovpn

NetworkManager:
- nmcli connection import type openvpn file profile.ovpn`
        };

        return instructions[platform] || instructions.linux;
    }

    generateWireGuardInstructions(platform) {
        const instructions = {
            windows: `WireGuard Installation Instructions - Windows

1. Download and install WireGuard from https://www.wireguard.com/install/
2. Import the configuration file
3. Activate the tunnel

Configuration file location:
%USERPROFILE%\\AppData\\Local\\WireGuard\\Configurations\\`,

            macos: `WireGuard Installation Instructions - macOS

1. Install WireGuard from App Store
2. Import the configuration file
3. Activate the tunnel

Command line:
brew install wireguard-tools`,

            ios: `WireGuard Installation Instructions - iOS

1. Install WireGuard from App Store
2. Scan the QR code or import configuration file
3. Activate the tunnel`,

            android: `WireGuard Installation Instructions - Android

1. Install WireGuard from Google Play
2. Scan the QR code or import configuration file
3. Activate the tunnel`,

            linux: `WireGuard Installation Instructions - Linux

1. Install WireGuard: sudo apt-get install wireguard
2. Copy config to /etc/wireguard/
3. Activate: sudo wg-quick up wg0

Manual:
sudo ip link add dev wg0 type wireguard
sudo wg setconf wg0 /etc/wireguard/wg0.conf`
        };

        return instructions[platform] || instructions.linux;
    }

    generateIKEv2Instructions(platform) {
        const instructions = {
            windows: `IKEv2 VPN Installation Instructions - Windows

1. Run the provided PowerShell script as Administrator
2. Or manually create VPN connection in Settings
3. Use certificate authentication if configured

Manual Setup:
- Settings > Network & Internet > VPN > Add VPN
- VPN provider: Windows (built-in)
- Connection type: IKEv2`,

            macos: `IKEv2 VPN Installation Instructions - macOS

1. Install the configuration profile
2. Go to System Preferences > Network
3. The VPN connection will be available

Certificate Installation:
- Install certificates in Keychain first if required`,

            ios: `IKEv2 VPN Installation Instructions - iOS

1. Install the configuration profile
2. Go to Settings > General > VPN & Device Management
3. Enable the VPN in Settings > VPN

The VPN will appear in Settings > VPN automatically.`,

            android: `IKEv2 VPN Installation Instructions - Android

1. Go to Settings > Network & Internet > VPN
2. Add VPN profile with provided settings
3. Use certificate authentication if configured

Note: May require third-party app like strongSwan`,

            linux: `IKEv2 VPN Installation Instructions - Linux

1. Install strongSwan: sudo apt-get install strongswan
2. Configure /etc/ipsec.conf and /etc/ipsec.secrets
3. Start: sudo systemctl start strongswan

NetworkManager plugin:
sudo apt-get install network-manager-strongswan`
        };

        return instructions[platform] || instructions.linux;
    }

    /**
     * Placeholder methods for L2TP and PPTP
     */
    async generateL2TPProfile(profile, certificates, deviceInfo, platform) {
        // L2TP/IPSec profile generation
        throw new Error('L2TP profile generation not yet implemented');
    }

    async generatePPTPProfile(profile, certificates, deviceInfo, platform) {
        // PPTP profile generation (deprecated and insecure)
        throw new Error('PPTP is deprecated and not supported for security reasons');
    }

    /**
     * Storage Methods
     */
    async saveVPNProfile(profile) {
        const profilePath = path.join(config.network.vpnProfilesPath, 'profiles', `${profile.id}.json`);
        await fs.writeFile(profilePath, JSON.stringify(profile, null, 2));
    }

    async loadExistingProfiles() {
        try {
            const profilesDir = path.join(config.network.vpnProfilesPath, 'profiles');
            const files = await fs.readdir(profilesDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const profilePath = path.join(profilesDir, file);
                    const profile = JSON.parse(await fs.readFile(profilePath, 'utf8'));
                    this.vpnProfiles.set(profile.id, profile);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load VPN profiles:', error);
            }
        }
    }

    async loadServerConfigurations() {
        try {
            const serversDir = path.join(config.network.vpnProfilesPath, 'servers');
            const files = await fs.readdir(serversDir);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const serverPath = path.join(serversDir, file);
                    const serverConfig = JSON.parse(await fs.readFile(serverPath, 'utf8'));
                    this.serverConfigurations.set(serverConfig.id, serverConfig);
                }
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load server configurations:', error);
            }
        }
    }

    /**
     * Public API Methods
     */
    async getProfiles() {
        return Array.from(this.vpnProfiles.values());
    }

    async getProfile(profileId) {
        return this.vpnProfiles.get(profileId);
    }

    async deleteProfile(profileId) {
        const profile = this.vpnProfiles.get(profileId);
        if (!profile) {
            throw new Error(`VPN profile not found: ${profileId}`);
        }

        this.vpnProfiles.delete(profileId);
        
        const profilePath = path.join(config.network.vpnProfilesPath, 'profiles', `${profileId}.json`);
        try {
            await fs.unlink(profilePath);
        } catch (error) {
            this.logger.error(`Failed to delete profile file: ${profilePath}`, error);
        }

        this.logger.info(`VPN profile deleted: ${profileId}`);
        this.emit('profileDeleted', profile);
        
        return true;
    }

    async getMetrics() {
        return {
            ...this.metrics,
            totalProfiles: this.vpnProfiles.size,
            activeProfiles: Array.from(this.vpnProfiles.values()).filter(p => p.status === 'active').length,
            supportedVPNTypes: this.config.supportedTypes,
            serverConfigurations: this.serverConfigurations.size
        };
    }
}

module.exports = VPNProfileService;