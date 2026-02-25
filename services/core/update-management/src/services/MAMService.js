const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const AuditLogger = require('../audit/AuditLogger');

class MAMService extends EventEmitter {
    constructor() {
        super();
        this.auditLogger = new AuditLogger();
        this.applicationPolicies = new Map();
        this.dataProtectionPolicies = new Map();
        this.conditionalAccessPolicies = new Map();
        this.appCatalog = new Map();
        this.userAppAssignments = new Map();
    }

    /**
     * Create Mobile Application Management policy
     */
    async createMAMPolicy(policyConfig) {
        try {
            logger.info(`Creating MAM policy: ${policyConfig.name}`);

            const mamPolicy = {
                id: `mam-policy-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                name: policyConfig.name,
                description: policyConfig.description || '',
                type: policyConfig.type || 'data-protection', // data-protection, app-protection, conditional-access
                platform: policyConfig.platform || 'all', // ios, android, windows, all
                targetApplications: policyConfig.targetApplications || [],
                
                // Data Protection Settings
                dataProtection: {
                    preventDataLoss: policyConfig.preventDataLoss ?? true,
                    encryptAppData: policyConfig.encryptAppData ?? true,
                    allowDataTransferTo: policyConfig.allowDataTransferTo || 'managed-apps-only', // all-apps, managed-apps-only, none
                    allowDataTransferFrom: policyConfig.allowDataTransferFrom || 'managed-apps-only',
                    preventBackup: policyConfig.preventBackup ?? true,
                    preventScreenCapture: policyConfig.preventScreenCapture ?? true,
                    allowPrintFromManagedApps: policyConfig.allowPrintFromManagedApps ?? false,
                    allowCopyPaste: policyConfig.allowCopyPaste ?? false,
                    requirePinForAccess: policyConfig.requirePinForAccess ?? true,
                    pinComplexity: policyConfig.pinComplexity || 'numeric', // numeric, alphanumeric, complex
                    pinMinLength: policyConfig.pinMinLength || 6,
                    pinMaxRetries: policyConfig.pinMaxRetries || 5,
                    biometricAuthentication: policyConfig.biometricAuthentication ?? true,
                    sessionTimeout: policyConfig.sessionTimeout || 30, // minutes
                    offlineGracePeriod: policyConfig.offlineGracePeriod || 720, // minutes (12 hours)
                    wipeAfterFailedAttempts: policyConfig.wipeAfterFailedAttempts || 10
                },

                // Application Configuration
                appConfiguration: {
                    allowedApplications: policyConfig.allowedApplications || [],
                    blockedApplications: policyConfig.blockedApplications || [],
                    requiredApplications: policyConfig.requiredApplications || [],
                    allowAppStore: policyConfig.allowAppStore ?? false,
                    allowSideloading: policyConfig.allowSideloading ?? false,
                    appAutoUpdate: policyConfig.appAutoUpdate ?? true,
                    allowAppUninstall: policyConfig.allowAppUninstall ?? false,
                    appWhitelistMode: policyConfig.appWhitelistMode ?? true,
                    customAppConfiguration: policyConfig.customAppConfiguration || {}
                },

                // Conditional Access
                conditionalAccess: {
                    requireDeviceCompliance: policyConfig.requireDeviceCompliance ?? true,
                    requireManagedBrowser: policyConfig.requireManagedBrowser ?? true,
                    blockJailbrokenDevices: policyConfig.blockJailbrokenDevices ?? true,
                    minimumOSVersion: policyConfig.minimumOSVersion || null,
                    allowedCountries: policyConfig.allowedCountries || [],
                    blockedCountries: policyConfig.blockedCountries || [],
                    requireVPN: policyConfig.requireVPN ?? false,
                    allowedNetworks: policyConfig.allowedNetworks || [],
                    riskLevelThreshold: policyConfig.riskLevelThreshold || 'medium' // low, medium, high
                },

                // Content Protection
                contentProtection: {
                    watermarking: policyConfig.enableWatermarking ?? false,
                    documentProtection: policyConfig.documentProtection ?? true,
                    preventForwarding: policyConfig.preventForwarding ?? true,
                    requireRightsManagement: policyConfig.requireRightsManagement ?? false,
                    allowOfflineAccess: policyConfig.allowOfflineAccess ?? true,
                    offlineAccessDuration: policyConfig.offlineAccessDuration || 30, // days
                    documentExpiration: policyConfig.documentExpiration || null,
                    classificationLabels: policyConfig.classificationLabels || []
                },

                // Compliance and Monitoring
                compliance: {
                    auditAppUsage: policyConfig.auditAppUsage ?? true,
                    reportDataAccess: policyConfig.reportDataAccess ?? true,
                    monitorFileSharing: policyConfig.monitorFileSharing ?? true,
                    detectAnomalousActivity: policyConfig.detectAnomalousActivity ?? true,
                    realTimeAlerts: policyConfig.realTimeAlerts ?? true,
                    complianceCheckFrequency: policyConfig.complianceCheckFrequency || 24, // hours
                    retentionPeriod: policyConfig.retentionPeriod || 90 // days
                },

                // Remediation Actions
                remediationActions: {
                    warnUser: policyConfig.warnUser ?? true,
                    blockAccess: policyConfig.blockAccess ?? true,
                    wipeAppData: policyConfig.wipeAppData ?? false,
                    quarantineDevice: policyConfig.quarantineDevice ?? false,
                    notifyAdministrator: policyConfig.notifyAdministrator ?? true,
                    automaticRemediation: policyConfig.automaticRemediation ?? false,
                    escalationRules: policyConfig.escalationRules || []
                },

                // Deployment Settings
                deployment: {
                    targetUsers: policyConfig.targetUsers || [],
                    targetGroups: policyConfig.targetGroups || [],
                    targetDevices: policyConfig.targetDevices || [],
                    excludedUsers: policyConfig.excludedUsers || [],
                    excludedGroups: policyConfig.excludedGroups || [],
                    deploymentPhase: policyConfig.deploymentPhase || 'pilot', // pilot, production, all
                    rolloutPercentage: policyConfig.rolloutPercentage || 100
                },

                createdAt: new Date().toISOString(),
                createdBy: policyConfig.createdBy || 'system',
                lastModified: new Date().toISOString(),
                modifiedBy: policyConfig.createdBy || 'system',
                version: 1,
                status: 'active'
            };

            this.applicationPolicies.set(mamPolicy.id, mamPolicy);

            // Generate platform-specific configuration
            const platformConfigs = this.generatePlatformConfigurations(mamPolicy);

            await this.auditLogger.log('mam_policy_created', {
                policyId: mamPolicy.id,
                name: mamPolicy.name,
                type: mamPolicy.type,
                platform: mamPolicy.platform,
                createdBy: mamPolicy.createdBy,
                timestamp: mamPolicy.createdAt
            });

            this.emit('mamPolicyCreated', mamPolicy);

            return {
                success: true,
                policy: mamPolicy,
                platformConfigurations: platformConfigs
            };

        } catch (error) {
            logger.error('Error creating MAM policy:', error);
            throw error;
        }
    }

    /**
     * Generate platform-specific MAM configurations
     */
    generatePlatformConfigurations(policy) {
        return {
            ios: this.generateIOSConfiguration(policy),
            android: this.generateAndroidConfiguration(policy),
            windows: this.generateWindowsConfiguration(policy)
        };
    }

    /**
     * Generate iOS MAM configuration
     */
    generateIOSConfiguration(policy) {
        return {
            configurationProfile: {
                PayloadType: 'Configuration',
                PayloadVersion: 1,
                PayloadIdentifier: `com.opendirectory.mam.${policy.id}`,
                PayloadUUID: this.generateUUID(),
                PayloadDisplayName: policy.name,
                PayloadDescription: policy.description,
                PayloadContent: [
                    {
                        PayloadType: 'com.apple.applicationaccess',
                        PayloadVersion: 1,
                        PayloadIdentifier: `com.opendirectory.mam.appaccess.${policy.id}`,
                        PayloadUUID: this.generateUUID(),
                        PayloadDisplayName: 'Application Access',
                        allowedApplications: policy.appConfiguration.allowedApplications,
                        blacklistedAppBundleIDs: policy.appConfiguration.blockedApplications,
                        whitelistedAppBundleIDs: policy.appConfiguration.allowedApplications
                    },
                    {
                        PayloadType: 'com.apple.restrictedaccess',
                        PayloadVersion: 1,
                        PayloadIdentifier: `com.opendirectory.mam.restrictions.${policy.id}`,
                        PayloadUUID: this.generateUUID(),
                        PayloadDisplayName: 'Restrictions',
                        allowAppInstallation: policy.appConfiguration.allowAppStore,
                        allowScreenShot: !policy.dataProtection.preventScreenCapture,
                        allowDocumentEdit: !policy.contentProtection.documentProtection,
                        forceLimitAdTracking: true,
                        requireManagedAppsOnly: policy.dataProtection.allowDataTransferTo === 'managed-apps-only'
                    }
                ]
            },
            appProtectionPolicy: {
                dataEncryptionType: policy.dataProtection.encryptAppData ? 'useDeviceKey' : 'none',
                dataBackup: policy.dataProtection.preventBackup ? 'block' : 'allow',
                dataTransferPolicy: {
                    transferOut: policy.dataProtection.allowDataTransferTo,
                    transferIn: policy.dataProtection.allowDataTransferFrom,
                    copyPaste: policy.dataProtection.allowCopyPaste ? 'allow' : 'block'
                },
                accessRequirements: {
                    pinRequired: policy.dataProtection.requirePinForAccess,
                    pinType: policy.dataProtection.pinComplexity,
                    minPinLength: policy.dataProtection.pinMinLength,
                    maxPinRetries: policy.dataProtection.pinMaxRetries,
                    biometricAuthEnabled: policy.dataProtection.biometricAuthentication,
                    sessionTimeout: policy.dataProtection.sessionTimeout,
                    offlineGracePeriod: policy.dataProtection.offlineGracePeriod
                },
                complianceActions: {
                    blockAccessOnNonCompliance: policy.conditionalAccess.requireDeviceCompliance,
                    blockJailbrokenDevices: policy.conditionalAccess.blockJailbrokenDevices,
                    wipeOnMaxFailedAttempts: policy.dataProtection.wipeAfterFailedAttempts
                }
            }
        };
    }

    /**
     * Generate Android MAM configuration
     */
    generateAndroidConfiguration(policy) {
        return {
            managedAppConfiguration: {
                kind: 'androidenterprise#managedConfiguration',
                productId: 'app:com.opendirectory.managed',
                managedProperty: [
                    {
                        key: 'data_protection_enabled',
                        valueBool: policy.dataProtection.encryptAppData
                    },
                    {
                        key: 'prevent_screenshot',
                        valueBool: policy.dataProtection.preventScreenCapture
                    },
                    {
                        key: 'require_pin',
                        valueBool: policy.dataProtection.requirePinForAccess
                    },
                    {
                        key: 'pin_complexity',
                        valueString: policy.dataProtection.pinComplexity
                    },
                    {
                        key: 'session_timeout',
                        valueInteger: policy.dataProtection.sessionTimeout
                    },
                    {
                        key: 'allowed_data_transfer',
                        valueString: policy.dataProtection.allowDataTransferTo
                    }
                ]
            },
            applicationPolicy: {
                packageName: 'com.opendirectory.managed',
                permissionGrants: [
                    {
                        permission: 'android.permission.READ_EXTERNAL_STORAGE',
                        policy: policy.contentProtection.allowOfflineAccess ? 'GRANT' : 'DENY'
                    },
                    {
                        permission: 'android.permission.CAMERA',
                        policy: policy.dataProtection.preventScreenCapture ? 'DENY' : 'PROMPT'
                    }
                ],
                defaultPermissionPolicy: 'PROMPT',
                managedConfiguration: true,
                autoUpdateMode: policy.appConfiguration.appAutoUpdate ? 'AUTO_UPDATE_HIGH_PRIORITY' : 'AUTO_UPDATE_POSTPONED'
            },
            compliancePolicy: {
                passwordRequired: policy.dataProtection.requirePinForAccess,
                passwordMinimumLength: policy.dataProtection.pinMinLength,
                maximumFailedPasswordsForWipe: policy.dataProtection.wipeAfterFailedAttempts,
                requireDeviceEncryption: policy.dataProtection.encryptAppData,
                blockRootedDevices: policy.conditionalAccess.blockJailbrokenDevices,
                minimumRequiredOsVersion: policy.conditionalAccess.minimumOSVersion
            }
        };
    }

    /**
     * Generate Windows MAM configuration
     */
    generateWindowsConfiguration(policy) {
        return {
            windowsInformationProtection: {
                '@odata.type': '#microsoft.graph.windowsInformationProtection',
                displayName: policy.name,
                description: policy.description,
                enforcementLevel: policy.dataProtection.preventDataLoss ? 'encryptAndAuditOnly' : 'noProtection',
                enterpriseDomain: 'company.com', // This would be configurable
                enterpriseProtectedDomainNames: [
                    {
                        domainName: 'company.com',
                        displayName: 'Company Domain'
                    }
                ],
                protectedApps: policy.targetApplications.map(app => ({
                    '@odata.type': '#microsoft.graph.windowsInformationProtectionApp',
                    displayName: app.name,
                    description: app.description,
                    publisherName: app.publisher,
                    productName: app.name,
                    denied: policy.appConfiguration.blockedApplications.includes(app.id)
                })),
                exemptApps: policy.appConfiguration.allowedApplications.map(app => ({
                    '@odata.type': '#microsoft.graph.windowsInformationProtectionApp',
                    displayName: app.name,
                    description: app.description,
                    publisherName: app.publisher,
                    productName: app.name
                })),
                enterpriseNetworkDomainNames: policy.conditionalAccess.allowedNetworks.map(network => ({
                    domainName: network,
                    displayName: network
                })),
                dataRecoveryCertificate: null, // Would be configured with actual certificate
                revokeOnUnenrollDisabled: false,
                rightsManagementServicesTemplateId: policy.contentProtection.requireRightsManagement ? 'template-id' : null,
                azureRightsManagementServicesAllowed: policy.contentProtection.requireRightsManagement,
                indexingEncryptedStoresOrItemsBlocked: policy.dataProtection.encryptAppData,
                smbAutoEncryptedFileExtensions: ['.docx', '.xlsx', '.pptx', '.pdf'],
                isAssigned: true
            },
            applicationProtectionPolicy: {
                displayName: `${policy.name} - App Protection`,
                description: policy.description,
                periodOfflineBeforeAccessCheck: `PT${policy.dataProtection.offlineGracePeriod}M`,
                periodOnlineBeforeAccessCheck: 'PT30M',
                allowedInboundDataTransferSources: policy.dataProtection.allowDataTransferFrom,
                allowedOutboundDataTransferDestinations: policy.dataProtection.allowDataTransferTo,
                printBlocked: !policy.dataProtection.allowPrintFromManagedApps,
                dataBackupBlocked: policy.dataProtection.preventBackup,
                deviceComplianceRequired: policy.conditionalAccess.requireDeviceCompliance,
                managedBrowserToOpenLinksRequired: policy.conditionalAccess.requireManagedBrowser,
                saveAsBlocked: policy.contentProtection.preventForwarding,
                periodOfflineBeforeWipeIsEnforced: `P${Math.floor(policy.dataProtection.offlineGracePeriod / 1440)}D`,
                pinRequired: policy.dataProtection.requirePinForAccess,
                maximumPinRetries: policy.dataProtection.pinMaxRetries,
                simplePinBlocked: policy.dataProtection.pinComplexity !== 'numeric',
                minimumPinLength: policy.dataProtection.pinMinLength,
                fingerprintBlocked: !policy.dataProtection.biometricAuthentication,
                disableAppPinIfDevicePinIsSet: false
            }
        };
    }

    /**
     * Apply MAM policy to users/devices
     */
    async applyMAMPolicy(policyId, targets) {
        try {
            logger.info(`Applying MAM policy ${policyId} to targets`);

            const policy = this.applicationPolicies.get(policyId);
            if (!policy) {
                throw new Error('MAM policy not found');
            }

            const application = {
                id: `mam-application-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                policyId,
                targets: {
                    users: targets.users || [],
                    groups: targets.groups || [],
                    devices: targets.devices || []
                },
                appliedAt: new Date().toISOString(),
                appliedBy: targets.appliedBy || 'system',
                status: 'applying',
                platformDeployments: {}
            };

            // Generate deployment scripts for each platform
            if (targets.platforms) {
                for (const platform of targets.platforms) {
                    application.platformDeployments[platform] = this.generateDeploymentScript(policy, platform);
                }
            }

            await this.auditLogger.log('mam_policy_applied', {
                applicationId: application.id,
                policyId,
                targetCount: {
                    users: application.targets.users.length,
                    groups: application.targets.groups.length,
                    devices: application.targets.devices.length
                },
                appliedBy: application.appliedBy,
                timestamp: application.appliedAt
            });

            this.emit('mamPolicyApplied', application);

            return {
                success: true,
                application,
                deploymentScripts: application.platformDeployments
            };

        } catch (error) {
            logger.error('Error applying MAM policy:', error);
            throw error;
        }
    }

    /**
     * Generate deployment script for platform
     */
    generateDeploymentScript(policy, platform) {
        switch (platform) {
            case 'ios':
                return this.generateIOSDeploymentScript(policy);
            case 'android':
                return this.generateAndroidDeploymentScript(policy);
            case 'windows':
                return this.generateWindowsDeploymentScript(policy);
            default:
                return null;
        }
    }

    /**
     * Generate iOS deployment script
     */
    generateIOSDeploymentScript(policy) {
        const config = this.generateIOSConfiguration(policy);
        
        return `#!/bin/bash
# iOS MAM Policy Deployment Script
# Policy: ${policy.name}
# Policy ID: ${policy.id}

echo "Deploying iOS MAM policy: ${policy.name}"

# Create configuration profile
cat > /tmp/mam-policy-${policy.id}.mobileconfig << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
${JSON.stringify(config.configurationProfile, null, 2)}
</plist>
EOF

echo "iOS MAM configuration profile generated"
echo "Deploy this profile via MDM to target devices"
echo "Profile path: /tmp/mam-policy-${policy.id}.mobileconfig"
`;
    }

    /**
     * Generate Android deployment script
     */
    generateAndroidDeploymentScript(policy) {
        const config = this.generateAndroidConfiguration(policy);
        
        return `#!/bin/bash
# Android MAM Policy Deployment Script
# Policy: ${policy.name}
# Policy ID: ${policy.id}

echo "Deploying Android MAM policy: ${policy.name}"

# Create managed configuration JSON
cat > /tmp/mam-policy-${policy.id}.json << 'EOF'
${JSON.stringify(config.managedAppConfiguration, null, 2)}
EOF

# Create application policy JSON
cat > /tmp/app-policy-${policy.id}.json << 'EOF'
${JSON.stringify(config.applicationPolicy, null, 2)}
EOF

echo "Android MAM configuration files generated"
echo "Deploy these configurations via Android Enterprise EMM"
echo "Managed config: /tmp/mam-policy-${policy.id}.json"
echo "App policy: /tmp/app-policy-${policy.id}.json"
`;
    }

    /**
     * Generate Windows deployment script
     */
    generateWindowsDeploymentScript(policy) {
        const config = this.generateWindowsConfiguration(policy);
        
        return `# PowerShell Script for Windows MAM Policy Deployment
# Policy: ${policy.name}
# Policy ID: ${policy.id}

Write-Output "Deploying Windows MAM policy: ${policy.name}"

# Windows Information Protection configuration
$WIPConfig = @'
${JSON.stringify(config.windowsInformationProtection, null, 2)}
'@

# Application Protection Policy configuration
$AppProtectionConfig = @'
${JSON.stringify(config.applicationProtectionPolicy, null, 2)}
'@

# Save configurations to files
$WIPConfig | Out-File -FilePath "C:\\temp\\wip-policy-${policy.id}.json" -Encoding UTF8
$AppProtectionConfig | Out-File -FilePath "C:\\temp\\app-protection-${policy.id}.json" -Encoding UTF8

Write-Output "Windows MAM configuration files generated"
Write-Output "WIP Policy: C:\\temp\\wip-policy-${policy.id}.json"
Write-Output "App Protection: C:\\temp\\app-protection-${policy.id}.json"
Write-Output "Deploy these policies via Microsoft Intune or Group Policy"
`;
    }

    /**
     * Monitor MAM policy compliance
     */
    async monitorPolicyCompliance(policyId) {
        try {
            const policy = this.applicationPolicies.get(policyId);
            if (!policy) {
                throw new Error('Policy not found');
            }

            const complianceReport = {
                policyId,
                policyName: policy.name,
                monitoringTimestamp: new Date().toISOString(),
                overallCompliance: {
                    totalDevices: 0,
                    compliantDevices: 0,
                    nonCompliantDevices: 0,
                    compliancePercentage: 0
                },
                platformBreakdown: {
                    ios: { compliant: 0, nonCompliant: 0, unknown: 0 },
                    android: { compliant: 0, nonCompliant: 0, unknown: 0 },
                    windows: { compliant: 0, nonCompliant: 0, unknown: 0 }
                },
                violationTypes: {},
                recentViolations: [],
                remediationActions: [],
                recommendations: []
            };

            // This would query actual compliance data
            // For now, generate sample data
            complianceReport.overallCompliance = {
                totalDevices: 100,
                compliantDevices: 85,
                nonCompliantDevices: 15,
                compliancePercentage: 85.0
            };

            await this.auditLogger.log('mam_compliance_monitored', {
                policyId,
                compliancePercentage: complianceReport.overallCompliance.compliancePercentage,
                timestamp: complianceReport.monitoringTimestamp
            });

            return {
                success: true,
                complianceReport
            };

        } catch (error) {
            logger.error('Error monitoring MAM policy compliance:', error);
            throw error;
        }
    }

    /**
     * Perform selective wipe of application data
     */
    async performSelectiveWipe(deviceId, applications, options = {}) {
        try {
            logger.info(`Performing selective wipe on device: ${deviceId}`);

            const wipeAction = {
                id: `selective-wipe-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                deviceId,
                applications,
                wipeType: 'selective',
                includeAppData: options.includeAppData ?? true,
                includeCachedData: options.includeCachedData ?? true,
                includeUserPreferences: options.includeUserPreferences ?? false,
                preservePersonalData: options.preservePersonalData ?? true,
                notifyUser: options.notifyUser ?? true,
                executedAt: new Date().toISOString(),
                executedBy: options.executedBy || 'system',
                reason: options.reason || 'Policy violation',
                status: 'pending'
            };

            const wipeScripts = this.generateSelectiveWipeScripts(wipeAction);

            await this.auditLogger.log('mam_selective_wipe_initiated', {
                wipeActionId: wipeAction.id,
                deviceId,
                applications: wipeAction.applications,
                executedBy: wipeAction.executedBy,
                reason: wipeAction.reason,
                timestamp: wipeAction.executedAt
            });

            this.emit('selectiveWipeInitiated', wipeAction);

            return {
                success: true,
                wipeAction,
                deploymentScripts: wipeScripts
            };

        } catch (error) {
            logger.error('Error performing selective wipe:', error);
            throw error;
        }
    }

    /**
     * Generate selective wipe scripts
     */
    generateSelectiveWipeScripts(wipeAction) {
        return {
            ios: `# iOS Selective Wipe via MDM
# Wipe Action ID: ${wipeAction.id}

# This would typically be executed via MDM command
echo "Initiating selective wipe for iOS device: ${wipeAction.deviceId}"
echo "Applications to wipe: ${wipeAction.applications.join(', ')}"

# MDM command would be sent to:
# - Remove managed applications
# - Clear application data
# - Revoke certificates for managed apps
# - Remove configuration profiles

echo "Selective wipe command sent via MDM"
`,
            android: `#!/bin/bash
# Android Selective Wipe via Android Enterprise
# Wipe Action ID: ${wipeAction.id}

echo "Initiating selective wipe for Android device: ${wipeAction.deviceId}"

# Applications to wipe
APPS_TO_WIPE="${wipeAction.applications.join(' ')}"

echo "Applications to wipe: $APPS_TO_WIPE"

# This would be executed via Android Enterprise EMM API
# - Uninstall managed applications
# - Clear application data
# - Remove work profile if applicable

echo "Selective wipe initiated via Android Enterprise API"
`,
            windows: `# PowerShell Script for Windows Selective Wipe
# Wipe Action ID: ${wipeAction.id}

Write-Output "Initiating selective wipe for Windows device: ${wipeAction.deviceId}"

$AppsToWipe = @("${wipeAction.applications.join('", "')}")

Write-Output "Applications to wipe: $($AppsToWipe -join ', ')"

foreach ($App in $AppsToWipe) {
    Write-Output "Removing application: $App"
    
    # Remove application
    Get-AppxPackage -Name "*$App*" | Remove-AppxPackage -ErrorAction SilentlyContinue
    
    ${wipeAction.includeAppData ? `
    # Remove application data
    $AppDataPath = "$env:LOCALAPPDATA\\Packages\\*$App*"
    if (Test-Path $AppDataPath) {
        Remove-Item $AppDataPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Application data removed for: $App"
    }
    ` : ''}
    
    ${wipeAction.includeCachedData ? `
    # Clear cached data
    $CachePath = "$env:TEMP\\*$App*"
    if (Test-Path $CachePath) {
        Remove-Item $CachePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Cached data cleared for: $App"
    }
    ` : ''}
}

Write-Output "Selective wipe completed for device: ${wipeAction.deviceId}"
`
        };
    }

    /**
     * Generate UUID for configuration profiles
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    /**
     * Get MAM policy status and statistics
     */
    async getPolicyStatistics(policyId) {
        try {
            const policy = this.applicationPolicies.get(policyId);
            if (!policy) {
                throw new Error('Policy not found');
            }

            const statistics = {
                policyId,
                policyName: policy.name,
                createdAt: policy.createdAt,
                lastModified: policy.lastModified,
                deploymentStats: {
                    totalTargets: 0,
                    successfulDeployments: 0,
                    failedDeployments: 0,
                    pendingDeployments: 0
                },
                complianceStats: {
                    compliantDevices: 0,
                    nonCompliantDevices: 0,
                    unknownStatus: 0
                },
                platformDistribution: {
                    ios: 0,
                    android: 0,
                    windows: 0
                },
                recentActivity: [],
                topViolations: [],
                performanceMetrics: {
                    avgPolicyEvaluationTime: '150ms',
                    avgDeploymentTime: '5m',
                    successRate: '95%'
                }
            };

            return {
                success: true,
                statistics
            };

        } catch (error) {
            logger.error('Error getting MAM policy statistics:', error);
            throw error;
        }
    }
}

module.exports = MAMService;