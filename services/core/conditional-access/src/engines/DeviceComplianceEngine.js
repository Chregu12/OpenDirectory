/**
 * Device Compliance Engine
 * Comprehensive compliance checking for Windows, macOS, and Linux devices
 */

const EventEmitter = require('events');
const crypto = require('crypto');

class DeviceComplianceEngine extends EventEmitter {
    constructor() {
        super();
        this.compliancePolicies = new Map();
        this.deviceStates = new Map();
        this.complianceResults = new Map();
        this.remediationActions = new Map();
        
        // Platform-specific compliance modules
        this.windowsCompliance = new WindowsComplianceChecker();
        this.macosCompliance = new MacOSComplianceChecker();
        this.linuxCompliance = new LinuxComplianceChecker();
        this.mobileCompliance = new MobileComplianceChecker();
        
        this.initializeDefaultPolicies();
    }

    async initialize() {
        console.log('🛡️ Initializing Device Compliance Engine...');
        
        // Initialize platform-specific checkers
        await this.windowsCompliance.initialize();
        await this.macosCompliance.initialize();
        await this.linuxCompliance.initialize();
        await this.mobileCompliance.initialize();
        
        console.log('✅ Device Compliance Engine initialized');
    }

    /**
     * Check device compliance against all applicable policies
     */
    async checkDeviceCompliance(deviceInfo, userId) {
        const checkId = crypto.randomUUID();
        const startTime = Date.now();
        
        try {
            // Determine device platform
            const platform = this.detectPlatform(deviceInfo);
            
            // Get applicable policies for this device
            const applicablePolicies = this.getApplicablePolicies(platform, userId);
            
            // Perform compliance checks
            const complianceResults = await this.performComplianceChecks(
                deviceInfo, 
                platform, 
                applicablePolicies
            );
            
            // Calculate overall compliance status
            const overallStatus = this.calculateOverallCompliance(complianceResults);
            
            // Generate remediation actions if needed
            const remediationActions = await this.generateRemediationActions(
                deviceInfo, 
                platform, 
                complianceResults
            );
            
            // Store results
            const result = {
                id: checkId,
                deviceId: deviceInfo.deviceId,
                userId,
                platform,
                timestamp: new Date(),
                overallStatus,
                policyResults: complianceResults,
                remediationActions,
                checkDuration: Date.now() - startTime
            };
            
            this.complianceResults.set(deviceInfo.deviceId, result);
            this.emit('complianceChecked', result);
            
            return result;
            
        } catch (error) {
            console.error('Device compliance check error:', error);
            this.emit('complianceCheckError', { checkId, deviceId: deviceInfo.deviceId, error: error.message });
            
            return {
                id: checkId,
                deviceId: deviceInfo.deviceId,
                userId,
                timestamp: new Date(),
                overallStatus: 'ERROR',
                error: error.message,
                checkDuration: Date.now() - startTime
            };
        }
    }

    /**
     * Perform platform-specific compliance checks
     */
    async performComplianceChecks(deviceInfo, platform, policies) {
        const results = [];
        
        let checker;
        switch (platform.toLowerCase()) {
            case 'windows':
                checker = this.windowsCompliance;
                break;
            case 'macos':
                checker = this.macosCompliance;
                break;
            case 'linux':
                checker = this.linuxCompliance;
                break;
            case 'ios':
            case 'android':
                checker = this.mobileCompliance;
                break;
            default:
                throw new Error(`Unsupported platform: ${platform}`);
        }
        
        for (const policy of policies) {
            const result = await checker.checkCompliance(deviceInfo, policy);
            results.push({
                policyId: policy.id,
                policyName: policy.name,
                status: result.compliant ? 'COMPLIANT' : 'NON_COMPLIANT',
                details: result.details,
                findings: result.findings,
                severity: result.severity,
                checkedAt: new Date()
            });
        }
        
        return results;
    }

    /**
     * Calculate overall compliance status
     */
    calculateOverallCompliance(complianceResults) {
        if (complianceResults.length === 0) {
            return 'UNKNOWN';
        }
        
        const criticalFailures = complianceResults.filter(r => 
            r.status === 'NON_COMPLIANT' && r.severity === 'CRITICAL'
        );
        
        const highFailures = complianceResults.filter(r => 
            r.status === 'NON_COMPLIANT' && r.severity === 'HIGH'
        );
        
        const anyFailures = complianceResults.filter(r => 
            r.status === 'NON_COMPLIANT'
        );
        
        if (criticalFailures.length > 0) {
            return 'CRITICAL_NON_COMPLIANT';
        } else if (highFailures.length > 0) {
            return 'HIGH_NON_COMPLIANT';
        } else if (anyFailures.length > 0) {
            return 'NON_COMPLIANT';
        } else {
            return 'COMPLIANT';
        }
    }

    /**
     * Generate automated remediation actions
     */
    async generateRemediationActions(deviceInfo, platform, complianceResults) {
        const actions = [];
        
        for (const result of complianceResults) {
            if (result.status === 'NON_COMPLIANT') {
                const remediationAction = this.getRemediationAction(
                    platform, 
                    result.policyId, 
                    result.findings
                );
                
                if (remediationAction) {
                    actions.push({
                        policyId: result.policyId,
                        action: remediationAction,
                        severity: result.severity,
                        autoExecutable: remediationAction.autoExecutable || false
                    });
                }
            }
        }
        
        return actions;
    }

    /**
     * Get remediation action for specific policy violation
     */
    getRemediationAction(platform, policyId, findings) {
        const remediationMap = {
            'bitlocker-encryption': {
                action: 'ENABLE_BITLOCKER',
                description: 'Enable BitLocker encryption',
                command: 'manage-bde -on C: -UsedSpaceOnly',
                autoExecutable: true,
                estimatedTime: 30 // minutes
            },
            'filevault-encryption': {
                action: 'ENABLE_FILEVAULT',
                description: 'Enable FileVault encryption',
                command: 'sudo fdesetup enable',
                autoExecutable: false, // Requires user interaction
                estimatedTime: 60
            },
            'luks-encryption': {
                action: 'ENABLE_LUKS',
                description: 'Enable LUKS encryption',
                command: 'cryptsetup luksFormat /dev/sdX',
                autoExecutable: false,
                estimatedTime: 45
            },
            'windows-defender': {
                action: 'ENABLE_WINDOWS_DEFENDER',
                description: 'Enable Windows Defender real-time protection',
                command: 'Set-MpPreference -DisableRealtimeMonitoring $false',
                autoExecutable: true,
                estimatedTime: 1
            },
            'windows-firewall': {
                action: 'ENABLE_WINDOWS_FIREWALL',
                description: 'Enable Windows Firewall',
                command: 'netsh advfirewall set allprofiles state on',
                autoExecutable: true,
                estimatedTime: 1
            },
            'macos-firewall': {
                action: 'ENABLE_MACOS_FIREWALL',
                description: 'Enable macOS Application Firewall',
                command: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on',
                autoExecutable: true,
                estimatedTime: 1
            },
            'system-updates': {
                action: 'INSTALL_UPDATES',
                description: 'Install pending system updates',
                command: platform === 'windows' ? 'UsoClient StartScan' : 'sudo softwareupdate -i -a',
                autoExecutable: true,
                estimatedTime: 60
            },
            'password-policy': {
                action: 'ENFORCE_PASSWORD_POLICY',
                description: 'Configure password complexity requirements',
                autoExecutable: false,
                estimatedTime: 5
            }
        };
        
        return remediationMap[policyId];
    }

    /**
     * Execute automated remediation
     */
    async executeRemediation(deviceId, actionId) {
        const device = this.deviceStates.get(deviceId);
        if (!device) {
            throw new Error('Device not found');
        }
        
        const action = this.remediationActions.get(actionId);
        if (!action) {
            throw new Error('Remediation action not found');
        }
        
        if (!action.autoExecutable) {
            throw new Error('Action requires manual execution');
        }
        
        try {
            // Execute remediation action
            const result = await this.executeRemediationCommand(device, action);
            
            this.emit('remediationExecuted', {
                deviceId,
                actionId,
                result,
                timestamp: new Date()
            });
            
            // Schedule compliance recheck
            setTimeout(() => {
                this.recheckDeviceCompliance(deviceId);
            }, action.estimatedTime * 60 * 1000); // Convert minutes to milliseconds
            
            return result;
            
        } catch (error) {
            console.error('Remediation execution error:', error);
            this.emit('remediationFailed', {
                deviceId,
                actionId,
                error: error.message,
                timestamp: new Date()
            });
            throw error;
        }
    }

    /**
     * Start continuous monitoring of device compliance
     */
    startContinuousMonitoring() {
        // Check all devices every hour
        setInterval(async () => {
            for (const [deviceId, deviceState] of this.deviceStates) {
                try {
                    await this.recheckDeviceCompliance(deviceId);
                } catch (error) {
                    console.error(`Error rechecking compliance for device ${deviceId}:`, error);
                }
            }
        }, 60 * 60 * 1000); // 1 hour
        
        console.log('🔄 Continuous compliance monitoring started');
    }

    /**
     * Recheck device compliance
     */
    async recheckDeviceCompliance(deviceId) {
        const deviceState = this.deviceStates.get(deviceId);
        if (deviceState) {
            return await this.checkDeviceCompliance(deviceState.deviceInfo, deviceState.userId);
        }
    }

    /**
     * Initialize default compliance policies
     */
    initializeDefaultPolicies() {
        // Windows compliance policies
        this.compliancePolicies.set('windows-security', {
            id: 'windows-security',
            name: 'Windows Security Baseline',
            description: 'Basic security requirements for Windows devices',
            platform: 'windows',
            enabled: true,
            checks: [
                {
                    id: 'bitlocker-encryption',
                    name: 'BitLocker Encryption',
                    description: 'Ensure BitLocker is enabled on system drive',
                    severity: 'CRITICAL',
                    required: true
                },
                {
                    id: 'windows-defender',
                    name: 'Windows Defender',
                    description: 'Ensure Windows Defender real-time protection is enabled',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'windows-firewall',
                    name: 'Windows Firewall',
                    description: 'Ensure Windows Firewall is enabled',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'system-updates',
                    name: 'System Updates',
                    description: 'Ensure system is up to date',
                    severity: 'MEDIUM',
                    required: true
                },
                {
                    id: 'password-policy',
                    name: 'Password Policy',
                    description: 'Ensure strong password policy is configured',
                    severity: 'MEDIUM',
                    required: true
                }
            ]
        });
        
        // macOS compliance policies
        this.compliancePolicies.set('macos-security', {
            id: 'macos-security',
            name: 'macOS Security Baseline',
            description: 'Basic security requirements for macOS devices',
            platform: 'macos',
            enabled: true,
            checks: [
                {
                    id: 'filevault-encryption',
                    name: 'FileVault Encryption',
                    description: 'Ensure FileVault disk encryption is enabled',
                    severity: 'CRITICAL',
                    required: true
                },
                {
                    id: 'macos-firewall',
                    name: 'Application Firewall',
                    description: 'Ensure macOS Application Firewall is enabled',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'gatekeeper',
                    name: 'Gatekeeper',
                    description: 'Ensure Gatekeeper is enabled',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'system-updates',
                    name: 'System Updates',
                    description: 'Ensure system is up to date',
                    severity: 'MEDIUM',
                    required: true
                },
                {
                    id: 'screen-lock',
                    name: 'Screen Lock',
                    description: 'Ensure screen lock is configured',
                    severity: 'MEDIUM',
                    required: true
                }
            ]
        });
        
        // Linux compliance policies
        this.compliancePolicies.set('linux-security', {
            id: 'linux-security',
            name: 'Linux Security Baseline',
            description: 'Basic security requirements for Linux devices',
            platform: 'linux',
            enabled: true,
            checks: [
                {
                    id: 'luks-encryption',
                    name: 'LUKS Encryption',
                    description: 'Ensure LUKS disk encryption is enabled',
                    severity: 'CRITICAL',
                    required: true
                },
                {
                    id: 'iptables-firewall',
                    name: 'iptables Firewall',
                    description: 'Ensure firewall is configured and active',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'selinux-apparmor',
                    name: 'Mandatory Access Control',
                    description: 'Ensure SELinux or AppArmor is enabled',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'system-updates',
                    name: 'System Updates',
                    description: 'Ensure system is up to date',
                    severity: 'MEDIUM',
                    required: true
                },
                {
                    id: 'ssh-hardening',
                    name: 'SSH Hardening',
                    description: 'Ensure SSH is properly configured',
                    severity: 'MEDIUM',
                    required: true
                }
            ]
        });
        
        // Mobile device policies
        this.compliancePolicies.set('mobile-security', {
            id: 'mobile-security',
            name: 'Mobile Device Security',
            description: 'Security requirements for iOS and Android devices',
            platform: 'mobile',
            enabled: true,
            checks: [
                {
                    id: 'device-encryption',
                    name: 'Device Encryption',
                    description: 'Ensure device storage is encrypted',
                    severity: 'CRITICAL',
                    required: true
                },
                {
                    id: 'screen-lock',
                    name: 'Screen Lock',
                    description: 'Ensure screen lock is enabled with PIN/password/biometric',
                    severity: 'HIGH',
                    required: true
                },
                {
                    id: 'os-version',
                    name: 'OS Version',
                    description: 'Ensure device is running supported OS version',
                    severity: 'MEDIUM',
                    required: true
                },
                {
                    id: 'app-store-only',
                    name: 'App Store Only',
                    description: 'Ensure only store-approved apps are installed',
                    severity: 'MEDIUM',
                    required: true
                },
                {
                    id: 'jailbreak-root',
                    name: 'Jailbreak/Root Detection',
                    description: 'Ensure device is not jailbroken or rooted',
                    severity: 'CRITICAL',
                    required: true
                }
            ]
        });
        
        console.log(`✅ Initialized ${this.compliancePolicies.size} compliance policies`);
    }

    /**
     * Detect device platform from device info
     */
    detectPlatform(deviceInfo) {
        const os = deviceInfo.operatingSystem?.toLowerCase() || '';
        const userAgent = deviceInfo.userAgent?.toLowerCase() || '';
        
        if (os.includes('windows') || userAgent.includes('windows')) {
            return 'windows';
        } else if (os.includes('mac') || os.includes('darwin') || userAgent.includes('mac')) {
            return 'macos';
        } else if (os.includes('linux') || userAgent.includes('linux')) {
            return 'linux';
        } else if (os.includes('ios') || userAgent.includes('iphone') || userAgent.includes('ipad')) {
            return 'ios';
        } else if (os.includes('android') || userAgent.includes('android')) {
            return 'android';
        } else {
            return 'unknown';
        }
    }

    /**
     * Get applicable policies for device platform and user
     */
    getApplicablePolicies(platform, userId) {
        const applicablePolicies = [];
        
        for (const [policyId, policy] of this.compliancePolicies) {
            if (policy.enabled && (policy.platform === platform || policy.platform === 'all')) {
                // TODO: Add user/group-specific policy filtering
                applicablePolicies.push(policy);
            }
        }
        
        return applicablePolicies;
    }

    /**
     * Get compliance status for device
     */
    getDeviceCompliance(deviceId) {
        return this.complianceResults.get(deviceId);
    }

    /**
     * Update device state
     */
    updateDeviceState(deviceId, deviceInfo, userId) {
        this.deviceStates.set(deviceId, {
            deviceInfo,
            userId,
            lastUpdated: new Date()
        });
    }

    /**
     * Shutdown the engine
     */
    async shutdown() {
        console.log('🛡️ Shutting down Device Compliance Engine...');
        this.removeAllListeners();
        this.compliancePolicies.clear();
        this.deviceStates.clear();
        this.complianceResults.clear();
        console.log('✅ Device Compliance Engine shutdown complete');
    }
}

/**
 * Platform-specific compliance checkers
 */

class WindowsComplianceChecker {
    async initialize() {
        console.log('🪟 Windows compliance checker initialized');
    }

    async checkCompliance(deviceInfo, policy) {
        const results = {
            compliant: true,
            details: [],
            findings: [],
            severity: 'LOW'
        };

        for (const check of policy.checks) {
            const checkResult = await this.performCheck(deviceInfo, check);
            results.details.push(checkResult);
            
            if (!checkResult.passed) {
                results.compliant = false;
                results.findings.push(checkResult.finding);
                
                if (check.severity === 'CRITICAL') {
                    results.severity = 'CRITICAL';
                } else if (check.severity === 'HIGH' && results.severity !== 'CRITICAL') {
                    results.severity = 'HIGH';
                }
            }
        }

        return results;
    }

    async performCheck(deviceInfo, check) {
        // Simulate compliance checking
        // In real implementation, this would make API calls to the device or agent
        
        switch (check.id) {
            case 'bitlocker-encryption':
                return this.checkBitLocker(deviceInfo);
            case 'windows-defender':
                return this.checkWindowsDefender(deviceInfo);
            case 'windows-firewall':
                return this.checkWindowsFirewall(deviceInfo);
            case 'system-updates':
                return this.checkSystemUpdates(deviceInfo);
            case 'password-policy':
                return this.checkPasswordPolicy(deviceInfo);
            default:
                return {
                    checkId: check.id,
                    passed: true,
                    finding: '',
                    value: 'unknown'
                };
        }
    }

    async checkBitLocker(deviceInfo) {
        // Simulate BitLocker check
        const encrypted = deviceInfo.encryption?.bitlocker?.enabled || false;
        return {
            checkId: 'bitlocker-encryption',
            passed: encrypted,
            finding: encrypted ? '' : 'BitLocker is not enabled on system drive',
            value: encrypted ? 'enabled' : 'disabled'
        };
    }

    async checkWindowsDefender(deviceInfo) {
        const enabled = deviceInfo.antivirus?.windowsDefender?.enabled || false;
        return {
            checkId: 'windows-defender',
            passed: enabled,
            finding: enabled ? '' : 'Windows Defender real-time protection is disabled',
            value: enabled ? 'enabled' : 'disabled'
        };
    }

    async checkWindowsFirewall(deviceInfo) {
        const enabled = deviceInfo.firewall?.windows?.enabled || false;
        return {
            checkId: 'windows-firewall',
            passed: enabled,
            finding: enabled ? '' : 'Windows Firewall is disabled',
            value: enabled ? 'enabled' : 'disabled'
        };
    }

    async checkSystemUpdates(deviceInfo) {
        const upToDate = deviceInfo.updates?.pendingCount === 0;
        return {
            checkId: 'system-updates',
            passed: upToDate,
            finding: upToDate ? '' : `${deviceInfo.updates?.pendingCount || 'Unknown'} pending updates`,
            value: deviceInfo.updates?.pendingCount || 'unknown'
        };
    }

    async checkPasswordPolicy(deviceInfo) {
        const configured = deviceInfo.passwordPolicy?.complexity || false;
        return {
            checkId: 'password-policy',
            passed: configured,
            finding: configured ? '' : 'Password complexity policy not configured',
            value: configured ? 'configured' : 'not configured'
        };
    }
}

class MacOSComplianceChecker {
    async initialize() {
        console.log('🍎 macOS compliance checker initialized');
    }

    async checkCompliance(deviceInfo, policy) {
        const results = {
            compliant: true,
            details: [],
            findings: [],
            severity: 'LOW'
        };

        for (const check of policy.checks) {
            const checkResult = await this.performCheck(deviceInfo, check);
            results.details.push(checkResult);
            
            if (!checkResult.passed) {
                results.compliant = false;
                results.findings.push(checkResult.finding);
                
                if (check.severity === 'CRITICAL') {
                    results.severity = 'CRITICAL';
                } else if (check.severity === 'HIGH' && results.severity !== 'CRITICAL') {
                    results.severity = 'HIGH';
                }
            }
        }

        return results;
    }

    async performCheck(deviceInfo, check) {
        switch (check.id) {
            case 'filevault-encryption':
                return this.checkFileVault(deviceInfo);
            case 'macos-firewall':
                return this.checkMacOSFirewall(deviceInfo);
            case 'gatekeeper':
                return this.checkGatekeeper(deviceInfo);
            case 'system-updates':
                return this.checkSystemUpdates(deviceInfo);
            case 'screen-lock':
                return this.checkScreenLock(deviceInfo);
            default:
                return {
                    checkId: check.id,
                    passed: true,
                    finding: '',
                    value: 'unknown'
                };
        }
    }

    async checkFileVault(deviceInfo) {
        const encrypted = deviceInfo.encryption?.filevault?.enabled || false;
        return {
            checkId: 'filevault-encryption',
            passed: encrypted,
            finding: encrypted ? '' : 'FileVault disk encryption is not enabled',
            value: encrypted ? 'enabled' : 'disabled'
        };
    }

    async checkMacOSFirewall(deviceInfo) {
        const enabled = deviceInfo.firewall?.applicationFirewall?.enabled || false;
        return {
            checkId: 'macos-firewall',
            passed: enabled,
            finding: enabled ? '' : 'Application Firewall is disabled',
            value: enabled ? 'enabled' : 'disabled'
        };
    }

    async checkGatekeeper(deviceInfo) {
        const enabled = deviceInfo.security?.gatekeeper?.enabled || false;
        return {
            checkId: 'gatekeeper',
            passed: enabled,
            finding: enabled ? '' : 'Gatekeeper is disabled',
            value: enabled ? 'enabled' : 'disabled'
        };
    }

    async checkSystemUpdates(deviceInfo) {
        const upToDate = deviceInfo.updates?.pendingCount === 0;
        return {
            checkId: 'system-updates',
            passed: upToDate,
            finding: upToDate ? '' : `${deviceInfo.updates?.pendingCount || 'Unknown'} pending updates`,
            value: deviceInfo.updates?.pendingCount || 'unknown'
        };
    }

    async checkScreenLock(deviceInfo) {
        const configured = deviceInfo.security?.screenLock?.configured || false;
        return {
            checkId: 'screen-lock',
            passed: configured,
            finding: configured ? '' : 'Screen lock is not configured',
            value: configured ? 'configured' : 'not configured'
        };
    }
}

class LinuxComplianceChecker {
    async initialize() {
        console.log('🐧 Linux compliance checker initialized');
    }

    async checkCompliance(deviceInfo, policy) {
        const results = {
            compliant: true,
            details: [],
            findings: [],
            severity: 'LOW'
        };

        for (const check of policy.checks) {
            const checkResult = await this.performCheck(deviceInfo, check);
            results.details.push(checkResult);
            
            if (!checkResult.passed) {
                results.compliant = false;
                results.findings.push(checkResult.finding);
                
                if (check.severity === 'CRITICAL') {
                    results.severity = 'CRITICAL';
                } else if (check.severity === 'HIGH' && results.severity !== 'CRITICAL') {
                    results.severity = 'HIGH';
                }
            }
        }

        return results;
    }

    async performCheck(deviceInfo, check) {
        switch (check.id) {
            case 'luks-encryption':
                return this.checkLUKS(deviceInfo);
            case 'iptables-firewall':
                return this.checkFirewall(deviceInfo);
            case 'selinux-apparmor':
                return this.checkMAC(deviceInfo);
            case 'system-updates':
                return this.checkSystemUpdates(deviceInfo);
            case 'ssh-hardening':
                return this.checkSSH(deviceInfo);
            default:
                return {
                    checkId: check.id,
                    passed: true,
                    finding: '',
                    value: 'unknown'
                };
        }
    }

    async checkLUKS(deviceInfo) {
        const encrypted = deviceInfo.encryption?.luks?.enabled || false;
        return {
            checkId: 'luks-encryption',
            passed: encrypted,
            finding: encrypted ? '' : 'LUKS disk encryption is not enabled',
            value: encrypted ? 'enabled' : 'disabled'
        };
    }

    async checkFirewall(deviceInfo) {
        const enabled = deviceInfo.firewall?.iptables?.active || false;
        return {
            checkId: 'iptables-firewall',
            passed: enabled,
            finding: enabled ? '' : 'Firewall is not active',
            value: enabled ? 'active' : 'inactive'
        };
    }

    async checkMAC(deviceInfo) {
        const selinux = deviceInfo.security?.selinux?.enforcing || false;
        const apparmor = deviceInfo.security?.apparmor?.enabled || false;
        const enabled = selinux || apparmor;
        
        return {
            checkId: 'selinux-apparmor',
            passed: enabled,
            finding: enabled ? '' : 'No mandatory access control (SELinux/AppArmor) is enabled',
            value: selinux ? 'selinux' : (apparmor ? 'apparmor' : 'none')
        };
    }

    async checkSystemUpdates(deviceInfo) {
        const upToDate = deviceInfo.updates?.pendingCount === 0;
        return {
            checkId: 'system-updates',
            passed: upToDate,
            finding: upToDate ? '' : `${deviceInfo.updates?.pendingCount || 'Unknown'} pending updates`,
            value: deviceInfo.updates?.pendingCount || 'unknown'
        };
    }

    async checkSSH(deviceInfo) {
        const hardened = deviceInfo.services?.ssh?.hardened || false;
        return {
            checkId: 'ssh-hardening',
            passed: hardened,
            finding: hardened ? '' : 'SSH is not properly hardened',
            value: hardened ? 'hardened' : 'not hardened'
        };
    }
}

class MobileComplianceChecker {
    async initialize() {
        console.log('📱 Mobile compliance checker initialized');
    }

    async checkCompliance(deviceInfo, policy) {
        const results = {
            compliant: true,
            details: [],
            findings: [],
            severity: 'LOW'
        };

        for (const check of policy.checks) {
            const checkResult = await this.performCheck(deviceInfo, check);
            results.details.push(checkResult);
            
            if (!checkResult.passed) {
                results.compliant = false;
                results.findings.push(checkResult.finding);
                
                if (check.severity === 'CRITICAL') {
                    results.severity = 'CRITICAL';
                } else if (check.severity === 'HIGH' && results.severity !== 'CRITICAL') {
                    results.severity = 'HIGH';
                }
            }
        }

        return results;
    }

    async performCheck(deviceInfo, check) {
        switch (check.id) {
            case 'device-encryption':
                return this.checkDeviceEncryption(deviceInfo);
            case 'screen-lock':
                return this.checkScreenLock(deviceInfo);
            case 'os-version':
                return this.checkOSVersion(deviceInfo);
            case 'app-store-only':
                return this.checkAppStoreOnly(deviceInfo);
            case 'jailbreak-root':
                return this.checkJailbreakRoot(deviceInfo);
            default:
                return {
                    checkId: check.id,
                    passed: true,
                    finding: '',
                    value: 'unknown'
                };
        }
    }

    async checkDeviceEncryption(deviceInfo) {
        const encrypted = deviceInfo.encryption?.device?.enabled || false;
        return {
            checkId: 'device-encryption',
            passed: encrypted,
            finding: encrypted ? '' : 'Device storage is not encrypted',
            value: encrypted ? 'enabled' : 'disabled'
        };
    }

    async checkScreenLock(deviceInfo) {
        const configured = deviceInfo.security?.screenLock?.configured || false;
        return {
            checkId: 'screen-lock',
            passed: configured,
            finding: configured ? '' : 'Screen lock is not configured',
            value: configured ? 'configured' : 'not configured'
        };
    }

    async checkOSVersion(deviceInfo) {
        // Define minimum supported versions
        const minVersions = {
            'ios': '15.0',
            'android': '11.0'
        };
        
        const platform = deviceInfo.platform?.toLowerCase();
        const version = deviceInfo.osVersion;
        const minVersion = minVersions[platform];
        
        if (!minVersion || !version) {
            return {
                checkId: 'os-version',
                passed: false,
                finding: 'Unable to determine OS version',
                value: 'unknown'
            };
        }
        
        const supported = this.compareVersions(version, minVersion) >= 0;
        return {
            checkId: 'os-version',
            passed: supported,
            finding: supported ? '' : `OS version ${version} is below minimum supported version ${minVersion}`,
            value: version
        };
    }

    async checkAppStoreOnly(deviceInfo) {
        const appStoreOnly = deviceInfo.security?.appStoreOnly || false;
        return {
            checkId: 'app-store-only',
            passed: appStoreOnly,
            finding: appStoreOnly ? '' : 'Unknown sources are allowed for app installation',
            value: appStoreOnly ? 'enforced' : 'not enforced'
        };
    }

    async checkJailbreakRoot(deviceInfo) {
        const jailbroken = deviceInfo.security?.jailbroken || false;
        const rooted = deviceInfo.security?.rooted || false;
        const compromised = jailbroken || rooted;
        
        return {
            checkId: 'jailbreak-root',
            passed: !compromised,
            finding: compromised ? 'Device is jailbroken or rooted' : '',
            value: compromised ? 'compromised' : 'secure'
        };
    }

    compareVersions(version1, version2) {
        const parts1 = version1.split('.').map(Number);
        const parts2 = version2.split('.').map(Number);
        
        for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
            const part1 = parts1[i] || 0;
            const part2 = parts2[i] || 0;
            
            if (part1 > part2) return 1;
            if (part1 < part2) return -1;
        }
        
        return 0;
    }
}

module.exports = DeviceComplianceEngine;