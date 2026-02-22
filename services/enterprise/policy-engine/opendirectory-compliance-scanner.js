#!/usr/bin/env node

/**
 * OpenDirectory MDM Compliance Scanner
 * Continuous compliance monitoring and security baseline validation
 * Operates invisibly in the background
 */

const fs = require('fs').promises;
const path = require('path');
const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class ComplianceScanner {
    constructor() {
        this.config = {
            scanInterval: 6 * 60 * 60 * 1000, // 6 hours
            fullScanInterval: 24 * 60 * 60 * 1000, // 24 hours
            complianceStandards: {
                cis: true,
                nist: true,
                iso27001: true,
                sox: false,
                hipaa: false,
                gdpr: true
            },
            alertThresholds: {
                critical: 0, // Alert on any critical violation
                high: 5,     // Alert if more than 5 high violations
                medium: 20   // Alert if more than 20 medium violations
            },
            excludePaths: [
                '/tmp',
                '/var/tmp',
                '/dev',
                '/proc',
                '/sys'
            ]
        };

        this.logFile = '/tmp/compliance-scanner.log';
        this.reportDir = '/tmp/compliance-reports';
        this.isRunning = false;
        this.lastScanResults = null;
        this.complianceRules = this.loadComplianceRules();
    }

    async start() {
        this.log('Compliance Scanner starting...');
        this.isRunning = true;

        // Initialize report directory
        await this.initializeReportDirectory();

        // Start scanning loop
        this.scanningLoop();

        // Set up cleanup on exit
        process.on('SIGTERM', () => this.shutdown());
        process.on('SIGINT', () => this.shutdown());

        // Perform initial scan
        await this.performComplianceScan();

        this.log('Compliance Scanner started successfully');
    }

    async initializeReportDirectory() {
        try {
            await fs.mkdir(this.reportDir, { recursive: true });
            await fs.mkdir(path.join(this.reportDir, 'daily'), { recursive: true });
            await fs.mkdir(path.join(this.reportDir, 'violations'), { recursive: true });
            await fs.mkdir(path.join(this.reportDir, 'trends'), { recursive: true });
        } catch (error) {
            this.log(`Failed to initialize report directory: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async scanningLoop() {
        while (this.isRunning) {
            try {
                await this.performComplianceScan();
                await this.sleep(this.config.scanInterval);
            } catch (error) {
                this.log(`Error in scanning loop: ${error.message}`, 'ERROR');
                await this.sleep(60000); // Wait 1 minute on error
            }
        }
    }

    async performComplianceScan() {
        this.log('Starting compliance scan...');
        const scanStart = Date.now();

        const scanResults = {
            timestamp: new Date().toISOString(),
            scanId: this.generateScanId(),
            duration: 0,
            standards: {},
            summary: {
                total: 0,
                passed: 0,
                failed: 0,
                skipped: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            },
            violations: [],
            recommendations: []
        };

        try {
            // Scan each enabled compliance standard
            for (const [standard, enabled] of Object.entries(this.config.complianceStandards)) {
                if (enabled) {
                    this.log(`Scanning ${standard.toUpperCase()} compliance...`);
                    scanResults.standards[standard] = await this.scanStandard(standard);
                }
            }

            // Aggregate results
            this.aggregateScanResults(scanResults);

            // Generate compliance report
            await this.generateComplianceReport(scanResults);

            // Check for violations and generate alerts
            await this.processViolations(scanResults);

            // Save scan results
            await this.saveScanResults(scanResults);

            scanResults.duration = Date.now() - scanStart;
            this.lastScanResults = scanResults;

            this.log(`Compliance scan completed in ${scanResults.duration}ms - Violations: ${scanResults.summary.failed}/${scanResults.summary.total}`);

        } catch (error) {
            this.log(`Compliance scan failed: ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async scanStandard(standard) {
        const results = {
            standard,
            timestamp: new Date().toISOString(),
            checks: [],
            summary: { total: 0, passed: 0, failed: 0, skipped: 0 }
        };

        const rules = this.complianceRules[standard] || [];

        for (const rule of rules) {
            try {
                const checkResult = await this.executeComplianceCheck(rule);
                results.checks.push(checkResult);
                results.summary.total++;

                switch (checkResult.status) {
                    case 'passed':
                        results.summary.passed++;
                        break;
                    case 'failed':
                        results.summary.failed++;
                        break;
                    case 'skipped':
                        results.summary.skipped++;
                        break;
                }
            } catch (error) {
                this.log(`Failed to execute rule ${rule.id}: ${error.message}`, 'ERROR');
                results.checks.push({
                    ruleId: rule.id,
                    status: 'error',
                    message: error.message
                });
            }
        }

        return results;
    }

    async executeComplianceCheck(rule) {
        const result = {
            ruleId: rule.id,
            title: rule.title,
            severity: rule.severity,
            category: rule.category,
            status: 'skipped',
            message: '',
            evidence: null,
            remediation: rule.remediation || ''
        };

        try {
            switch (rule.type) {
                case 'file_permissions':
                    return await this.checkFilePermissions(rule, result);
                case 'file_exists':
                    return await this.checkFileExists(rule, result);
                case 'service_status':
                    return await this.checkServiceStatus(rule, result);
                case 'configuration':
                    return await this.checkConfiguration(rule, result);
                case 'password_policy':
                    return await this.checkPasswordPolicy(rule, result);
                case 'network_config':
                    return await this.checkNetworkConfig(rule, result);
                case 'system_setting':
                    return await this.checkSystemSetting(rule, result);
                case 'software_version':
                    return await this.checkSoftwareVersion(rule, result);
                case 'license_compliance':
                    return await this.checkLicenseCompliance(rule, result);
                default:
                    result.status = 'skipped';
                    result.message = `Unknown rule type: ${rule.type}`;
                    return result;
            }
        } catch (error) {
            result.status = 'error';
            result.message = error.message;
            return result;
        }
    }

    async checkFilePermissions(rule, result) {
        try {
            const { stdout } = await execAsync(`ls -la "${rule.path}" 2>/dev/null`);
            const permissions = stdout.trim().split(/\s+/)[0];
            
            if (rule.expectedPermissions) {
                if (permissions === rule.expectedPermissions) {
                    result.status = 'passed';
                    result.message = `File permissions are correct: ${permissions}`;
                } else {
                    result.status = 'failed';
                    result.message = `File permissions are ${permissions}, expected ${rule.expectedPermissions}`;
                    result.evidence = { actual: permissions, expected: rule.expectedPermissions };
                }
            } else if (rule.forbiddenPermissions && permissions.includes(rule.forbiddenPermissions)) {
                result.status = 'failed';
                result.message = `File has forbidden permissions: ${permissions}`;
                result.evidence = { actual: permissions, forbidden: rule.forbiddenPermissions };
            } else {
                result.status = 'passed';
                result.message = `File permissions check passed: ${permissions}`;
            }
        } catch (error) {
            result.status = 'failed';
            result.message = `File not found or access denied: ${rule.path}`;
        }

        return result;
    }

    async checkFileExists(rule, result) {
        try {
            await fs.access(rule.path);
            
            if (rule.shouldExist !== false) {
                result.status = 'passed';
                result.message = `Required file exists: ${rule.path}`;
            } else {
                result.status = 'failed';
                result.message = `File should not exist: ${rule.path}`;
            }
        } catch (error) {
            if (rule.shouldExist === false) {
                result.status = 'passed';
                result.message = `File correctly does not exist: ${rule.path}`;
            } else {
                result.status = 'failed';
                result.message = `Required file does not exist: ${rule.path}`;
            }
        }

        return result;
    }

    async checkServiceStatus(rule, result) {
        try {
            const isRunning = await this.isServiceRunning(rule.service);
            
            if (rule.shouldBeRunning && isRunning) {
                result.status = 'passed';
                result.message = `Service is running as expected: ${rule.service}`;
            } else if (!rule.shouldBeRunning && !isRunning) {
                result.status = 'passed';
                result.message = `Service is correctly stopped: ${rule.service}`;
            } else {
                result.status = 'failed';
                result.message = `Service status incorrect: ${rule.service} (running: ${isRunning}, expected: ${rule.shouldBeRunning})`;
                result.evidence = { running: isRunning, expected: rule.shouldBeRunning };
            }
        } catch (error) {
            result.status = 'error';
            result.message = `Failed to check service status: ${error.message}`;
        }

        return result;
    }

    async checkConfiguration(rule, result) {
        try {
            const configContent = await fs.readFile(rule.configFile, 'utf8');
            
            if (rule.expectedValue) {
                const regex = new RegExp(rule.pattern);
                const match = configContent.match(regex);
                
                if (match && match[1] === rule.expectedValue) {
                    result.status = 'passed';
                    result.message = `Configuration is correct: ${rule.parameter} = ${rule.expectedValue}`;
                } else {
                    result.status = 'failed';
                    result.message = `Configuration mismatch: ${rule.parameter} = ${match ? match[1] : 'not found'}, expected ${rule.expectedValue}`;
                    result.evidence = { actual: match ? match[1] : null, expected: rule.expectedValue };
                }
            } else if (rule.forbiddenValue) {
                if (configContent.includes(rule.forbiddenValue)) {
                    result.status = 'failed';
                    result.message = `Configuration contains forbidden value: ${rule.forbiddenValue}`;
                } else {
                    result.status = 'passed';
                    result.message = `Configuration does not contain forbidden value`;
                }
            }
        } catch (error) {
            result.status = 'error';
            result.message = `Failed to read configuration file: ${error.message}`;
        }

        return result;
    }

    async checkPasswordPolicy(rule, result) {
        // Simulated password policy check - would integrate with actual system
        try {
            const policies = {
                minLength: 8,
                requireUppercase: true,
                requireLowercase: true,
                requireNumbers: true,
                requireSpecialChars: true,
                maxAge: 90,
                history: 5
            };

            const violations = [];

            if (rule.minLength && policies.minLength < rule.minLength) {
                violations.push(`Minimum length ${policies.minLength} is less than required ${rule.minLength}`);
            }

            if (rule.requireComplexity && !policies.requireUppercase) {
                violations.push('Uppercase letters not required');
            }

            if (violations.length > 0) {
                result.status = 'failed';
                result.message = `Password policy violations: ${violations.join(', ')}`;
                result.evidence = { violations, currentPolicy: policies };
            } else {
                result.status = 'passed';
                result.message = 'Password policy is compliant';
            }
        } catch (error) {
            result.status = 'error';
            result.message = `Failed to check password policy: ${error.message}`;
        }

        return result;
    }

    async checkNetworkConfig(rule, result) {
        try {
            switch (rule.check) {
                case 'firewall_enabled':
                    const { stdout: firewallStatus } = await execAsync('sudo pfctl -s info 2>/dev/null || echo "disabled"');
                    const firewallEnabled = !firewallStatus.includes('disabled');
                    
                    if (rule.expectedEnabled && firewallEnabled) {
                        result.status = 'passed';
                        result.message = 'Firewall is enabled as required';
                    } else if (!rule.expectedEnabled && !firewallEnabled) {
                        result.status = 'passed';
                        result.message = 'Firewall is disabled as expected';
                    } else {
                        result.status = 'failed';
                        result.message = `Firewall status incorrect: ${firewallEnabled ? 'enabled' : 'disabled'}`;
                    }
                    break;

                case 'ssh_config':
                    const sshConfig = await fs.readFile('/etc/ssh/sshd_config', 'utf8');
                    
                    if (rule.setting === 'PermitRootLogin' && sshConfig.includes('PermitRootLogin no')) {
                        result.status = 'passed';
                        result.message = 'SSH root login is disabled';
                    } else if (rule.setting === 'PasswordAuthentication' && sshConfig.includes('PasswordAuthentication no')) {
                        result.status = 'passed';
                        result.message = 'SSH password authentication is disabled';
                    } else {
                        result.status = 'failed';
                        result.message = `SSH configuration does not meet requirement: ${rule.setting}`;
                    }
                    break;

                default:
                    result.status = 'skipped';
                    result.message = `Unknown network check: ${rule.check}`;
            }
        } catch (error) {
            result.status = 'error';
            result.message = `Network configuration check failed: ${error.message}`;
        }

        return result;
    }

    async checkSystemSetting(rule, result) {
        try {
            const { stdout } = await execAsync(rule.command);
            const actualValue = stdout.trim();
            
            if (rule.expectedValue && actualValue === rule.expectedValue) {
                result.status = 'passed';
                result.message = `System setting is correct: ${actualValue}`;
            } else if (rule.expectedValue) {
                result.status = 'failed';
                result.message = `System setting mismatch: ${actualValue}, expected ${rule.expectedValue}`;
                result.evidence = { actual: actualValue, expected: rule.expectedValue };
            } else {
                result.status = 'passed';
                result.message = `System setting retrieved: ${actualValue}`;
                result.evidence = { value: actualValue };
            }
        } catch (error) {
            result.status = 'error';
            result.message = `Failed to check system setting: ${error.message}`;
        }

        return result;
    }

    async checkSoftwareVersion(rule, result) {
        try {
            const { stdout } = await execAsync(rule.versionCommand);
            const version = stdout.trim();
            
            if (rule.minimumVersion) {
                const isCompliant = this.compareVersions(version, rule.minimumVersion) >= 0;
                
                if (isCompliant) {
                    result.status = 'passed';
                    result.message = `Software version is compliant: ${version} >= ${rule.minimumVersion}`;
                } else {
                    result.status = 'failed';
                    result.message = `Software version is outdated: ${version} < ${rule.minimumVersion}`;
                    result.evidence = { actual: version, minimum: rule.minimumVersion };
                }
            } else {
                result.status = 'passed';
                result.message = `Software version: ${version}`;
                result.evidence = { version };
            }
        } catch (error) {
            result.status = 'failed';
            result.message = `Software not found or version check failed: ${error.message}`;
        }

        return result;
    }

    async checkLicenseCompliance(rule, result) {
        // Simulated license compliance check
        try {
            const licenses = {
                'node': { type: 'MIT', compliant: true },
                'openssl': { type: 'OpenSSL', compliant: true },
                'gpl-software': { type: 'GPL', compliant: false }
            };

            const license = licenses[rule.software];
            
            if (!license) {
                result.status = 'skipped';
                result.message = `No license information available for ${rule.software}`;
            } else if (license.compliant) {
                result.status = 'passed';
                result.message = `License is compliant: ${rule.software} (${license.type})`;
            } else {
                result.status = 'failed';
                result.message = `License compliance violation: ${rule.software} (${license.type})`;
                result.evidence = license;
            }
        } catch (error) {
            result.status = 'error';
            result.message = `License compliance check failed: ${error.message}`;
        }

        return result;
    }

    aggregateScanResults(scanResults) {
        for (const standard of Object.values(scanResults.standards)) {
            for (const check of standard.checks) {
                scanResults.summary.total++;
                
                switch (check.status) {
                    case 'passed':
                        scanResults.summary.passed++;
                        break;
                    case 'failed':
                        scanResults.summary.failed++;
                        scanResults.violations.push(check);
                        
                        switch (check.severity) {
                            case 'critical':
                                scanResults.summary.critical++;
                                break;
                            case 'high':
                                scanResults.summary.high++;
                                break;
                            case 'medium':
                                scanResults.summary.medium++;
                                break;
                            case 'low':
                                scanResults.summary.low++;
                                break;
                        }
                        break;
                    case 'skipped':
                        scanResults.summary.skipped++;
                        break;
                }

                // Generate recommendations for failed checks
                if (check.status === 'failed' && check.remediation) {
                    scanResults.recommendations.push({
                        ruleId: check.ruleId,
                        title: check.title,
                        severity: check.severity,
                        remediation: check.remediation
                    });
                }
            }
        }
    }

    async generateComplianceReport(scanResults) {
        const reportPath = path.join(this.reportDir, 'daily', `compliance-${scanResults.scanId}.json`);
        const htmlReportPath = path.join(this.reportDir, 'daily', `compliance-${scanResults.scanId}.html`);

        try {
            // Save JSON report
            await fs.writeFile(reportPath, JSON.stringify(scanResults, null, 2));

            // Generate HTML report
            const htmlReport = this.generateHtmlReport(scanResults);
            await fs.writeFile(htmlReportPath, htmlReport);

            this.log(`Compliance report generated: ${reportPath}`);
        } catch (error) {
            this.log(`Failed to generate compliance report: ${error.message}`, 'ERROR');
        }
    }

    generateHtmlReport(scanResults) {
        const timestamp = new Date(scanResults.timestamp).toLocaleString();
        
        return `
<!DOCTYPE html>
<html>
<head>
    <title>OpenDirectory MDM Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; }
        .violations { margin: 20px 0; }
        .violation { background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }
        .violation.critical { border-color: #d32f2f; }
        .violation.high { border-color: #f57c00; }
        .violation.medium { border-color: #fbc02d; }
        .violation.low { border-color: #689f38; }
        .standards { margin: 20px 0; }
        .standard { border: 1px solid #ddd; margin: 10px 0; border-radius: 5px; }
        .standard-header { background: #f5f5f5; padding: 10px; font-weight: bold; }
        .standard-content { padding: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OpenDirectory MDM Compliance Report</h1>
        <p>Generated: ${timestamp}</p>
        <p>Scan ID: ${scanResults.scanId}</p>
        <p>Duration: ${scanResults.duration}ms</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>Total Checks</h3>
            <div style="font-size: 2em; color: #333;">${scanResults.summary.total}</div>
        </div>
        <div class="metric">
            <h3>Passed</h3>
            <div style="font-size: 2em; color: #4caf50;">${scanResults.summary.passed}</div>
        </div>
        <div class="metric">
            <h3>Failed</h3>
            <div style="font-size: 2em; color: #f44336;">${scanResults.summary.failed}</div>
        </div>
        <div class="metric">
            <h3>Critical</h3>
            <div style="font-size: 2em; color: #d32f2f;">${scanResults.summary.critical}</div>
        </div>
    </div>

    <div class="violations">
        <h2>Compliance Violations (${scanResults.violations.length})</h2>
        ${scanResults.violations.map(violation => `
            <div class="violation ${violation.severity}">
                <h4>[${violation.severity.toUpperCase()}] ${violation.title}</h4>
                <p><strong>Rule ID:</strong> ${violation.ruleId}</p>
                <p><strong>Message:</strong> ${violation.message}</p>
                ${violation.remediation ? `<p><strong>Remediation:</strong> ${violation.remediation}</p>` : ''}
                ${violation.evidence ? `<p><strong>Evidence:</strong> ${JSON.stringify(violation.evidence)}</p>` : ''}
            </div>
        `).join('')}
    </div>

    <div class="standards">
        <h2>Standards Compliance</h2>
        ${Object.entries(scanResults.standards).map(([name, standard]) => `
            <div class="standard">
                <div class="standard-header">
                    ${name.toUpperCase()} - ${standard.summary.passed}/${standard.summary.total} passed
                </div>
                <div class="standard-content">
                    <p>Failed: ${standard.summary.failed}, Skipped: ${standard.summary.skipped}</p>
                </div>
            </div>
        `).join('')}
    </div>

    ${scanResults.recommendations.length > 0 ? `
    <div class="recommendations">
        <h2>Recommendations (${scanResults.recommendations.length})</h2>
        ${scanResults.recommendations.map(rec => `
            <div class="violation ${rec.severity}">
                <h4>${rec.title}</h4>
                <p>${rec.remediation}</p>
            </div>
        `).join('')}
    </div>
    ` : ''}
</body>
</html>
        `;
    }

    async processViolations(scanResults) {
        const alerts = [];

        // Check if violations exceed thresholds
        if (scanResults.summary.critical > this.config.alertThresholds.critical) {
            alerts.push({
                level: 'critical',
                message: `${scanResults.summary.critical} critical compliance violations detected`,
                violations: scanResults.violations.filter(v => v.severity === 'critical')
            });
        }

        if (scanResults.summary.high > this.config.alertThresholds.high) {
            alerts.push({
                level: 'high',
                message: `${scanResults.summary.high} high severity compliance violations detected`,
                violations: scanResults.violations.filter(v => v.severity === 'high')
            });
        }

        if (scanResults.summary.medium > this.config.alertThresholds.medium) {
            alerts.push({
                level: 'medium',
                message: `${scanResults.summary.medium} medium severity compliance violations detected`,
                violations: scanResults.violations.filter(v => v.severity === 'medium')
            });
        }

        // Generate alerts
        for (const alert of alerts) {
            await this.generateAlert(alert);
        }

        // Save violations for trending
        if (scanResults.violations.length > 0) {
            const violationPath = path.join(this.reportDir, 'violations', `violations-${scanResults.scanId}.json`);
            await fs.writeFile(violationPath, JSON.stringify(scanResults.violations, null, 2));
        }
    }

    async generateAlert(alert) {
        const alertPath = path.join(this.reportDir, 'alerts', `alert-${Date.now()}.json`);
        
        try {
            await fs.mkdir(path.dirname(alertPath), { recursive: true });
            await fs.writeFile(alertPath, JSON.stringify({
                timestamp: new Date().toISOString(),
                level: alert.level,
                message: alert.message,
                violations: alert.violations
            }, null, 2));

            this.log(`Compliance alert generated: ${alert.level} - ${alert.message}`, alert.level.toUpperCase());
        } catch (error) {
            this.log(`Failed to generate alert: ${error.message}`, 'ERROR');
        }
    }

    async saveScanResults(scanResults) {
        const resultsPath = path.join(this.reportDir, `latest-scan.json`);
        
        try {
            await fs.writeFile(resultsPath, JSON.stringify(scanResults, null, 2));
        } catch (error) {
            this.log(`Failed to save scan results: ${error.message}`, 'ERROR');
        }
    }

    loadComplianceRules() {
        return {
            cis: [
                {
                    id: 'CIS-1.1.1',
                    title: 'Ensure mounting of cramfs filesystems is disabled',
                    type: 'file_exists',
                    path: '/etc/modprobe.d/cramfs.conf',
                    shouldExist: true,
                    severity: 'medium',
                    category: 'filesystem',
                    remediation: 'Create /etc/modprobe.d/cramfs.conf with "install cramfs /bin/true"'
                },
                {
                    id: 'CIS-2.1.1',
                    title: 'Ensure xinetd is not installed',
                    type: 'service_status',
                    service: 'xinetd',
                    shouldBeRunning: false,
                    severity: 'high',
                    category: 'services'
                },
                {
                    id: 'CIS-3.1.1',
                    title: 'Ensure IP forwarding is disabled',
                    type: 'system_setting',
                    command: 'sysctl net.ipv4.ip_forward',
                    expectedValue: 'net.ipv4.ip_forward = 0',
                    severity: 'medium',
                    category: 'network'
                },
                {
                    id: 'CIS-5.1.1',
                    title: 'Ensure cron daemon is enabled',
                    type: 'service_status',
                    service: 'cron',
                    shouldBeRunning: true,
                    severity: 'low',
                    category: 'scheduling'
                },
                {
                    id: 'CIS-5.2.1',
                    title: 'Ensure permissions on /etc/ssh/sshd_config are configured',
                    type: 'file_permissions',
                    path: '/etc/ssh/sshd_config',
                    expectedPermissions: '-rw-------',
                    severity: 'high',
                    category: 'ssh'
                }
            ],
            nist: [
                {
                    id: 'NIST-AC-2',
                    title: 'Account Management',
                    type: 'password_policy',
                    minLength: 12,
                    requireComplexity: true,
                    severity: 'high',
                    category: 'access_control'
                },
                {
                    id: 'NIST-AU-2',
                    title: 'Audit Events',
                    type: 'service_status',
                    service: 'auditd',
                    shouldBeRunning: true,
                    severity: 'high',
                    category: 'auditing'
                },
                {
                    id: 'NIST-SC-7',
                    title: 'Boundary Protection',
                    type: 'network_config',
                    check: 'firewall_enabled',
                    expectedEnabled: true,
                    severity: 'critical',
                    category: 'network_security'
                }
            ],
            iso27001: [
                {
                    id: 'ISO-A.9.2.1',
                    title: 'User registration and de-registration',
                    type: 'system_setting',
                    command: 'id guest',
                    severity: 'medium',
                    category: 'access_management'
                },
                {
                    id: 'ISO-A.12.6.1',
                    title: 'Management of technical vulnerabilities',
                    type: 'software_version',
                    versionCommand: 'openssl version',
                    minimumVersion: '1.1.1',
                    severity: 'high',
                    category: 'vulnerability_management'
                }
            ],
            gdpr: [
                {
                    id: 'GDPR-32',
                    title: 'Security of processing',
                    type: 'file_permissions',
                    path: '/var/log/auth.log',
                    expectedPermissions: '-rw-r-----',
                    severity: 'high',
                    category: 'data_protection'
                }
            ]
        };
    }

    async isServiceRunning(serviceName) {
        try {
            const { stdout } = await execAsync(`pgrep -f "${serviceName}"`);
            return stdout.trim().length > 0;
        } catch (error) {
            return false;
        }
    }

    compareVersions(version1, version2) {
        const v1Parts = version1.split('.').map(Number);
        const v2Parts = version2.split('.').map(Number);
        const maxLength = Math.max(v1Parts.length, v2Parts.length);

        for (let i = 0; i < maxLength; i++) {
            const v1Part = v1Parts[i] || 0;
            const v2Part = v2Parts[i] || 0;

            if (v1Part > v2Part) return 1;
            if (v1Part < v2Part) return -1;
        }

        return 0;
    }

    generateScanId() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        return `scan-${timestamp}-${Math.random().toString(36).substr(2, 8)}`;
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;

        try {
            await fs.appendFile(this.logFile, logEntry);
            console.log(`Compliance Scanner: ${message}`);
        } catch (error) {
            console.error(`Failed to write log: ${error.message}`);
        }
    }

    async shutdown() {
        this.log('Compliance Scanner shutting down...');
        this.isRunning = false;
    }
}

// Start the service
if (require.main === module) {
    const service = new ComplianceScanner();
    service.start().catch(error => {
        console.error('Failed to start Compliance Scanner:', error);
        process.exit(1);
    });
}

module.exports = ComplianceScanner;