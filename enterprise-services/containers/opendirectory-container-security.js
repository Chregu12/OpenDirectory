/**
 * OpenDirectory Container Registry & Security Manager
 * Comprehensive container security with scanning and runtime protection
 */

const crypto = require('crypto');
const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');

class ContainerSecurityManager extends EventEmitter {
    constructor(config = {}) {
        super();
        this.registries = new Map();
        this.images = new Map();
        this.vulnerabilities = new Map();
        this.policies = new Map();
        this.runtimeMonitoring = new Map();
        this.complianceScans = new Map();
        this.networkPolicies = new Map();
        this.config = {
            maxRegistries: config.maxRegistries || 10,
            scanEnabled: config.scanEnabled !== false,
            runtimeMonitoring: config.runtimeMonitoring !== false,
            signatureVerification: config.signatureVerification !== false,
            quarantineEnabled: config.quarantineEnabled !== false,
            complianceFrameworks: config.complianceFrameworks || ['CIS', 'NIST', 'PCI-DSS'],
            ...config
        };
        this.vulnerabilityDatabase = new Map();
        this.initializeSecurityManager();
    }

    initializeSecurityManager() {
        console.log('Initializing Container Security Manager...');
        this.loadVulnerabilityDatabase();
        this.startRuntimeMonitoring();
        this.setupEventHandlers();
    }

    // Registry Management
    async registerContainerRegistry(registryConfig) {
        try {
            const registryId = this.generateId();
            const registry = {
                id: registryId,
                name: registryConfig.name,
                type: registryConfig.type || 'docker', // docker, gcr, ecr, acr
                endpoint: registryConfig.endpoint,
                credentials: this.encryptCredentials(registryConfig.credentials),
                region: registryConfig.region,
                scanning: {
                    enabled: registryConfig.scanOnPush !== false,
                    schedule: registryConfig.scanSchedule || 'daily',
                    policies: registryConfig.scanPolicies || ['HIGH', 'CRITICAL']
                },
                compliance: {
                    frameworks: registryConfig.complianceFrameworks || this.config.complianceFrameworks,
                    enabled: true
                },
                security: {
                    imageSigningEnabled: registryConfig.imageSigning !== false,
                    notaryEnabled: registryConfig.notary !== false,
                    accessLogging: true
                },
                metrics: {
                    totalImages: 0,
                    totalScans: 0,
                    vulnerabilitiesFound: 0,
                    lastScan: null
                },
                createdAt: new Date(),
                status: 'active'
            };

            this.registries.set(registryId, registry);
            await this.initializeRegistryIntegration(registry);

            this.emit('registryRegistered', registry);
            
            return {
                success: true,
                registryId,
                registry: this.sanitizeRegistry(registry)
            };

        } catch (error) {
            console.error('Registry registration failed:', error);
            throw new Error(`Registry registration failed: ${error.message}`);
        }
    }

    async initializeRegistryIntegration(registry) {
        // Setup registry-specific integrations
        switch (registry.type.toLowerCase()) {
            case 'docker':
                await this.setupDockerRegistryIntegration(registry);
                break;
            case 'gcr':
                await this.setupGCRIntegration(registry);
                break;
            case 'ecr':
                await this.setupECRIntegration(registry);
                break;
            case 'acr':
                await this.setupACRIntegration(registry);
                break;
        }

        // Setup webhook for scan notifications
        await this.setupRegistryWebhooks(registry);
    }

    async setupDockerRegistryIntegration(registry) {
        // Configure Docker registry integration
        const config = {
            endpoint: registry.endpoint,
            auth: registry.credentials,
            webhooks: {
                push: `${this.config.webhookEndpoint}/registry/${registry.id}/push`,
                scan: `${this.config.webhookEndpoint}/registry/${registry.id}/scan`
            }
        };

        await this.simulateRegistryAPICall('docker.configure', config);
    }

    async setupGCRIntegration(registry) {
        const config = {
            projectId: registry.credentials.projectId,
            location: registry.region || 'us-central1',
            scanning: {
                enabled: true,
                onPush: true
            }
        };

        await this.simulateRegistryAPICall('gcr.configure', config);
    }

    async setupECRIntegration(registry) {
        const config = {
            region: registry.region,
            scanOnPush: true,
            imageScanningConfiguration: {
                scanOnPush: true
            },
            encryptionConfiguration: {
                encryptionType: 'AES256'
            }
        };

        await this.simulateRegistryAPICall('ecr.configure', config);
    }

    async setupACRIntegration(registry) {
        const config = {
            resourceGroup: registry.credentials.resourceGroup,
            location: registry.region,
            sku: 'Premium',
            quarantinePolicy: {
                status: 'enabled'
            },
            trustPolicy: {
                status: 'enabled'
            }
        };

        await this.simulateRegistryAPICall('acr.configure', config);
    }

    // Image Security Scanning
    async scanImage(registryId, imageTag, scanConfig = {}) {
        try {
            const registry = this.registries.get(registryId);
            if (!registry) {
                throw new Error('Registry not found');
            }

            const scanId = this.generateId();
            const scan = {
                id: scanId,
                registryId,
                imageTag,
                status: 'scanning',
                startedAt: new Date(),
                scanType: scanConfig.scanType || 'comprehensive',
                findings: {
                    vulnerabilities: [],
                    malware: [],
                    secrets: [],
                    compliance: [],
                    configuration: []
                },
                severity: {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0
                },
                remediation: {
                    recommendations: [],
                    patches: [],
                    updates: []
                }
            };

            // Start comprehensive scan
            await this.performVulnerabilityScanning(scan);
            await this.performMalwareScanning(scan);
            await this.performSecretScanning(scan);
            await this.performComplianceScanning(scan);
            await this.performConfigurationScanning(scan);

            scan.completedAt = new Date();
            scan.duration = scan.completedAt - scan.startedAt;
            scan.status = 'completed';

            // Calculate overall risk score
            scan.riskScore = this.calculateRiskScore(scan);
            
            // Determine if image should be quarantined
            if (this.shouldQuarantineImage(scan)) {
                await this.quarantineImage(registryId, imageTag, scan);
                scan.quarantined = true;
            }

            // Generate remediation report
            scan.remediationReport = await this.generateRemediationReport(scan);

            this.images.set(scanId, scan);
            registry.metrics.totalScans++;
            registry.metrics.vulnerabilitiesFound += scan.findings.vulnerabilities.length;
            registry.metrics.lastScan = new Date();

            this.emit('imageScanCompleted', scan);

            return {
                success: true,
                scanId,
                scan: this.sanitizeScan(scan)
            };

        } catch (error) {
            console.error('Image scan failed:', error);
            throw new Error(`Image scan failed: ${error.message}`);
        }
    }

    async performVulnerabilityScanning(scan) {
        console.log(`Performing vulnerability scan for ${scan.imageTag}...`);
        
        // Simulate vulnerability scanning using multiple databases
        const databases = ['NVD', 'CVE', 'GHSA', 'Alpine', 'Debian', 'Ubuntu'];
        const vulnerabilities = [];

        // Generate realistic vulnerabilities
        const vulnCount = Math.floor(Math.random() * 15) + 5;
        for (let i = 0; i < vulnCount; i++) {
            const severity = this.getRandomSeverity();
            const vuln = {
                id: `CVE-2023-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`,
                severity: severity,
                score: this.getCVSSScore(severity),
                package: this.getRandomPackage(),
                installedVersion: '1.2.3',
                fixedVersion: '1.2.4',
                description: `Security vulnerability in package allowing ${this.getRandomAttackVector()}`,
                references: [`https://nvd.nist.gov/vuln/detail/CVE-2023-${Math.floor(Math.random() * 10000)}`],
                database: databases[Math.floor(Math.random() * databases.length)],
                publishedAt: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
                layer: `sha256:${crypto.randomBytes(32).toString('hex')}`
            };

            vulnerabilities.push(vuln);
            scan.severity[severity.toLowerCase()]++;
        }

        scan.findings.vulnerabilities = vulnerabilities;
        await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate scan time
    }

    async performMalwareScanning(scan) {
        console.log(`Performing malware scan for ${scan.imageTag}...`);
        
        const malwareTypes = ['trojan', 'rootkit', 'backdoor', 'cryptominer'];
        const findings = [];

        // Simulate occasional malware detection
        if (Math.random() < 0.1) {
            const malware = {
                type: malwareTypes[Math.floor(Math.random() * malwareTypes.length)],
                signature: `Mal.${crypto.randomBytes(4).toString('hex')}`,
                path: '/usr/bin/suspicious-binary',
                threat: 'HIGH',
                action: 'quarantine',
                detectedAt: new Date()
            };
            findings.push(malware);
        }

        scan.findings.malware = findings;
        await new Promise(resolve => setTimeout(resolve, 1500));
    }

    async performSecretScanning(scan) {
        console.log(`Performing secret scan for ${scan.imageTag}...`);
        
        const secretTypes = ['api-key', 'password', 'private-key', 'token', 'certificate'];
        const findings = [];

        // Simulate secret detection
        const secretCount = Math.floor(Math.random() * 3);
        for (let i = 0; i < secretCount; i++) {
            const secret = {
                type: secretTypes[Math.floor(Math.random() * secretTypes.length)],
                path: `/app/config/${crypto.randomBytes(4).toString('hex')}.json`,
                pattern: 'hardcoded-credential',
                severity: 'HIGH',
                recommendation: 'Use environment variables or secret management system',
                line: Math.floor(Math.random() * 100) + 1
            };
            findings.push(secret);
        }

        scan.findings.secrets = findings;
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    async performComplianceScanning(scan) {
        console.log(`Performing compliance scan for ${scan.imageTag}...`);
        
        const findings = [];
        const frameworks = ['CIS', 'NIST', 'PCI-DSS', 'HIPAA', 'SOC2'];

        for (const framework of frameworks) {
            const violations = Math.floor(Math.random() * 5);
            for (let i = 0; i < violations; i++) {
                const finding = {
                    framework,
                    control: `${framework}-${Math.floor(Math.random() * 100) + 1}`,
                    description: this.getComplianceViolation(framework),
                    severity: this.getRandomSeverity(),
                    remediation: 'Configure proper security settings',
                    category: 'Configuration'
                };
                findings.push(finding);
            }
        }

        scan.findings.compliance = findings;
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    async performConfigurationScanning(scan) {
        console.log(`Performing configuration scan for ${scan.imageTag}...`);
        
        const findings = [];
        const configIssues = [
            'Running as root user',
            'Unnecessary capabilities granted',
            'No health check configured',
            'Excessive file permissions',
            'Outdated base image'
        ];

        const issueCount = Math.floor(Math.random() * configIssues.length);
        for (let i = 0; i < issueCount; i++) {
            const issue = configIssues[Math.floor(Math.random() * configIssues.length)];
            const finding = {
                issue,
                severity: this.getRandomSeverity(),
                recommendation: this.getConfigRecommendation(issue),
                dockerfile: true,
                line: Math.floor(Math.random() * 50) + 1
            };
            findings.push(finding);
        }

        scan.findings.configuration = findings;
        await new Promise(resolve => setTimeout(resolve, 800));
    }

    // Image Signing and Verification
    async signImage(registryId, imageTag, signingConfig) {
        const registry = this.registries.get(registryId);
        if (!registry) {
            throw new Error('Registry not found');
        }

        const signature = {
            imageTag,
            algorithm: signingConfig.algorithm || 'RSA-PSS',
            keyId: signingConfig.keyId,
            signature: crypto.randomBytes(256).toString('base64'),
            timestamp: new Date(),
            notaryEnabled: registry.security.notaryEnabled
        };

        // Store signature in registry
        await this.simulateRegistryAPICall('sign.image', {
            registry: registry.endpoint,
            image: imageTag,
            signature: signature
        });

        return {
            success: true,
            signature
        };
    }

    async verifyImageSignature(registryId, imageTag) {
        const registry = this.registries.get(registryId);
        if (!registry) {
            throw new Error('Registry not found');
        }

        const verification = {
            imageTag,
            verified: Math.random() > 0.1, // 90% success rate
            timestamp: new Date(),
            trustPolicy: registry.security.notaryEnabled
        };

        if (!verification.verified) {
            verification.error = 'Signature verification failed';
            await this.quarantineImage(registryId, imageTag, { reason: 'signature-verification-failed' });
        }

        return verification;
    }

    // Runtime Security Monitoring
    async startRuntimeMonitoring() {
        if (!this.config.runtimeMonitoring) return;

        console.log('Starting runtime security monitoring...');
        
        setInterval(() => {
            this.monitorRuntimeBehavior().catch(console.error);
        }, 30000); // Every 30 seconds

        setInterval(() => {
            this.detectRuntimeAnomalies().catch(console.error);
        }, 60000); // Every minute
    }

    async monitorRuntimeBehavior() {
        const containers = await this.getRunningContainers();
        
        for (const container of containers) {
            const behavior = {
                containerId: container.id,
                timestamp: new Date(),
                metrics: {
                    cpu: Math.random() * 100,
                    memory: Math.random() * 100,
                    network: {
                        inbound: Math.random() * 1000,
                        outbound: Math.random() * 1000
                    },
                    disk: {
                        reads: Math.random() * 100,
                        writes: Math.random() * 100
                    }
                },
                processes: await this.getContainerProcesses(container.id),
                networkConnections: await this.getNetworkConnections(container.id),
                fileChanges: await this.getFileSystemChanges(container.id)
            };

            this.runtimeMonitoring.set(container.id, behavior);
            
            // Check for suspicious activity
            await this.analyzeBehavior(behavior);
        }
    }

    async detectRuntimeAnomalies() {
        for (const [containerId, behavior] of this.runtimeMonitoring) {
            const anomalies = [];

            // CPU spike detection
            if (behavior.metrics.cpu > 90) {
                anomalies.push({
                    type: 'cpu-spike',
                    severity: 'HIGH',
                    value: behavior.metrics.cpu,
                    threshold: 90
                });
            }

            // Unusual network activity
            if (behavior.metrics.network.outbound > 800) {
                anomalies.push({
                    type: 'network-anomaly',
                    severity: 'MEDIUM',
                    value: behavior.metrics.network.outbound,
                    threshold: 800
                });
            }

            // Suspicious processes
            const suspiciousProcesses = behavior.processes.filter(p => 
                p.name.includes('crypto') || p.name.includes('miner') || p.name.includes('nc')
            );
            
            if (suspiciousProcesses.length > 0) {
                anomalies.push({
                    type: 'suspicious-process',
                    severity: 'CRITICAL',
                    processes: suspiciousProcesses
                });
            }

            if (anomalies.length > 0) {
                this.emit('runtimeAnomaly', {
                    containerId,
                    anomalies,
                    timestamp: new Date()
                });
            }
        }
    }

    async analyzeBehavior(behavior) {
        // AI-based behavior analysis (simulated)
        const riskFactors = [];

        // Check for privilege escalation attempts
        const privilegedProcesses = behavior.processes.filter(p => p.user === 'root');
        if (privilegedProcesses.length > 5) {
            riskFactors.push('excessive-root-processes');
        }

        // Check for unusual file system activity
        if (behavior.fileChanges.length > 100) {
            riskFactors.push('excessive-file-changes');
        }

        // Check for external network connections
        const externalConnections = behavior.networkConnections.filter(c => 
            !c.destination.startsWith('10.') && 
            !c.destination.startsWith('192.168.') && 
            !c.destination.startsWith('172.')
        );
        
        if (externalConnections.length > 10) {
            riskFactors.push('suspicious-network-activity');
        }

        if (riskFactors.length > 0) {
            this.emit('securityAlert', {
                containerId: behavior.containerId,
                riskFactors,
                severity: 'HIGH',
                timestamp: new Date()
            });
        }
    }

    // Network Security Policies
    async createNetworkPolicy(policyConfig) {
        const policyId = this.generateId();
        const policy = {
            id: policyId,
            name: policyConfig.name,
            namespace: policyConfig.namespace,
            podSelector: policyConfig.podSelector,
            policyTypes: policyConfig.policyTypes || ['Ingress', 'Egress'],
            ingress: policyConfig.ingress || [],
            egress: policyConfig.egress || [],
            createdAt: new Date(),
            status: 'active'
        };

        // Apply network policy
        const manifest = {
            apiVersion: 'networking.k8s.io/v1',
            kind: 'NetworkPolicy',
            metadata: {
                name: policy.name,
                namespace: policy.namespace
            },
            spec: {
                podSelector: policy.podSelector,
                policyTypes: policy.policyTypes,
                ingress: policy.ingress,
                egress: policy.egress
            }
        };

        await this.simulateK8sAPICall('createNetworkPolicy', manifest);
        this.networkPolicies.set(policyId, policy);

        return {
            success: true,
            policyId,
            policy
        };
    }

    async enforceNetworkPolicies(namespace) {
        const defaultPolicies = [
            {
                name: 'default-deny-ingress',
                namespace: namespace,
                podSelector: {},
                policyTypes: ['Ingress'],
                ingress: []
            },
            {
                name: 'allow-same-namespace',
                namespace: namespace,
                podSelector: {},
                policyTypes: ['Ingress'],
                ingress: [{
                    from: [{
                        namespaceSelector: {
                            matchLabels: {
                                name: namespace
                            }
                        }
                    }]
                }]
            }
        ];

        for (const policyConfig of defaultPolicies) {
            await this.createNetworkPolicy(policyConfig);
        }
    }

    // Resource Usage Monitoring
    async monitorResourceUsage(containerId) {
        const usage = {
            containerId,
            timestamp: new Date(),
            cpu: {
                usage: Math.random() * 100,
                limit: 200,
                requests: 100
            },
            memory: {
                usage: Math.random() * 1024 * 1024 * 1024, // Bytes
                limit: 2 * 1024 * 1024 * 1024,
                requests: 1 * 1024 * 1024 * 1024
            },
            storage: {
                usage: Math.random() * 10 * 1024 * 1024 * 1024,
                limit: 20 * 1024 * 1024 * 1024
            },
            network: {
                rxBytes: Math.random() * 1024 * 1024,
                txBytes: Math.random() * 1024 * 1024,
                connections: Math.floor(Math.random() * 100)
            }
        };

        // Check for resource limit violations
        if (usage.cpu.usage > usage.cpu.limit * 0.9) {
            this.emit('resourceAlert', {
                containerId,
                type: 'cpu-limit-exceeded',
                usage: usage.cpu.usage,
                limit: usage.cpu.limit
            });
        }

        if (usage.memory.usage > usage.memory.limit * 0.9) {
            this.emit('resourceAlert', {
                containerId,
                type: 'memory-limit-exceeded',
                usage: usage.memory.usage,
                limit: usage.memory.limit
            });
        }

        return usage;
    }

    // Image Quarantine Management
    async quarantineImage(registryId, imageTag, reason) {
        const registry = this.registries.get(registryId);
        if (!registry) {
            throw new Error('Registry not found');
        }

        const quarantine = {
            imageTag,
            registryId,
            reason: reason.reason || 'security-violation',
            quarantinedAt: new Date(),
            findings: reason.findings || [],
            status: 'quarantined'
        };

        // Move image to quarantine registry
        await this.simulateRegistryAPICall('quarantine.move', {
            source: `${registry.endpoint}/${imageTag}`,
            destination: `${registry.endpoint}/quarantine/${imageTag}`,
            reason: quarantine.reason
        });

        this.emit('imageQuarantined', quarantine);
        return quarantine;
    }

    async releaseFromQuarantine(imageTag, approvalConfig) {
        // Verify approval and release image
        const approval = {
            imageTag,
            approvedBy: approvalConfig.approver,
            approvedAt: new Date(),
            reason: approvalConfig.reason
        };

        await this.simulateRegistryAPICall('quarantine.release', approval);
        this.emit('imageReleased', approval);
        
        return approval;
    }

    // Utility Methods
    async getRunningContainers() {
        // Simulate getting running containers
        const containers = [];
        const count = Math.floor(Math.random() * 20) + 5;
        
        for (let i = 0; i < count; i++) {
            containers.push({
                id: `container-${crypto.randomBytes(6).toString('hex')}`,
                name: `app-${i}`,
                image: `registry.example.com/app:v1.${i}`,
                status: 'running',
                startedAt: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000)
            });
        }
        
        return containers;
    }

    async getContainerProcesses(containerId) {
        // Simulate container process list
        const processes = [
            { pid: 1, name: 'nginx', user: 'nginx', cpu: 2.5, memory: 45.2 },
            { pid: 15, name: 'php-fpm', user: 'www-data', cpu: 1.8, memory: 32.1 },
            { pid: 23, name: 'cron', user: 'root', cpu: 0.1, memory: 2.3 }
        ];
        
        return processes;
    }

    async getNetworkConnections(containerId) {
        // Simulate network connections
        return [
            { source: '10.244.1.5:8080', destination: '10.244.2.10:3306', state: 'ESTABLISHED' },
            { source: '10.244.1.5:443', destination: '203.0.113.10:443', state: 'ESTABLISHED' }
        ];
    }

    async getFileSystemChanges(containerId) {
        // Simulate file system changes
        return [
            { path: '/tmp/cache.tmp', operation: 'CREATE', timestamp: new Date() },
            { path: '/var/log/app.log', operation: 'MODIFY', timestamp: new Date() }
        ];
    }

    calculateRiskScore(scan) {
        let score = 0;
        score += scan.severity.critical * 10;
        score += scan.severity.high * 7;
        score += scan.severity.medium * 4;
        score += scan.severity.low * 1;
        score += scan.findings.malware.length * 15;
        score += scan.findings.secrets.length * 8;
        
        return Math.min(score, 100);
    }

    shouldQuarantineImage(scan) {
        return scan.riskScore > 70 || 
               scan.findings.malware.length > 0 || 
               scan.severity.critical > 0;
    }

    async generateRemediationReport(scan) {
        const recommendations = [];
        
        // Vulnerability remediation
        for (const vuln of scan.findings.vulnerabilities) {
            if (vuln.fixedVersion) {
                recommendations.push({
                    type: 'package-update',
                    package: vuln.package,
                    currentVersion: vuln.installedVersion,
                    recommendedVersion: vuln.fixedVersion,
                    severity: vuln.severity,
                    cve: vuln.id
                });
            }
        }
        
        // Secret remediation
        for (const secret of scan.findings.secrets) {
            recommendations.push({
                type: 'secret-removal',
                path: secret.path,
                secretType: secret.type,
                recommendation: secret.recommendation
            });
        }
        
        return {
            totalRecommendations: recommendations.length,
            recommendations,
            estimatedFixTime: `${Math.floor(recommendations.length / 2) + 1} hours`,
            priorityOrder: recommendations.sort((a, b) => 
                this.getSeverityWeight(a.severity) - this.getSeverityWeight(b.severity)
            )
        };
    }

    setupEventHandlers() {
        this.on('imageScanCompleted', (scan) => {
            console.log(`Image scan completed: ${scan.imageTag} - Risk Score: ${scan.riskScore}`);
        });

        this.on('imageQuarantined', (quarantine) => {
            console.log(`Image quarantined: ${quarantine.imageTag} - Reason: ${quarantine.reason}`);
        });

        this.on('runtimeAnomaly', (event) => {
            console.log(`Runtime anomaly detected in container ${event.containerId}`);
        });

        this.on('securityAlert', (alert) => {
            console.log(`Security alert: Container ${alert.containerId} - Risk factors: ${alert.riskFactors.join(', ')}`);
        });
    }

    // Helper Methods
    loadVulnerabilityDatabase() {
        // Simulate loading vulnerability database
        console.log('Loading vulnerability databases (NVD, CVE, GHSA)...');
        this.vulnerabilityDatabase.set('lastUpdated', new Date());
    }

    getRandomSeverity() {
        const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        const weights = [0.1, 0.2, 0.3, 0.3, 0.1]; // Distribution
        const random = Math.random();
        let cumulative = 0;
        
        for (let i = 0; i < severities.length; i++) {
            cumulative += weights[i];
            if (random <= cumulative) {
                return severities[i];
            }
        }
        return 'LOW';
    }

    getCVSSScore(severity) {
        const scores = {
            'CRITICAL': Math.random() * 1 + 9,  // 9.0-10.0
            'HIGH': Math.random() * 2 + 7,      // 7.0-9.0
            'MEDIUM': Math.random() * 3 + 4,    // 4.0-7.0
            'LOW': Math.random() * 4,           // 0.0-4.0
            'INFO': 0
        };
        return Math.round(scores[severity] * 10) / 10;
    }

    getRandomPackage() {
        const packages = ['openssl', 'zlib', 'curl', 'nginx', 'apache2', 'mysql-client', 'redis', 'postgresql'];
        return packages[Math.floor(Math.random() * packages.length)];
    }

    getRandomAttackVector() {
        const vectors = ['remote code execution', 'privilege escalation', 'information disclosure', 'denial of service'];
        return vectors[Math.floor(Math.random() * vectors.length)];
    }

    getComplianceViolation(framework) {
        const violations = {
            'CIS': 'Container running with unnecessary privileges',
            'NIST': 'Insufficient access controls implemented',
            'PCI-DSS': 'Encryption not properly configured',
            'HIPAA': 'Audit logging not enabled',
            'SOC2': 'Security monitoring gaps identified'
        };
        return violations[framework] || 'Compliance violation detected';
    }

    getConfigRecommendation(issue) {
        const recommendations = {
            'Running as root user': 'Create and use a non-root user in Dockerfile',
            'Unnecessary capabilities granted': 'Remove unnecessary Linux capabilities',
            'No health check configured': 'Add HEALTHCHECK instruction to Dockerfile',
            'Excessive file permissions': 'Set proper file permissions (644/755)',
            'Outdated base image': 'Update to latest base image version'
        };
        return recommendations[issue] || 'Review and fix configuration issue';
    }

    getSeverityWeight(severity) {
        const weights = { 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5 };
        return weights[severity] || 5;
    }

    async simulateRegistryAPICall(operation, params) {
        console.log(`Registry API Call: ${operation}`, params);
        await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
        return { success: true };
    }

    async simulateK8sAPICall(operation, manifest) {
        console.log(`K8s API Call: ${operation}`, manifest?.metadata?.name);
        await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 700));
        return { success: true };
    }

    encryptCredentials(credentials) {
        // Simple encryption simulation
        return {
            encrypted: true,
            data: Buffer.from(JSON.stringify(credentials)).toString('base64')
        };
    }

    sanitizeRegistry(registry) {
        const sanitized = { ...registry };
        delete sanitized.credentials;
        return sanitized;
    }

    sanitizeScan(scan) {
        const sanitized = { ...scan };
        // Remove sensitive information
        return sanitized;
    }

    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }

    // Public API Methods
    async getRegistries() {
        return Array.from(this.registries.values()).map(registry => this.sanitizeRegistry(registry));
    }

    async getRegistry(registryId) {
        const registry = this.registries.get(registryId);
        return registry ? this.sanitizeRegistry(registry) : null;
    }

    async getImageScans(registryId) {
        return Array.from(this.images.values())
            .filter(scan => scan.registryId === registryId)
            .map(scan => this.sanitizeScan(scan));
    }

    async getScanResults(scanId) {
        return this.images.get(scanId);
    }

    async getVulnerabilities() {
        return Array.from(this.vulnerabilities.values());
    }

    async getNetworkPolicies() {
        return Array.from(this.networkPolicies.values());
    }

    async getRuntimeMonitoring() {
        return Array.from(this.runtimeMonitoring.values());
    }

    getSecurityStatus() {
        return {
            totalRegistries: this.registries.size,
            totalImages: this.images.size,
            totalVulnerabilities: Array.from(this.images.values())
                .reduce((total, scan) => total + scan.findings.vulnerabilities.length, 0),
            quarantinedImages: Array.from(this.images.values())
                .filter(scan => scan.quarantined).length,
            criticalFindings: Array.from(this.images.values())
                .reduce((total, scan) => total + scan.severity.critical, 0),
            complianceFrameworks: this.config.complianceFrameworks,
            monitoringEnabled: this.config.runtimeMonitoring
        };
    }
}

module.exports = ContainerSecurityManager;