/**
 * Endpoint Detection & Response (EDR) Integration Service
 * Real-time threat detection and automated response capabilities
 */

const EventEmitter = require('events');
const crypto = require('crypto');

class EDRIntegration extends EventEmitter {
    constructor() {
        super();
        this.threats = new Map();
        this.policies = new Map();
        this.agents = new Map();
        this.quarantinedDevices = new Set();
        this.activeIncidents = new Map();
        
        // Threat detection engines
        this.behaviorAnalytics = new BehaviorAnalyticsEngine();
        this.signatureDetection = new SignatureDetectionEngine();
        this.anomalyDetection = new AnomalyDetectionEngine();
        this.mlThreatDetection = new MLThreatDetectionEngine();
        
        // Response orchestrator
        this.responseOrchestrator = new AutomatedResponseOrchestrator();
        
        this.initializeDefaultPolicies();
    }

    async initialize() {
        console.log('🛡️ Initializing EDR Integration...');
        
        // Initialize detection engines
        await this.behaviorAnalytics.initialize();
        await this.signatureDetection.initialize();
        await this.anomalyDetection.initialize();
        await this.mlThreatDetection.initialize();
        
        // Initialize response orchestrator
        await this.responseOrchestrator.initialize();
        
        console.log('✅ EDR Integration initialized');
    }

    /**
     * Start threat monitoring for all endpoints
     */
    startThreatMonitoring() {
        // Real-time threat monitoring
        setInterval(async () => {
            await this.performThreatScan();
        }, 30000); // Every 30 seconds
        
        // Behavioral analysis
        setInterval(async () => {
            await this.performBehavioralAnalysis();
        }, 60000); // Every minute
        
        // Anomaly detection
        setInterval(async () => {
            await this.performAnomalyDetection();
        }, 120000); // Every 2 minutes
        
        console.log('🔄 EDR threat monitoring started');
    }

    /**
     * Register EDR agent
     */
    async registerAgent(agentInfo) {
        const agentId = crypto.randomUUID();
        const agent = {
            id: agentId,
            deviceId: agentInfo.deviceId,
            platform: agentInfo.platform,
            version: agentInfo.version,
            capabilities: agentInfo.capabilities || [],
            status: 'ACTIVE',
            lastHeartbeat: new Date(),
            registeredAt: new Date(),
            telemetryConfig: this.getDefaultTelemetryConfig(agentInfo.platform)
        };
        
        this.agents.set(agentId, agent);
        
        this.emit('agentRegistered', {
            agentId,
            deviceId: agentInfo.deviceId,
            platform: agentInfo.platform
        });
        
        return {
            agentId,
            telemetryConfig: agent.telemetryConfig,
            policies: this.getApplicablePolicies(agentInfo.platform)
        };
    }

    /**
     * Process telemetry data from agents
     */
    async processTelemetry(agentId, telemetryData) {
        const agent = this.agents.get(agentId);
        if (!agent) {
            throw new Error('Agent not registered');
        }
        
        // Update agent heartbeat
        agent.lastHeartbeat = new Date();
        
        const analysisResults = [];
        
        // Analyze telemetry with different engines
        try {
            // Signature-based detection
            const signatureResults = await this.signatureDetection.analyze(telemetryData, agent);
            analysisResults.push(...signatureResults);
            
            // Behavioral analysis
            const behaviorResults = await this.behaviorAnalytics.analyze(telemetryData, agent);
            analysisResults.push(...behaviorResults);
            
            // Anomaly detection
            const anomalyResults = await this.anomalyDetection.analyze(telemetryData, agent);
            analysisResults.push(...anomalyResults);
            
            // Machine learning detection
            const mlResults = await this.mlThreatDetection.analyze(telemetryData, agent);
            analysisResults.push(...mlResults);
            
            // Process detected threats
            for (const result of analysisResults) {
                if (result.threatDetected) {
                    await this.handleThreatDetection(agent, result);
                }
            }
            
        } catch (error) {
            console.error('Error processing telemetry:', error);
            this.emit('telemetryProcessingError', {
                agentId,
                error: error.message
            });
        }
        
        return {
            processed: true,
            threatsDetected: analysisResults.filter(r => r.threatDetected).length,
            timestamp: new Date()
        };
    }

    /**
     * Handle threat detection
     */
    async handleThreatDetection(agent, threatResult) {
        const threatId = crypto.randomUUID();
        const threat = {
            id: threatId,
            agentId: agent.id,
            deviceId: agent.deviceId,
            type: threatResult.threatType,
            severity: threatResult.severity,
            confidence: threatResult.confidence,
            description: threatResult.description,
            indicators: threatResult.indicators,
            detectedAt: new Date(),
            status: 'DETECTED',
            containmentStatus: 'NONE'
        };
        
        this.threats.set(threatId, threat);
        
        this.emit('threatDetected', {
            threatId,
            deviceId: agent.deviceId,
            threatType: threat.type,
            severity: threat.severity
        });
        
        // Determine response based on severity and policy
        const responsePolicy = this.getResponsePolicy(threat.type, threat.severity);
        if (responsePolicy) {
            await this.executeAutomatedResponse(threat, responsePolicy);
        }
        
        // Create incident if severity is high
        if (threat.severity >= 7) {
            await this.createSecurityIncident(threat);
        }
        
        return threat;
    }

    /**
     * Execute automated response to threat
     */
    async executeAutomatedResponse(threat, responsePolicy) {
        const responseId = crypto.randomUUID();
        
        try {
            const response = await this.responseOrchestrator.executeResponse(threat, responsePolicy);
            
            // Update threat status
            threat.containmentStatus = response.containmentAction;
            threat.responseId = responseId;
            threat.responseExecutedAt = new Date();
            
            this.emit('responseExecuted', {
                threatId: threat.id,
                responseId,
                actions: response.actions,
                success: response.success
            });
            
            return response;
            
        } catch (error) {
            console.error('Error executing automated response:', error);
            this.emit('responseExecutionFailed', {
                threatId: threat.id,
                responseId,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Quarantine device
     */
    async quarantineDevice(deviceId, reason, duration = 24) {
        if (this.quarantinedDevices.has(deviceId)) {
            throw new Error('Device is already quarantined');
        }
        
        const quarantineId = crypto.randomUUID();
        const quarantine = {
            id: quarantineId,
            deviceId,
            reason,
            startTime: new Date(),
            duration: duration * 60 * 60 * 1000, // Convert hours to ms
            status: 'ACTIVE'
        };
        
        this.quarantinedDevices.add(deviceId);
        
        // Notify conditional access engine
        this.emit('deviceQuarantined', {
            deviceId,
            quarantineId,
            reason,
            duration
        });
        
        // Schedule automatic release
        setTimeout(() => {
            this.releaseDeviceFromQuarantine(deviceId, 'Automatic release after duration');
        }, quarantine.duration);
        
        return quarantine;
    }

    /**
     * Release device from quarantine
     */
    async releaseDeviceFromQuarantine(deviceId, reason) {
        if (!this.quarantinedDevices.has(deviceId)) {
            throw new Error('Device is not quarantined');
        }
        
        this.quarantinedDevices.delete(deviceId);
        
        this.emit('deviceReleasedFromQuarantine', {
            deviceId,
            reason,
            releasedAt: new Date()
        });
        
        return {
            deviceId,
            status: 'RELEASED',
            releasedAt: new Date()
        };
    }

    /**
     * Create security incident
     */
    async createSecurityIncident(threat) {
        const incidentId = crypto.randomUUID();
        const incident = {
            id: incidentId,
            title: `${threat.type} detected on ${threat.deviceId}`,
            description: threat.description,
            severity: this.mapThreatSeverityToIncident(threat.severity),
            status: 'OPEN',
            createdAt: new Date(),
            threats: [threat.id],
            assignedTo: null,
            tags: ['edr', 'automated', threat.type.toLowerCase()]
        };
        
        this.activeIncidents.set(incidentId, incident);
        
        this.emit('securityIncidentCreated', {
            incidentId,
            severity: incident.severity,
            threatId: threat.id
        });
        
        return incident;
    }

    /**
     * Perform comprehensive threat scan
     */
    async performThreatScan() {
        const scanId = crypto.randomUUID();
        const scanResults = [];
        
        for (const [agentId, agent] of this.agents) {
            if (agent.status !== 'ACTIVE') continue;
            
            try {
                // Request immediate scan from agent
                const scanResult = await this.requestAgentScan(agent);
                scanResults.push(scanResult);
                
            } catch (error) {
                console.error(`Error scanning agent ${agentId}:`, error);
            }
        }
        
        this.emit('threatScanCompleted', {
            scanId,
            scannedAgents: scanResults.length,
            threatsFound: scanResults.reduce((total, result) => total + result.threatsFound, 0)
        });
        
        return scanResults;
    }

    /**
     * Perform behavioral analysis across all endpoints
     */
    async performBehavioralAnalysis() {
        const analysisId = crypto.randomUUID();
        const patterns = [];
        
        // Analyze patterns across all agents
        const agentBehaviors = Array.from(this.agents.values()).map(agent => ({
            agentId: agent.id,
            deviceId: agent.deviceId,
            recentActivity: agent.recentActivity || []
        }));
        
        const suspiciousPatterns = await this.behaviorAnalytics.analyzeGlobalPatterns(agentBehaviors);
        
        for (const pattern of suspiciousPatterns) {
            this.emit('suspiciousPatternDetected', {
                analysisId,
                pattern,
                affectedDevices: pattern.affectedDevices
            });
        }
        
        return {
            analysisId,
            patternsDetected: suspiciousPatterns.length
        };
    }

    /**
     * Perform anomaly detection
     */
    async performAnomalyDetection() {
        const detectionId = crypto.randomUUID();
        const anomalies = [];
        
        for (const [agentId, agent] of this.agents) {
            if (agent.status !== 'ACTIVE') continue;
            
            const agentAnomalies = await this.anomalyDetection.detectAnomalies(agent);
            anomalies.push(...agentAnomalies);
        }
        
        this.emit('anomaliesDetected', {
            detectionId,
            anomaliesFound: anomalies.length,
            anomalies
        });
        
        return {
            detectionId,
            anomalies
        };
    }

    /**
     * Initialize default EDR policies
     */
    initializeDefaultPolicies() {
        // Malware detection policy
        this.policies.set('malware-detection', {
            id: 'malware-detection',
            name: 'Malware Detection Policy',
            description: 'Detect and respond to malware threats',
            enabled: true,
            threatTypes: ['malware', 'virus', 'trojan', 'ransomware'],
            severityThreshold: 5,
            autoResponse: true,
            responseActions: [
                {
                    action: 'quarantine_file',
                    condition: 'severity >= 7'
                },
                {
                    action: 'isolate_device',
                    condition: 'severity >= 9'
                }
            ]
        });
        
        // Suspicious behavior policy
        this.policies.set('suspicious-behavior', {
            id: 'suspicious-behavior',
            name: 'Suspicious Behavior Detection',
            description: 'Detect suspicious user and system behavior',
            enabled: true,
            threatTypes: ['suspicious_behavior', 'privilege_escalation', 'lateral_movement'],
            severityThreshold: 6,
            autoResponse: true,
            responseActions: [
                {
                    action: 'require_mfa',
                    condition: 'severity >= 6'
                },
                {
                    action: 'quarantine_device',
                    condition: 'severity >= 8'
                }
            ]
        });
        
        // Data exfiltration policy
        this.policies.set('data-exfiltration', {
            id: 'data-exfiltration',
            name: 'Data Exfiltration Prevention',
            description: 'Detect and prevent data exfiltration attempts',
            enabled: true,
            threatTypes: ['data_exfiltration', 'unauthorized_transfer'],
            severityThreshold: 7,
            autoResponse: true,
            responseActions: [
                {
                    action: 'block_network',
                    condition: 'severity >= 7'
                },
                {
                    action: 'isolate_device',
                    condition: 'severity >= 8'
                }
            ]
        });
        
        console.log(`✅ Initialized ${this.policies.size} EDR policies`);
    }

    /**
     * Helper methods
     */
    getDefaultTelemetryConfig(platform) {
        return {
            processMonitoring: true,
            fileSystemMonitoring: true,
            networkMonitoring: true,
            registryMonitoring: platform === 'windows',
            kernelMonitoring: platform === 'linux',
            reportingInterval: 30000, // 30 seconds
            detailedLogging: false
        };
    }

    getApplicablePolicies(platform) {
        const policies = [];
        for (const [policyId, policy] of this.policies) {
            if (policy.enabled) {
                policies.push({
                    id: policy.id,
                    name: policy.name,
                    severityThreshold: policy.severityThreshold
                });
            }
        }
        return policies;
    }

    getResponsePolicy(threatType, severity) {
        for (const [policyId, policy] of this.policies) {
            if (policy.enabled && 
                policy.threatTypes.includes(threatType) && 
                severity >= policy.severityThreshold) {
                return policy;
            }
        }
        return null;
    }

    mapThreatSeverityToIncident(threatSeverity) {
        if (threatSeverity >= 9) return 'CRITICAL';
        if (threatSeverity >= 7) return 'HIGH';
        if (threatSeverity >= 5) return 'MEDIUM';
        return 'LOW';
    }

    async requestAgentScan(agent) {
        // Simulate agent scan request
        return {
            agentId: agent.id,
            deviceId: agent.deviceId,
            threatsFound: Math.floor(Math.random() * 3), // Simulate random threats
            scanDuration: Math.random() * 30000 + 10000 // 10-40 seconds
        };
    }

    /**
     * Get threat status
     */
    getThreat(threatId) {
        return this.threats.get(threatId);
    }

    /**
     * Get device threats
     */
    getDeviceThreats(deviceId) {
        const threats = [];
        for (const [threatId, threat] of this.threats) {
            if (threat.deviceId === deviceId) {
                threats.push(threat);
            }
        }
        return threats;
    }

    /**
     * Check if device is quarantined
     */
    isDeviceQuarantined(deviceId) {
        return this.quarantinedDevices.has(deviceId);
    }

    /**
     * Get active incidents
     */
    getActiveIncidents() {
        return Array.from(this.activeIncidents.values());
    }

    /**
     * Shutdown the integration
     */
    async shutdown() {
        console.log('🛡️ Shutting down EDR Integration...');
        this.removeAllListeners();
        this.threats.clear();
        this.agents.clear();
        this.quarantinedDevices.clear();
        this.activeIncidents.clear();
        console.log('✅ EDR Integration shutdown complete');
    }
}

/**
 * Behavior Analytics Engine
 */
class BehaviorAnalyticsEngine {
    async initialize() {
        console.log('📊 Behavior Analytics Engine initialized');
    }

    async analyze(telemetryData, agent) {
        const results = [];
        
        // Analyze process behavior
        if (telemetryData.processes) {
            for (const process of telemetryData.processes) {
                const suspiciousScore = this.analyzeProcessBehavior(process);
                if (suspiciousScore > 0.7) {
                    results.push({
                        threatDetected: true,
                        threatType: 'suspicious_behavior',
                        severity: Math.round(suspiciousScore * 10),
                        confidence: suspiciousScore,
                        description: `Suspicious process behavior detected: ${process.name}`,
                        indicators: [`process:${process.name}`, `pid:${process.pid}`]
                    });
                }
            }
        }
        
        return results;
    }

    analyzeProcessBehavior(process) {
        let suspiciousScore = 0;
        
        // Check for suspicious process characteristics
        if (process.name && process.name.match(/[a-f0-9]{8,}/i)) {
            suspiciousScore += 0.3; // Random hex name
        }
        
        if (process.path && process.path.includes('temp')) {
            suspiciousScore += 0.2; // Running from temp directory
        }
        
        if (process.parentProcess === 'explorer.exe' && process.name.endsWith('.exe')) {
            suspiciousScore += 0.1; // Direct execution from explorer
        }
        
        return Math.min(1.0, suspiciousScore);
    }

    async analyzeGlobalPatterns(agentBehaviors) {
        // Simulate global pattern analysis
        const patterns = [];
        
        // Check for coordinated activities across devices
        const processNames = new Map();
        for (const agent of agentBehaviors) {
            for (const activity of agent.recentActivity) {
                if (activity.type === 'process_start') {
                    const count = processNames.get(activity.processName) || 0;
                    processNames.set(activity.processName, count + 1);
                }
            }
        }
        
        // Detect processes running on multiple devices simultaneously
        for (const [processName, count] of processNames) {
            if (count > agentBehaviors.length * 0.3) { // More than 30% of devices
                patterns.push({
                    type: 'coordinated_execution',
                    description: `Process ${processName} detected on ${count} devices`,
                    affectedDevices: agentBehaviors.length,
                    severity: 6
                });
            }
        }
        
        return patterns;
    }
}

/**
 * Signature Detection Engine
 */
class SignatureDetectionEngine {
    constructor() {
        this.signatures = new Map();
        this.loadDefaultSignatures();
    }

    async initialize() {
        console.log('🔍 Signature Detection Engine initialized');
    }

    async analyze(telemetryData, agent) {
        const results = [];
        
        for (const [signatureId, signature] of this.signatures) {
            const match = this.matchSignature(telemetryData, signature);
            if (match) {
                results.push({
                    threatDetected: true,
                    threatType: signature.threatType,
                    severity: signature.severity,
                    confidence: 0.95,
                    description: signature.description,
                    indicators: match.indicators,
                    signatureId
                });
            }
        }
        
        return results;
    }

    loadDefaultSignatures() {
        // Malware signatures
        this.signatures.set('wannacry-ransomware', {
            id: 'wannacry-ransomware',
            name: 'WannaCry Ransomware',
            threatType: 'ransomware',
            severity: 10,
            description: 'WannaCry ransomware detected',
            patterns: {
                fileExtensions: ['.wncry', '.wcry'],
                processNames: ['wannacry.exe', 'wcry.exe'],
                registryKeys: ['HKLM\\SOFTWARE\\WanaCrypt0r']
            }
        });
        
        this.signatures.set('mimikatz', {
            id: 'mimikatz',
            name: 'Mimikatz Credential Dumper',
            threatType: 'credential_theft',
            severity: 9,
            description: 'Mimikatz credential dumping tool detected',
            patterns: {
                processNames: ['mimikatz.exe'],
                memoryStrings: ['sekurlsa::logonpasswords', 'privilege::debug']
            }
        });
        
        console.log(`✅ Loaded ${this.signatures.size} threat signatures`);
    }

    matchSignature(telemetryData, signature) {
        const indicators = [];
        
        // Check process names
        if (signature.patterns.processNames && telemetryData.processes) {
            for (const process of telemetryData.processes) {
                if (signature.patterns.processNames.includes(process.name)) {
                    indicators.push(`process:${process.name}`);
                }
            }
        }
        
        // Check file extensions
        if (signature.patterns.fileExtensions && telemetryData.files) {
            for (const file of telemetryData.files) {
                for (const ext of signature.patterns.fileExtensions) {
                    if (file.path && file.path.endsWith(ext)) {
                        indicators.push(`file:${file.path}`);
                    }
                }
            }
        }
        
        return indicators.length > 0 ? { indicators } : null;
    }
}

/**
 * Anomaly Detection Engine
 */
class AnomalyDetectionEngine {
    async initialize() {
        console.log('📈 Anomaly Detection Engine initialized');
    }

    async analyze(telemetryData, agent) {
        const results = [];
        
        // Detect unusual resource usage
        if (telemetryData.systemMetrics) {
            const anomalies = this.detectResourceAnomalies(telemetryData.systemMetrics);
            results.push(...anomalies);
        }
        
        // Detect unusual network activity
        if (telemetryData.networkConnections) {
            const networkAnomalies = this.detectNetworkAnomalies(telemetryData.networkConnections);
            results.push(...networkAnomalies);
        }
        
        return results;
    }

    async detectAnomalies(agent) {
        // Simulate anomaly detection for agent
        const anomalies = [];
        
        // Random anomaly generation for demonstration
        if (Math.random() < 0.1) { // 10% chance
            anomalies.push({
                type: 'unusual_cpu_usage',
                severity: 6,
                description: 'Unusual CPU usage pattern detected',
                deviceId: agent.deviceId
            });
        }
        
        return anomalies;
    }

    detectResourceAnomalies(metrics) {
        const results = [];
        
        // Detect high CPU usage
        if (metrics.cpuUsage > 90) {
            results.push({
                threatDetected: true,
                threatType: 'resource_abuse',
                severity: 6,
                confidence: 0.8,
                description: 'Abnormally high CPU usage detected',
                indicators: [`cpu_usage:${metrics.cpuUsage}%`]
            });
        }
        
        // Detect unusual memory patterns
        if (metrics.memoryUsage > 95) {
            results.push({
                threatDetected: true,
                threatType: 'resource_abuse',
                severity: 5,
                confidence: 0.7,
                description: 'Abnormally high memory usage detected',
                indicators: [`memory_usage:${metrics.memoryUsage}%`]
            });
        }
        
        return results;
    }

    detectNetworkAnomalies(connections) {
        const results = [];
        
        // Detect connections to suspicious domains
        const suspiciousDomains = ['malware.com', 'evil.org', 'badactor.net'];
        
        for (const connection of connections) {
            if (suspiciousDomains.some(domain => connection.destination?.includes(domain))) {
                results.push({
                    threatDetected: true,
                    threatType: 'malicious_communication',
                    severity: 8,
                    confidence: 0.9,
                    description: 'Connection to known malicious domain detected',
                    indicators: [`destination:${connection.destination}`]
                });
            }
        }
        
        return results;
    }
}

/**
 * ML Threat Detection Engine
 */
class MLThreatDetectionEngine {
    async initialize() {
        console.log('🤖 ML Threat Detection Engine initialized');
    }

    async analyze(telemetryData, agent) {
        const results = [];
        
        // Simulate ML-based threat detection
        const mlScore = this.calculateMLThreatScore(telemetryData);
        
        if (mlScore > 0.8) {
            results.push({
                threatDetected: true,
                threatType: 'ml_detected_threat',
                severity: Math.round(mlScore * 10),
                confidence: mlScore,
                description: 'Machine learning model detected potential threat',
                indicators: ['ml_model_prediction']
            });
        }
        
        return results;
    }

    calculateMLThreatScore(telemetryData) {
        // Simulate ML threat scoring
        let score = 0;
        
        // Factor in various telemetry aspects
        if (telemetryData.processes?.length > 50) score += 0.2;
        if (telemetryData.networkConnections?.length > 100) score += 0.3;
        if (telemetryData.fileChanges?.length > 200) score += 0.2;
        
        // Add some randomness to simulate ML uncertainty
        score += (Math.random() - 0.5) * 0.4;
        
        return Math.max(0, Math.min(1, score));
    }
}

/**
 * Automated Response Orchestrator
 */
class AutomatedResponseOrchestrator {
    async initialize() {
        console.log('🤖 Automated Response Orchestrator initialized');
    }

    async executeResponse(threat, policy) {
        const actions = [];
        
        for (const responseAction of policy.responseActions) {
            if (this.evaluateCondition(responseAction.condition, threat)) {
                const result = await this.executeAction(responseAction.action, threat);
                actions.push({
                    action: responseAction.action,
                    result,
                    executedAt: new Date()
                });
            }
        }
        
        const containmentAction = this.determineContainmentAction(actions);
        
        return {
            success: actions.length > 0,
            actions,
            containmentAction
        };
    }

    evaluateCondition(condition, threat) {
        // Simple condition evaluation
        if (condition.includes('severity >= ')) {
            const threshold = parseInt(condition.split('severity >= ')[1]);
            return threat.severity >= threshold;
        }
        return true;
    }

    async executeAction(action, threat) {
        switch (action) {
            case 'quarantine_file':
                return this.quarantineFile(threat);
            case 'isolate_device':
                return this.isolateDevice(threat);
            case 'quarantine_device':
                return this.quarantineDevice(threat);
            case 'require_mfa':
                return this.requireMFA(threat);
            case 'block_network':
                return this.blockNetwork(threat);
            default:
                return { success: false, message: 'Unknown action' };
        }
    }

    async quarantineFile(threat) {
        // Simulate file quarantine
        return { 
            success: true, 
            message: 'File quarantined successfully',
            quarantinedFiles: threat.indicators.filter(i => i.startsWith('file:'))
        };
    }

    async isolateDevice(threat) {
        // Simulate device isolation
        return { 
            success: true, 
            message: 'Device isolated from network',
            deviceId: threat.deviceId
        };
    }

    async quarantineDevice(threat) {
        // Simulate device quarantine
        return { 
            success: true, 
            message: 'Device quarantined',
            deviceId: threat.deviceId
        };
    }

    async requireMFA(threat) {
        // Simulate MFA requirement
        return { 
            success: true, 
            message: 'Additional authentication required',
            deviceId: threat.deviceId
        };
    }

    async blockNetwork(threat) {
        // Simulate network blocking
        return { 
            success: true, 
            message: 'Network access blocked',
            deviceId: threat.deviceId
        };
    }

    determineContainmentAction(actions) {
        const actionTypes = actions.map(a => a.action);
        
        if (actionTypes.includes('isolate_device')) return 'ISOLATED';
        if (actionTypes.includes('quarantine_device')) return 'QUARANTINED';
        if (actionTypes.includes('quarantine_file')) return 'FILE_QUARANTINED';
        if (actionTypes.includes('block_network')) return 'NETWORK_BLOCKED';
        if (actionTypes.includes('require_mfa')) return 'MFA_REQUIRED';
        
        return 'NONE';
    }
}

module.exports = EDRIntegration;