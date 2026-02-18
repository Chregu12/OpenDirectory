/**
 * OpenDirectory Pattern Recognition System
 * 
 * Advanced pattern detection and analysis for identifying recurring issues,
 * user behavior patterns, security threats, and system anomalies.
 * 
 * Features:
 * - Recurring issue identification
 * - User activity pattern recognition
 * - Network traffic anomaly detection
 * - Application usage patterns
 * - Security breach pattern detection
 * - Performance degradation patterns
 * - Event correlation analysis
 * - Root cause analysis
 */

const fs = require('fs');
const crypto = require('crypto');

class PatternRecognitionEngine {
    constructor(config = {}) {
        this.config = {
            minPatternOccurrences: config.minPatternOccurrences || 3,
            patternWindow: config.patternWindow || 3600000, // 1 hour
            analysisInterval: config.analysisInterval || 300000, // 5 minutes
            maxPatternAge: config.maxPatternAge || 7 * 24 * 60 * 60 * 1000, // 1 week
            correlationThreshold: config.correlationThreshold || 0.7,
            ...config
        };

        this.patterns = new Map();
        this.events = [];
        this.userSessions = new Map();
        this.networkFlows = [];
        this.securityEvents = [];
        this.performanceMetrics = [];
        this.isRunning = false;
    }

    /**
     * Initialize the pattern recognition engine
     */
    async initialize() {
        console.log('Initializing Pattern Recognition Engine...');
        
        // Load existing patterns
        await this.loadPatterns();
        
        // Start pattern analysis
        this.startPatternAnalysis();
        
        console.log('Pattern Recognition Engine initialized successfully');
        return this;
    }

    /**
     * Load existing patterns from storage
     */
    async loadPatterns() {
        try {
            const patternsFile = '/tmp/patterns-database.json';
            if (fs.existsSync(patternsFile)) {
                const data = JSON.parse(fs.readFileSync(patternsFile, 'utf8'));
                
                if (data.patterns) {
                    Object.entries(data.patterns).forEach(([key, pattern]) => {
                        this.patterns.set(key, pattern);
                    });
                }
                
                console.log(`Loaded ${this.patterns.size} existing patterns`);
            }
        } catch (error) {
            console.warn('Could not load existing patterns:', error.message);
        }
    }

    /**
     * Start continuous pattern analysis
     */
    startPatternAnalysis() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.analysisLoop();
    }

    /**
     * Stop pattern analysis
     */
    stopPatternAnalysis() {
        this.isRunning = false;
    }

    /**
     * Main analysis loop
     */
    async analysisLoop() {
        while (this.isRunning) {
            try {
                await this.performPatternAnalysis();
                await this.sleep(this.config.analysisInterval);
            } catch (error) {
                console.error('Pattern analysis error:', error);
                await this.sleep(10000); // Wait 10 seconds on error
            }
        }
    }

    /**
     * Perform comprehensive pattern analysis
     */
    async performPatternAnalysis() {
        const timestamp = Date.now();
        
        // Collect new data
        await this.collectData();
        
        // Analyze different types of patterns
        const recurringIssues = this.detectRecurringIssues();
        const userPatterns = this.analyzeUserPatterns();
        const networkPatterns = this.analyzeNetworkPatterns();
        const securityPatterns = this.detectSecurityPatterns();
        const performancePatterns = this.analyzePerformancePatterns();
        const correlations = this.findEventCorrelations();
        
        // Update pattern database
        this.updatePatterns({
            recurring: recurringIssues,
            user: userPatterns,
            network: networkPatterns,
            security: securityPatterns,
            performance: performancePatterns,
            correlations: correlations
        });
        
        // Perform root cause analysis
        const rootCauses = this.performRootCauseAnalysis();
        
        // Store results
        await this.storePatterns(timestamp);
    }

    /**
     * Collect data from various sources
     */
    async collectData() {
        // Simulate data collection - in real implementation, this would
        // interface with actual system logs and monitoring APIs
        
        // Add system events
        this.addEvent({
            type: 'system',
            category: Math.random() > 0.5 ? 'error' : 'warning',
            message: this.generateSampleMessage(),
            timestamp: Date.now(),
            source: this.getRandomSource(),
            severity: this.getRandomSeverity()
        });
        
        // Add user activity
        this.addUserActivity({
            userId: `user_${Math.floor(Math.random() * 100)}`,
            action: this.getRandomUserAction(),
            resource: this.getRandomResource(),
            timestamp: Date.now(),
            success: Math.random() > 0.1,
            ip: this.generateRandomIP(),
            userAgent: 'Mozilla/5.0...'
        });
        
        // Add network data
        this.addNetworkFlow({
            sourceIP: this.generateRandomIP(),
            destIP: this.generateRandomIP(),
            port: Math.floor(Math.random() * 65536),
            protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
            bytes: Math.floor(Math.random() * 10000),
            timestamp: Date.now(),
            flags: ['SYN', 'ACK', 'FIN'][Math.floor(Math.random() * 3)]
        });
        
        // Add security events
        if (Math.random() < 0.1) { // 10% chance of security event
            this.addSecurityEvent({
                type: ['failed_login', 'suspicious_activity', 'malware_detected'][Math.floor(Math.random() * 3)],
                sourceIP: this.generateRandomIP(),
                targetResource: this.getRandomResource(),
                timestamp: Date.now(),
                severity: this.getRandomSeverity(),
                details: { attempts: Math.floor(Math.random() * 10) + 1 }
            });
        }
        
        // Add performance metrics
        this.addPerformanceMetric({
            metric: 'response_time',
            value: Math.random() * 5000,
            service: this.getRandomService(),
            timestamp: Date.now()
        });
    }

    /**
     * Add system event
     */
    addEvent(event) {
        this.events.push(event);
        
        // Keep only recent events
        const cutoff = Date.now() - this.config.maxPatternAge;
        this.events = this.events.filter(e => e.timestamp > cutoff);
    }

    /**
     * Add user activity
     */
    addUserActivity(activity) {
        const userId = activity.userId;
        
        if (!this.userSessions.has(userId)) {
            this.userSessions.set(userId, []);
        }
        
        this.userSessions.get(userId).push(activity);
        
        // Keep only recent activities per user
        this.userSessions.forEach((activities, user) => {
            const cutoff = Date.now() - this.config.maxPatternAge;
            this.userSessions.set(user, activities.filter(a => a.timestamp > cutoff));
        });
    }

    /**
     * Add network flow
     */
    addNetworkFlow(flow) {
        this.networkFlows.push(flow);
        
        // Keep only recent flows
        const cutoff = Date.now() - this.config.maxPatternAge;
        this.networkFlows = this.networkFlows.filter(f => f.timestamp > cutoff);
    }

    /**
     * Add security event
     */
    addSecurityEvent(event) {
        this.securityEvents.push(event);
        
        // Keep only recent security events
        const cutoff = Date.now() - this.config.maxPatternAge;
        this.securityEvents = this.securityEvents.filter(e => e.timestamp > cutoff);
    }

    /**
     * Add performance metric
     */
    addPerformanceMetric(metric) {
        this.performanceMetrics.push(metric);
        
        // Keep only recent metrics
        const cutoff = Date.now() - this.config.maxPatternAge;
        this.performanceMetrics = this.performanceMetrics.filter(m => m.timestamp > cutoff);
    }

    /**
     * Detect recurring issues
     */
    detectRecurringIssues() {
        const patterns = [];
        const issueGroups = new Map();
        
        // Group events by message similarity
        this.events.forEach(event => {
            const key = this.normalizeMessage(event.message);
            
            if (!issueGroups.has(key)) {
                issueGroups.set(key, []);
            }
            issueGroups.get(key).push(event);
        });
        
        // Find patterns in grouped issues
        issueGroups.forEach((events, messageKey) => {
            if (events.length >= this.config.minPatternOccurrences) {
                const pattern = this.analyzeIssuePattern(events, messageKey);
                if (pattern) {
                    patterns.push(pattern);
                }
            }
        });
        
        return patterns;
    }

    /**
     * Normalize error message for grouping
     */
    normalizeMessage(message) {
        return message
            .toLowerCase()
            .replace(/\d+/g, 'N') // Replace numbers with N
            .replace(/\b\w{32,}\b/g, 'HASH') // Replace long strings (hashes/IDs)
            .replace(/\s+/g, ' ') // Normalize whitespace
            .trim();
    }

    /**
     * Analyze pattern in grouped issues
     */
    analyzeIssuePattern(events, messageKey) {
        // Calculate time intervals
        const sortedEvents = events.sort((a, b) => a.timestamp - b.timestamp);
        const intervals = [];
        
        for (let i = 1; i < sortedEvents.length; i++) {
            intervals.push(sortedEvents[i].timestamp - sortedEvents[i-1].timestamp);
        }
        
        if (intervals.length < 2) return null;
        
        // Statistical analysis of intervals
        const avgInterval = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
        const stdDev = Math.sqrt(intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length);
        const consistency = 1 - (stdDev / avgInterval);
        
        // Check for different pattern types
        let patternType = 'irregular';
        if (consistency > 0.7) {
            if (avgInterval < 60000) patternType = 'burst';
            else if (avgInterval < 3600000) patternType = 'periodic';
            else patternType = 'scheduled';
        }
        
        return {
            id: crypto.randomUUID(),
            type: 'recurring_issue',
            messagePattern: messageKey,
            occurrences: events.length,
            avgInterval: avgInterval,
            consistency: consistency,
            patternType: patternType,
            severity: this.calculatePatternSeverity(events),
            sources: [...new Set(events.map(e => e.source))],
            firstSeen: sortedEvents[0].timestamp,
            lastSeen: sortedEvents[sortedEvents.length - 1].timestamp,
            confidence: Math.min(consistency + (events.length / 10), 1)
        };
    }

    /**
     * Analyze user patterns
     */
    analyzeUserPatterns() {
        const patterns = [];
        
        this.userSessions.forEach((activities, userId) => {
            if (activities.length < 10) return;
            
            // Analyze login patterns
            const loginPattern = this.analyzeLoginPattern(activities);
            if (loginPattern) {
                patterns.push({
                    ...loginPattern,
                    userId: userId,
                    type: 'user_login_pattern'
                });
            }
            
            // Analyze activity patterns
            const activityPattern = this.analyzeActivityPattern(activities);
            if (activityPattern) {
                patterns.push({
                    ...activityPattern,
                    userId: userId,
                    type: 'user_activity_pattern'
                });
            }
            
            // Detect suspicious behavior
            const suspiciousPattern = this.detectSuspiciousBehavior(activities);
            if (suspiciousPattern) {
                patterns.push({
                    ...suspiciousPattern,
                    userId: userId,
                    type: 'suspicious_behavior'
                });
            }
        });
        
        return patterns;
    }

    /**
     * Analyze login patterns for a user
     */
    analyzeLoginPattern(activities) {
        const logins = activities.filter(a => a.action === 'login');
        if (logins.length < 5) return null;
        
        // Analyze time patterns
        const hours = logins.map(l => new Date(l.timestamp).getHours());
        const hourCounts = new Array(24).fill(0);
        hours.forEach(hour => hourCounts[hour]++);
        
        // Find peak hours
        const maxCount = Math.max(...hourCounts);
        const peakHours = hourCounts.map((count, hour) => ({ hour, count }))
            .filter(h => h.count === maxCount)
            .map(h => h.hour);
        
        // Calculate regularity
        const totalLogins = logins.length;
        const regularity = maxCount / totalLogins;
        
        return {
            id: crypto.randomUUID(),
            totalLogins: totalLogins,
            peakHours: peakHours,
            regularity: regularity,
            avgLoginsPerDay: totalLogins / 7,
            confidence: Math.min(regularity + 0.3, 1)
        };
    }

    /**
     * Analyze general activity patterns
     */
    analyzeActivityPattern(activities) {
        const actionCounts = new Map();
        const resourceCounts = new Map();
        
        activities.forEach(activity => {
            actionCounts.set(activity.action, (actionCounts.get(activity.action) || 0) + 1);
            resourceCounts.set(activity.resource, (resourceCounts.get(activity.resource) || 0) + 1);
        });
        
        // Find dominant patterns
        const topAction = Array.from(actionCounts.entries()).sort((a, b) => b[1] - a[1])[0];
        const topResource = Array.from(resourceCounts.entries()).sort((a, b) => b[1] - a[1])[0];
        
        return {
            id: crypto.randomUUID(),
            totalActivities: activities.length,
            topAction: topAction[0],
            topActionCount: topAction[1],
            topResource: topResource[0],
            topResourceCount: topResource[1],
            actionDiversity: actionCounts.size,
            resourceDiversity: resourceCounts.size,
            confidence: 0.8
        };
    }

    /**
     * Detect suspicious user behavior
     */
    detectSuspiciousBehavior(activities) {
        const recentActivities = activities.filter(a => a.timestamp > Date.now() - 24 * 60 * 60 * 1000);
        
        // Check for suspicious indicators
        const failureRate = recentActivities.filter(a => !a.success).length / recentActivities.length;
        const uniqueIPs = new Set(recentActivities.map(a => a.ip)).size;
        const offHoursActivity = recentActivities.filter(a => {
            const hour = new Date(a.timestamp).getHours();
            return hour < 6 || hour > 22;
        }).length;
        
        let suspicionScore = 0;
        const indicators = [];
        
        if (failureRate > 0.3) {
            suspicionScore += 0.4;
            indicators.push('high_failure_rate');
        }
        
        if (uniqueIPs > 3) {
            suspicionScore += 0.3;
            indicators.push('multiple_ips');
        }
        
        if (offHoursActivity / recentActivities.length > 0.5) {
            suspicionScore += 0.3;
            indicators.push('off_hours_activity');
        }
        
        if (suspicionScore > 0.6) {
            return {
                id: crypto.randomUUID(),
                suspicionScore: suspicionScore,
                indicators: indicators,
                failureRate: failureRate,
                uniqueIPs: uniqueIPs,
                offHoursActivities: offHoursActivity,
                confidence: suspicionScore
            };
        }
        
        return null;
    }

    /**
     * Analyze network patterns
     */
    analyzeNetworkPatterns() {
        const patterns = [];
        
        // Analyze traffic by IP
        const ipTraffic = new Map();
        this.networkFlows.forEach(flow => {
            const key = `${flow.sourceIP}-${flow.destIP}`;
            if (!ipTraffic.has(key)) {
                ipTraffic.set(key, []);
            }
            ipTraffic.get(key).push(flow);
        });
        
        // Detect unusual traffic patterns
        ipTraffic.forEach((flows, ipPair) => {
            if (flows.length < 10) return;
            
            const pattern = this.analyzeTrafficPattern(flows, ipPair);
            if (pattern) {
                patterns.push(pattern);
            }
        });
        
        // Port scan detection
        const portScans = this.detectPortScans();
        patterns.push(...portScans);
        
        return patterns;
    }

    /**
     * Analyze traffic pattern for IP pair
     */
    analyzeTrafficPattern(flows, ipPair) {
        const [sourceIP, destIP] = ipPair.split('-');
        const totalBytes = flows.reduce((sum, flow) => sum + flow.bytes, 0);
        const avgBytes = totalBytes / flows.length;
        const uniquePorts = new Set(flows.map(f => f.port)).size;
        
        // Calculate time distribution
        const sortedFlows = flows.sort((a, b) => a.timestamp - b.timestamp);
        const duration = sortedFlows[sortedFlows.length - 1].timestamp - sortedFlows[0].timestamp;
        const flowRate = flows.length / (duration / 1000); // flows per second
        
        // Detect anomalies
        let anomalyScore = 0;
        const anomalies = [];
        
        if (flowRate > 10) {
            anomalyScore += 0.3;
            anomalies.push('high_flow_rate');
        }
        
        if (avgBytes < 100) {
            anomalyScore += 0.2;
            anomalies.push('small_packets');
        }
        
        if (uniquePorts > 100) {
            anomalyScore += 0.4;
            anomalies.push('port_scanning');
        }
        
        return {
            id: crypto.randomUUID(),
            type: 'network_traffic_pattern',
            sourceIP: sourceIP,
            destIP: destIP,
            flowCount: flows.length,
            totalBytes: totalBytes,
            avgBytes: avgBytes,
            uniquePorts: uniquePorts,
            flowRate: flowRate,
            duration: duration,
            anomalyScore: anomalyScore,
            anomalies: anomalies,
            confidence: Math.min(anomalyScore + 0.3, 1)
        };
    }

    /**
     * Detect port scanning attempts
     */
    detectPortScans() {
        const scans = [];
        const scannerMap = new Map();
        
        // Group flows by source IP
        this.networkFlows.forEach(flow => {
            if (!scannerMap.has(flow.sourceIP)) {
                scannerMap.set(flow.sourceIP, new Map());
            }
            
            const destMap = scannerMap.get(flow.sourceIP);
            if (!destMap.has(flow.destIP)) {
                destMap.set(flow.destIP, new Set());
            }
            
            destMap.get(flow.destIP).add(flow.port);
        });
        
        // Analyze for scanning behavior
        scannerMap.forEach((destMap, sourceIP) => {
            destMap.forEach((ports, destIP) => {
                if (ports.size > 20) { // More than 20 different ports
                    scans.push({
                        id: crypto.randomUUID(),
                        type: 'port_scan',
                        sourceIP: sourceIP,
                        targetIP: destIP,
                        portsScanned: ports.size,
                        severity: ports.size > 100 ? 'high' : 'medium',
                        confidence: Math.min(ports.size / 50, 1)
                    });
                }
            });
        });
        
        return scans;
    }

    /**
     * Detect security patterns
     */
    detectSecurityPatterns() {
        const patterns = [];
        
        // Brute force detection
        const bruteForce = this.detectBruteForce();
        patterns.push(...bruteForce);
        
        // Lateral movement detection
        const lateralMovement = this.detectLateralMovement();
        patterns.push(...lateralMovement);
        
        // Data exfiltration patterns
        const dataExfiltration = this.detectDataExfiltration();
        patterns.push(...dataExfiltration);
        
        return patterns;
    }

    /**
     * Detect brute force attacks
     */
    detectBruteForce() {
        const patterns = [];
        const failuresByIP = new Map();
        
        // Group failed login attempts by IP
        this.securityEvents
            .filter(event => event.type === 'failed_login')
            .forEach(event => {
                if (!failuresByIP.has(event.sourceIP)) {
                    failuresByIP.set(event.sourceIP, []);
                }
                failuresByIP.get(event.sourceIP).push(event);
            });
        
        // Analyze for brute force patterns
        failuresByIP.forEach((failures, sourceIP) => {
            if (failures.length < 5) return;
            
            const timeWindow = 15 * 60 * 1000; // 15 minutes
            const recentFailures = failures.filter(f => f.timestamp > Date.now() - timeWindow);
            
            if (recentFailures.length >= 5) {
                patterns.push({
                    id: crypto.randomUUID(),
                    type: 'brute_force',
                    sourceIP: sourceIP,
                    attempts: recentFailures.length,
                    timeWindow: timeWindow,
                    severity: recentFailures.length > 20 ? 'critical' : 'high',
                    targets: [...new Set(recentFailures.map(f => f.targetResource))],
                    confidence: Math.min(recentFailures.length / 10, 1)
                });
            }
        });
        
        return patterns;
    }

    /**
     * Detect lateral movement
     */
    detectLateralMovement() {
        const patterns = [];
        // Simplified lateral movement detection
        // In real implementation, this would analyze network flows and user activities
        
        const suspiciousIPs = new Set();
        
        // Look for IPs that access multiple resources in short time
        const recentFlows = this.networkFlows.filter(f => f.timestamp > Date.now() - 60 * 60 * 1000);
        const ipResourceMap = new Map();
        
        recentFlows.forEach(flow => {
            if (!ipResourceMap.has(flow.sourceIP)) {
                ipResourceMap.set(flow.sourceIP, new Set());
            }
            ipResourceMap.get(flow.sourceIP).add(flow.destIP);
        });
        
        ipResourceMap.forEach((resources, sourceIP) => {
            if (resources.size > 10) { // Accessed more than 10 different resources
                patterns.push({
                    id: crypto.randomUUID(),
                    type: 'lateral_movement',
                    sourceIP: sourceIP,
                    resourcesAccessed: resources.size,
                    severity: 'high',
                    confidence: Math.min(resources.size / 20, 1)
                });
            }
        });
        
        return patterns;
    }

    /**
     * Detect data exfiltration patterns
     */
    detectDataExfiltration() {
        const patterns = [];
        
        // Look for unusual outbound traffic volumes
        const outboundTraffic = new Map();
        
        this.networkFlows
            .filter(flow => this.isInternalIP(flow.sourceIP) && !this.isInternalIP(flow.destIP))
            .forEach(flow => {
                const key = `${flow.sourceIP}-${flow.destIP}`;
                if (!outboundTraffic.has(key)) {
                    outboundTraffic.set(key, { flows: [], totalBytes: 0 });
                }
                
                const traffic = outboundTraffic.get(key);
                traffic.flows.push(flow);
                traffic.totalBytes += flow.bytes;
            });
        
        outboundTraffic.forEach((traffic, key) => {
            const [sourceIP, destIP] = key.split('-');
            
            // Check for large data transfers
            if (traffic.totalBytes > 10000000) { // More than 10MB
                patterns.push({
                    id: crypto.randomUUID(),
                    type: 'data_exfiltration',
                    sourceIP: sourceIP,
                    destIP: destIP,
                    totalBytes: traffic.totalBytes,
                    flowCount: traffic.flows.length,
                    severity: traffic.totalBytes > 100000000 ? 'critical' : 'high',
                    confidence: Math.min(traffic.totalBytes / 50000000, 1)
                });
            }
        });
        
        return patterns;
    }

    /**
     * Check if IP is internal
     */
    isInternalIP(ip) {
        return ip.startsWith('192.168.') || 
               ip.startsWith('10.') || 
               ip.startsWith('172.16.') ||
               ip === '127.0.0.1';
    }

    /**
     * Analyze performance patterns
     */
    analyzePerformancePatterns() {
        const patterns = [];
        
        // Group metrics by service
        const serviceMetrics = new Map();
        this.performanceMetrics.forEach(metric => {
            if (!serviceMetrics.has(metric.service)) {
                serviceMetrics.set(metric.service, []);
            }
            serviceMetrics.get(metric.service).push(metric);
        });
        
        // Analyze each service
        serviceMetrics.forEach((metrics, service) => {
            const pattern = this.analyzeServicePerformance(metrics, service);
            if (pattern) {
                patterns.push(pattern);
            }
        });
        
        return patterns;
    }

    /**
     * Analyze performance pattern for a service
     */
    analyzeServicePerformance(metrics, service) {
        if (metrics.length < 10) return null;
        
        const values = metrics.map(m => m.value);
        const timestamps = metrics.map(m => m.timestamp);
        
        // Calculate statistics
        const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
        const max = Math.max(...values);
        const min = Math.min(...values);
        const stdDev = Math.sqrt(values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length);
        
        // Detect degradation trend
        const recentValues = values.slice(-10);
        const recentAvg = recentValues.reduce((sum, val) => sum + val, 0) / recentValues.length;
        const degradation = (recentAvg - avg) / avg;
        
        // Calculate volatility
        const volatility = stdDev / avg;
        
        let severity = 'low';
        if (degradation > 0.5 || volatility > 1.0) severity = 'high';
        else if (degradation > 0.2 || volatility > 0.5) severity = 'medium';
        
        return {
            id: crypto.randomUUID(),
            type: 'performance_pattern',
            service: service,
            avgValue: avg,
            maxValue: max,
            minValue: min,
            standardDeviation: stdDev,
            degradation: degradation,
            volatility: volatility,
            severity: severity,
            confidence: Math.min((metrics.length / 50) + 0.5, 1)
        };
    }

    /**
     * Find correlations between different events
     */
    findEventCorrelations() {
        const correlations = [];
        
        // Correlate security events with network patterns
        const securityCorrelations = this.correlateSecurityEvents();
        correlations.push(...securityCorrelations);
        
        // Correlate performance issues with system events
        const performanceCorrelations = this.correlatePerformanceEvents();
        correlations.push(...performanceCorrelations);
        
        return correlations;
    }

    /**
     * Correlate security events with network activity
     */
    correlateSecurityEvents() {
        const correlations = [];
        const timeWindow = 5 * 60 * 1000; // 5 minutes
        
        this.securityEvents.forEach(secEvent => {
            // Find related network flows
            const relatedFlows = this.networkFlows.filter(flow => 
                Math.abs(flow.timestamp - secEvent.timestamp) < timeWindow &&
                (flow.sourceIP === secEvent.sourceIP || flow.destIP === secEvent.sourceIP)
            );
            
            if (relatedFlows.length > 0) {
                correlations.push({
                    id: crypto.randomUUID(),
                    type: 'security_network_correlation',
                    securityEvent: secEvent.type,
                    sourceIP: secEvent.sourceIP,
                    relatedFlowCount: relatedFlows.length,
                    timeWindow: timeWindow,
                    confidence: Math.min(relatedFlows.length / 10, 1)
                });
            }
        });
        
        return correlations;
    }

    /**
     * Correlate performance issues with system events
     */
    correlatePerformanceEvents() {
        const correlations = [];
        const timeWindow = 10 * 60 * 1000; // 10 minutes
        
        // Find performance degradation events
        const perfIssues = this.performanceMetrics.filter(metric => metric.value > 2000);
        
        perfIssues.forEach(perfIssue => {
            // Find related system events
            const relatedEvents = this.events.filter(event =>
                Math.abs(event.timestamp - perfIssue.timestamp) < timeWindow &&
                event.category === 'error'
            );
            
            if (relatedEvents.length > 0) {
                correlations.push({
                    id: crypto.randomUUID(),
                    type: 'performance_error_correlation',
                    service: perfIssue.service,
                    performanceValue: perfIssue.value,
                    relatedErrorCount: relatedEvents.length,
                    timeWindow: timeWindow,
                    confidence: Math.min(relatedEvents.length / 5, 1)
                });
            }
        });
        
        return correlations;
    }

    /**
     * Perform root cause analysis
     */
    performRootCauseAnalysis() {
        const rootCauses = [];
        
        // Analyze recent issues for common root causes
        const recentAnomalies = this.getRecentPatterns('recurring_issue', 24);
        
        recentAnomalies.forEach(anomaly => {
            const rootCause = this.identifyRootCause(anomaly);
            if (rootCause) {
                rootCauses.push(rootCause);
            }
        });
        
        return rootCauses;
    }

    /**
     * Identify potential root cause for an issue
     */
    identifyRootCause(issue) {
        const timeWindow = 30 * 60 * 1000; // 30 minutes
        
        // Look for correlated events before the issue
        const correlatedEvents = this.events.filter(event =>
            event.timestamp < issue.firstSeen &&
            event.timestamp > issue.firstSeen - timeWindow
        );
        
        if (correlatedEvents.length > 0) {
            return {
                id: crypto.randomUUID(),
                type: 'root_cause_analysis',
                issue: issue.messagePattern,
                potentialCauses: correlatedEvents.map(e => ({
                    type: e.category,
                    message: e.message,
                    source: e.source,
                    timestamp: e.timestamp
                })),
                confidence: Math.min(correlatedEvents.length / 5, 1)
            };
        }
        
        return null;
    }

    /**
     * Update pattern database
     */
    updatePatterns(newPatterns) {
        const timestamp = Date.now();
        
        Object.entries(newPatterns).forEach(([category, patterns]) => {
            patterns.forEach(pattern => {
                const key = `${category}_${pattern.id}`;
                this.patterns.set(key, {
                    ...pattern,
                    category: category,
                    createdAt: timestamp,
                    lastUpdated: timestamp
                });
            });
        });
        
        // Clean old patterns
        this.cleanOldPatterns();
    }

    /**
     * Clean old patterns from memory
     */
    cleanOldPatterns() {
        const cutoff = Date.now() - this.config.maxPatternAge;
        
        this.patterns.forEach((pattern, key) => {
            if (pattern.createdAt < cutoff) {
                this.patterns.delete(key);
            }
        });
    }

    /**
     * Get recent patterns by type
     */
    getRecentPatterns(type, hours = 24) {
        const cutoff = Date.now() - (hours * 60 * 60 * 1000);
        
        return Array.from(this.patterns.values()).filter(pattern =>
            pattern.type === type && pattern.createdAt > cutoff
        );
    }

    /**
     * Get all patterns
     */
    getAllPatterns() {
        return Array.from(this.patterns.values());
    }

    /**
     * Calculate pattern severity
     */
    calculatePatternSeverity(events) {
        const errorCount = events.filter(e => e.category === 'error').length;
        const warningCount = events.filter(e => e.category === 'warning').length;
        
        const errorRatio = errorCount / events.length;
        
        if (errorRatio > 0.8) return 'critical';
        if (errorRatio > 0.5) return 'high';
        if (errorRatio > 0.2) return 'medium';
        return 'low';
    }

    /**
     * Store patterns to persistent storage
     */
    async storePatterns(timestamp) {
        try {
            const patternsData = {
                timestamp: timestamp,
                patterns: Object.fromEntries(this.patterns),
                statistics: {
                    totalPatterns: this.patterns.size,
                    patternsByType: this.getPatternStatistics()
                }
            };
            
            await fs.promises.writeFile('/tmp/patterns-database.json', JSON.stringify(patternsData, null, 2));
            
            // Also create a summary file
            const summary = {
                timestamp: timestamp,
                totalPatterns: this.patterns.size,
                recentPatterns: this.getRecentPatterns('', 1).length,
                highSeverityPatterns: Array.from(this.patterns.values()).filter(p => p.severity === 'high' || p.severity === 'critical').length
            };
            
            await fs.promises.writeFile('/tmp/patterns-summary.json', JSON.stringify(summary, null, 2));
            
        } catch (error) {
            console.error('Failed to store patterns:', error);
        }
    }

    /**
     * Get pattern statistics
     */
    getPatternStatistics() {
        const stats = new Map();
        
        this.patterns.forEach(pattern => {
            const type = pattern.type || 'unknown';
            stats.set(type, (stats.get(type) || 0) + 1);
        });
        
        return Object.fromEntries(stats);
    }

    // Helper functions for data generation (simulation)
    generateSampleMessage() {
        const messages = [
            'Connection timeout to database server',
            'Failed to authenticate user credentials',
            'Disk space critically low on partition /var',
            'Network interface eth0 experiencing packet loss',
            'Service httpd failed to start',
            'Memory usage exceeded threshold',
            'SSL certificate validation failed',
            'Database query execution timeout'
        ];
        return messages[Math.floor(Math.random() * messages.length)];
    }

    getRandomSource() {
        const sources = ['web-server', 'database', 'auth-service', 'network', 'storage', 'monitoring'];
        return sources[Math.floor(Math.random() * sources.length)];
    }

    getRandomSeverity() {
        const severities = ['low', 'medium', 'high', 'critical'];
        return severities[Math.floor(Math.random() * severities.length)];
    }

    getRandomUserAction() {
        const actions = ['login', 'logout', 'view', 'edit', 'delete', 'create', 'download', 'upload'];
        return actions[Math.floor(Math.random() * actions.length)];
    }

    getRandomResource() {
        const resources = ['/dashboard', '/users', '/settings', '/reports', '/api/data', '/admin', '/files'];
        return resources[Math.floor(Math.random() * resources.length)];
    }

    getRandomService() {
        const services = ['web-server', 'database', 'cache', 'auth-service', 'api-gateway', 'file-service'];
        return services[Math.floor(Math.random() * services.length)];
    }

    generateRandomIP() {
        return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Shutdown the engine
     */
    async shutdown() {
        this.isRunning = false;
        await this.storePatterns(Date.now());
        console.log('Pattern Recognition Engine shut down successfully');
    }
}

// REST API Interface
class PatternAPI {
    constructor(engine) {
        this.engine = engine;
    }

    getMiddleware() {
        return {
            '/api/patterns/all': this.getAllPatterns.bind(this),
            '/api/patterns/recent': this.getRecentPatterns.bind(this),
            '/api/patterns/type/:type': this.getPatternsByType.bind(this),
            '/api/patterns/statistics': this.getStatistics.bind(this),
            '/api/patterns/correlations': this.getCorrelations.bind(this)
        };
    }

    async getAllPatterns(req, res) {
        try {
            const patterns = this.engine.getAllPatterns();
            res.json({ success: true, data: patterns });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getRecentPatterns(req, res) {
        try {
            const hours = parseInt(req.query.hours) || 24;
            const patterns = this.engine.getRecentPatterns('', hours);
            res.json({ success: true, data: patterns });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getPatternsByType(req, res) {
        try {
            const type = req.params.type;
            const patterns = this.engine.getRecentPatterns(type);
            res.json({ success: true, data: patterns });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getStatistics(req, res) {
        try {
            const stats = this.engine.getPatternStatistics();
            res.json({ success: true, data: stats });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getCorrelations(req, res) {
        try {
            const correlations = this.engine.findEventCorrelations();
            res.json({ success: true, data: correlations });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }
}

module.exports = {
    PatternRecognitionEngine,
    PatternAPI
};

// Example usage
if (require.main === module) {
    const engine = new PatternRecognitionEngine({
        analysisInterval: 60000 // 1 minute for demo
    });

    engine.initialize().then(() => {
        console.log('Pattern Recognition Engine running...');
        
        process.on('SIGINT', async () => {
            console.log('Shutting down Pattern Recognition Engine...');
            await engine.shutdown();
            process.exit(0);
        });
    }).catch(error => {
        console.error('Failed to initialize pattern recognition engine:', error);
        process.exit(1);
    });
}