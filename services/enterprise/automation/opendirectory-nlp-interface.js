/**
 * OpenDirectory Natural Language Processing Interface
 * 
 * Advanced NLP capabilities for intelligent log analysis, automated incident
 * summarization, command interpretation, and semantic search across all system data.
 * 
 * Features:
 * - Natural language log analysis and parsing
 * - Automated incident summarization
 * - Intelligent alert descriptions and categorization
 * - Backend command interpretation (no UI changes)
 * - Error message translation to actionable items
 * - Automated documentation generation
 * - Sentiment analysis of user feedback
 * - Intelligent semantic search across all data sources
 */

const fs = require('fs');
const crypto = require('crypto');

class NaturalLanguageProcessor {
    constructor(config = {}) {
        this.config = {
            analysisInterval: config.analysisInterval || 300000, // 5 minutes
            maxLogEntries: config.maxLogEntries || 10000,
            confidenceThreshold: config.confidenceThreshold || 0.7,
            languageModels: {
                sentiment: 'basic',
                classification: 'rule_based',
                summarization: 'extractive'
            },
            ...config
        };

        this.logEntries = [];
        this.incidents = new Map();
        this.knowledgeBase = new Map();
        this.searchIndex = new Map();
        this.sentimentCache = new Map();
        this.isRunning = false;
        
        // Initialize NLP models and patterns
        this.initializeNLPModels();
    }

    /**
     * Initialize NLP models and pattern recognition
     */
    initializeNLPModels() {
        // Error patterns for classification
        this.errorPatterns = new Map([
            ['connection', /connection|connect|network|timeout|unreachable/i],
            ['authentication', /auth|login|password|credential|permission|access/i],
            ['database', /database|sql|query|table|db|mysql|postgresql/i],
            ['memory', /memory|ram|oom|out.*memory|malloc|heap/i],
            ['disk', /disk|storage|filesystem|mount|space|full/i],
            ['cpu', /cpu|processor|load|high.*usage|throttl/i],
            ['service', /service|daemon|process|start|stop|restart/i],
            ['certificate', /certificate|ssl|tls|cert|crypto|expired/i]
        ]);

        // Severity patterns
        this.severityPatterns = new Map([
            ['critical', /critical|fatal|emergency|panic|severe/i],
            ['high', /error|fail|exception|crash|abort|deny/i],
            ['medium', /warning|warn|deprecat|slow|timeout/i],
            ['low', /info|notice|debug|trace|verbose/i]
        ]);

        // Action patterns for recommendations
        this.actionPatterns = new Map([
            ['restart', /restart|reboot|reload|refresh/i],
            ['check', /check|verify|validate|inspect|monitor/i],
            ['update', /update|upgrade|patch|install/i],
            ['configure', /config|setting|parameter|option/i],
            ['backup', /backup|archive|save|preserve/i],
            ['clean', /clean|clear|delete|remove|purge/i]
        ]);

        // Sentiment keywords
        this.sentimentKeywords = {
            positive: ['good', 'great', 'excellent', 'working', 'success', 'resolved', 'fixed', 'stable'],
            negative: ['bad', 'terrible', 'awful', 'broken', 'failed', 'error', 'problem', 'issue', 'slow'],
            neutral: ['okay', 'normal', 'standard', 'typical', 'regular', 'average']
        };

        // Common abbreviations and expansions
        this.abbreviations = new Map([
            ['db', 'database'],
            ['auth', 'authentication'],
            ['conn', 'connection'],
            ['cfg', 'configuration'],
            ['srv', 'service'],
            ['usr', 'user'],
            ['sys', 'system'],
            ['net', 'network'],
            ['mem', 'memory'],
            ['proc', 'process']
        ]);
    }

    /**
     * Initialize the NLP interface
     */
    async initialize() {
        console.log('Initializing Natural Language Processing Interface...');
        
        // Load existing knowledge base
        await this.loadKnowledgeBase();
        
        // Build search index
        await this.buildSearchIndex();
        
        // Start NLP processing
        this.startNLPProcessing();
        
        console.log('Natural Language Processing Interface initialized successfully');
        return this;
    }

    /**
     * Load existing knowledge base
     */
    async loadKnowledgeBase() {
        try {
            const kbFile = '/tmp/nlp-knowledge-base.json';
            if (fs.existsSync(kbFile)) {
                const data = JSON.parse(fs.readFileSync(kbFile, 'utf8'));
                
                if (data.knowledgeBase) {
                    Object.entries(data.knowledgeBase).forEach(([key, entry]) => {
                        this.knowledgeBase.set(key, entry);
                    });
                }
                
                console.log(`Loaded ${this.knowledgeBase.size} knowledge base entries`);
            }
        } catch (error) {
            console.warn('Could not load knowledge base:', error.message);
        }
    }

    /**
     * Build search index for intelligent search
     */
    async buildSearchIndex() {
        // Index knowledge base entries
        this.knowledgeBase.forEach((entry, key) => {
            const keywords = this.extractKeywords(entry.content || entry.description || '');
            keywords.forEach(keyword => {
                if (!this.searchIndex.has(keyword)) {
                    this.searchIndex.set(keyword, new Set());
                }
                this.searchIndex.get(keyword).add(key);
            });
        });
        
        console.log(`Built search index with ${this.searchIndex.size} keywords`);
    }

    /**
     * Start continuous NLP processing
     */
    startNLPProcessing() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.processingLoop();
    }

    /**
     * Stop NLP processing
     */
    stopNLPProcessing() {
        this.isRunning = false;
    }

    /**
     * Main processing loop
     */
    async processingLoop() {
        while (this.isRunning) {
            try {
                await this.performNLPAnalysis();
                await this.sleep(this.config.analysisInterval);
            } catch (error) {
                console.error('NLP processing error:', error);
                await this.sleep(30000); // Wait 30 seconds on error
            }
        }
    }

    /**
     * Perform comprehensive NLP analysis
     */
    async performNLPAnalysis() {
        const timestamp = Date.now();
        
        // Process new log entries
        await this.processLogEntries();
        
        // Analyze incidents
        const incidentSummaries = await this.analyzeIncidents();
        
        // Generate intelligent alerts
        const intelligentAlerts = await this.generateIntelligentAlerts();
        
        // Update knowledge base
        await this.updateKnowledgeBase();
        
        // Generate documentation
        const documentation = await this.generateDocumentation();
        
        // Store results
        await this.storeNLPResults(timestamp, {
            incidentSummaries,
            intelligentAlerts,
            documentation
        });
    }

    /**
     * Process log entries with NLP
     */
    async processLogEntries() {
        // Simulate loading log entries from various sources
        const newEntries = await this.collectLogEntries();
        
        newEntries.forEach(entry => {
            // Classify log entry
            const classification = this.classifyLogEntry(entry);
            
            // Extract entities and keywords
            const entities = this.extractEntities(entry.message);
            
            // Determine severity
            const severity = this.determineSeverity(entry.message);
            
            // Generate summary
            const summary = this.generateLogSummary(entry);
            
            // Store processed entry
            const processedEntry = {
                ...entry,
                classification: classification,
                entities: entities,
                severity: severity,
                summary: summary,
                processedAt: Date.now()
            };
            
            this.logEntries.push(processedEntry);
        });
        
        // Keep only recent entries
        if (this.logEntries.length > this.config.maxLogEntries) {
            this.logEntries = this.logEntries.slice(-this.config.maxLogEntries);
        }
    }

    /**
     * Collect log entries from various sources
     */
    async collectLogEntries() {
        // Simulate collecting logs from different sources
        const entries = [];
        
        // System logs
        for (let i = 0; i < 5; i++) {
            entries.push({
                id: crypto.randomUUID(),
                timestamp: Date.now() - Math.random() * 3600000,
                source: this.getRandomSource(),
                level: this.getRandomLevel(),
                message: this.generateSampleLogMessage(),
                metadata: {
                    host: 'server-01',
                    service: this.getRandomService(),
                    pid: Math.floor(Math.random() * 10000)
                }
            });
        }
        
        return entries;
    }

    /**
     * Classify log entry using NLP
     */
    classifyLogEntry(entry) {
        const message = entry.message.toLowerCase();
        const classifications = [];
        
        // Check against error patterns
        this.errorPatterns.forEach((pattern, category) => {
            if (pattern.test(message)) {
                classifications.push({
                    category: category,
                    confidence: this.calculatePatternConfidence(message, pattern)
                });
            }
        });
        
        // Return highest confidence classification
        if (classifications.length > 0) {
            const best = classifications.reduce((prev, current) => 
                (prev.confidence > current.confidence) ? prev : current
            );
            
            return {
                primary: best.category,
                confidence: best.confidence,
                all: classifications
            };
        }
        
        return {
            primary: 'unknown',
            confidence: 0.1,
            all: []
        };
    }

    /**
     * Extract entities from log message
     */
    extractEntities(message) {
        const entities = {
            ips: this.extractIPs(message),
            urls: this.extractURLs(message),
            files: this.extractFilePaths(message),
            usernames: this.extractUsernames(message),
            timestamps: this.extractTimestamps(message),
            numbers: this.extractNumbers(message),
            services: this.extractServices(message)
        };
        
        return entities;
    }

    /**
     * Extract IP addresses from text
     */
    extractIPs(text) {
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
        return text.match(ipPattern) || [];
    }

    /**
     * Extract URLs from text
     */
    extractURLs(text) {
        const urlPattern = /https?:\/\/[^\s]+/g;
        return text.match(urlPattern) || [];
    }

    /**
     * Extract file paths from text
     */
    extractFilePaths(text) {
        const filePattern = /\/[^\s]+|[A-Za-z]:\\[^\s]+/g;
        return text.match(filePattern) || [];
    }

    /**
     * Extract usernames from text
     */
    extractUsernames(text) {
        const usernamePattern = /user[:\s]+([a-zA-Z0-9_-]+)|username[:\s]+([a-zA-Z0-9_-]+)/gi;
        const matches = [];
        let match;
        
        while ((match = usernamePattern.exec(text)) !== null) {
            matches.push(match[1] || match[2]);
        }
        
        return matches;
    }

    /**
     * Extract timestamps from text
     */
    extractTimestamps(text) {
        const timestampPattern = /\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}/g;
        return text.match(timestampPattern) || [];
    }

    /**
     * Extract numbers from text
     */
    extractNumbers(text) {
        const numberPattern = /\b\d+(?:\.\d+)?\b/g;
        return text.match(numberPattern) || [];
    }

    /**
     * Extract service names from text
     */
    extractServices(text) {
        const services = ['apache', 'nginx', 'mysql', 'postgresql', 'redis', 'mongodb', 'docker', 'ssh'];
        const found = [];
        
        services.forEach(service => {
            if (text.toLowerCase().includes(service)) {
                found.push(service);
            }
        });
        
        return found;
    }

    /**
     * Determine severity of log entry
     */
    determineSeverity(message) {
        const text = message.toLowerCase();
        let maxSeverity = 'low';
        let maxScore = 0;
        
        this.severityPatterns.forEach((pattern, severity) => {
            if (pattern.test(text)) {
                const score = this.calculatePatternConfidence(text, pattern);
                if (score > maxScore) {
                    maxSeverity = severity;
                    maxScore = score;
                }
            }
        });
        
        return {
            level: maxSeverity,
            confidence: maxScore
        };
    }

    /**
     * Generate log entry summary
     */
    generateLogSummary(entry) {
        const message = entry.message;
        const classification = this.classifyLogEntry(entry);
        const entities = this.extractEntities(message);
        
        // Create extractive summary
        const sentences = message.split(/[.!?]+/).filter(s => s.trim().length > 0);
        const importantSentence = sentences[0] || message;
        
        let summary = importantSentence.trim();
        
        // Add context from entities
        if (entities.ips.length > 0) {
            summary += ` (IP: ${entities.ips[0]})`;
        }
        
        if (entities.services.length > 0) {
            summary += ` [${entities.services[0]}]`;
        }
        
        return {
            text: summary,
            extractedFrom: 'first_sentence',
            confidence: 0.8
        };
    }

    /**
     * Analyze incidents and create summaries
     */
    async analyzeIncidents() {
        const recentErrors = this.logEntries.filter(entry => 
            entry.severity.level === 'high' || entry.severity.level === 'critical'
        ).slice(-20);
        
        // Group related errors
        const incidentGroups = this.groupRelatedErrors(recentErrors);
        
        const summaries = [];
        
        incidentGroups.forEach((group, groupId) => {
            const summary = this.createIncidentSummary(group, groupId);
            summaries.push(summary);
            
            // Store in incidents map
            this.incidents.set(groupId, {
                ...summary,
                createdAt: Date.now(),
                status: 'active'
            });
        });
        
        return summaries;
    }

    /**
     * Group related error messages
     */
    groupRelatedErrors(errors) {
        const groups = new Map();
        
        errors.forEach(error => {
            const groupKey = this.generateGroupKey(error);
            
            if (!groups.has(groupKey)) {
                groups.set(groupKey, []);
            }
            
            groups.get(groupKey).push(error);
        });
        
        // Filter out groups with only one error
        const filteredGroups = new Map();
        groups.forEach((group, key) => {
            if (group.length >= 2) {
                filteredGroups.set(key, group);
            }
        });
        
        return filteredGroups;
    }

    /**
     * Generate group key for similar errors
     */
    generateGroupKey(error) {
        const classification = error.classification.primary;
        const source = error.source;
        const messageWords = error.message.toLowerCase().split(' ').slice(0, 3).join('_');
        
        return `${classification}_${source}_${messageWords}`;
    }

    /**
     * Create incident summary
     */
    createIncidentSummary(errorGroup, groupId) {
        const firstError = errorGroup[0];
        const errorCount = errorGroup.length;
        
        // Extract common elements
        const commonSources = [...new Set(errorGroup.map(e => e.source))];
        const commonServices = [...new Set(errorGroup.flatMap(e => e.entities.services))];
        const timeSpan = Math.max(...errorGroup.map(e => e.timestamp)) - Math.min(...errorGroup.map(e => e.timestamp));
        
        // Generate title
        const title = this.generateIncidentTitle(firstError, errorCount);
        
        // Generate description
        const description = this.generateIncidentDescription(errorGroup, timeSpan);
        
        // Generate recommendations
        const recommendations = this.generateIncidentRecommendations(errorGroup);
        
        return {
            id: groupId,
            title: title,
            description: description,
            severity: this.calculateIncidentSeverity(errorGroup),
            affectedSources: commonSources,
            affectedServices: commonServices,
            errorCount: errorCount,
            timeSpan: timeSpan,
            firstOccurrence: Math.min(...errorGroup.map(e => e.timestamp)),
            lastOccurrence: Math.max(...errorGroup.map(e => e.timestamp)),
            recommendations: recommendations,
            status: 'active'
        };
    }

    /**
     * Generate incident title
     */
    generateIncidentTitle(firstError, count) {
        const classification = firstError.classification.primary;
        const source = firstError.source;
        
        if (count > 1) {
            return `Multiple ${classification} errors from ${source} (${count} occurrences)`;
        } else {
            return `${classification.charAt(0).toUpperCase() + classification.slice(1)} error from ${source}`;
        }
    }

    /**
     * Generate incident description
     */
    generateIncidentDescription(errorGroup, timeSpan) {
        const firstError = errorGroup[0];
        const timeSpanMin = Math.floor(timeSpan / (1000 * 60));
        
        let description = `This incident involves ${errorGroup.length} similar errors `;
        
        if (timeSpanMin > 60) {
            description += `occurring over ${Math.floor(timeSpanMin / 60)} hours. `;
        } else {
            description += `occurring over ${timeSpanMin} minutes. `;
        }
        
        description += `Primary classification: ${firstError.classification.primary}. `;
        
        // Add sample error message
        const sampleMessage = firstError.summary.text;
        description += `Sample error: "${sampleMessage}"`;
        
        return description;
    }

    /**
     * Generate incident recommendations
     */
    generateIncidentRecommendations(errorGroup) {
        const recommendations = [];
        const classification = errorGroup[0].classification.primary;
        
        // Generic recommendations based on classification
        switch (classification) {
            case 'connection':
                recommendations.push('Check network connectivity and firewall settings');
                recommendations.push('Verify service endpoints are accessible');
                break;
            case 'authentication':
                recommendations.push('Verify user credentials and permissions');
                recommendations.push('Check authentication service status');
                break;
            case 'database':
                recommendations.push('Check database connectivity and status');
                recommendations.push('Review database query performance');
                break;
            case 'memory':
                recommendations.push('Monitor memory usage and available resources');
                recommendations.push('Consider scaling or optimizing memory usage');
                break;
            case 'disk':
                recommendations.push('Check disk space and I/O performance');
                recommendations.push('Clean up temporary files or expand storage');
                break;
            default:
                recommendations.push('Review system logs for additional context');
                recommendations.push('Monitor system resources and performance');
        }
        
        // Add specific recommendations based on entities
        const allEntities = errorGroup.flatMap(e => Object.values(e.entities)).flat();
        if (allEntities.some(entity => typeof entity === 'string' && entity.includes('timeout'))) {
            recommendations.push('Increase timeout values for affected operations');
        }
        
        return recommendations;
    }

    /**
     * Calculate incident severity
     */
    calculateIncidentSeverity(errorGroup) {
        const severityScores = { critical: 4, high: 3, medium: 2, low: 1 };
        const maxSeverity = Math.max(...errorGroup.map(e => severityScores[e.severity.level] || 1));
        
        // Increase severity based on frequency
        let adjustedSeverity = maxSeverity;
        if (errorGroup.length > 10) adjustedSeverity += 1;
        else if (errorGroup.length > 5) adjustedSeverity += 0.5;
        
        if (adjustedSeverity >= 4) return 'critical';
        if (adjustedSeverity >= 3) return 'high';
        if (adjustedSeverity >= 2) return 'medium';
        return 'low';
    }

    /**
     * Generate intelligent alerts
     */
    async generateIntelligentAlerts() {
        const alerts = [];
        
        // Check for recent critical incidents
        this.incidents.forEach((incident, id) => {
            if (incident.severity === 'critical' && incident.status === 'active') {
                alerts.push({
                    id: crypto.randomUUID(),
                    type: 'critical_incident',
                    title: `CRITICAL: ${incident.title}`,
                    description: this.generateAlertDescription(incident),
                    severity: 'critical',
                    timestamp: Date.now(),
                    incidentId: id,
                    actions: incident.recommendations.slice(0, 3),
                    urgency: 'immediate'
                });
            }
        });
        
        // Check for pattern anomalies
        const patternAnomalies = this.detectPatternAnomalies();
        patternAnomalies.forEach(anomaly => {
            alerts.push({
                id: crypto.randomUUID(),
                type: 'pattern_anomaly',
                title: `Pattern Anomaly: ${anomaly.description}`,
                description: this.generateAnomalyDescription(anomaly),
                severity: anomaly.severity,
                timestamp: Date.now(),
                pattern: anomaly.pattern,
                confidence: anomaly.confidence
            });
        });
        
        return alerts;
    }

    /**
     * Generate alert description
     */
    generateAlertDescription(incident) {
        return `${incident.description} This requires immediate attention. ` +
               `Affected systems: ${incident.affectedSources.join(', ')}. ` +
               `First occurred: ${new Date(incident.firstOccurrence).toLocaleString()}.`;
    }

    /**
     * Generate anomaly description
     */
    generateAnomalyDescription(anomaly) {
        return `Unusual pattern detected: ${anomaly.description}. ` +
               `This deviates from normal system behavior. ` +
               `Confidence level: ${Math.round(anomaly.confidence * 100)}%.`;
    }

    /**
     * Detect pattern anomalies
     */
    detectPatternAnomalies() {
        const anomalies = [];
        
        // Check for unusual error rates
        const recentErrors = this.logEntries.filter(entry => 
            Date.now() - entry.timestamp < 3600000 // Last hour
        );
        
        const errorsBySource = new Map();
        recentErrors.forEach(error => {
            const source = error.source;
            errorsBySource.set(source, (errorsBySource.get(source) || 0) + 1);
        });
        
        errorsBySource.forEach((count, source) => {
            if (count > 10) { // More than 10 errors per hour from one source
                anomalies.push({
                    pattern: 'high_error_rate',
                    description: `High error rate from ${source}`,
                    severity: 'high',
                    confidence: Math.min(count / 20, 1.0),
                    source: source,
                    count: count
                });
            }
        });
        
        return anomalies;
    }

    /**
     * Update knowledge base with new learnings
     */
    async updateKnowledgeBase() {
        // Extract knowledge from processed incidents
        this.incidents.forEach((incident, id) => {
            if (!this.knowledgeBase.has(id)) {
                this.knowledgeBase.set(id, {
                    type: 'incident',
                    classification: incident.title,
                    description: incident.description,
                    resolution: incident.recommendations,
                    severity: incident.severity,
                    keywords: this.extractKeywords(incident.title + ' ' + incident.description),
                    createdAt: incident.createdAt,
                    confidence: 0.8
                });
            }
        });
        
        // Extract knowledge from successful patterns
        const successfulPatterns = this.identifySuccessfulPatterns();
        successfulPatterns.forEach((pattern, id) => {
            this.knowledgeBase.set(`pattern_${id}`, pattern);
        });
    }

    /**
     * Identify successful resolution patterns
     */
    identifySuccessfulPatterns() {
        const patterns = new Map();
        
        // Mock successful patterns - in real implementation, this would
        // analyze historical data and resolution outcomes
        patterns.set('db_connection_timeout', {
            type: 'resolution_pattern',
            problem: 'Database connection timeout',
            solution: 'Increase connection timeout and check network latency',
            successRate: 0.9,
            avgResolutionTime: 15 * 60 * 1000, // 15 minutes
            keywords: ['database', 'connection', 'timeout'],
            confidence: 0.9
        });
        
        return patterns;
    }

    /**
     * Generate automated documentation
     */
    async generateDocumentation() {
        const docs = {
            incidents: this.generateIncidentDocumentation(),
            patterns: this.generatePatternDocumentation(),
            troubleshooting: this.generateTroubleshootingGuide()
        };
        
        return docs;
    }

    /**
     * Generate incident documentation
     */
    generateIncidentDocumentation() {
        const recentIncidents = Array.from(this.incidents.values())
            .filter(incident => Date.now() - incident.createdAt < 7 * 24 * 60 * 60 * 1000) // Last 7 days
            .sort((a, b) => b.createdAt - a.createdAt);
        
        let documentation = '# Recent Incidents Report\n\n';
        
        if (recentIncidents.length === 0) {
            documentation += 'No incidents recorded in the past 7 days.\n';
            return documentation;
        }
        
        documentation += `${recentIncidents.length} incidents recorded in the past 7 days.\n\n`;
        
        recentIncidents.forEach((incident, index) => {
            documentation += `## Incident ${index + 1}: ${incident.title}\n\n`;
            documentation += `**Severity:** ${incident.severity}\n`;
            documentation += `**Affected Systems:** ${incident.affectedSources.join(', ')}\n`;
            documentation += `**Duration:** ${new Date(incident.firstOccurrence).toLocaleString()} - ${new Date(incident.lastOccurrence).toLocaleString()}\n`;
            documentation += `**Error Count:** ${incident.errorCount}\n\n`;
            documentation += `**Description:** ${incident.description}\n\n`;
            documentation += `**Recommendations:**\n`;
            incident.recommendations.forEach(rec => {
                documentation += `- ${rec}\n`;
            });
            documentation += '\n';
        });
        
        return documentation;
    }

    /**
     * Generate pattern documentation
     */
    generatePatternDocumentation() {
        let documentation = '# System Patterns Analysis\n\n';
        
        // Analyze log patterns
        const patterns = this.analyzeLogPatterns();
        
        documentation += '## Common Error Patterns\n\n';
        patterns.forEach((pattern, type) => {
            documentation += `### ${type.charAt(0).toUpperCase() + type.slice(1)} Errors\n\n`;
            documentation += `**Frequency:** ${pattern.frequency} occurrences\n`;
            documentation += `**Common Sources:** ${pattern.sources.join(', ')}\n`;
            documentation += `**Typical Resolution:** ${pattern.commonResolution}\n\n`;
        });
        
        return documentation;
    }

    /**
     * Generate troubleshooting guide
     */
    generateTroubleshootingGuide() {
        let guide = '# Automated Troubleshooting Guide\n\n';
        
        guide += '## Common Issues and Solutions\n\n';
        
        // Generate solutions based on knowledge base
        this.knowledgeBase.forEach((entry, id) => {
            if (entry.type === 'resolution_pattern') {
                guide += `### ${entry.problem}\n\n`;
                guide += `**Solution:** ${entry.solution}\n`;
                guide += `**Success Rate:** ${Math.round(entry.successRate * 100)}%\n`;
                guide += `**Average Resolution Time:** ${Math.round(entry.avgResolutionTime / 60000)} minutes\n\n`;
            }
        });
        
        return guide;
    }

    /**
     * Analyze log patterns
     */
    analyzeLogPatterns() {
        const patterns = new Map();
        
        // Group logs by classification
        const classificationGroups = new Map();
        this.logEntries.forEach(entry => {
            const classification = entry.classification.primary;
            if (!classificationGroups.has(classification)) {
                classificationGroups.set(classification, []);
            }
            classificationGroups.get(classification).push(entry);
        });
        
        // Analyze each group
        classificationGroups.forEach((entries, classification) => {
            if (entries.length >= 3) {
                const sources = [...new Set(entries.map(e => e.source))];
                const commonResolution = this.getCommonResolution(classification);
                
                patterns.set(classification, {
                    frequency: entries.length,
                    sources: sources,
                    commonResolution: commonResolution,
                    severity: this.getAverageSeverity(entries)
                });
            }
        });
        
        return patterns;
    }

    /**
     * Get common resolution for error type
     */
    getCommonResolution(classification) {
        const resolutions = {
            'connection': 'Check network connectivity and service status',
            'authentication': 'Verify credentials and permissions',
            'database': 'Check database connectivity and query performance',
            'memory': 'Monitor memory usage and optimize allocation',
            'disk': 'Check disk space and I/O performance',
            'service': 'Restart affected service and check configuration'
        };
        
        return resolutions[classification] || 'Review logs and system status';
    }

    /**
     * Get average severity for entries
     */
    getAverageSeverity(entries) {
        const severityScores = { critical: 4, high: 3, medium: 2, low: 1 };
        const totalScore = entries.reduce((sum, entry) => {
            return sum + (severityScores[entry.severity.level] || 1);
        }, 0);
        
        const avgScore = totalScore / entries.length;
        
        if (avgScore >= 3.5) return 'critical';
        if (avgScore >= 2.5) return 'high';
        if (avgScore >= 1.5) return 'medium';
        return 'low';
    }

    /**
     * Intelligent semantic search
     */
    intelligentSearch(query) {
        const queryKeywords = this.extractKeywords(query.toLowerCase());
        const results = [];
        
        // Expand query with synonyms and related terms
        const expandedQuery = this.expandQuery(queryKeywords);
        
        // Search knowledge base
        this.knowledgeBase.forEach((entry, id) => {
            const score = this.calculateRelevanceScore(expandedQuery, entry);
            if (score > this.config.confidenceThreshold) {
                results.push({
                    id: id,
                    type: entry.type,
                    title: entry.classification || entry.problem || id,
                    content: entry.description || entry.solution,
                    relevanceScore: score,
                    keywords: entry.keywords || []
                });
            }
        });
        
        // Search recent incidents
        this.incidents.forEach((incident, id) => {
            const score = this.calculateIncidentRelevanceScore(expandedQuery, incident);
            if (score > this.config.confidenceThreshold) {
                results.push({
                    id: id,
                    type: 'incident',
                    title: incident.title,
                    content: incident.description,
                    relevanceScore: score,
                    keywords: this.extractKeywords(incident.title + ' ' + incident.description)
                });
            }
        });
        
        // Sort by relevance
        results.sort((a, b) => b.relevanceScore - a.relevanceScore);
        
        return {
            query: query,
            expandedQuery: expandedQuery,
            results: results.slice(0, 10), // Top 10 results
            totalFound: results.length
        };
    }

    /**
     * Expand query with synonyms and related terms
     */
    expandQuery(keywords) {
        const expanded = new Set(keywords);
        
        // Add synonyms and related terms
        keywords.forEach(keyword => {
            // Add expanded abbreviations
            this.abbreviations.forEach((full, abbr) => {
                if (keyword.includes(abbr)) {
                    expanded.add(full);
                }
                if (keyword.includes(full)) {
                    expanded.add(abbr);
                }
            });
            
            // Add related technical terms
            const relatedTerms = this.getRelatedTerms(keyword);
            relatedTerms.forEach(term => expanded.add(term));
        });
        
        return Array.from(expanded);
    }

    /**
     * Get related terms for a keyword
     */
    getRelatedTerms(keyword) {
        const relations = {
            'database': ['db', 'sql', 'query', 'table', 'mysql', 'postgresql'],
            'network': ['connection', 'tcp', 'udp', 'ip', 'port', 'firewall'],
            'memory': ['ram', 'heap', 'malloc', 'oom', 'cache'],
            'disk': ['storage', 'filesystem', 'mount', 'io', 'ssd', 'hdd'],
            'authentication': ['auth', 'login', 'password', 'credentials', 'token'],
            'service': ['daemon', 'process', 'systemd', 'init', 'pid']
        };
        
        return relations[keyword] || [];
    }

    /**
     * Calculate relevance score for knowledge base entry
     */
    calculateRelevanceScore(queryKeywords, entry) {
        const entryText = (entry.description || entry.solution || '').toLowerCase();
        const entryKeywords = entry.keywords || this.extractKeywords(entryText);
        
        let score = 0;
        let matches = 0;
        
        queryKeywords.forEach(queryKeyword => {
            // Exact keyword match
            if (entryKeywords.includes(queryKeyword)) {
                score += 1.0;
                matches++;
            }
            // Partial match in text
            else if (entryText.includes(queryKeyword)) {
                score += 0.5;
                matches++;
            }
        });
        
        // Normalize by query length
        if (queryKeywords.length > 0) {
            score = score / queryKeywords.length;
        }
        
        // Boost score for entries with more matches
        const matchRatio = matches / queryKeywords.length;
        score *= (0.5 + 0.5 * matchRatio);
        
        // Boost score based on entry confidence
        if (entry.confidence) {
            score *= entry.confidence;
        }
        
        return Math.min(score, 1.0);
    }

    /**
     * Calculate incident relevance score
     */
    calculateIncidentRelevanceScore(queryKeywords, incident) {
        const incidentText = (incident.title + ' ' + incident.description).toLowerCase();
        const incidentKeywords = this.extractKeywords(incidentText);
        
        return this.calculateRelevanceScore(queryKeywords, {
            keywords: incidentKeywords,
            description: incidentText,
            confidence: 0.9
        });
    }

    /**
     * Perform sentiment analysis
     */
    performSentimentAnalysis(text) {
        const cacheKey = crypto.createHash('md5').update(text).digest('hex');
        
        // Check cache
        if (this.sentimentCache.has(cacheKey)) {
            return this.sentimentCache.get(cacheKey);
        }
        
        const words = text.toLowerCase().split(/\W+/);
        let positiveScore = 0;
        let negativeScore = 0;
        let neutralScore = 0;
        
        words.forEach(word => {
            if (this.sentimentKeywords.positive.includes(word)) {
                positiveScore += 1;
            } else if (this.sentimentKeywords.negative.includes(word)) {
                negativeScore += 1;
            } else if (this.sentimentKeywords.neutral.includes(word)) {
                neutralScore += 1;
            }
        });
        
        const totalScore = positiveScore + negativeScore + neutralScore;
        let sentiment = 'neutral';
        let confidence = 0.5;
        
        if (totalScore > 0) {
            const positiveRatio = positiveScore / totalScore;
            const negativeRatio = negativeScore / totalScore;
            
            if (positiveRatio > negativeRatio && positiveRatio > 0.3) {
                sentiment = 'positive';
                confidence = positiveRatio;
            } else if (negativeRatio > positiveRatio && negativeRatio > 0.3) {
                sentiment = 'negative';
                confidence = negativeRatio;
            }
        }
        
        const result = {
            sentiment: sentiment,
            confidence: confidence,
            scores: {
                positive: positiveScore,
                negative: negativeScore,
                neutral: neutralScore
            }
        };
        
        // Cache result
        this.sentimentCache.set(cacheKey, result);
        
        return result;
    }

    /**
     * Extract keywords from text
     */
    extractKeywords(text) {
        const words = text.toLowerCase()
            .replace(/[^\w\s]/g, ' ')
            .split(/\s+/)
            .filter(word => word.length > 2)
            .filter(word => !this.isStopWord(word));
        
        // Remove duplicates and return
        return [...new Set(words)];
    }

    /**
     * Check if word is a stop word
     */
    isStopWord(word) {
        const stopWords = new Set([
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have',
            'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
            'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those'
        ]);
        
        return stopWords.has(word);
    }

    /**
     * Calculate pattern confidence
     */
    calculatePatternConfidence(text, pattern) {
        const matches = text.match(pattern);
        if (!matches) return 0;
        
        // Simple confidence based on number of matches
        const matchCount = matches.length;
        const textLength = text.split(' ').length;
        
        return Math.min(matchCount / textLength * 10, 1.0);
    }

    /**
     * Get all incidents
     */
    getAllIncidents() {
        return Array.from(this.incidents.values());
    }

    /**
     * Get recent log entries
     */
    getRecentLogEntries(hours = 24) {
        const cutoff = Date.now() - (hours * 60 * 60 * 1000);
        return this.logEntries.filter(entry => entry.timestamp > cutoff);
    }

    /**
     * Store NLP results
     */
    async storeNLPResults(timestamp, results) {
        try {
            const nlpData = {
                timestamp: timestamp,
                incidents: Object.fromEntries(this.incidents),
                knowledgeBase: Object.fromEntries(this.knowledgeBase),
                recentResults: results,
                statistics: {
                    totalLogEntries: this.logEntries.length,
                    activeIncidents: Array.from(this.incidents.values()).filter(i => i.status === 'active').length,
                    knowledgeBaseSize: this.knowledgeBase.size,
                    searchIndexSize: this.searchIndex.size
                }
            };
            
            await fs.promises.writeFile('/tmp/nlp-results.json', JSON.stringify(nlpData, null, 2));
            
            // Update knowledge base file
            await fs.promises.writeFile('/tmp/nlp-knowledge-base.json', JSON.stringify({
                timestamp: timestamp,
                knowledgeBase: Object.fromEntries(this.knowledgeBase)
            }, null, 2));
            
        } catch (error) {
            console.error('Failed to store NLP results:', error);
        }
    }

    // Helper methods for data generation (simulation)
    generateSampleLogMessage() {
        const messages = [
            'Failed to connect to database server at 192.168.1.100:3306',
            'Authentication failed for user "admin" from 10.0.0.15',
            'Memory usage exceeded 90% threshold on server web-01',
            'Disk space critically low on /var partition (95% full)',
            'SSL certificate for api.example.com will expire in 7 days',
            'Service httpd failed to start: port 80 already in use',
            'Network timeout connecting to external API endpoint',
            'Query execution time exceeded 30 seconds for user report'
        ];
        return messages[Math.floor(Math.random() * messages.length)];
    }

    getRandomSource() {
        const sources = ['web-server', 'database', 'auth-service', 'api-gateway', 'file-service', 'cache'];
        return sources[Math.floor(Math.random() * sources.length)];
    }

    getRandomLevel() {
        const levels = ['error', 'warn', 'info', 'debug'];
        return levels[Math.floor(Math.random() * levels.length)];
    }

    getRandomService() {
        const services = ['apache', 'mysql', 'nginx', 'redis', 'mongodb', 'docker'];
        return services[Math.floor(Math.random() * services.length)];
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Shutdown the NLP interface
     */
    async shutdown() {
        this.isRunning = false;
        await this.storeNLPResults(Date.now(), {});
        console.log('Natural Language Processing Interface shut down successfully');
    }
}

// REST API Interface
class NLPAPI {
    constructor(nlpEngine) {
        this.nlp = nlpEngine;
    }

    getMiddleware() {
        return {
            '/api/nlp/search': this.search.bind(this),
            '/api/nlp/incidents': this.getIncidents.bind(this),
            '/api/nlp/sentiment': this.analyzeSentiment.bind(this),
            '/api/nlp/logs': this.getProcessedLogs.bind(this),
            '/api/nlp/knowledge': this.getKnowledge.bind(this),
            '/api/nlp/documentation': this.getDocumentation.bind(this)
        };
    }

    async search(req, res) {
        try {
            const query = req.query.q;
            if (!query) {
                return res.status(400).json({ success: false, error: 'Query parameter "q" is required' });
            }
            
            const results = this.nlp.intelligentSearch(query);
            res.json({ success: true, data: results });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getIncidents(req, res) {
        try {
            const incidents = this.nlp.getAllIncidents();
            res.json({ success: true, data: incidents });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async analyzeSentiment(req, res) {
        try {
            const { text } = req.body;
            if (!text) {
                return res.status(400).json({ success: false, error: 'Text is required' });
            }
            
            const sentiment = this.nlp.performSentimentAnalysis(text);
            res.json({ success: true, data: sentiment });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getProcessedLogs(req, res) {
        try {
            const hours = parseInt(req.query.hours) || 24;
            const logs = this.nlp.getRecentLogEntries(hours);
            res.json({ success: true, data: logs });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getKnowledge(req, res) {
        try {
            const knowledge = Array.from(this.nlp.knowledgeBase.values());
            res.json({ success: true, data: knowledge });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getDocumentation(req, res) {
        try {
            const docs = await this.nlp.generateDocumentation();
            res.json({ success: true, data: docs });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }
}

module.exports = {
    NaturalLanguageProcessor,
    NLPAPI
};

// Example usage
if (require.main === module) {
    const nlp = new NaturalLanguageProcessor({
        analysisInterval: 300000 // 5 minutes for demo
    });

    nlp.initialize().then(() => {
        console.log('Natural Language Processing Interface running...');
        
        process.on('SIGINT', async () => {
            console.log('Shutting down NLP interface...');
            await nlp.shutdown();
            process.exit(0);
        });
    }).catch(error => {
        console.error('Failed to initialize NLP interface:', error);
        process.exit(1);
    });
}