/**
 * OpenDirectory Intelligent Recommendations System
 * 
 * Provides AI-driven optimization recommendations, security improvements,
 * resource allocation suggestions, and performance tuning advice.
 * 
 * Features:
 * - System optimization recommendations
 * - Security improvement suggestions
 * - Resource allocation optimization
 * - Application update recommendations
 * - Policy optimization suggestions
 * - Cost optimization recommendations
 * - Performance tuning suggestions
 * - Preventive maintenance recommendations
 */

const fs = require('fs');
const crypto = require('crypto');

class IntelligentRecommendationEngine {
    constructor(config = {}) {
        this.config = {
            analysisInterval: config.analysisInterval || 900000, // 15 minutes
            minConfidence: config.minConfidence || 0.6,
            maxRecommendations: config.maxRecommendations || 50,
            severityWeights: {
                critical: 1.0,
                high: 0.8,
                medium: 0.6,
                low: 0.4
            },
            ...config
        };

        this.recommendations = new Map();
        this.executedRecommendations = new Set();
        this.systemMetrics = new Map();
        this.patterns = [];
        this.anomalies = [];
        this.isRunning = false;
    }

    /**
     * Initialize the recommendation engine
     */
    async initialize() {
        console.log('Initializing Intelligent Recommendation Engine...');
        
        // Load historical recommendations
        await this.loadRecommendationHistory();
        
        // Start recommendation analysis
        this.startRecommendationAnalysis();
        
        console.log('Intelligent Recommendation Engine initialized successfully');
        return this;
    }

    /**
     * Load historical recommendations
     */
    async loadRecommendationHistory() {
        try {
            const historyFile = '/tmp/recommendation-history.json';
            if (fs.existsSync(historyFile)) {
                const data = JSON.parse(fs.readFileSync(historyFile, 'utf8'));
                
                if (data.executed) {
                    this.executedRecommendations = new Set(data.executed);
                }
                
                console.log(`Loaded ${this.executedRecommendations.size} executed recommendations`);
            }
        } catch (error) {
            console.warn('Could not load recommendation history:', error.message);
        }
    }

    /**
     * Start continuous recommendation analysis
     */
    startRecommendationAnalysis() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.recommendationLoop();
    }

    /**
     * Stop recommendation analysis
     */
    stopRecommendationAnalysis() {
        this.isRunning = false;
    }

    /**
     * Main recommendation loop
     */
    async recommendationLoop() {
        while (this.isRunning) {
            try {
                await this.generateRecommendations();
                await this.sleep(this.config.analysisInterval);
            } catch (error) {
                console.error('Recommendation generation error:', error);
                await this.sleep(30000); // Wait 30 seconds on error
            }
        }
    }

    /**
     * Generate comprehensive recommendations
     */
    async generateRecommendations() {
        const timestamp = Date.now();
        
        // Collect current system state
        await this.collectSystemState();
        
        // Generate different types of recommendations
        const optimizationRecs = await this.generateOptimizationRecommendations();
        const securityRecs = await this.generateSecurityRecommendations();
        const resourceRecs = await this.generateResourceRecommendations();
        const updateRecs = await this.generateUpdateRecommendations();
        const policyRecs = await this.generatePolicyRecommendations();
        const costRecs = await this.generateCostOptimizationRecommendations();
        const performanceRecs = await this.generatePerformanceRecommendations();
        const maintenanceRecs = await this.generateMaintenanceRecommendations();
        
        // Consolidate and rank recommendations
        const allRecommendations = [
            ...optimizationRecs,
            ...securityRecs,
            ...resourceRecs,
            ...updateRecs,
            ...policyRecs,
            ...costRecs,
            ...performanceRecs,
            ...maintenanceRecs
        ];
        
        // Filter and rank recommendations
        const rankedRecommendations = this.rankRecommendations(allRecommendations);
        
        // Update recommendations database
        this.updateRecommendations(rankedRecommendations, timestamp);
        
        // Store results
        await this.storeRecommendations(timestamp);
    }

    /**
     * Collect current system state
     */
    async collectSystemState() {
        // In real implementation, this would interface with actual monitoring APIs
        // For now, we'll simulate collecting system metrics
        
        this.systemMetrics.set('cpu_usage', Math.random() * 100);
        this.systemMetrics.set('memory_usage', Math.random() * 100);
        this.systemMetrics.set('disk_usage', Math.random() * 100);
        this.systemMetrics.set('network_utilization', Math.random() * 100);
        this.systemMetrics.set('active_connections', Math.floor(Math.random() * 1000));
        this.systemMetrics.set('error_rate', Math.random() * 0.1);
        this.systemMetrics.set('response_time', Math.random() * 5000);
        
        // Load patterns and anomalies from other components
        await this.loadPatternData();
        await this.loadAnomalyData();
    }

    /**
     * Load pattern data from pattern engine
     */
    async loadPatternData() {
        try {
            const patternsFile = '/tmp/patterns-summary.json';
            if (fs.existsSync(patternsFile)) {
                const data = JSON.parse(fs.readFileSync(patternsFile, 'utf8'));
                this.patterns = data.patterns || [];
            }
        } catch (error) {
            console.warn('Could not load pattern data:', error.message);
        }
    }

    /**
     * Load anomaly data from analytics engine
     */
    async loadAnomalyData() {
        try {
            const analyticsFile = '/tmp/analytics-summary.json';
            if (fs.existsSync(analyticsFile)) {
                const data = JSON.parse(fs.readFileSync(analyticsFile, 'utf8'));
                this.anomalies = data.anomalies || [];
            }
        } catch (error) {
            console.warn('Could not load anomaly data:', error.message);
        }
    }

    /**
     * Generate system optimization recommendations
     */
    async generateOptimizationRecommendations() {
        const recommendations = [];
        
        // CPU optimization
        const cpuUsage = this.systemMetrics.get('cpu_usage') || 0;
        if (cpuUsage > 80) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'optimization',
                category: 'cpu',
                title: 'High CPU Usage Optimization',
                description: 'System CPU usage is consistently high. Consider implementing CPU optimization strategies.',
                priority: 'high',
                impact: 'performance',
                effort: 'medium',
                confidence: 0.9,
                actions: [
                    'Identify CPU-intensive processes',
                    'Implement process optimization',
                    'Consider adding CPU cores or upgrading hardware',
                    'Enable CPU throttling for non-critical processes'
                ],
                metrics: { current_cpu: cpuUsage, target_cpu: 70 },
                estimatedBenefit: 'Reduce CPU usage by 15-20%',
                riskLevel: 'low'
            });
        }
        
        // Memory optimization
        const memoryUsage = this.systemMetrics.get('memory_usage') || 0;
        if (memoryUsage > 85) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'optimization',
                category: 'memory',
                title: 'Memory Usage Optimization',
                description: 'Memory usage is approaching critical levels. Optimize memory allocation.',
                priority: 'high',
                impact: 'stability',
                effort: 'medium',
                confidence: 0.85,
                actions: [
                    'Analyze memory-intensive applications',
                    'Implement memory caching strategies',
                    'Configure swap file optimization',
                    'Consider memory hardware upgrade'
                ],
                metrics: { current_memory: memoryUsage, target_memory: 75 },
                estimatedBenefit: 'Improve system stability and reduce OOM risks',
                riskLevel: 'low'
            });
        }
        
        // Disk optimization
        const diskUsage = this.systemMetrics.get('disk_usage') || 0;
        if (diskUsage > 80) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'optimization',
                category: 'storage',
                title: 'Disk Space Optimization',
                description: 'Disk usage is high. Implement disk cleanup and optimization strategies.',
                priority: 'medium',
                impact: 'performance',
                effort: 'low',
                confidence: 0.95,
                actions: [
                    'Clean up temporary files and logs',
                    'Implement log rotation policies',
                    'Archive old data',
                    'Consider additional storage capacity'
                ],
                metrics: { current_disk: diskUsage, target_disk: 70 },
                estimatedBenefit: 'Free up 10-15% disk space',
                riskLevel: 'very_low'
            });
        }
        
        // Network optimization
        const networkUtil = this.systemMetrics.get('network_utilization') || 0;
        if (networkUtil > 75) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'optimization',
                category: 'network',
                title: 'Network Performance Optimization',
                description: 'Network utilization is high. Optimize network configuration and traffic.',
                priority: 'medium',
                impact: 'performance',
                effort: 'medium',
                confidence: 0.8,
                actions: [
                    'Implement traffic shaping',
                    'Optimize network buffer sizes',
                    'Enable compression for data transfers',
                    'Consider bandwidth upgrade'
                ],
                metrics: { current_network: networkUtil, target_network: 60 },
                estimatedBenefit: 'Improve network responsiveness by 20%',
                riskLevel: 'low'
            });
        }
        
        return recommendations;
    }

    /**
     * Generate security recommendations
     */
    async generateSecurityRecommendations() {
        const recommendations = [];
        
        // Failed login analysis
        const errorRate = this.systemMetrics.get('error_rate') || 0;
        if (errorRate > 0.05) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'security',
                category: 'authentication',
                title: 'Implement Enhanced Authentication Security',
                description: 'High error rate detected, potentially indicating brute force attempts.',
                priority: 'critical',
                impact: 'security',
                effort: 'medium',
                confidence: 0.8,
                actions: [
                    'Enable account lockout policies',
                    'Implement CAPTCHA for failed attempts',
                    'Set up IP-based blocking',
                    'Enable multi-factor authentication'
                ],
                estimatedBenefit: 'Reduce security threats by 70%',
                riskLevel: 'low'
            });
        }
        
        // Certificate management
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'security',
            category: 'certificates',
            title: 'Certificate Expiration Monitoring',
            description: 'Implement automated certificate monitoring and renewal.',
            priority: 'high',
            impact: 'security',
            effort: 'low',
            confidence: 0.9,
            actions: [
                'Set up certificate expiration alerts',
                'Implement automated certificate renewal',
                'Monitor certificate chain validity',
                'Create certificate backup procedures'
            ],
            estimatedBenefit: 'Prevent service outages due to expired certificates',
            riskLevel: 'very_low'
        });
        
        // Vulnerability scanning
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'security',
            category: 'vulnerability',
            title: 'Regular Vulnerability Assessments',
            description: 'Implement automated vulnerability scanning and assessment.',
            priority: 'high',
            impact: 'security',
            effort: 'medium',
            confidence: 0.85,
            actions: [
                'Set up automated vulnerability scans',
                'Implement patch management system',
                'Create security baseline configurations',
                'Establish security incident response plan'
            ],
            estimatedBenefit: 'Early detection and mitigation of security vulnerabilities',
            riskLevel: 'low'
        });
        
        // Access control
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'security',
            category: 'access_control',
            title: 'Implement Role-Based Access Control',
            description: 'Enhance access control with granular permission management.',
            priority: 'medium',
            impact: 'security',
            effort: 'high',
            confidence: 0.9,
            actions: [
                'Define role-based access policies',
                'Implement least privilege principle',
                'Set up access audit logging',
                'Regular access review processes'
            ],
            estimatedBenefit: 'Reduce unauthorized access risks by 60%',
            riskLevel: 'low'
        });
        
        return recommendations;
    }

    /**
     * Generate resource allocation recommendations
     */
    async generateResourceRecommendations() {
        const recommendations = [];
        
        // Load balancing
        const activeConnections = this.systemMetrics.get('active_connections') || 0;
        if (activeConnections > 500) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'resource',
                category: 'load_balancing',
                title: 'Implement Load Balancing',
                description: 'High connection count detected. Consider load balancing implementation.',
                priority: 'medium',
                impact: 'performance',
                effort: 'high',
                confidence: 0.8,
                actions: [
                    'Deploy load balancer',
                    'Configure server clustering',
                    'Implement session persistence',
                    'Set up health monitoring'
                ],
                metrics: { current_connections: activeConnections, target_distribution: 'balanced' },
                estimatedBenefit: 'Improve response times by 30-40%',
                riskLevel: 'medium'
            });
        }
        
        // Database optimization
        const responseTime = this.systemMetrics.get('response_time') || 0;
        if (responseTime > 2000) {
            recommendations.push({
                id: crypto.randomUUID(),
                type: 'resource',
                category: 'database',
                title: 'Database Performance Optimization',
                description: 'Slow response times detected. Optimize database performance.',
                priority: 'high',
                impact: 'performance',
                effort: 'medium',
                confidence: 0.85,
                actions: [
                    'Analyze and optimize database queries',
                    'Implement database indexing strategy',
                    'Set up database connection pooling',
                    'Consider database caching'
                ],
                metrics: { current_response_time: responseTime, target_response_time: 1000 },
                estimatedBenefit: 'Reduce response times by 50%',
                riskLevel: 'low'
            });
        }
        
        // Caching strategy
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'resource',
            category: 'caching',
            title: 'Implement Intelligent Caching',
            description: 'Deploy caching mechanisms to improve system performance.',
            priority: 'medium',
            impact: 'performance',
            effort: 'medium',
            confidence: 0.9,
            actions: [
                'Implement Redis/Memcached caching',
                'Set up application-level caching',
                'Configure browser caching policies',
                'Implement cache invalidation strategies'
            ],
            estimatedBenefit: 'Reduce server load by 40% and improve response times',
            riskLevel: 'low'
        });
        
        return recommendations;
    }

    /**
     * Generate application update recommendations
     */
    async generateUpdateRecommendations() {
        const recommendations = [];
        
        // Security updates
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'update',
            category: 'security_updates',
            title: 'Critical Security Updates',
            description: 'Apply critical security patches and updates.',
            priority: 'critical',
            impact: 'security',
            effort: 'low',
            confidence: 0.95,
            actions: [
                'Review available security patches',
                'Test updates in staging environment',
                'Schedule maintenance window',
                'Apply security updates'
            ],
            estimatedBenefit: 'Address known security vulnerabilities',
            riskLevel: 'low'
        });
        
        // Performance updates
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'update',
            category: 'performance_updates',
            title: 'Performance Enhancement Updates',
            description: 'Update applications and services for better performance.',
            priority: 'medium',
            impact: 'performance',
            effort: 'medium',
            confidence: 0.8,
            actions: [
                'Identify performance-enhancing updates',
                'Benchmark current performance',
                'Test updates in controlled environment',
                'Deploy performance updates'
            ],
            estimatedBenefit: 'Improve system performance by 15-25%',
            riskLevel: 'medium'
        });
        
        return recommendations;
    }

    /**
     * Generate policy optimization recommendations
     */
    async generatePolicyRecommendations() {
        const recommendations = [];
        
        // Backup policy
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'policy',
            category: 'backup',
            title: 'Optimize Backup Policies',
            description: 'Review and optimize backup strategies and schedules.',
            priority: 'high',
            impact: 'reliability',
            effort: 'low',
            confidence: 0.9,
            actions: [
                'Review current backup schedules',
                'Implement incremental backup strategies',
                'Test backup restoration procedures',
                'Set up backup monitoring and alerts'
            ],
            estimatedBenefit: 'Improve data protection and reduce recovery time',
            riskLevel: 'very_low'
        });
        
        // Retention policy
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'policy',
            category: 'retention',
            title: 'Data Retention Policy Optimization',
            description: 'Implement intelligent data retention and archival policies.',
            priority: 'medium',
            impact: 'storage',
            effort: 'medium',
            confidence: 0.85,
            actions: [
                'Define data retention requirements',
                'Implement automated archival processes',
                'Set up data lifecycle management',
                'Configure compliance reporting'
            ],
            estimatedBenefit: 'Reduce storage costs by 20-30%',
            riskLevel: 'low'
        });
        
        return recommendations;
    }

    /**
     * Generate cost optimization recommendations
     */
    async generateCostOptimizationRecommendations() {
        const recommendations = [];
        
        // Resource rightsizing
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'cost',
            category: 'rightsizing',
            title: 'Resource Rightsizing Analysis',
            description: 'Analyze resource utilization and rightsize infrastructure.',
            priority: 'medium',
            impact: 'cost',
            effort: 'medium',
            confidence: 0.8,
            actions: [
                'Analyze resource utilization patterns',
                'Identify oversized resources',
                'Plan resource optimization',
                'Implement rightsizing recommendations'
            ],
            estimatedBenefit: 'Reduce infrastructure costs by 15-25%',
            riskLevel: 'medium'
        });
        
        // Automation
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'cost',
            category: 'automation',
            title: 'Process Automation Implementation',
            description: 'Automate routine tasks to reduce operational costs.',
            priority: 'medium',
            impact: 'efficiency',
            effort: 'high',
            confidence: 0.85,
            actions: [
                'Identify automatable processes',
                'Design automation workflows',
                'Implement automation tools',
                'Monitor automation effectiveness'
            ],
            estimatedBenefit: 'Reduce operational overhead by 30%',
            riskLevel: 'low'
        });
        
        return recommendations;
    }

    /**
     * Generate performance tuning recommendations
     */
    async generatePerformanceRecommendations() {
        const recommendations = [];
        
        // Application performance
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'performance',
            category: 'application',
            title: 'Application Performance Tuning',
            description: 'Optimize application performance through configuration tuning.',
            priority: 'medium',
            impact: 'performance',
            effort: 'medium',
            confidence: 0.8,
            actions: [
                'Profile application performance',
                'Optimize database queries',
                'Implement code optimizations',
                'Configure performance monitoring'
            ],
            estimatedBenefit: 'Improve application responsiveness by 25%',
            riskLevel: 'low'
        });
        
        // System tuning
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'performance',
            category: 'system',
            title: 'System-Level Performance Tuning',
            description: 'Optimize system-level configurations for better performance.',
            priority: 'medium',
            impact: 'performance',
            effort: 'low',
            confidence: 0.9,
            actions: [
                'Tune kernel parameters',
                'Optimize I/O scheduling',
                'Configure network stack',
                'Implement performance baselines'
            ],
            estimatedBenefit: 'Improve overall system performance by 15%',
            riskLevel: 'low'
        });
        
        return recommendations;
    }

    /**
     * Generate maintenance recommendations
     */
    async generateMaintenanceRecommendations() {
        const recommendations = [];
        
        // Preventive maintenance
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'maintenance',
            category: 'preventive',
            title: 'Scheduled Preventive Maintenance',
            description: 'Implement regular preventive maintenance procedures.',
            priority: 'medium',
            impact: 'reliability',
            effort: 'low',
            confidence: 0.9,
            actions: [
                'Schedule regular system health checks',
                'Implement log rotation and cleanup',
                'Plan hardware health monitoring',
                'Set up maintenance notifications'
            ],
            estimatedBenefit: 'Reduce unexpected downtime by 40%',
            riskLevel: 'very_low'
        });
        
        // Health monitoring
        recommendations.push({
            id: crypto.randomUUID(),
            type: 'maintenance',
            category: 'monitoring',
            title: 'Enhanced Health Monitoring',
            description: 'Implement comprehensive system health monitoring.',
            priority: 'high',
            impact: 'visibility',
            effort: 'medium',
            confidence: 0.85,
            actions: [
                'Deploy advanced monitoring tools',
                'Set up predictive health alerts',
                'Implement automated health reports',
                'Create health dashboards'
            ],
            estimatedBenefit: 'Early detection of 80% of potential issues',
            riskLevel: 'low'
        });
        
        return recommendations;
    }

    /**
     * Rank recommendations by priority and impact
     */
    rankRecommendations(recommendations) {
        return recommendations
            .filter(rec => rec.confidence >= this.config.minConfidence)
            .filter(rec => !this.executedRecommendations.has(rec.id))
            .sort((a, b) => {
                // Priority ranking
                const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
                const aPriority = priorityOrder[a.priority] || 0;
                const bPriority = priorityOrder[b.priority] || 0;
                
                if (aPriority !== bPriority) {
                    return bPriority - aPriority;
                }
                
                // Confidence ranking
                if (a.confidence !== b.confidence) {
                    return b.confidence - a.confidence;
                }
                
                // Effort ranking (prefer lower effort)
                const effortOrder = { low: 3, medium: 2, high: 1 };
                const aEffort = effortOrder[a.effort] || 0;
                const bEffort = effortOrder[b.effort] || 0;
                
                return bEffort - aEffort;
            })
            .slice(0, this.config.maxRecommendations);
    }

    /**
     * Update recommendations database
     */
    updateRecommendations(recommendations, timestamp) {
        // Clear old recommendations
        this.recommendations.clear();
        
        // Add new recommendations
        recommendations.forEach(rec => {
            this.recommendations.set(rec.id, {
                ...rec,
                createdAt: timestamp,
                status: 'pending'
            });
        });
    }

    /**
     * Get recommendations by category
     */
    getRecommendationsByCategory(category) {
        return Array.from(this.recommendations.values())
            .filter(rec => rec.category === category);
    }

    /**
     * Get recommendations by type
     */
    getRecommendationsByType(type) {
        return Array.from(this.recommendations.values())
            .filter(rec => rec.type === type);
    }

    /**
     * Get recommendations by priority
     */
    getRecommendationsByPriority(priority) {
        return Array.from(this.recommendations.values())
            .filter(rec => rec.priority === priority);
    }

    /**
     * Get all recommendations
     */
    getAllRecommendations() {
        return Array.from(this.recommendations.values());
    }

    /**
     * Mark recommendation as executed
     */
    markRecommendationExecuted(recommendationId, result = {}) {
        this.executedRecommendations.add(recommendationId);
        
        if (this.recommendations.has(recommendationId)) {
            const rec = this.recommendations.get(recommendationId);
            rec.status = 'executed';
            rec.executedAt = Date.now();
            rec.result = result;
        }
    }

    /**
     * Get recommendation statistics
     */
    getRecommendationStatistics() {
        const all = Array.from(this.recommendations.values());
        const stats = {
            total: all.length,
            byPriority: {},
            byType: {},
            byCategory: {},
            executed: this.executedRecommendations.size,
            pending: all.filter(r => r.status === 'pending').length
        };
        
        all.forEach(rec => {
            // By priority
            stats.byPriority[rec.priority] = (stats.byPriority[rec.priority] || 0) + 1;
            
            // By type
            stats.byType[rec.type] = (stats.byType[rec.type] || 0) + 1;
            
            // By category
            stats.byCategory[rec.category] = (stats.byCategory[rec.category] || 0) + 1;
        });
        
        return stats;
    }

    /**
     * Store recommendations to persistent storage
     */
    async storeRecommendations(timestamp) {
        try {
            const recommendationsData = {
                timestamp: timestamp,
                recommendations: Object.fromEntries(this.recommendations),
                executed: Array.from(this.executedRecommendations),
                statistics: this.getRecommendationStatistics()
            };
            
            await fs.promises.writeFile('/tmp/recommendations-database.json', JSON.stringify(recommendationsData, null, 2));
            
            // Store history
            const historyData = {
                timestamp: timestamp,
                executed: Array.from(this.executedRecommendations)
            };
            
            await fs.promises.writeFile('/tmp/recommendation-history.json', JSON.stringify(historyData, null, 2));
            
            // Create summary
            const summary = {
                timestamp: timestamp,
                totalRecommendations: this.recommendations.size,
                criticalRecommendations: Array.from(this.recommendations.values()).filter(r => r.priority === 'critical').length,
                highPriorityRecommendations: Array.from(this.recommendations.values()).filter(r => r.priority === 'high').length,
                executedRecommendations: this.executedRecommendations.size
            };
            
            await fs.promises.writeFile('/tmp/recommendations-summary.json', JSON.stringify(summary, null, 2));
            
        } catch (error) {
            console.error('Failed to store recommendations:', error);
        }
    }

    /**
     * Utility sleep function
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Shutdown the engine
     */
    async shutdown() {
        this.isRunning = false;
        await this.storeRecommendations(Date.now());
        console.log('Intelligent Recommendation Engine shut down successfully');
    }
}

// REST API Interface
class RecommendationAPI {
    constructor(engine) {
        this.engine = engine;
    }

    getMiddleware() {
        return {
            '/api/recommendations/all': this.getAllRecommendations.bind(this),
            '/api/recommendations/category/:category': this.getByCategory.bind(this),
            '/api/recommendations/type/:type': this.getByType.bind(this),
            '/api/recommendations/priority/:priority': this.getByPriority.bind(this),
            '/api/recommendations/statistics': this.getStatistics.bind(this),
            '/api/recommendations/execute': this.executeRecommendation.bind(this)
        };
    }

    async getAllRecommendations(req, res) {
        try {
            const recommendations = this.engine.getAllRecommendations();
            res.json({ success: true, data: recommendations });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getByCategory(req, res) {
        try {
            const category = req.params.category;
            const recommendations = this.engine.getRecommendationsByCategory(category);
            res.json({ success: true, data: recommendations });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getByType(req, res) {
        try {
            const type = req.params.type;
            const recommendations = this.engine.getRecommendationsByType(type);
            res.json({ success: true, data: recommendations });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getByPriority(req, res) {
        try {
            const priority = req.params.priority;
            const recommendations = this.engine.getRecommendationsByPriority(priority);
            res.json({ success: true, data: recommendations });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getStatistics(req, res) {
        try {
            const statistics = this.engine.getRecommendationStatistics();
            res.json({ success: true, data: statistics });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async executeRecommendation(req, res) {
        try {
            const { recommendationId, result } = req.body;
            
            if (!recommendationId) {
                return res.status(400).json({ success: false, error: 'Recommendation ID required' });
            }
            
            this.engine.markRecommendationExecuted(recommendationId, result);
            res.json({ success: true, message: 'Recommendation marked as executed' });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }
}

module.exports = {
    IntelligentRecommendationEngine,
    RecommendationAPI
};

// Example usage
if (require.main === module) {
    const engine = new IntelligentRecommendationEngine({
        analysisInterval: 600000 // 10 minutes for demo
    });

    engine.initialize().then(() => {
        console.log('Intelligent Recommendation Engine running...');
        
        process.on('SIGINT', async () => {
            console.log('Shutting down recommendation engine...');
            await engine.shutdown();
            process.exit(0);
        });
    }).catch(error => {
        console.error('Failed to initialize recommendation engine:', error);
        process.exit(1);
    });
}