/**
 * OpenDirectory Predictive Maintenance System
 * 
 * Advanced predictive maintenance capabilities for proactive system management,
 * hardware failure prediction, and automated maintenance scheduling.
 * 
 * Features:
 * - Hardware failure prediction using SMART data and usage patterns
 * - Disk failure prediction and early warning systems
 * - Certificate and license expiration tracking
 * - Service degradation prediction
 * - Maintenance window optimization
 * - Automated maintenance scheduling
 * - Risk assessment and scoring
 * - Preventive maintenance recommendations
 */

const fs = require('fs');
const crypto = require('crypto');

class PredictiveMaintenanceSystem {
    constructor(config = {}) {
        this.config = {
            analysisInterval: config.analysisInterval || 1800000, // 30 minutes
            predictionHorizon: config.predictionHorizon || 30 * 24 * 60 * 60 * 1000, // 30 days
            riskThresholds: {
                critical: 0.8,
                high: 0.6,
                medium: 0.4,
                low: 0.2
            },
            maintenanceWindow: {
                preferredDays: ['saturday', 'sunday'],
                preferredHours: [2, 3, 4, 5], // 2-6 AM
                maxDuration: 4 * 60 * 60 * 1000 // 4 hours
            },
            ...config
        };

        this.hardwareComponents = new Map();
        this.certificates = new Map();
        this.licenses = new Map();
        this.services = new Map();
        this.maintenanceSchedule = new Map();
        this.riskAssessments = new Map();
        this.isRunning = false;
    }

    /**
     * Initialize the predictive maintenance system
     */
    async initialize() {
        console.log('Initializing Predictive Maintenance System...');
        
        // Load existing maintenance data
        await this.loadMaintenanceData();
        
        // Discover system components
        await this.discoverSystemComponents();
        
        // Start predictive analysis
        this.startPredictiveAnalysis();
        
        console.log('Predictive Maintenance System initialized successfully');
        return this;
    }

    /**
     * Load existing maintenance data
     */
    async loadMaintenanceData() {
        try {
            const maintenanceFile = '/tmp/maintenance-database.json';
            if (fs.existsSync(maintenanceFile)) {
                const data = JSON.parse(fs.readFileSync(maintenanceFile, 'utf8'));
                
                if (data.schedule) {
                    Object.entries(data.schedule).forEach(([key, maintenance]) => {
                        this.maintenanceSchedule.set(key, maintenance);
                    });
                }
                
                if (data.risks) {
                    Object.entries(data.risks).forEach(([key, risk]) => {
                        this.riskAssessments.set(key, risk);
                    });
                }
                
                console.log(`Loaded maintenance data for ${this.maintenanceSchedule.size} components`);
            }
        } catch (error) {
            console.warn('Could not load maintenance data:', error.message);
        }
    }

    /**
     * Discover system components for monitoring
     */
    async discoverSystemComponents() {
        // In real implementation, this would scan actual system components
        // For now, we'll simulate discovering various components
        
        // Hardware components
        this.hardwareComponents.set('disk_sda', {
            type: 'storage',
            device: '/dev/sda',
            capacity: 1000000000000, // 1TB
            smart: {
                temperature: 35,
                powerOnHours: 8760,
                reallocatedSectors: 0,
                currentPendingSectors: 0,
                offlineUncorrectable: 0,
                rawReadErrorRate: 0
            },
            lastHealthCheck: Date.now(),
            vendor: 'Seagate',
            model: 'ST1000DM003'
        });
        
        this.hardwareComponents.set('disk_sdb', {
            type: 'storage',
            device: '/dev/sdb',
            capacity: 2000000000000, // 2TB
            smart: {
                temperature: 38,
                powerOnHours: 15000,
                reallocatedSectors: 2,
                currentPendingSectors: 0,
                offlineUncorrectable: 0,
                rawReadErrorRate: 1
            },
            lastHealthCheck: Date.now(),
            vendor: 'Western Digital',
            model: 'WD2000FYYZ'
        });
        
        this.hardwareComponents.set('cpu_0', {
            type: 'processor',
            cores: 8,
            temperature: 45,
            utilization: Math.random() * 100,
            throttlingEvents: 0,
            lastHealthCheck: Date.now(),
            vendor: 'Intel',
            model: 'Xeon E5-2640'
        });
        
        this.hardwareComponents.set('memory_0', {
            type: 'memory',
            capacity: 32000000000, // 32GB
            correctedErrors: 0,
            uncorrectedErrors: 0,
            temperature: 42,
            lastHealthCheck: Date.now(),
            vendor: 'Kingston',
            model: 'DDR4-2400'
        });
        
        // Certificates
        this.certificates.set('ssl_primary', {
            domain: 'opendirectory.example.com',
            issuer: 'Let\'s Encrypt',
            issuedDate: Date.now() - (30 * 24 * 60 * 60 * 1000), // 30 days ago
            expirationDate: Date.now() + (60 * 24 * 60 * 60 * 1000), // 60 days from now
            autoRenewal: true,
            keySize: 2048,
            status: 'active'
        });
        
        this.certificates.set('ssl_secondary', {
            domain: '*.api.opendirectory.com',
            issuer: 'DigiCert',
            issuedDate: Date.now() - (200 * 24 * 60 * 60 * 1000), // 200 days ago
            expirationDate: Date.now() + (165 * 24 * 60 * 60 * 1000), // 165 days from now
            autoRenewal: false,
            keySize: 2048,
            status: 'active'
        });
        
        // Software licenses
        this.licenses.set('database_license', {
            software: 'Enterprise Database',
            licensedUsers: 100,
            currentUsers: 85,
            expirationDate: Date.now() + (90 * 24 * 60 * 60 * 1000), // 90 days
            renewalRequired: true,
            cost: 50000,
            vendor: 'DatabaseCorp'
        });
        
        // Services
        this.services.set('web_server', {
            name: 'Apache HTTP Server',
            version: '2.4.41',
            status: 'running',
            uptime: 86400000, // 1 day
            memoryUsage: 512000000, // 512MB
            cpuUsage: Math.random() * 50,
            connections: Math.floor(Math.random() * 1000),
            errorRate: Math.random() * 0.01,
            lastRestart: Date.now() - 86400000
        });
        
        this.services.set('database', {
            name: 'MySQL Server',
            version: '8.0.25',
            status: 'running',
            uptime: 2592000000, // 30 days
            memoryUsage: 2048000000, // 2GB
            cpuUsage: Math.random() * 70,
            connections: Math.floor(Math.random() * 200),
            errorRate: Math.random() * 0.005,
            lastRestart: Date.now() - 2592000000
        });
    }

    /**
     * Start continuous predictive analysis
     */
    startPredictiveAnalysis() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.analysisLoop();
    }

    /**
     * Stop predictive analysis
     */
    stopPredictiveAnalysis() {
        this.isRunning = false;
    }

    /**
     * Main analysis loop
     */
    async analysisLoop() {
        while (this.isRunning) {
            try {
                await this.performPredictiveAnalysis();
                await this.sleep(this.config.analysisInterval);
            } catch (error) {
                console.error('Predictive analysis error:', error);
                await this.sleep(60000); // Wait 1 minute on error
            }
        }
    }

    /**
     * Perform comprehensive predictive analysis
     */
    async performPredictiveAnalysis() {
        const timestamp = Date.now();
        
        // Update component health data
        await this.updateHealthData();
        
        // Perform various predictions
        const hardwareFailures = await this.predictHardwareFailures();
        const diskFailures = await this.predictDiskFailures();
        const expirations = await this.trackExpirations();
        const serviceIssues = await this.predictServiceDegradation();
        
        // Calculate risk assessments
        this.calculateRiskAssessments();
        
        // Optimize maintenance windows
        this.optimizeMaintenanceWindows();
        
        // Schedule maintenance tasks
        this.scheduleMaintenanceTasks();
        
        // Store results
        await this.storeMaintenanceData(timestamp);
    }

    /**
     * Update health data for all components
     */
    async updateHealthData() {
        // Update hardware component health
        this.hardwareComponents.forEach((component, id) => {
            if (component.type === 'storage') {
                // Simulate SMART data updates
                component.smart.temperature = 30 + Math.random() * 20;
                component.smart.powerOnHours += 0.5; // Half hour increment
                
                // Occasionally increment wear indicators
                if (Math.random() < 0.01) {
                    component.smart.reallocatedSectors += 1;
                }
                if (Math.random() < 0.005) {
                    component.smart.currentPendingSectors += 1;
                }
            } else if (component.type === 'processor') {
                component.temperature = 35 + Math.random() * 25;
                component.utilization = Math.random() * 100;
            } else if (component.type === 'memory') {
                component.temperature = 35 + Math.random() * 15;
                
                // Very rare memory errors
                if (Math.random() < 0.001) {
                    component.correctedErrors += 1;
                }
            }
            
            component.lastHealthCheck = Date.now();
        });
        
        // Update service health
        this.services.forEach((service, id) => {
            service.uptime += this.config.analysisInterval;
            service.cpuUsage = Math.random() * 80;
            service.memoryUsage *= (0.95 + Math.random() * 0.1); // Slight variation
            service.connections = Math.floor(Math.random() * service.connections * 1.2);
            service.errorRate = Math.random() * 0.02;
        });
    }

    /**
     * Predict hardware failures
     */
    async predictHardwareFailures() {
        const predictions = [];
        
        this.hardwareComponents.forEach((component, id) => {
            const prediction = this.analyzeComponentHealth(component, id);
            if (prediction.riskScore > this.config.riskThresholds.medium) {
                predictions.push(prediction);
            }
        });
        
        return predictions;
    }

    /**
     * Analyze individual component health
     */
    analyzeComponentHealth(component, componentId) {
        let riskScore = 0;
        const riskFactors = [];
        
        if (component.type === 'storage') {
            // SMART data analysis
            const smart = component.smart;
            
            // Temperature risk
            if (smart.temperature > 50) {
                riskScore += 0.2;
                riskFactors.push('high_temperature');
            }
            
            // Power-on hours risk
            const powerOnYears = smart.powerOnHours / (24 * 365);
            if (powerOnYears > 3) {
                riskScore += 0.3;
                riskFactors.push('high_power_on_hours');
            }
            
            // Reallocated sectors risk
            if (smart.reallocatedSectors > 0) {
                riskScore += 0.4;
                riskFactors.push('reallocated_sectors');
            }
            
            // Pending sectors risk
            if (smart.currentPendingSectors > 0) {
                riskScore += 0.5;
                riskFactors.push('pending_sectors');
            }
            
            // Offline uncorrectable risk
            if (smart.offlineUncorrectable > 0) {
                riskScore += 0.6;
                riskFactors.push('uncorrectable_errors');
            }
            
            // Read error rate risk
            if (smart.rawReadErrorRate > 0) {
                riskScore += 0.2;
                riskFactors.push('read_errors');
            }
            
        } else if (component.type === 'processor') {
            // CPU temperature risk
            if (component.temperature > 70) {
                riskScore += 0.3;
                riskFactors.push('high_cpu_temperature');
            }
            
            // High utilization risk
            if (component.utilization > 90) {
                riskScore += 0.1;
                riskFactors.push('high_utilization');
            }
            
            // Throttling events
            if (component.throttlingEvents > 0) {
                riskScore += 0.4;
                riskFactors.push('thermal_throttling');
            }
            
        } else if (component.type === 'memory') {
            // Memory errors
            if (component.correctedErrors > 10) {
                riskScore += 0.3;
                riskFactors.push('corrected_errors');
            }
            
            if (component.uncorrectedErrors > 0) {
                riskScore += 0.8;
                riskFactors.push('uncorrected_errors');
            }
            
            // Temperature risk
            if (component.temperature > 55) {
                riskScore += 0.2;
                riskFactors.push('high_memory_temperature');
            }
        }
        
        // Cap risk score at 1.0
        riskScore = Math.min(riskScore, 1.0);
        
        return {
            componentId: componentId,
            type: component.type,
            riskScore: riskScore,
            riskLevel: this.getRiskLevel(riskScore),
            riskFactors: riskFactors,
            predictedFailureDate: this.calculateFailureDate(riskScore),
            recommendedActions: this.getRecommendedActions(component, riskFactors),
            confidence: this.calculateConfidence(component, riskFactors)
        };
    }

    /**
     * Predict disk failures specifically
     */
    async predictDiskFailures() {
        const diskFailures = [];
        
        this.hardwareComponents.forEach((component, id) => {
            if (component.type === 'storage') {
                const failurePrediction = this.predictDiskFailure(component, id);
                if (failurePrediction.likelihood > 0.3) {
                    diskFailures.push(failurePrediction);
                }
            }
        });
        
        return diskFailures;
    }

    /**
     * Predict individual disk failure
     */
    predictDiskFailure(disk, diskId) {
        const smart = disk.smart;
        let failureLikelihood = 0;
        const indicators = [];
        
        // Age factor
        const ageYears = smart.powerOnHours / (24 * 365);
        if (ageYears > 5) {
            failureLikelihood += 0.3;
            indicators.push('old_age');
        } else if (ageYears > 3) {
            failureLikelihood += 0.1;
            indicators.push('moderate_age');
        }
        
        // Critical SMART attributes
        if (smart.reallocatedSectors > 5) {
            failureLikelihood += 0.6;
            indicators.push('excessive_reallocated_sectors');
        } else if (smart.reallocatedSectors > 0) {
            failureLikelihood += 0.2;
            indicators.push('some_reallocated_sectors');
        }
        
        if (smart.currentPendingSectors > 0) {
            failureLikelihood += 0.4;
            indicators.push('pending_sectors');
        }
        
        if (smart.offlineUncorrectable > 0) {
            failureLikelihood += 0.5;
            indicators.push('uncorrectable_sectors');
        }
        
        // Temperature degradation
        if (smart.temperature > 55) {
            failureLikelihood += 0.3;
            indicators.push('excessive_temperature');
        } else if (smart.temperature > 45) {
            failureLikelihood += 0.1;
            indicators.push('high_temperature');
        }
        
        // Read error rate
        if (smart.rawReadErrorRate > 10) {
            failureLikelihood += 0.4;
            indicators.push('high_error_rate');
        } else if (smart.rawReadErrorRate > 0) {
            failureLikelihood += 0.1;
            indicators.push('some_read_errors');
        }
        
        failureLikelihood = Math.min(failureLikelihood, 1.0);
        
        return {
            diskId: diskId,
            device: disk.device,
            vendor: disk.vendor,
            model: disk.model,
            likelihood: failureLikelihood,
            timeToFailure: this.estimateTimeToFailure(failureLikelihood),
            indicators: indicators,
            smartData: { ...smart },
            recommendedActions: this.getDiskRecommendations(failureLikelihood, indicators)
        };
    }

    /**
     * Track certificate and license expirations
     */
    async trackExpirations() {
        const expirations = [];
        const now = Date.now();
        
        // Certificate expirations
        this.certificates.forEach((cert, id) => {
            const daysToExpiration = Math.floor((cert.expirationDate - now) / (24 * 60 * 60 * 1000));
            
            if (daysToExpiration <= 30 || (!cert.autoRenewal && daysToExpiration <= 60)) {
                expirations.push({
                    type: 'certificate',
                    id: id,
                    item: cert.domain,
                    expirationDate: cert.expirationDate,
                    daysRemaining: daysToExpiration,
                    autoRenewal: cert.autoRenewal,
                    urgency: this.getExpirationUrgency(daysToExpiration),
                    actions: cert.autoRenewal ? 
                        ['Verify auto-renewal configuration', 'Monitor renewal process'] :
                        ['Schedule manual renewal', 'Prepare certificate signing request', 'Contact certificate authority']
                });
            }
        });
        
        // License expirations
        this.licenses.forEach((license, id) => {
            const daysToExpiration = Math.floor((license.expirationDate - now) / (24 * 60 * 60 * 1000));
            
            if (daysToExpiration <= 90) {
                expirations.push({
                    type: 'license',
                    id: id,
                    item: license.software,
                    expirationDate: license.expirationDate,
                    daysRemaining: daysToExpiration,
                    cost: license.cost,
                    urgency: this.getExpirationUrgency(daysToExpiration),
                    actions: [
                        'Contact vendor for renewal',
                        'Review licensing requirements',
                        'Budget for renewal cost',
                        'Test license renewal process'
                    ]
                });
            }
        });
        
        return expirations;
    }

    /**
     * Predict service degradation
     */
    async predictServiceDegradation() {
        const predictions = [];
        
        this.services.forEach((service, id) => {
            const degradation = this.analyzeServiceHealth(service, id);
            if (degradation.riskScore > this.config.riskThresholds.low) {
                predictions.push(degradation);
            }
        });
        
        return predictions;
    }

    /**
     * Analyze service health for degradation prediction
     */
    analyzeServiceHealth(service, serviceId) {
        let riskScore = 0;
        const riskFactors = [];
        
        // Memory usage trend
        const memoryUsageGB = service.memoryUsage / (1024 * 1024 * 1024);
        if (memoryUsageGB > 4) {
            riskScore += 0.3;
            riskFactors.push('high_memory_usage');
        } else if (memoryUsageGB > 2) {
            riskScore += 0.1;
            riskFactors.push('moderate_memory_usage');
        }
        
        // CPU usage
        if (service.cpuUsage > 80) {
            riskScore += 0.3;
            riskFactors.push('high_cpu_usage');
        } else if (service.cpuUsage > 60) {
            riskScore += 0.1;
            riskFactors.push('moderate_cpu_usage');
        }
        
        // Error rate
        if (service.errorRate > 0.01) {
            riskScore += 0.4;
            riskFactors.push('high_error_rate');
        } else if (service.errorRate > 0.005) {
            riskScore += 0.2;
            riskFactors.push('moderate_error_rate');
        }
        
        // Uptime without restart
        const daysSinceRestart = (Date.now() - service.lastRestart) / (24 * 60 * 60 * 1000);
        if (daysSinceRestart > 90) {
            riskScore += 0.2;
            riskFactors.push('long_uptime');
        }
        
        // Connection overload
        if (service.name.includes('HTTP') && service.connections > 800) {
            riskScore += 0.2;
            riskFactors.push('connection_overload');
        } else if (service.name.includes('MySQL') && service.connections > 150) {
            riskScore += 0.2;
            riskFactors.push('connection_overload');
        }
        
        riskScore = Math.min(riskScore, 1.0);
        
        return {
            serviceId: serviceId,
            serviceName: service.name,
            riskScore: riskScore,
            riskLevel: this.getRiskLevel(riskScore),
            riskFactors: riskFactors,
            recommendedActions: this.getServiceRecommendations(service, riskFactors),
            nextMaintenanceWindow: this.calculateNextMaintenanceWindow()
        };
    }

    /**
     * Calculate risk assessments for all components
     */
    calculateRiskAssessments() {
        const timestamp = Date.now();
        
        // Clear old assessments
        this.riskAssessments.clear();
        
        // Assess hardware risks
        this.hardwareComponents.forEach((component, id) => {
            const assessment = this.analyzeComponentHealth(component, id);
            this.riskAssessments.set(`hardware_${id}`, {
                ...assessment,
                timestamp: timestamp,
                category: 'hardware'
            });
        });
        
        // Assess service risks
        this.services.forEach((service, id) => {
            const assessment = this.analyzeServiceHealth(service, id);
            this.riskAssessments.set(`service_${id}`, {
                ...assessment,
                timestamp: timestamp,
                category: 'service'
            });
        });
        
        // Overall system risk
        const allRisks = Array.from(this.riskAssessments.values());
        const avgRisk = allRisks.reduce((sum, risk) => sum + risk.riskScore, 0) / allRisks.length;
        const maxRisk = Math.max(...allRisks.map(risk => risk.riskScore));
        
        this.riskAssessments.set('system_overall', {
            type: 'system',
            riskScore: Math.max(avgRisk, maxRisk * 0.8), // Weight towards highest risk
            riskLevel: this.getRiskLevel(Math.max(avgRisk, maxRisk * 0.8)),
            components: allRisks.length,
            highRiskComponents: allRisks.filter(r => r.riskScore > this.config.riskThresholds.high).length,
            timestamp: timestamp,
            category: 'system'
        });
    }

    /**
     * Optimize maintenance windows
     */
    optimizeMaintenanceWindows() {
        const maintenanceTasks = this.getMaintenanceTasks();
        const optimizedWindows = new Map();
        
        // Group tasks by urgency and estimated duration
        const urgentTasks = maintenanceTasks.filter(task => task.urgency === 'critical' || task.urgency === 'high');
        const regularTasks = maintenanceTasks.filter(task => task.urgency === 'medium' || task.urgency === 'low');
        
        // Schedule urgent tasks ASAP
        if (urgentTasks.length > 0) {
            const nextUrgentWindow = this.findNextAvailableWindow('urgent');
            optimizedWindows.set('urgent_maintenance', {
                type: 'urgent',
                scheduledTime: nextUrgentWindow,
                tasks: urgentTasks,
                estimatedDuration: this.calculateTotalDuration(urgentTasks),
                impact: 'high'
            });
        }
        
        // Schedule regular tasks in preferred windows
        if (regularTasks.length > 0) {
            const batchedTasks = this.batchTasksByWindow(regularTasks);
            
            batchedTasks.forEach((tasks, windowId) => {
                const scheduledTime = this.findOptimalMaintenanceWindow();
                optimizedWindows.set(`regular_${windowId}`, {
                    type: 'regular',
                    scheduledTime: scheduledTime,
                    tasks: tasks,
                    estimatedDuration: this.calculateTotalDuration(tasks),
                    impact: 'medium'
                });
            });
        }
        
        this.maintenanceSchedule = optimizedWindows;
    }

    /**
     * Schedule maintenance tasks
     */
    scheduleMaintenanceTasks() {
        const tasks = [];
        
        // Hardware maintenance tasks
        this.riskAssessments.forEach((assessment, id) => {
            if (assessment.category === 'hardware' && assessment.riskScore > this.config.riskThresholds.medium) {
                tasks.push({
                    id: crypto.randomUUID(),
                    type: 'hardware_maintenance',
                    componentId: id,
                    description: `Preventive maintenance for ${assessment.type} component`,
                    urgency: this.getMaintenanceUrgency(assessment.riskScore),
                    estimatedDuration: this.getMaintenanceDuration(assessment.type),
                    requiredActions: assessment.recommendedActions,
                    riskReduction: assessment.riskScore * 0.7
                });
            }
        });
        
        // Service maintenance tasks
        this.services.forEach((service, id) => {
            const assessment = this.riskAssessments.get(`service_${id}`);
            if (assessment && assessment.riskScore > this.config.riskThresholds.low) {
                tasks.push({
                    id: crypto.randomUUID(),
                    type: 'service_maintenance',
                    serviceId: id,
                    description: `Service optimization for ${service.name}`,
                    urgency: this.getMaintenanceUrgency(assessment.riskScore),
                    estimatedDuration: 30 * 60 * 1000, // 30 minutes
                    requiredActions: assessment.recommendedActions,
                    riskReduction: assessment.riskScore * 0.5
                });
            }
        });
        
        // Certificate renewal tasks
        this.certificates.forEach((cert, id) => {
            const daysToExpiration = Math.floor((cert.expirationDate - Date.now()) / (24 * 60 * 60 * 1000));
            if (daysToExpiration <= 30 && !cert.autoRenewal) {
                tasks.push({
                    id: crypto.randomUUID(),
                    type: 'certificate_renewal',
                    certificateId: id,
                    description: `Renew SSL certificate for ${cert.domain}`,
                    urgency: daysToExpiration <= 7 ? 'critical' : 'high',
                    estimatedDuration: 60 * 60 * 1000, // 1 hour
                    requiredActions: ['Prepare CSR', 'Contact CA', 'Install certificate', 'Verify deployment'],
                    riskReduction: 1.0
                });
            }
        });
        
        return tasks;
    }

    /**
     * Get all maintenance tasks
     */
    getMaintenanceTasks() {
        return this.scheduleMaintenanceTasks();
    }

    /**
     * Get risk level from score
     */
    getRiskLevel(score) {
        if (score >= this.config.riskThresholds.critical) return 'critical';
        if (score >= this.config.riskThresholds.high) return 'high';
        if (score >= this.config.riskThresholds.medium) return 'medium';
        return 'low';
    }

    /**
     * Calculate predicted failure date
     */
    calculateFailureDate(riskScore) {
        if (riskScore < 0.1) return null;
        
        // Higher risk means sooner failure
        const daysToFailure = Math.max(1, 365 * (1 - riskScore));
        return Date.now() + (daysToFailure * 24 * 60 * 60 * 1000);
    }

    /**
     * Get recommended actions for component
     */
    getRecommendedActions(component, riskFactors) {
        const actions = [];
        
        riskFactors.forEach(factor => {
            switch (factor) {
                case 'high_temperature':
                    actions.push('Check cooling system', 'Clean dust from fans');
                    break;
                case 'reallocated_sectors':
                    actions.push('Schedule immediate backup', 'Plan disk replacement');
                    break;
                case 'pending_sectors':
                    actions.push('Run disk surface scan', 'Monitor sector reallocations');
                    break;
                case 'thermal_throttling':
                    actions.push('Improve CPU cooling', 'Check thermal paste');
                    break;
                case 'corrected_errors':
                    actions.push('Run memory diagnostic', 'Check memory modules');
                    break;
            }
        });
        
        return [...new Set(actions)]; // Remove duplicates
    }

    /**
     * Calculate confidence in prediction
     */
    calculateConfidence(component, riskFactors) {
        let confidence = 0.5; // Base confidence
        
        // More risk factors increase confidence
        confidence += Math.min(riskFactors.length * 0.1, 0.3);
        
        // Recent health check increases confidence
        const hoursSinceCheck = (Date.now() - component.lastHealthCheck) / (60 * 60 * 1000);
        if (hoursSinceCheck < 1) confidence += 0.2;
        else if (hoursSinceCheck < 24) confidence += 0.1;
        
        return Math.min(confidence, 1.0);
    }

    /**
     * Estimate time to failure for disks
     */
    estimateTimeToFailure(likelihood) {
        if (likelihood > 0.8) return { value: 1, unit: 'weeks' };
        if (likelihood > 0.6) return { value: 1, unit: 'months' };
        if (likelihood > 0.4) return { value: 3, unit: 'months' };
        if (likelihood > 0.2) return { value: 6, unit: 'months' };
        return { value: 1, unit: 'years' };
    }

    /**
     * Get disk-specific recommendations
     */
    getDiskRecommendations(likelihood, indicators) {
        const recommendations = ['Monitor SMART attributes closely'];
        
        if (likelihood > 0.7) {
            recommendations.push('Schedule immediate replacement');
            recommendations.push('Perform full backup');
        } else if (likelihood > 0.4) {
            recommendations.push('Order replacement disk');
            recommendations.push('Increase backup frequency');
        } else if (likelihood > 0.2) {
            recommendations.push('Plan for future replacement');
        }
        
        if (indicators.includes('excessive_temperature')) {
            recommendations.push('Improve cooling');
        }
        
        if (indicators.includes('reallocated_sectors')) {
            recommendations.push('Avoid heavy write operations');
        }
        
        return recommendations;
    }

    /**
     * Get expiration urgency level
     */
    getExpirationUrgency(daysRemaining) {
        if (daysRemaining <= 7) return 'critical';
        if (daysRemaining <= 14) return 'high';
        if (daysRemaining <= 30) return 'medium';
        return 'low';
    }

    /**
     * Get service-specific recommendations
     */
    getServiceRecommendations(service, riskFactors) {
        const recommendations = [];
        
        riskFactors.forEach(factor => {
            switch (factor) {
                case 'high_memory_usage':
                    recommendations.push('Optimize memory usage', 'Consider memory upgrade');
                    break;
                case 'high_cpu_usage':
                    recommendations.push('Optimize CPU usage', 'Scale horizontally');
                    break;
                case 'high_error_rate':
                    recommendations.push('Investigate error logs', 'Fix application issues');
                    break;
                case 'long_uptime':
                    recommendations.push('Schedule service restart', 'Apply updates');
                    break;
                case 'connection_overload':
                    recommendations.push('Implement connection pooling', 'Add load balancing');
                    break;
            }
        });
        
        return [...new Set(recommendations)];
    }

    /**
     * Calculate next maintenance window
     */
    calculateNextMaintenanceWindow() {
        const now = new Date();
        const nextSaturday = new Date(now);
        
        // Find next Saturday at 2 AM
        const daysUntilSaturday = (6 - now.getDay()) % 7 || 7;
        nextSaturday.setDate(now.getDate() + daysUntilSaturday);
        nextSaturday.setHours(2, 0, 0, 0);
        
        return nextSaturday.getTime();
    }

    /**
     * Find optimal maintenance window
     */
    findOptimalMaintenanceWindow() {
        // Return next preferred maintenance window
        return this.calculateNextMaintenanceWindow();
    }

    /**
     * Find next available window for urgent tasks
     */
    findNextAvailableWindow(type) {
        const now = new Date();
        
        if (type === 'urgent') {
            // Schedule urgent maintenance for next off-peak hour (2 AM)
            const tomorrow = new Date(now);
            tomorrow.setDate(now.getDate() + 1);
            tomorrow.setHours(2, 0, 0, 0);
            return tomorrow.getTime();
        }
        
        return this.calculateNextMaintenanceWindow();
    }

    /**
     * Calculate total duration for tasks
     */
    calculateTotalDuration(tasks) {
        return tasks.reduce((total, task) => total + (task.estimatedDuration || 0), 0);
    }

    /**
     * Batch tasks by maintenance window
     */
    batchTasksByWindow(tasks) {
        const batches = new Map();
        const maxWindowDuration = this.config.maintenanceWindow.maxDuration;
        
        let currentBatch = [];
        let currentDuration = 0;
        let batchId = 1;
        
        tasks.forEach(task => {
            const taskDuration = task.estimatedDuration || 0;
            
            if (currentDuration + taskDuration <= maxWindowDuration) {
                currentBatch.push(task);
                currentDuration += taskDuration;
            } else {
                if (currentBatch.length > 0) {
                    batches.set(batchId++, [...currentBatch]);
                }
                currentBatch = [task];
                currentDuration = taskDuration;
            }
        });
        
        if (currentBatch.length > 0) {
            batches.set(batchId, currentBatch);
        }
        
        return batches;
    }

    /**
     * Get maintenance urgency from risk score
     */
    getMaintenanceUrgency(riskScore) {
        if (riskScore >= this.config.riskThresholds.critical) return 'critical';
        if (riskScore >= this.config.riskThresholds.high) return 'high';
        if (riskScore >= this.config.riskThresholds.medium) return 'medium';
        return 'low';
    }

    /**
     * Get maintenance duration by component type
     */
    getMaintenanceDuration(componentType) {
        const durations = {
            'storage': 2 * 60 * 60 * 1000, // 2 hours
            'processor': 1 * 60 * 60 * 1000, // 1 hour
            'memory': 30 * 60 * 1000, // 30 minutes
            'network': 1 * 60 * 60 * 1000 // 1 hour
        };
        
        return durations[componentType] || 60 * 60 * 1000; // Default 1 hour
    }

    /**
     * Get all risk assessments
     */
    getAllRiskAssessments() {
        return Array.from(this.riskAssessments.values());
    }

    /**
     * Get risk assessments by level
     */
    getRiskAssessmentsByLevel(level) {
        return Array.from(this.riskAssessments.values())
            .filter(assessment => assessment.riskLevel === level);
    }

    /**
     * Get maintenance schedule
     */
    getMaintenanceSchedule() {
        return Array.from(this.maintenanceSchedule.values());
    }

    /**
     * Get component health status
     */
    getComponentHealth() {
        const health = {
            hardware: {},
            services: {},
            certificates: {},
            licenses: {}
        };
        
        this.hardwareComponents.forEach((component, id) => {
            const assessment = this.riskAssessments.get(`hardware_${id}`);
            health.hardware[id] = {
                type: component.type,
                riskLevel: assessment ? assessment.riskLevel : 'unknown',
                riskScore: assessment ? assessment.riskScore : 0,
                lastCheck: component.lastHealthCheck
            };
        });
        
        this.services.forEach((service, id) => {
            const assessment = this.riskAssessments.get(`service_${id}`);
            health.services[id] = {
                name: service.name,
                status: service.status,
                riskLevel: assessment ? assessment.riskLevel : 'unknown',
                riskScore: assessment ? assessment.riskScore : 0,
                uptime: service.uptime
            };
        });
        
        this.certificates.forEach((cert, id) => {
            const daysToExpiration = Math.floor((cert.expirationDate - Date.now()) / (24 * 60 * 60 * 1000));
            health.certificates[id] = {
                domain: cert.domain,
                daysToExpiration: daysToExpiration,
                autoRenewal: cert.autoRenewal,
                status: cert.status
            };
        });
        
        this.licenses.forEach((license, id) => {
            const daysToExpiration = Math.floor((license.expirationDate - Date.now()) / (24 * 60 * 60 * 1000));
            health.licenses[id] = {
                software: license.software,
                daysToExpiration: daysToExpiration,
                renewalRequired: license.renewalRequired
            };
        });
        
        return health;
    }

    /**
     * Store maintenance data
     */
    async storeMaintenanceData(timestamp) {
        try {
            const maintenanceData = {
                timestamp: timestamp,
                riskAssessments: Object.fromEntries(this.riskAssessments),
                maintenanceSchedule: Object.fromEntries(this.maintenanceSchedule),
                componentHealth: this.getComponentHealth(),
                statistics: {
                    totalComponents: this.hardwareComponents.size,
                    totalServices: this.services.size,
                    totalCertificates: this.certificates.size,
                    totalLicenses: this.licenses.size,
                    criticalRisks: this.getRiskAssessmentsByLevel('critical').length,
                    highRisks: this.getRiskAssessmentsByLevel('high').length
                }
            };
            
            await fs.promises.writeFile('/tmp/maintenance-database.json', JSON.stringify(maintenanceData, null, 2));
            
            // Create summary
            const summary = {
                timestamp: timestamp,
                systemRiskLevel: this.riskAssessments.get('system_overall')?.riskLevel || 'unknown',
                systemRiskScore: this.riskAssessments.get('system_overall')?.riskScore || 0,
                upcomingMaintenanceTasks: this.getMaintenanceTasks().length,
                criticalComponents: this.getRiskAssessmentsByLevel('critical').length,
                expiringCertificates: Array.from(this.certificates.values()).filter(cert => 
                    (cert.expirationDate - Date.now()) / (24 * 60 * 60 * 1000) <= 30
                ).length
            };
            
            await fs.promises.writeFile('/tmp/maintenance-summary.json', JSON.stringify(summary, null, 2));
            
        } catch (error) {
            console.error('Failed to store maintenance data:', error);
        }
    }

    /**
     * Utility sleep function
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Shutdown the system
     */
    async shutdown() {
        this.isRunning = false;
        await this.storeMaintenanceData(Date.now());
        console.log('Predictive Maintenance System shut down successfully');
    }
}

// REST API Interface
class MaintenanceAPI {
    constructor(system) {
        this.system = system;
    }

    getMiddleware() {
        return {
            '/api/maintenance/risks': this.getRiskAssessments.bind(this),
            '/api/maintenance/risks/:level': this.getRisksByLevel.bind(this),
            '/api/maintenance/schedule': this.getMaintenanceSchedule.bind(this),
            '/api/maintenance/health': this.getComponentHealth.bind(this),
            '/api/maintenance/tasks': this.getMaintenanceTasks.bind(this),
            '/api/maintenance/statistics': this.getStatistics.bind(this)
        };
    }

    async getRiskAssessments(req, res) {
        try {
            const assessments = this.system.getAllRiskAssessments();
            res.json({ success: true, data: assessments });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getRisksByLevel(req, res) {
        try {
            const level = req.params.level;
            const assessments = this.system.getRiskAssessmentsByLevel(level);
            res.json({ success: true, data: assessments });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getMaintenanceSchedule(req, res) {
        try {
            const schedule = this.system.getMaintenanceSchedule();
            res.json({ success: true, data: schedule });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getComponentHealth(req, res) {
        try {
            const health = this.system.getComponentHealth();
            res.json({ success: true, data: health });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getMaintenanceTasks(req, res) {
        try {
            const tasks = this.system.getMaintenanceTasks();
            res.json({ success: true, data: tasks });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getStatistics(req, res) {
        try {
            const stats = {
                totalAssessments: this.system.getAllRiskAssessments().length,
                riskDistribution: {
                    critical: this.system.getRiskAssessmentsByLevel('critical').length,
                    high: this.system.getRiskAssessmentsByLevel('high').length,
                    medium: this.system.getRiskAssessmentsByLevel('medium').length,
                    low: this.system.getRiskAssessmentsByLevel('low').length
                },
                upcomingMaintenance: this.system.getMaintenanceSchedule().length,
                componentHealth: this.system.getComponentHealth()
            };
            
            res.json({ success: true, data: stats });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }
}

module.exports = {
    PredictiveMaintenanceSystem,
    MaintenanceAPI
};

// Example usage
if (require.main === module) {
    const system = new PredictiveMaintenanceSystem({
        analysisInterval: 600000 // 10 minutes for demo
    });

    system.initialize().then(() => {
        console.log('Predictive Maintenance System running...');
        
        process.on('SIGINT', async () => {
            console.log('Shutting down maintenance system...');
            await system.shutdown();
            process.exit(0);
        });
    }).catch(error => {
        console.error('Failed to initialize maintenance system:', error);
        process.exit(1);
    });
}