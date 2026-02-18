/**
 * OpenDirectory AI-Powered Predictive Analytics Engine
 * 
 * Provides machine learning-based failure prediction, anomaly detection,
 * and intelligent insights for OpenDirectory MDM systems.
 * 
 * Features:
 * - Real-time failure prediction
 * - Statistical anomaly detection
 * - Resource usage forecasting
 * - Application crash prediction
 * - Security threat detection
 * - Performance analysis
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class PredictiveAnalyticsEngine {
    constructor(config = {}) {
        this.config = {
            analysisInterval: config.analysisInterval || 60000, // 1 minute
            predictionHorizon: config.predictionHorizon || 3600000, // 1 hour
            anomalyThreshold: config.anomalyThreshold || 2.5, // Standard deviations
            minDataPoints: config.minDataPoints || 30,
            maxHistorySize: config.maxHistorySize || 10000,
            ...config
        };

        this.dataHistory = new Map();
        this.models = new Map();
        this.predictions = new Map();
        this.anomalies = [];
        this.isRunning = false;
    }

    /**
     * Initialize the analytics engine
     */
    async initialize() {
        console.log('Initializing Predictive Analytics Engine...');
        
        // Load historical data if available
        await this.loadHistoricalData();
        
        // Initialize prediction models
        this.initializeModels();
        
        // Start real-time analysis
        this.startAnalysis();
        
        console.log('Predictive Analytics Engine initialized successfully');
        return this;
    }

    /**
     * Load historical data for training
     */
    async loadHistoricalData() {
        try {
            const historyFile = '/tmp/analytics-history.json';
            if (fs.existsSync(historyFile)) {
                const data = JSON.parse(fs.readFileSync(historyFile, 'utf8'));
                this.dataHistory = new Map(Object.entries(data.history || {}));
                console.log(`Loaded ${this.dataHistory.size} historical data series`);
            }
        } catch (error) {
            console.warn('Could not load historical data:', error.message);
        }
    }

    /**
     * Initialize prediction models
     */
    initializeModels() {
        const modelTypes = [
            'cpu_usage',
            'memory_usage',
            'disk_usage',
            'network_traffic',
            'application_response_time',
            'error_rate',
            'user_activity',
            'security_events'
        ];

        modelTypes.forEach(type => {
            this.models.set(type, {
                type: 'time_series',
                weights: [],
                bias: 0,
                lastTrained: null,
                accuracy: 0
            });
        });
    }

    /**
     * Start continuous analysis
     */
    startAnalysis() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.analysisLoop();
    }

    /**
     * Stop analysis
     */
    stopAnalysis() {
        this.isRunning = false;
    }

    /**
     * Main analysis loop
     */
    async analysisLoop() {
        while (this.isRunning) {
            try {
                await this.performAnalysis();
                await this.sleep(this.config.analysisInterval);
            } catch (error) {
                console.error('Analysis loop error:', error);
                await this.sleep(5000); // Wait 5 seconds on error
            }
        }
    }

    /**
     * Perform comprehensive analysis
     */
    async performAnalysis() {
        const timestamp = Date.now();
        
        // Collect current system metrics
        const metrics = await this.collectMetrics();
        
        // Update historical data
        this.updateHistory(metrics, timestamp);
        
        // Detect anomalies
        const anomalies = this.detectAnomalies(metrics, timestamp);
        
        // Generate predictions
        const predictions = this.generatePredictions(timestamp);
        
        // Analyze patterns
        const patterns = this.analyzePatterns();
        
        // Update models
        this.updateModels(metrics, timestamp);
        
        // Store results
        await this.storeResults({
            timestamp,
            metrics,
            anomalies,
            predictions,
            patterns
        });
    }

    /**
     * Collect system metrics
     */
    async collectMetrics() {
        // Simulate metric collection - in real implementation, this would
        // interface with actual system monitoring APIs
        return {
            cpu: {
                usage: Math.random() * 100,
                temperature: 40 + Math.random() * 40,
                load_average: [Math.random() * 4, Math.random() * 4, Math.random() * 4]
            },
            memory: {
                used: Math.random() * 8192,
                available: 8192 - (Math.random() * 8192),
                swap_used: Math.random() * 2048
            },
            disk: {
                used_percentage: Math.random() * 100,
                io_read: Math.random() * 1000,
                io_write: Math.random() * 1000,
                queue_depth: Math.random() * 10
            },
            network: {
                bytes_in: Math.random() * 10000000,
                bytes_out: Math.random() * 10000000,
                packets_in: Math.random() * 10000,
                packets_out: Math.random() * 10000,
                errors: Math.random() * 10
            },
            applications: {
                response_time: Math.random() * 5000,
                error_rate: Math.random() * 0.1,
                active_connections: Math.random() * 1000,
                queue_size: Math.random() * 100
            },
            security: {
                failed_logins: Math.random() * 10,
                suspicious_activities: Math.random() * 5,
                firewall_blocks: Math.random() * 50
            },
            users: {
                active_sessions: Math.random() * 100,
                login_rate: Math.random() * 20,
                activity_score: Math.random() * 100
            }
        };
    }

    /**
     * Update historical data
     */
    updateHistory(metrics, timestamp) {
        const flatMetrics = this.flattenMetrics(metrics);
        
        Object.entries(flatMetrics).forEach(([key, value]) => {
            if (!this.dataHistory.has(key)) {
                this.dataHistory.set(key, []);
            }
            
            const history = this.dataHistory.get(key);
            history.push({ timestamp, value });
            
            // Keep only recent history
            if (history.length > this.config.maxHistorySize) {
                history.shift();
            }
        });
    }

    /**
     * Flatten nested metrics object
     */
    flattenMetrics(obj, prefix = '') {
        const flattened = {};
        
        Object.entries(obj).forEach(([key, value]) => {
            const newKey = prefix ? `${prefix}.${key}` : key;
            
            if (typeof value === 'object' && !Array.isArray(value)) {
                Object.assign(flattened, this.flattenMetrics(value, newKey));
            } else if (Array.isArray(value)) {
                value.forEach((item, index) => {
                    flattened[`${newKey}.${index}`] = item;
                });
            } else if (typeof value === 'number') {
                flattened[newKey] = value;
            }
        });
        
        return flattened;
    }

    /**
     * Detect anomalies using statistical methods
     */
    detectAnomalies(metrics, timestamp) {
        const anomalies = [];
        const flatMetrics = this.flattenMetrics(metrics);
        
        Object.entries(flatMetrics).forEach(([key, currentValue]) => {
            const history = this.dataHistory.get(key);
            
            if (!history || history.length < this.config.minDataPoints) {
                return;
            }
            
            const values = history.map(h => h.value);
            const stats = this.calculateStatistics(values);
            
            // Z-score based anomaly detection
            const zScore = Math.abs((currentValue - stats.mean) / stats.stdDev);
            
            if (zScore > this.config.anomalyThreshold) {
                anomalies.push({
                    metric: key,
                    value: currentValue,
                    expected: stats.mean,
                    zScore: zScore,
                    severity: this.calculateSeverity(zScore),
                    timestamp: timestamp,
                    type: 'statistical'
                });
            }
            
            // Trend-based anomaly detection
            const trendAnomaly = this.detectTrendAnomaly(history, currentValue);
            if (trendAnomaly) {
                anomalies.push({
                    ...trendAnomaly,
                    metric: key,
                    timestamp: timestamp,
                    type: 'trend'
                });
            }
        });
        
        // Update anomalies list
        this.anomalies = this.anomalies.concat(anomalies);
        
        // Keep only recent anomalies (last 24 hours)
        const dayAgo = timestamp - (24 * 60 * 60 * 1000);
        this.anomalies = this.anomalies.filter(a => a.timestamp > dayAgo);
        
        return anomalies;
    }

    /**
     * Calculate basic statistics
     */
    calculateStatistics(values) {
        const n = values.length;
        const mean = values.reduce((sum, val) => sum + val, 0) / n;
        const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / n;
        const stdDev = Math.sqrt(variance);
        
        return {
            mean,
            variance,
            stdDev,
            min: Math.min(...values),
            max: Math.max(...values),
            median: this.calculateMedian(values)
        };
    }

    /**
     * Calculate median value
     */
    calculateMedian(values) {
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        
        return sorted.length % 2 !== 0 
            ? sorted[mid] 
            : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    /**
     * Detect trend-based anomalies
     */
    detectTrendAnomaly(history, currentValue) {
        if (history.length < 10) return null;
        
        const recent = history.slice(-10);
        const trend = this.calculateTrend(recent);
        
        // Sudden direction change
        if (Math.abs(trend.slope) > trend.avgChange * 3) {
            return {
                value: currentValue,
                severity: 'medium',
                description: 'Sudden trend change detected'
            };
        }
        
        return null;
    }

    /**
     * Calculate trend information
     */
    calculateTrend(data) {
        if (data.length < 2) return { slope: 0, avgChange: 0 };
        
        const changes = [];
        for (let i = 1; i < data.length; i++) {
            changes.push(data[i].value - data[i-1].value);
        }
        
        const avgChange = changes.reduce((sum, change) => sum + Math.abs(change), 0) / changes.length;
        const slope = (data[data.length - 1].value - data[0].value) / (data.length - 1);
        
        return { slope, avgChange };
    }

    /**
     * Calculate anomaly severity
     */
    calculateSeverity(zScore) {
        if (zScore > 4) return 'critical';
        if (zScore > 3) return 'high';
        if (zScore > 2.5) return 'medium';
        return 'low';
    }

    /**
     * Generate predictions using time series analysis
     */
    generatePredictions(timestamp) {
        const predictions = {};
        
        this.models.forEach((model, metricKey) => {
            const history = this.dataHistory.get(metricKey);
            
            if (!history || history.length < this.config.minDataPoints) {
                return;
            }
            
            const prediction = this.predictTimeSeries(history, model);
            
            if (prediction) {
                predictions[metricKey] = {
                    value: prediction.value,
                    confidence: prediction.confidence,
                    horizon: this.config.predictionHorizon,
                    timestamp: timestamp + this.config.predictionHorizon,
                    model: model.type
                };
            }
        });
        
        this.predictions.set(timestamp, predictions);
        return predictions;
    }

    /**
     * Simple time series prediction using linear regression
     */
    predictTimeSeries(history, model) {
        const recentData = history.slice(-50); // Use last 50 points
        
        if (recentData.length < 10) return null;
        
        // Simple linear regression
        const n = recentData.length;
        const x = recentData.map((_, i) => i);
        const y = recentData.map(d => d.value);
        
        const sumX = x.reduce((sum, val) => sum + val, 0);
        const sumY = y.reduce((sum, val) => sum + val, 0);
        const sumXY = x.reduce((sum, val, i) => sum + val * y[i], 0);
        const sumXX = x.reduce((sum, val) => sum + val * val, 0);
        
        const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        const intercept = (sumY - slope * sumX) / n;
        
        // Predict next value
        const nextX = n;
        const predictedValue = slope * nextX + intercept;
        
        // Calculate confidence based on historical accuracy
        const errors = y.map((actual, i) => Math.abs(actual - (slope * i + intercept)));
        const avgError = errors.reduce((sum, err) => sum + err, 0) / errors.length;
        const confidence = Math.max(0, 1 - (avgError / Math.abs(predictedValue)));
        
        return {
            value: predictedValue,
            confidence: Math.min(confidence, 1),
            slope,
            intercept
        };
    }

    /**
     * Analyze patterns in the data
     */
    analyzePatterns() {
        const patterns = {
            recurring: this.findRecurringPatterns(),
            seasonal: this.findSeasonalPatterns(),
            correlations: this.findCorrelations()
        };
        
        return patterns;
    }

    /**
     * Find recurring patterns
     */
    findRecurringPatterns() {
        const patterns = [];
        
        // Analyze anomalies for recurring patterns
        const recentAnomalies = this.anomalies.slice(-100);
        const anomalyGroups = new Map();
        
        recentAnomalies.forEach(anomaly => {
            const key = anomaly.metric;
            if (!anomalyGroups.has(key)) {
                anomalyGroups.set(key, []);
            }
            anomalyGroups.get(key).push(anomaly);
        });
        
        anomalyGroups.forEach((anomalies, metric) => {
            if (anomalies.length >= 3) {
                const intervals = [];
                for (let i = 1; i < anomalies.length; i++) {
                    intervals.push(anomalies[i].timestamp - anomalies[i-1].timestamp);
                }
                
                const avgInterval = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
                const stdDev = Math.sqrt(intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length);
                
                if (stdDev / avgInterval < 0.3) { // Low variance indicates recurring pattern
                    patterns.push({
                        type: 'recurring_anomaly',
                        metric: metric,
                        interval: avgInterval,
                        occurrences: anomalies.length,
                        confidence: 1 - (stdDev / avgInterval)
                    });
                }
            }
        });
        
        return patterns;
    }

    /**
     * Find seasonal patterns
     */
    findSeasonalPatterns() {
        const patterns = [];
        
        this.dataHistory.forEach((history, metric) => {
            if (history.length < 144) return; // Need at least 24 hours of data (every 10 min)
            
            // Check for daily patterns
            const hourlyAverages = new Array(24).fill(0);
            const hourlyCounts = new Array(24).fill(0);
            
            history.forEach(point => {
                const hour = new Date(point.timestamp).getHours();
                hourlyAverages[hour] += point.value;
                hourlyCounts[hour]++;
            });
            
            // Calculate averages
            for (let i = 0; i < 24; i++) {
                if (hourlyCounts[i] > 0) {
                    hourlyAverages[i] /= hourlyCounts[i];
                }
            }
            
            // Find peak and valley
            const maxHour = hourlyAverages.indexOf(Math.max(...hourlyAverages));
            const minHour = hourlyAverages.indexOf(Math.min(...hourlyAverages));
            const variation = (Math.max(...hourlyAverages) - Math.min(...hourlyAverages)) / Math.max(...hourlyAverages);
            
            if (variation > 0.2) { // Significant daily variation
                patterns.push({
                    type: 'daily_pattern',
                    metric: metric,
                    peakHour: maxHour,
                    valleyHour: minHour,
                    variation: variation
                });
            }
        });
        
        return patterns;
    }

    /**
     * Find correlations between metrics
     */
    findCorrelations() {
        const correlations = [];
        const metrics = Array.from(this.dataHistory.keys());
        
        for (let i = 0; i < metrics.length; i++) {
            for (let j = i + 1; j < metrics.length; j++) {
                const correlation = this.calculateCorrelation(metrics[i], metrics[j]);
                
                if (Math.abs(correlation) > 0.7) {
                    correlations.push({
                        metric1: metrics[i],
                        metric2: metrics[j],
                        correlation: correlation,
                        type: correlation > 0 ? 'positive' : 'negative'
                    });
                }
            }
        }
        
        return correlations;
    }

    /**
     * Calculate correlation between two metrics
     */
    calculateCorrelation(metric1, metric2) {
        const history1 = this.dataHistory.get(metric1);
        const history2 = this.dataHistory.get(metric2);
        
        if (!history1 || !history2) return 0;
        
        // Align timestamps
        const aligned = this.alignTimeSeries(history1, history2);
        
        if (aligned.length < 10) return 0;
        
        const values1 = aligned.map(point => point.value1);
        const values2 = aligned.map(point => point.value2);
        
        const mean1 = values1.reduce((sum, val) => sum + val, 0) / values1.length;
        const mean2 = values2.reduce((sum, val) => sum + val, 0) / values2.length;
        
        let numerator = 0;
        let sum1Sq = 0;
        let sum2Sq = 0;
        
        for (let i = 0; i < values1.length; i++) {
            const diff1 = values1[i] - mean1;
            const diff2 = values2[i] - mean2;
            
            numerator += diff1 * diff2;
            sum1Sq += diff1 * diff1;
            sum2Sq += diff2 * diff2;
        }
        
        const denominator = Math.sqrt(sum1Sq * sum2Sq);
        
        return denominator === 0 ? 0 : numerator / denominator;
    }

    /**
     * Align two time series by timestamp
     */
    alignTimeSeries(series1, series2) {
        const aligned = [];
        const tolerance = 60000; // 1 minute tolerance
        
        series1.forEach(point1 => {
            const matchingPoint = series2.find(point2 => 
                Math.abs(point1.timestamp - point2.timestamp) <= tolerance
            );
            
            if (matchingPoint) {
                aligned.push({
                    timestamp: point1.timestamp,
                    value1: point1.value,
                    value2: matchingPoint.value
                });
            }
        });
        
        return aligned;
    }

    /**
     * Update machine learning models
     */
    updateModels(metrics, timestamp) {
        const flatMetrics = this.flattenMetrics(metrics);
        
        Object.entries(flatMetrics).forEach(([key, value]) => {
            const model = this.models.get(key);
            if (!model) return;
            
            const history = this.dataHistory.get(key);
            if (!history || history.length < this.config.minDataPoints) return;
            
            // Simple online learning update
            this.updateModel(model, history);
            model.lastTrained = timestamp;
        });
    }

    /**
     * Update individual model
     */
    updateModel(model, history) {
        // Simple exponential smoothing for time series
        const alpha = 0.1; // Smoothing factor
        const recent = history.slice(-20);
        
        if (recent.length < 2) return;
        
        let smoothedValue = recent[0].value;
        for (let i = 1; i < recent.length; i++) {
            smoothedValue = alpha * recent[i].value + (1 - alpha) * smoothedValue;
        }
        
        // Update model accuracy based on recent predictions
        if (model.weights.length > 0) {
            const actualValues = recent.slice(-5).map(r => r.value);
            const predictedValues = actualValues.map(() => smoothedValue);
            
            const mse = actualValues.reduce((sum, actual, i) => {
                return sum + Math.pow(actual - predictedValues[i], 2);
            }, 0) / actualValues.length;
            
            model.accuracy = 1 / (1 + mse);
        }
        
        model.weights = [smoothedValue];
    }

    /**
     * Store analysis results
     */
    async storeResults(results) {
        try {
            // Store in memory for API access
            const resultId = crypto.randomUUID();
            
            // Save to file for persistence
            const outputFile = `/tmp/analytics-results-${Date.now()}.json`;
            await fs.promises.writeFile(outputFile, JSON.stringify(results, null, 2));
            
            // Update summary stats
            await this.updateSummaryStats(results);
            
        } catch (error) {
            console.error('Failed to store results:', error);
        }
    }

    /**
     * Update summary statistics
     */
    async updateSummaryStats(results) {
        const summary = {
            timestamp: results.timestamp,
            totalAnomalies: results.anomalies.length,
            criticalAnomalies: results.anomalies.filter(a => a.severity === 'critical').length,
            predictionsCount: Object.keys(results.predictions).length,
            patternsFound: results.patterns.recurring.length + results.patterns.seasonal.length,
            systemHealth: this.calculateSystemHealth(results)
        };
        
        await fs.promises.writeFile('/tmp/analytics-summary.json', JSON.stringify(summary, null, 2));
    }

    /**
     * Calculate overall system health score
     */
    calculateSystemHealth(results) {
        let healthScore = 100;
        
        // Reduce score based on anomalies
        results.anomalies.forEach(anomaly => {
            switch (anomaly.severity) {
                case 'critical': healthScore -= 20; break;
                case 'high': healthScore -= 10; break;
                case 'medium': healthScore -= 5; break;
                case 'low': healthScore -= 2; break;
            }
        });
        
        return Math.max(0, healthScore);
    }

    /**
     * Get current predictions
     */
    getPredictions() {
        const latest = Array.from(this.predictions.keys()).sort().pop();
        return latest ? this.predictions.get(latest) : {};
    }

    /**
     * Get recent anomalies
     */
    getAnomalies(hours = 24) {
        const cutoff = Date.now() - (hours * 60 * 60 * 1000);
        return this.anomalies.filter(a => a.timestamp > cutoff);
    }

    /**
     * Get system health score
     */
    async getSystemHealth() {
        try {
            const summary = JSON.parse(await fs.promises.readFile('/tmp/analytics-summary.json', 'utf8'));
            return summary.systemHealth || 100;
        } catch {
            return 100;
        }
    }

    /**
     * Get performance metrics
     */
    getPerformanceMetrics() {
        const metrics = {};
        
        this.models.forEach((model, key) => {
            metrics[key] = {
                accuracy: model.accuracy,
                lastTrained: model.lastTrained,
                dataPoints: this.dataHistory.get(key)?.length || 0
            };
        });
        
        return metrics;
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
        
        // Save historical data
        try {
            const historyData = {
                timestamp: Date.now(),
                history: Object.fromEntries(this.dataHistory)
            };
            
            await fs.promises.writeFile('/tmp/analytics-history.json', JSON.stringify(historyData, null, 2));
            console.log('Analytics engine shut down successfully');
        } catch (error) {
            console.error('Error saving data on shutdown:', error);
        }
    }
}

// REST API Interface
class AnalyticsAPI {
    constructor(engine) {
        this.engine = engine;
    }

    /**
     * Express middleware for analytics API
     */
    getMiddleware() {
        return {
            '/api/analytics/predictions': this.getPredictions.bind(this),
            '/api/analytics/anomalies': this.getAnomalies.bind(this),
            '/api/analytics/health': this.getHealth.bind(this),
            '/api/analytics/metrics': this.getMetrics.bind(this),
            '/api/analytics/patterns': this.getPatterns.bind(this)
        };
    }

    async getPredictions(req, res) {
        try {
            const predictions = this.engine.getPredictions();
            res.json({ success: true, data: predictions });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getAnomalies(req, res) {
        try {
            const hours = parseInt(req.query.hours) || 24;
            const anomalies = this.engine.getAnomalies(hours);
            res.json({ success: true, data: anomalies });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getHealth(req, res) {
        try {
            const health = await this.engine.getSystemHealth();
            res.json({ success: true, data: { score: health } });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getMetrics(req, res) {
        try {
            const metrics = this.engine.getPerformanceMetrics();
            res.json({ success: true, data: metrics });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }

    async getPatterns(req, res) {
        try {
            // Get latest patterns from analysis
            const patterns = this.engine.analyzePatterns();
            res.json({ success: true, data: patterns });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    }
}

// Export for use in OpenDirectory MDM
module.exports = {
    PredictiveAnalyticsEngine,
    AnalyticsAPI
};

// Example usage
if (require.main === module) {
    const engine = new PredictiveAnalyticsEngine({
        analysisInterval: 30000, // 30 seconds for demo
        anomalyThreshold: 2.0
    });

    engine.initialize().then(() => {
        console.log('Analytics engine running...');
        
        // Handle graceful shutdown
        process.on('SIGINT', async () => {
            console.log('Shutting down analytics engine...');
            await engine.shutdown();
            process.exit(0);
        });
    }).catch(error => {
        console.error('Failed to initialize analytics engine:', error);
        process.exit(1);
    });
}