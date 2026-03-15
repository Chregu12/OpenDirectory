/**
 * Analytics Bridge
 * Connects agent command results to AI Analytics, Pattern Engine, and Threat Intelligence services.
 * Ingests real-time events from the agent dispatch pipeline and feeds them into ML analysis.
 */

const EventEmitter = require('events');

class AnalyticsBridge extends EventEmitter {
    constructor(config = {}) {
        super();

        // Service references (injected via registerServices)
        this.aiAnalytics = null;
        this.patternEngine = null;
        this.threatIntel = null;
        this.predictiveMaintenance = null;
        this.recommendations = null;

        // Internal state
        this.eventBuffer = [];
        this.bufferFlushInterval = config.bufferFlushInterval || 5000;
        this.maxBufferSize = config.maxBufferSize || 1000;
        this.enabled = config.enabled !== false;

        // Metrics
        this.metrics = {
            eventsProcessed: 0,
            threatsDetected: 0,
            anomaliesDetected: 0,
            predictionsGenerated: 0,
            errors: 0
        };

        // Threat/anomaly stores for API queries
        this.activeThreats = [];
        this.recentAnomalies = [];
        this.predictions = [];
        this.activeRecommendations = [];

        // Start buffer flush timer
        this._flushTimer = setInterval(() => this._flushEventBuffer(), this.bufferFlushInterval);
    }

    /**
     * Register external analytics services
     */
    registerServices(services) {
        if (services.aiAnalytics) this.aiAnalytics = services.aiAnalytics;
        if (services.patternEngine) this.patternEngine = services.patternEngine;
        if (services.threatIntel) this.threatIntel = services.threatIntel;
        if (services.predictiveMaintenance) this.predictiveMaintenance = services.predictiveMaintenance;
        if (services.recommendations) this.recommendations = services.recommendations;
        console.log(`AnalyticsBridge: ${Object.keys(services).length} analytics services registered`);
    }

    /**
     * Process an agent command result event.
     * Called from device-service command_result handler.
     */
    processEvent(deviceId, command, result) {
        if (!this.enabled) return;

        const event = {
            deviceId,
            command,
            result,
            timestamp: Date.now(),
            status: result.status || (result.success ? 'success' : 'error')
        };

        this.metrics.eventsProcessed++;

        // Buffer for batch processing
        this.eventBuffer.push(event);
        if (this.eventBuffer.length >= this.maxBufferSize) {
            this._flushEventBuffer();
        }

        // Immediate processing for security-relevant events
        this._processSecurityEvent(event);
        this._processComplianceEvent(event);
        this._processUpdateEvent(event);
        this._processFailureEvent(event);
    }

    /**
     * Security-relevant events → Threat Intelligence
     */
    _processSecurityEvent(event) {
        const securityPrefixes = ['comp-', 'enc-'];
        const isSecurityEvent = securityPrefixes.some(p => event.command.startsWith(p));

        if (!isSecurityEvent) return;

        // Check for compliance violations
        if (event.command.startsWith('comp-') && event.result.violations && event.result.violations.length > 0) {
            const threat = {
                id: `thr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                severity: event.result.violations.some(v => v.severity === 'critical') ? 'critical' : 'warning',
                category: 'compliance_violation',
                description: `Device ${event.deviceId}: ${event.result.violations.length} compliance violation(s) detected`,
                deviceId: event.deviceId,
                source: 'compliance_check',
                detectedAt: new Date().toISOString(),
                status: 'active',
                mitreTactic: 'defense-evasion',
                violations: event.result.violations
            };

            this.activeThreats.push(threat);
            this.metrics.threatsDetected++;
            this.emit('threat:detected', threat);

            // Forward to Threat Intelligence service if available
            if (this.threatIntel?.analyzeThreat) {
                try { this.threatIntel.analyzeThreat(threat); } catch (e) { /* best-effort */ }
            }
        }

        // Encryption not enabled
        if (event.command.startsWith('enc-') && event.result.encrypted === false) {
            const threat = {
                id: `thr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                severity: 'warning',
                category: 'unencrypted_device',
                description: `Device ${event.deviceId} is not encrypted`,
                deviceId: event.deviceId,
                source: 'encryption_check',
                detectedAt: new Date().toISOString(),
                status: 'active',
                mitreTactic: 'collection'
            };

            this.activeThreats.push(threat);
            this.metrics.threatsDetected++;
            this.emit('threat:detected', threat);
        }
    }

    /**
     * Compliance events → Anomaly detection
     */
    _processComplianceEvent(event) {
        if (!event.command.startsWith('comp-')) return;

        // Score-based anomaly detection
        const score = event.result.score ?? event.result.complianceScore;
        if (score !== undefined && score < 50) {
            const anomaly = {
                id: `ano-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                type: 'low_compliance_score',
                severity: score < 25 ? 'critical' : 'warning',
                description: `Device ${event.deviceId} compliance score dropped to ${score}%`,
                deviceId: event.deviceId,
                metric: 'compliance_score',
                expectedValue: 80,
                actualValue: score,
                detectedAt: new Date().toISOString()
            };

            this.recentAnomalies.push(anomaly);
            this.metrics.anomaliesDetected++;
            this.emit('anomaly:detected', anomaly);
        }

        // Forward to pattern engine
        if (this.patternEngine?.ingestEvent) {
            try { this.patternEngine.ingestEvent(event); } catch (e) { /* best-effort */ }
        }
    }

    /**
     * Update events → Predictive maintenance
     */
    _processUpdateEvent(event) {
        if (!event.command.startsWith('upd-')) return;

        if (event.status === 'error') {
            // Track update failures for prediction
            if (this.predictiveMaintenance?.recordUpdateFailure) {
                try { this.predictiveMaintenance.recordUpdateFailure(event.deviceId, event.result); } catch (e) { /* best-effort */ }
            }

            // Generate prediction after repeated failures
            const deviceFailures = this.eventBuffer.filter(
                e => e.deviceId === event.deviceId && e.command.startsWith('upd-') && e.status === 'error'
            );

            if (deviceFailures.length >= 3) {
                const prediction = {
                    id: `pred-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                    type: 'update_failure_pattern',
                    confidence: Math.min(0.5 + (deviceFailures.length * 0.1), 0.95),
                    description: `Device ${event.deviceId} showing recurring update failures (${deviceFailures.length} in buffer)`,
                    deviceId: event.deviceId,
                    predictedDate: new Date(Date.now() + 86400000).toISOString(),
                    recommendation: 'Investigate OS integrity or network connectivity'
                };

                this.predictions.push(prediction);
                this.metrics.predictionsGenerated++;
                this.emit('prediction:generated', prediction);
            }
        }
    }

    /**
     * General failure tracking
     */
    _processFailureEvent(event) {
        if (event.status !== 'error') return;

        // Forward to AI analytics for pattern analysis
        if (this.aiAnalytics?.recordFailure) {
            try {
                this.aiAnalytics.recordFailure(event.deviceId, event.command, event.result);
            } catch (e) { /* best-effort */ }
        }
    }

    /**
     * Flush buffered events to pattern engine
     */
    _flushEventBuffer() {
        if (this.eventBuffer.length === 0) return;

        const events = this.eventBuffer.splice(0);

        if (this.patternEngine?.ingestBatch) {
            try { this.patternEngine.ingestBatch(events); } catch (e) { this.metrics.errors++; }
        }

        // Generate recommendations based on patterns
        if (this.recommendations?.analyze && events.length >= 10) {
            try {
                const recs = this.recommendations.analyze(events);
                if (recs && recs.length > 0) {
                    this.activeRecommendations.push(...recs);
                }
            } catch (e) { /* best-effort */ }
        }

        // Trim old data (keep last 1000 of each)
        if (this.activeThreats.length > 1000) this.activeThreats = this.activeThreats.slice(-1000);
        if (this.recentAnomalies.length > 1000) this.recentAnomalies = this.recentAnomalies.slice(-1000);
        if (this.predictions.length > 500) this.predictions = this.predictions.slice(-500);
        if (this.activeRecommendations.length > 200) this.activeRecommendations = this.activeRecommendations.slice(-200);
    }

    // =====================================================
    // API Query Methods (used by API routes and GraphQL)
    // =====================================================

    getThreats(filters = {}) {
        let threats = [...this.activeThreats];
        if (filters.severity) threats = threats.filter(t => t.severity === filters.severity);
        if (filters.deviceId) threats = threats.filter(t => t.deviceId === filters.deviceId);
        if (filters.limit) threats = threats.slice(-filters.limit);
        return threats;
    }

    getAnomalies(filters = {}) {
        let anomalies = [...this.recentAnomalies];
        if (filters.deviceId) anomalies = anomalies.filter(a => a.deviceId === filters.deviceId);
        if (filters.limit) anomalies = anomalies.slice(-filters.limit);
        return anomalies;
    }

    getPredictions(filters = {}) {
        let preds = [...this.predictions];
        if (filters.type) preds = preds.filter(p => p.type === filters.type);
        if (filters.deviceId) preds = preds.filter(p => p.deviceId === filters.deviceId);
        return preds;
    }

    getRecommendations(filters = {}) {
        let recs = [...this.activeRecommendations];
        if (filters.category) recs = recs.filter(r => r.category === filters.category);
        return recs;
    }

    getMetrics() {
        return { ...this.metrics };
    }

    /**
     * Resolve a threat (mark as resolved)
     */
    resolveThreat(threatId) {
        const threat = this.activeThreats.find(t => t.id === threatId);
        if (threat) {
            threat.status = 'resolved';
            threat.resolvedAt = new Date().toISOString();
            this.emit('threat:resolved', threat);
        }
        return threat;
    }

    destroy() {
        clearInterval(this._flushTimer);
        this.removeAllListeners();
    }
}

module.exports = { AnalyticsBridge };
