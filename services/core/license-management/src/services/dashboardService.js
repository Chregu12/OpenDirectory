/**
 * Dashboard Aggregation Service
 * Aggregates data from all OpenDirectory services into dashboard-ready widgets.
 * Uses the existing reportingService for scheduled report generation.
 */

const EventEmitter = require('events');
const crypto = require('crypto');

class DashboardService extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            cacheTimeout: config.cacheTimeout || 60000, // 1 minute cache
            ...config
        };

        // Service references (injected)
        this.services = {};

        // Dashboard data cache
        this._cache = {};
        this._cacheTimestamps = {};

        // Time series data store (in-memory rolling window)
        this.timeSeries = {
            compliance: [],
            threats: [],
            updates: [],
            agents: [],
            commands: []
        };

        // Track events for time series
        this._metricsInterval = setInterval(() => this._recordMetricsSnapshot(), 60000);
    }

    registerServices(services) {
        this.services = services;
        console.log(`DashboardService: ${Object.keys(services).length} services registered`);
    }

    /**
     * Get full dashboard data (all widgets)
     */
    async getDashboardData() {
        const cached = this._getCached('dashboard');
        if (cached) return cached;

        const data = {
            devices: await this._getDeviceStats(),
            updates: await this._getUpdateStats(),
            threats: await this._getThreatStats(),
            certificates: await this._getCertificateStats(),
            compliance: await this._getComplianceStats(),
            backups: await this._getBackupStats(),
            agents: await this._getAgentStats(),
            timestamp: new Date().toISOString()
        };

        this._setCache('dashboard', data);
        return data;
    }

    async _getDeviceStats() {
        try {
            const deviceService = this.services.deviceService;
            if (!deviceService) return { total: 0, online: 0, offline: 0, byPlatform: {} };

            const devices = deviceService.getDevices?.() || [];
            const online = devices.filter(d => d.status === 'online' || d.status === 'active').length;

            const byPlatform = {};
            for (const d of devices) {
                const p = d.platform || 'unknown';
                byPlatform[p] = (byPlatform[p] || 0) + 1;
            }

            return { total: devices.length, online, offline: devices.length - online, byPlatform };
        } catch (e) {
            return { total: 0, online: 0, offline: 0, byPlatform: {} };
        }
    }

    async _getUpdateStats() {
        try {
            const bridge = this.services.analyticsBridge;
            if (!bridge) return { pending: 0, installed: 0, failed: 0, complianceRatio: 1.0 };

            const metrics = bridge.getMetrics?.() || {};
            return {
                pending: 0,
                installed: metrics.eventsProcessed || 0,
                failed: metrics.errors || 0,
                complianceRatio: metrics.errors ? Math.max(0, 1 - (metrics.errors / Math.max(1, metrics.eventsProcessed))) : 1.0
            };
        } catch (e) {
            return { pending: 0, installed: 0, failed: 0, complianceRatio: 1.0 };
        }
    }

    async _getThreatStats() {
        try {
            const bridge = this.services.analyticsBridge;
            if (!bridge) return { active: 0, resolved: 0, critical: 0, byCategory: {} };

            const threats = bridge.getThreats?.() || [];
            const active = threats.filter(t => t.status === 'active');
            const resolved = threats.filter(t => t.status === 'resolved');
            const critical = active.filter(t => t.severity === 'critical');

            const byCategory = {};
            for (const t of active) {
                const cat = t.category || 'unknown';
                byCategory[cat] = (byCategory[cat] || 0) + 1;
            }

            return { active: active.length, resolved: resolved.length, critical: critical.length, byCategory };
        } catch (e) {
            return { active: 0, resolved: 0, critical: 0, byCategory: {} };
        }
    }

    async _getCertificateStats() {
        return { valid: 0, expiringSoon: 0, expired: 0, totalIssued: 0 };
    }

    async _getComplianceStats() {
        try {
            const bridge = this.services.analyticsBridge;
            const anomalies = bridge?.getAnomalies?.() || [];
            const complianceAnomalies = anomalies.filter(a => a.type === 'low_compliance_score');

            return {
                compliantDevices: 0,
                nonCompliantDevices: complianceAnomalies.length,
                overallScore: complianceAnomalies.length === 0 ? 100 : 75
            };
        } catch (e) {
            return { compliantDevices: 0, nonCompliantDevices: 0, overallScore: 100 };
        }
    }

    async _getBackupStats() {
        return { lastSuccess: null, nextScheduled: null, storageUsedGB: 0 };
    }

    async _getAgentStats() {
        try {
            const deviceService = this.services.deviceService;
            const wss = deviceService?.wss;
            const connected = wss?.clients?.size || 0;
            return { connected, disconnected: 0, byPlatform: {} };
        } catch (e) {
            return { connected: 0, disconnected: 0, byPlatform: {} };
        }
    }

    /**
     * Get time series data for a metric
     */
    getTimeSeries(metric, timeframe = '24h') {
        const series = this.timeSeries[metric];
        if (!series) return [];

        const now = Date.now();
        const timeframes = { '1h': 3600000, '6h': 21600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
        const window = timeframes[timeframe] || 86400000;

        return series.filter(point => (now - new Date(point.timestamp).getTime()) <= window);
    }

    _recordMetricsSnapshot() {
        const now = new Date().toISOString();
        const bridge = this.services.analyticsBridge;

        if (bridge) {
            const metrics = bridge.getMetrics?.() || {};
            const threats = bridge.getThreats?.() || [];
            const anomalies = bridge.getAnomalies?.() || [];

            this.timeSeries.threats.push({ timestamp: now, value: threats.filter(t => t.status === 'active').length, label: 'active_threats' });
            this.timeSeries.compliance.push({ timestamp: now, value: anomalies.length, label: 'anomalies' });
            this.timeSeries.commands.push({ timestamp: now, value: metrics.eventsProcessed || 0, label: 'events_processed' });
        }

        // Trim to last 30 days
        const cutoff = Date.now() - 2592000000;
        for (const key of Object.keys(this.timeSeries)) {
            this.timeSeries[key] = this.timeSeries[key].filter(p => new Date(p.timestamp).getTime() > cutoff);
        }
    }

    // =====================================================
    // Report Integration
    // =====================================================

    /**
     * Get available report templates
     */
    getReportTemplates() {
        return [
            { id: 'license-inventory', name: 'License Inventory', category: 'inventory', formats: ['pdf', 'excel', 'json'] },
            { id: 'usage-analytics', name: 'Usage Analytics', category: 'analytics', formats: ['pdf', 'excel', 'json'] },
            { id: 'compliance-report', name: 'Compliance Report', category: 'compliance', formats: ['pdf', 'excel', 'json'] },
            { id: 'cost-analysis', name: 'Cost Analysis', category: 'financial', formats: ['pdf', 'excel', 'json'] },
            { id: 'optimization', name: 'Optimization Report', category: 'optimization', formats: ['pdf', 'excel', 'json'] },
            { id: 'renewal-schedule', name: 'Renewal Schedule', category: 'planning', formats: ['pdf', 'excel', 'json'] },
            { id: 'executive-summary', name: 'Executive Summary', category: 'executive', formats: ['pdf', 'json'] },
            { id: 'audit-trail', name: 'Audit Trail', category: 'audit', formats: ['excel', 'json'] },
            { id: 'device-inventory', name: 'Device Inventory', category: 'inventory', formats: ['pdf', 'excel', 'json'] },
            { id: 'threat-report', name: 'Threat Report', category: 'security', formats: ['pdf', 'json'] }
        ];
    }

    /**
     * Generate a report
     */
    async generateReport(template, format, params = {}) {
        const reportId = `rpt-${crypto.randomUUID().slice(0, 8)}`;
        const reportingService = this.services.reportingService;

        if (reportingService?.generateReport) {
            await reportingService.generateReport(template, format, params);
        }

        return {
            id: reportId,
            template,
            format,
            status: 'generating',
            generatedAt: new Date().toISOString(),
            downloadUrl: `/api/reports/${reportId}/download`
        };
    }

    // =====================================================
    // Cache helpers
    // =====================================================

    _getCached(key) {
        const ts = this._cacheTimestamps[key];
        if (ts && (Date.now() - ts) < this.config.cacheTimeout) {
            return this._cache[key];
        }
        return null;
    }

    _setCache(key, data) {
        this._cache[key] = data;
        this._cacheTimestamps[key] = Date.now();
    }

    destroy() {
        clearInterval(this._metricsInterval);
        this.removeAllListeners();
    }
}

module.exports = { DashboardService };
