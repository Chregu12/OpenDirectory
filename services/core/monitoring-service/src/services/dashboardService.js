'use strict';

const logger = require('../utils/logger');

/**
 * DashboardService — assembles aggregated metric snapshots for the various
 * dashboard views consumed by the frontend and WebSocket subscribers.
 */
class DashboardService {
  constructor(timeSeriesDB, metricsCache) {
    this._tsdb = timeSeriesDB;
    this._cache = metricsCache;
    logger.info('DashboardService initialised');
  }

  // ---------------------------------------------------------------------------
  // Real-time helpers
  // ---------------------------------------------------------------------------

  async getRealTimeMetrics() {
    const cached = this._cache.get('dashboard.realtime');
    if (cached) return cached;

    const result = this._buildRealTimeSnapshot();
    this._cache.set('dashboard.realtime', result, 5000);
    return result;
  }

  async getLiveMetrics(timeRange = '5m') {
    return this.getRealTimeMetrics();
  }

  _buildRealTimeSnapshot() {
    const systemCurrent = this._cache.get('system.current') || {};
    const now = Date.now();

    return {
      timestamp: now,
      system: {
        cpu: systemCurrent.cpu || 0,
        memPercent: systemCurrent.memPercent || 0,
        memUsed: systemCurrent.memUsed || 0,
        memTotal: systemCurrent.memTotal || 0,
        load1m: systemCurrent.load1m || 0,
        load5m: systemCurrent.load5m || 0,
        load15m: systemCurrent.load15m || 0,
        uptime: systemCurrent.uptime || process.uptime(),
      },
      services: this._mockServiceMetrics(),
    };
  }

  _mockServiceMetrics() {
    const services = ['auth-service', 'user-service', 'device-service', 'policy-service', 'api-gateway'];
    return services.map((name) => ({
      name,
      status: Math.random() > 0.1 ? 'healthy' : 'degraded',
      requestsPerSec: Math.floor(Math.random() * 200) + 10,
      avgResponseMs: Math.floor(Math.random() * 150) + 20,
      errorRate: Math.random() * 2,
      cpuPercent: Math.random() * 40 + 5,
      memMB: Math.floor(Math.random() * 300) + 50,
    }));
  }

  // ---------------------------------------------------------------------------
  // Dashboard views
  // ---------------------------------------------------------------------------

  async getOverview(timeRange = '1h') {
    return {
      timeRange,
      realTime: await this.getRealTimeMetrics(),
      summary: {
        totalServices: 12,
        healthyServices: 11,
        degradedServices: 1,
        criticalAlerts: 0,
        warningAlerts: 2,
        infoAlerts: 5,
        slaCompliance: 99.95,
      },
      trends: this._buildTrends(timeRange),
    };
  }

  async getPerformanceDashboard(timeRange = '1h') {
    return {
      timeRange,
      services: this._mockServiceMetrics(),
      topSlowest: [
        { service: 'report-service', endpoint: '/api/reports/generate', avgMs: 1850 },
        { service: 'analytics-service', endpoint: '/api/analytics/predictions', avgMs: 920 },
        { service: 'auth-service', endpoint: '/api/auth/validate', avgMs: 45 },
      ],
      throughput: { rps: 847, peak: 1200 },
    };
  }

  async getSecurityDashboard(timeRange = '1h') {
    return {
      timeRange,
      events: { total: 1240, critical: 3, warning: 18, info: 1219 },
      topRisks: [
        { type: 'Failed Login Attempts', count: 12, severity: 'warning' },
        { type: 'Unusual Access Pattern', count: 3, severity: 'critical' },
      ],
    };
  }

  async getInfrastructureDashboard(timeRange = '1h') {
    return {
      timeRange,
      nodes: [
        { name: 'node-1', cpu: 42, mem: 67, disk: 54, status: 'healthy' },
        { name: 'node-2', cpu: 28, mem: 45, disk: 38, status: 'healthy' },
        { name: 'node-3', cpu: 88, mem: 91, disk: 71, status: 'degraded' },
      ],
    };
  }

  async getCustomDashboard(dashboardId) {
    return { dashboardId, message: 'Custom dashboard not yet configured', widgets: [] };
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  _buildTrends(timeRange) {
    const points = 20;
    const now = Date.now();
    const rangeMs = this._rangeToMs(timeRange);
    const step = rangeMs / points;

    return Array.from({ length: points }, (_, i) => ({
      ts: now - (points - i) * step,
      cpu: Math.random() * 30 + 20,
      mem: Math.random() * 20 + 50,
      rps: Math.floor(Math.random() * 200) + 600,
    }));
  }

  _rangeToMs(range) {
    const units = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    const match = String(range).match(/^(\d+)([smhd])$/);
    if (!match) return 3600000;
    return parseInt(match[1], 10) * (units[match[2]] || 1000);
  }
}

module.exports = DashboardService;
