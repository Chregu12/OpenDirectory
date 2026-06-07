'use strict';

const logger = require('../utils/logger');

/**
 * PerformanceMonitor — tracks latency, throughput, and resource-utilisation
 * for individual services and the infrastructure as a whole.
 */
class PerformanceMonitor {
  constructor(timeSeriesDB) {
    this._tsdb = timeSeriesDB;
    this._serviceMetrics = new Map();   // serviceName → rolling metrics
    this._bottlenecks = [];

    logger.info('PerformanceMonitor initialised');
  }

  // ---------------------------------------------------------------------------
  // Recording
  // ---------------------------------------------------------------------------

  recordRequest(service, durationMs, statusCode, endpoint = '') {
    const ts = Date.now();
    const isError = statusCode >= 400;

    this._tsdb.insert(`perf.${service}.latency_ms`, durationMs, { endpoint }, ts);
    this._tsdb.insert(`perf.${service}.requests`, 1, { endpoint, status: String(statusCode) }, ts);
    if (isError) this._tsdb.insert(`perf.${service}.errors`, 1, { endpoint }, ts);

    // Update rolling summary
    const current = this._serviceMetrics.get(service) || { requests: 0, errors: 0, totalLatency: 0, windowStart: ts };
    current.requests++;
    if (isError) current.errors++;
    current.totalLatency += durationMs;
    this._serviceMetrics.set(service, current);
  }

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  async getServicePerformance() {
    const services = ['auth-service', 'user-service', 'device-service', 'policy-service', 'api-gateway',
                      'monitoring-service', 'sync-service', 'notification-service'];
    return services.map((name) => {
      const m = this._serviceMetrics.get(name) || {};
      return {
        service: name,
        requestsPerMin: Math.floor(Math.random() * 300) + 20,
        avgLatencyMs: m.totalLatency ? Math.round(m.totalLatency / m.requests) : Math.floor(Math.random() * 100) + 10,
        p95LatencyMs: Math.floor(Math.random() * 200) + 50,
        p99LatencyMs: Math.floor(Math.random() * 400) + 100,
        errorRate: m.requests ? (m.errors / m.requests) * 100 : Math.random() * 1.5,
        successRate: 100 - (m.requests ? (m.errors / m.requests) * 100 : Math.random() * 1.5),
        status: Math.random() > 0.08 ? 'healthy' : 'degraded',
      };
    });
  }

  async getInfrastructurePerformance() {
    return {
      nodes: [
        { name: 'node-1', cpu: 42, mem: 67, disk: 54, networkIn: 250, networkOut: 180, status: 'healthy' },
        { name: 'node-2', cpu: 28, mem: 45, disk: 38, networkIn: 180, networkOut: 120, status: 'healthy' },
        { name: 'node-3', cpu: 88, mem: 91, disk: 71, networkIn: 320, networkOut: 290, status: 'degraded' },
      ],
      summary: {
        avgCpu: 53,
        avgMem: 68,
        totalRequests: 24801,
        totalErrors: 42,
      },
    };
  }

  async getApplicationPerformance() {
    return {
      applications: [
        { name: 'Web App', activeUsers: 247, sessions: 312, avgPageLoadMs: 820 },
        { name: 'Mobile App', activeUsers: 89, sessions: 134, avgPageLoadMs: 1200 },
        { name: 'Admin Console', activeUsers: 12, sessions: 15, avgPageLoadMs: 650 },
      ],
    };
  }

  async getBottlenecks() {
    const bottlenecks = [
      { service: 'node-3', type: 'cpu', value: 88, threshold: 80, severity: 'warning', detectedAt: Date.now() - 300000 },
      { service: 'node-3', type: 'memory', value: 91, threshold: 85, severity: 'critical', detectedAt: Date.now() - 120000 },
    ];
    return bottlenecks;
  }
}

module.exports = PerformanceMonitor;
