'use strict';

const logger = require('../utils/logger');

/**
 * SLAMonitor — tracks Service Level Agreement targets and reports
 * compliance metrics.
 */
class SLAMonitor {
  constructor(timeSeriesDB, alertManager) {
    this._tsdb = timeSeriesDB;
    this._alertManager = alertManager;
    this._targets = new Map();   // targetId → SLATarget
    this._nextId = 1;

    // Seed default SLA targets
    this._seedDefaults();

    logger.info('SLAMonitor initialised');
  }

  _seedDefaults() {
    const defaults = [
      { name: 'API Availability', service: 'api-gateway',    metric: 'uptime',        target: 99.9,  period: '30d', unit: '%' },
      { name: 'Auth Latency P95', service: 'auth-service',   metric: 'latency_p95',   target: 500,   period: '7d',  unit: 'ms' },
      { name: 'Error Rate',       service: 'all',             metric: 'error_rate',    target: 1.0,   period: '1d',  unit: '%', direction: 'below' },
    ];
    defaults.forEach((t) => this.createTarget(t));
  }

  // ---------------------------------------------------------------------------
  // Target CRUD
  // ---------------------------------------------------------------------------

  createTarget(data) {
    const id = data.id || `sla-${this._nextId++}`;
    const target = {
      id,
      name: data.name || 'Unnamed SLA',
      service: data.service || 'all',
      metric: data.metric || 'uptime',
      target: data.target ?? 99.9,
      direction: data.direction || 'above',  // 'above' or 'below'
      period: data.period || '30d',
      unit: data.unit || '%',
      createdAt: Date.now(),
    };
    this._targets.set(id, target);
    return target;
  }

  updateTarget(id, changes) {
    const t = this._targets.get(id);
    if (!t) return null;
    const updated = { ...t, ...changes, id };
    this._targets.set(id, updated);
    return updated;
  }

  // ---------------------------------------------------------------------------
  // SLA checks (background job)
  // ---------------------------------------------------------------------------

  async checkSLAs() {
    for (const target of this._targets.values()) {
      const current = this._computeCurrentValue(target);
      const breached = this._isBreached(target, current);

      if (breached) {
        logger.warn('SLA breach detected', { sla: target.name, current, target: target.target });
        await this._alertManager.trigger({
          name: `SLA Breach: ${target.name}`,
          service: target.service,
          severity: 'critical',
          message: `SLA "${target.name}" breached. Current: ${current}${target.unit}, Target: ${target.direction} ${target.target}${target.unit}`,
          metric: target.metric,
          currentValue: current,
          threshold: target.target,
        });
      }
    }
  }

  _isBreached(target, current) {
    if (target.direction === 'above') return current < target.target;
    return current > target.target;
  }

  _computeCurrentValue(target) {
    // Stub: return a mock value; replace with real aggregation in production
    if (target.metric === 'uptime') return 99.95 + Math.random() * 0.05;
    if (target.metric === 'error_rate') return Math.random() * 0.5;
    if (target.metric === 'latency_p95') return Math.floor(Math.random() * 200) + 100;
    return 100;
  }

  // ---------------------------------------------------------------------------
  // Reports
  // ---------------------------------------------------------------------------

  async getSLAStatus() {
    return Array.from(this._targets.values()).map((t) => {
      const current = this._computeCurrentValue(t);
      return {
        ...t,
        currentValue: current,
        compliant: !this._isBreached(t, current),
        compliance: t.metric === 'uptime' ? 99.95 : null,
      };
    });
  }

  async getSLAReports(period = '30d') {
    const statuses = await this.getSLAStatus();
    return {
      period,
      generatedAt: new Date().toISOString(),
      targets: statuses,
      overallCompliance: statuses.filter((s) => s.compliant).length / statuses.length * 100,
    };
  }
}

module.exports = SLAMonitor;
