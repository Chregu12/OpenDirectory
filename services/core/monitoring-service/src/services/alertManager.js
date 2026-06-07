'use strict';

const logger = require('../utils/logger');

/**
 * AlertManager — manages alert rules, active alerts, and lifecycle (trigger /
 * acknowledge / resolve).
 *
 * Dependencies injected via constructor:
 *   alertStore  — AlertStore instance
 *   eventBus    — EventBus instance
 */
class AlertManager {
  constructor(alertStore, eventBus) {
    this._store = alertStore;
    this._bus = eventBus;

    // In-memory rule registry: Map<ruleId, rule>
    this._rules = new Map();
    this._nextRuleId = 1;

    // Seed with a few default rules so the service has something to show
    this._seedDefaultRules();

    logger.info('AlertManager initialised');
  }

  // ---------------------------------------------------------------------------
  // Rule management
  // ---------------------------------------------------------------------------

  _seedDefaultRules() {
    const defaults = [
      { name: 'High CPU Usage', service: 'all', metric: 'system.cpu_percent', operator: '>', threshold: 90, severity: 'critical', notificationChannels: ['email'], enabled: true },
      { name: 'Memory Pressure', service: 'all', metric: 'system.mem_percent', operator: '>', threshold: 85, severity: 'warning', notificationChannels: ['email', 'slack'], enabled: true },
      { name: 'High Error Rate', service: 'api', metric: 'api.error_rate', operator: '>', threshold: 5, severity: 'warning', notificationChannels: ['slack'], enabled: true },
      { name: 'Disk Usage Critical', service: 'all', metric: 'disk.usage_percent', operator: '>', threshold: 95, severity: 'critical', notificationChannels: ['email', 'slack', 'webhook'], enabled: true },
      { name: 'Response Time Slow', service: 'api', metric: 'api.response_time_ms', operator: '>', threshold: 2000, severity: 'warning', notificationChannels: ['slack'], enabled: false },
    ];
    defaults.forEach((r) => this.addRule(r));
  }

  addRule(ruleData) {
    const id = ruleData.id || `rule-${this._nextRuleId++}`;
    const rule = {
      id,
      name: ruleData.name || 'Unnamed Rule',
      service: ruleData.service || 'all',
      metric: ruleData.metric || '',
      operator: ruleData.operator || '>',
      threshold: ruleData.threshold ?? 0,
      severity: ruleData.severity || 'info',
      notificationChannels: ruleData.notificationChannels || [],
      enabled: ruleData.enabled !== false,
      createdAt: Date.now(),
    };
    this._rules.set(id, rule);
    return rule;
  }

  updateRule(id, changes) {
    const rule = this._rules.get(id);
    if (!rule) return null;
    const updated = { ...rule, ...changes, id };
    this._rules.set(id, updated);
    return updated;
  }

  deleteRule(id) {
    return this._rules.delete(id);
  }

  getRules() {
    return Array.from(this._rules.values());
  }

  getRule(id) {
    return this._rules.get(id) || null;
  }

  // ---------------------------------------------------------------------------
  // Alert lifecycle
  // ---------------------------------------------------------------------------

  async trigger(alertData) {
    const alert = await this._store.create({
      ...alertData,
      status: 'active',
      createdAt: Date.now(),
    });
    logger.info('Alert triggered', { id: alert.id, name: alert.name, severity: alert.severity });
    this._bus.emit('alert:triggered', alert);
    return alert;
  }

  async resolve(alertId) {
    const alert = await this._store.resolve(alertId);
    if (alert) {
      logger.info('Alert resolved', { id: alertId });
      this._bus.emit('alert:resolved', alert);
    }
    return alert;
  }

  async acknowledge(alertId, by = 'system') {
    const alert = await this._store.acknowledge(alertId, by);
    if (alert) {
      logger.info('Alert acknowledged', { id: alertId, by });
      this._bus.emit('alert:acknowledged', alert);
    }
    return alert;
  }

  async bulkAcknowledge(alertIds, by = 'system') {
    const results = [];
    for (const id of alertIds) {
      const result = await this.acknowledge(id, by);
      if (result) results.push(result);
    }
    return results;
  }

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  async getActiveAlerts() {
    return this._store.findAll({ status: 'active' });
  }

  async getAllAlerts(filters = {}) {
    return this._store.findAll(filters);
  }

  async getAlertById(id) {
    return this._store.findById(id);
  }

  async updateAlert(id, changes) {
    return this._store.update(id, changes);
  }

  async deleteAlert(id) {
    return this._store.delete(id);
  }

  async getActiveAlertCount() {
    return this._store.getActiveCount();
  }

  // ---------------------------------------------------------------------------
  // Evaluation
  // ---------------------------------------------------------------------------

  /**
   * Evaluate all enabled rules against a snapshot of current metric values.
   * @param {object} metricValues  { [metricName]: number }
   */
  async evaluateRules(metricValues) {
    for (const rule of this._rules.values()) {
      if (!rule.enabled) continue;
      const currentValue = metricValues[rule.metric];
      if (currentValue === undefined || currentValue === null) continue;

      const breached = this._evaluate(currentValue, rule.operator, rule.threshold);
      if (breached) {
        // Check if there's already an active alert for this rule
        const existing = await this._store.findAll({ status: 'active', service: rule.service });
        const already = existing.find((a) => a.name === rule.name);
        if (!already) {
          await this.trigger({
            name: rule.name,
            service: rule.service,
            severity: rule.severity,
            message: `${rule.metric} is ${currentValue} (threshold: ${rule.operator} ${rule.threshold})`,
            metric: rule.metric,
            threshold: rule.threshold,
            currentValue,
          });
        }
      }
    }
  }

  _evaluate(value, operator, threshold) {
    switch (operator) {
      case '>':  return value > threshold;
      case '<':  return value < threshold;
      case '>=': return value >= threshold;
      case '<=': return value <= threshold;
      case '==': return value === threshold;
      case '!=': return value !== threshold;
      default:   return false;
    }
  }
}

module.exports = AlertManager;
