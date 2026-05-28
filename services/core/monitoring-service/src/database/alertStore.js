'use strict';

const logger = require('../utils/logger');

/**
 * AlertStore — persistent-ish storage for alerts.
 *
 * Falls back to an in-memory Map when PostgreSQL is not configured / reachable.
 * All public methods are async so callers don't need to change when a real DB
 * backend is wired in later.
 */
class AlertStore {
  constructor() {
    // In-memory store: Map<alertId, alert>
    this._alerts = new Map();
    this._nextId = 1;
    this._closed = false;

    logger.info('AlertStore initialised (in-memory)');
  }

  // ---------------------------------------------------------------------------
  // CRUD
  // ---------------------------------------------------------------------------

  async create(alertData) {
    const id = alertData.id || `alert-${Date.now()}-${this._nextId++}`;
    const alert = {
      id,
      name: alertData.name || 'Unnamed Alert',
      service: alertData.service || 'unknown',
      severity: alertData.severity || 'info',   // critical | warning | info
      status: alertData.status || 'active',     // active | acknowledged | resolved
      message: alertData.message || '',
      metric: alertData.metric || null,
      threshold: alertData.threshold ?? null,
      currentValue: alertData.currentValue ?? null,
      labels: alertData.labels || {},
      notificationsSent: alertData.notificationsSent || [],
      createdAt: alertData.createdAt || Date.now(),
      updatedAt: Date.now(),
      acknowledgedAt: null,
      acknowledgedBy: null,
      resolvedAt: null,
    };
    this._alerts.set(id, alert);
    logger.debug('AlertStore: created', { id, severity: alert.severity });
    return alert;
  }

  async findById(id) {
    return this._alerts.get(id) || null;
  }

  async findAll({ status, severity, service, limit = 100, offset = 0 } = {}) {
    let results = Array.from(this._alerts.values());

    if (status)   results = results.filter((a) => a.status === status);
    if (severity) results = results.filter((a) => a.severity === severity);
    if (service)  results = results.filter((a) => a.service === service);

    // Most-recent first
    results.sort((a, b) => b.createdAt - a.createdAt);

    return results.slice(offset, offset + limit);
  }

  async update(id, changes) {
    const existing = this._alerts.get(id);
    if (!existing) return null;
    const updated = { ...existing, ...changes, updatedAt: Date.now() };
    this._alerts.set(id, updated);
    return updated;
  }

  async delete(id) {
    return this._alerts.delete(id);
  }

  // ---------------------------------------------------------------------------
  // Convenience helpers
  // ---------------------------------------------------------------------------

  async acknowledge(id, acknowledgedBy = 'system') {
    return this.update(id, {
      status: 'acknowledged',
      acknowledgedAt: Date.now(),
      acknowledgedBy,
    });
  }

  async resolve(id) {
    return this.update(id, {
      status: 'resolved',
      resolvedAt: Date.now(),
    });
  }

  async countByStatus() {
    const counts = { active: 0, acknowledged: 0, resolved: 0 };
    for (const a of this._alerts.values()) {
      if (counts[a.status] !== undefined) counts[a.status]++;
    }
    return counts;
  }

  async getActiveCount() {
    let n = 0;
    for (const a of this._alerts.values()) {
      if (a.status === 'active') n++;
    }
    return n;
  }

  async close() {
    this._closed = true;
    logger.info('AlertStore closed');
  }
}

module.exports = AlertStore;
