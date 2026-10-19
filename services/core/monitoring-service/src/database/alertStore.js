'use strict';

const logger = require('../utils/logger');
const db = require('../db/client');

/**
 * AlertStore — DB-first alert persistence with an in-memory fallback.
 *
 * All public methods keep the exact same signatures and return shapes as
 * the original in-memory-only implementation. Reads are DB-first, falling
 * back to the in-memory Map when the DB is unavailable or a query errors;
 * writes always update the in-memory Map too (so it stays a faithful
 * mirror for the fallback path) and are best-effort against the DB — a DB
 * write failure is logged and swallowed rather than thrown, since alerting
 * must keep working even if PostgreSQL is flaky. Every returned alert
 * object is built/merged in JS rather than handed back verbatim from a DB
 * row, so callers see the same shape and field types (e.g. createdAt stays
 * a JS number) whether or not the DB is available.
 *
 * See src/db/client.js for the connection/migration wiring and
 * src/db/migrations/001_alerts_schema.sql for the schema.
 */
class AlertStore {
  constructor() {
    // In-memory store: Map<alertId, alert> — the fallback for when
    // PostgreSQL is unavailable, and the read source before initDb()
    // resolves.
    this._alerts = new Map();
    this._nextId = 1;
    this._closed = false;

    // Fire-and-forget: connects + runs migrations in the background.
    // Every method below checks db.isAvailable() before touching the DB,
    // so callers don't need to await this — behavior degrades gracefully
    // to pure in-memory until/unless it resolves successfully.
    db.initDb().catch((err) => logger.warn('AlertStore: initDb failed', { error: err.message }));

    logger.info('AlertStore initialised (in-memory, DB-first once connected)');
  }

  // ---------------------------------------------------------------------------
  // Row <-> object mapping
  // ---------------------------------------------------------------------------

  static _rowToAlert(row) {
    return {
      id: row.id,
      name: row.name,
      service: row.service,
      severity: row.severity,
      status: row.status,
      message: row.message,
      metric: row.metric,
      threshold: row.threshold,
      currentValue: row.current_value,
      labels: row.labels || {},
      notificationsSent: row.notifications_sent || [],
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      acknowledgedAt: row.acknowledged_at,
      acknowledgedBy: row.acknowledged_by,
      resolvedAt: row.resolved_at,
    };
  }

  async _dbInsert(alert) {
    if (!db.isAvailable()) return;
    try {
      await db.query(
        `INSERT INTO alerts(id, name, service, severity, status, message, metric, threshold, current_value,
                             labels, notifications_sent, created_at, updated_at, acknowledged_at, acknowledged_by, resolved_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         ON CONFLICT (id) DO NOTHING`,
        [
          alert.id, alert.name, alert.service, alert.severity, alert.status, alert.message, alert.metric,
          alert.threshold, alert.currentValue, JSON.stringify(alert.labels), JSON.stringify(alert.notificationsSent),
          alert.createdAt, alert.updatedAt, alert.acknowledgedAt, alert.acknowledgedBy, alert.resolvedAt,
        ]
      );
    } catch (err) {
      logger.warn('AlertStore: DB insert failed', { error: err.message });
    }
  }

  async _dbUpdate(alert) {
    if (!db.isAvailable()) return;
    try {
      await db.query(
        `UPDATE alerts SET name=$2, service=$3, severity=$4, status=$5, message=$6, metric=$7, threshold=$8,
                            current_value=$9, labels=$10, notifications_sent=$11, updated_at=$12,
                            acknowledged_at=$13, acknowledged_by=$14, resolved_at=$15
         WHERE id=$1`,
        [
          alert.id, alert.name, alert.service, alert.severity, alert.status, alert.message, alert.metric,
          alert.threshold, alert.currentValue, JSON.stringify(alert.labels), JSON.stringify(alert.notificationsSent),
          alert.updatedAt, alert.acknowledgedAt, alert.acknowledgedBy, alert.resolvedAt,
        ]
      );
    } catch (err) {
      logger.warn('AlertStore: DB update failed', { error: err.message });
    }
  }

  async _dbDelete(id) {
    if (!db.isAvailable()) return;
    try {
      await db.query('DELETE FROM alerts WHERE id=$1', [id]);
    } catch (err) {
      logger.warn('AlertStore: DB delete failed', { error: err.message });
    }
  }

  async _dbFindById(id) {
    if (!db.isAvailable()) return undefined;
    try {
      const r = await db.query('SELECT * FROM alerts WHERE id=$1', [id]);
      return r.rows.length ? AlertStore._rowToAlert(r.rows[0]) : null;
    } catch (err) {
      logger.warn('AlertStore: DB findById failed, falling back to in-memory', { error: err.message });
      return undefined;
    }
  }

  async _dbFindAll() {
    if (!db.isAvailable()) return null;
    try {
      const r = await db.query('SELECT * FROM alerts');
      return r.rows.map(AlertStore._rowToAlert);
    } catch (err) {
      logger.warn('AlertStore: DB findAll failed, falling back to in-memory', { error: err.message });
      return null;
    }
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
    await this._dbInsert(alert);
    this._alerts.set(id, alert);
    logger.debug('AlertStore: created', { id, severity: alert.severity });
    return alert;
  }

  async findById(id) {
    const fromDb = await this._dbFindById(id);
    if (fromDb !== undefined) return fromDb;
    return this._alerts.get(id) || null;
  }

  async findAll({ status, severity, service, limit = 100, offset = 0 } = {}) {
    const fromDb = await this._dbFindAll();
    let results = fromDb !== null ? fromDb : Array.from(this._alerts.values());

    if (status)   results = results.filter((a) => a.status === status);
    if (severity) results = results.filter((a) => a.severity === severity);
    if (service)  results = results.filter((a) => a.service === service);

    // Most-recent first
    results.sort((a, b) => b.createdAt - a.createdAt);

    return results.slice(offset, offset + limit);
  }

  async update(id, changes) {
    const existing = await this.findById(id);
    if (!existing) return null;
    const updated = { ...existing, ...changes, updatedAt: Date.now() };
    await this._dbUpdate(updated);
    this._alerts.set(id, updated);
    return updated;
  }

  async delete(id) {
    const existing = await this.findById(id);
    if (!existing) return false;
    await this._dbDelete(id);
    this._alerts.delete(id);
    return true;
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
    // Unbounded: countByStatus must reflect every alert, not just the
    // default findAll() page size.
    const all = await this.findAll({ limit: Number.MAX_SAFE_INTEGER, offset: 0 });
    const counts = { active: 0, acknowledged: 0, resolved: 0 };
    for (const a of all) {
      if (counts[a.status] !== undefined) counts[a.status]++;
    }
    return counts;
  }

  async getActiveCount() {
    const all = await this.findAll({ status: 'active', limit: Number.MAX_SAFE_INTEGER, offset: 0 });
    return all.length;
  }

  async close() {
    this._closed = true;
    logger.info('AlertStore closed');
  }
}

module.exports = AlertStore;
