'use strict';

const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

/**
 * AuditService
 *
 * Persists authentication and security events to the database when available,
 * and falls back to in-memory storage (with structured log output) when the DB
 * is offline.  All methods are async to make the call-site uniform.
 */
class AuditService {
  constructor() {
    // Lazy-load db to avoid crashing at require-time if it is absent
    this._db = null;
    this._inMemory = [];
    this._dbAvailable = false;
    this._initDb();
  }

  // ── Initialisation ──────────────────────────────────────────────────────────

  async _initDb() {
    try {
      const db = require('../db');
      this._db = db;
      this._dbAvailable = typeof db.isAvailable === 'function'
        ? await db.isAvailable()
        : true;

      if (this._dbAvailable) {
        await this._ensureSchema();
        logger.info('AuditService: database backend ready');
      } else {
        logger.warn('AuditService: database not available, using in-memory fallback');
      }
    } catch (err) {
      logger.warn('AuditService: db module not found, using in-memory fallback', { error: err.message });
      this._dbAvailable = false;
    }
  }

  async _ensureSchema() {
    if (!this._dbAvailable || !this._db) return;
    try {
      await this._db.query(`
        CREATE TABLE IF NOT EXISTS audit_events (
          id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          event_type  VARCHAR(64)  NOT NULL,
          user_id     VARCHAR(128),
          username    VARCHAR(256),
          ip_address  VARCHAR(64),
          user_agent  TEXT,
          metadata    JSONB,
          created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await this._db.query(`
        CREATE INDEX IF NOT EXISTS idx_audit_user_id   ON audit_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at DESC);
      `);
    } catch (err) {
      logger.warn('AuditService: schema init warning', { error: err.message });
    }
  }

  // ── Core persistence ────────────────────────────────────────────────────────

  async _record(eventType, userId, metadata = {}, req = null) {
    const event = {
      id: uuidv4(),
      event_type: eventType,
      user_id: userId || null,
      username: metadata.username || null,
      ip_address: req?.ip || null,
      user_agent: req?.headers?.['user-agent'] || null,
      metadata,
      created_at: new Date().toISOString(),
    };

    logger.info(`audit: ${eventType}`, { userId, ip: event.ip_address, ...metadata });

    if (this._dbAvailable && this._db) {
      try {
        await this._db.query(
          `INSERT INTO audit_events (id, event_type, user_id, username, ip_address, user_agent, metadata, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [
            event.id,
            event.event_type,
            event.user_id,
            event.username,
            event.ip_address,
            event.user_agent,
            JSON.stringify(event.metadata),
            event.created_at,
          ]
        );
        return event;
      } catch (err) {
        logger.warn('AuditService: db write failed, buffering in memory', { error: err.message });
        this._dbAvailable = false;
      }
    }

    // In-memory fallback — keep last 10 000 events
    this._inMemory.push(event);
    if (this._inMemory.length > 10000) {
      this._inMemory.splice(0, this._inMemory.length - 10000);
    }

    return event;
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  /**
   * Log a successful authentication event.
   */
  async logSuccessfulAuth(userId, req, provider = 'local') {
    return this._record('auth_success', userId, { provider }, req);
  }

  /**
   * Log a failed authentication attempt.
   */
  async logFailedAuth(username, req, reason = 'unknown') {
    return this._record('auth_failure', null, { username, reason }, req);
  }

  /**
   * Log a generic security event (MFA changes, session revocation, etc.).
   */
  async logSecurityEvent(eventType, userId, req, extra = {}) {
    return this._record(eventType, userId, extra, req);
  }

  /**
   * Log a user lifecycle event (registration, profile update, etc.).
   */
  async logUserEvent(eventType, userId, req, extra = {}) {
    return this._record(eventType, userId, extra, req);
  }

  /**
   * Log an admin action.
   */
  async logAdminAction(action, adminUserId, details = {}, req = null) {
    return this._record('admin_action', adminUserId, { action, ...details }, req);
  }

  // ── Query API ────────────────────────────────────────────────────────────────

  /**
   * Return the most recent login events for a user.
   */
  async getLoginHistory(userId, limit = 50) {
    const events = await this._queryEvents({
      userId,
      eventTypes: ['auth_success', 'auth_failure'],
      limit,
    });
    return events;
  }

  /**
   * Return security events filtered by various criteria.
   */
  async getSecurityEvents({ userId, eventType, startDate, endDate, limit = 100 } = {}) {
    return this._queryEvents({ userId, eventType, startDate, endDate, limit });
  }

  async _queryEvents({ userId, eventType, eventTypes, startDate, endDate, limit = 100 }) {
    if (this._dbAvailable && this._db) {
      try {
        const conditions = [];
        const params = [];

        if (userId) {
          conditions.push(`user_id = $${params.length + 1}`);
          params.push(userId);
        }

        if (eventType) {
          conditions.push(`event_type = $${params.length + 1}`);
          params.push(eventType);
        } else if (eventTypes && eventTypes.length > 0) {
          conditions.push(`event_type = ANY($${params.length + 1})`);
          params.push(eventTypes);
        }

        if (startDate) {
          conditions.push(`created_at >= $${params.length + 1}`);
          params.push(new Date(startDate));
        }

        if (endDate) {
          conditions.push(`created_at <= $${params.length + 1}`);
          params.push(new Date(endDate));
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        params.push(Math.min(limit, 1000));

        const { rows } = await this._db.query(
          `SELECT * FROM audit_events ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
          params
        );
        return rows;
      } catch (err) {
        logger.warn('AuditService: query error, falling back to in-memory', { error: err.message });
      }
    }

    // In-memory fallback
    let results = [...this._inMemory];

    if (userId) results = results.filter(e => e.user_id === userId);
    if (eventType) results = results.filter(e => e.event_type === eventType);
    if (eventTypes) results = results.filter(e => eventTypes.includes(e.event_type));
    if (startDate) results = results.filter(e => new Date(e.created_at) >= new Date(startDate));
    if (endDate) results = results.filter(e => new Date(e.created_at) <= new Date(endDate));

    return results.reverse().slice(0, limit);
  }
}

module.exports = AuditService;
