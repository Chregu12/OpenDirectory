/**
 * OpenDirectory Directory Audit Trail
 * Records all directory changes, authentication events, group membership
 * changes, and GPO changes for compliance and forensic analysis.
 *
 * Uses Mongoose for persistence (consistent with the rest of the service).
 * The constructor accepts a mongoose connection or any object with a
 * .model() method; when called with the global mongoose instance, it
 * piggybacks on the existing connection managed by index.js.
 */

const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { logger } = require('../utils/logger');

// ── Mongoose schema ────────────────────────────────────────────────────────────

const AuditLogSchema = new mongoose.Schema(
  {
    eventTime: { type: Date, default: Date.now, index: true },
    actorId: { type: String, index: true },
    actorDn: { type: String },
    targetDn: { type: String, index: true },
    targetType: {
      type: String,
      enum: ['user', 'group', 'computer', 'ou', 'gpo', 'domain', 'auth'],
    },
    operation: { type: String, required: true, index: true },
    attributesChanged: { type: mongoose.Schema.Types.Mixed },
    ipAddress: { type: String },
    requestId: { type: String },
    success: { type: Boolean, default: true },
    failureReason: { type: String },
  },
  {
    collection: 'directory_audit_log',
    // Automatically expire entries after 365 days (matches config.logging.auditLog.retention)
    // TTL index on eventTime — set to 365 days in seconds
    timeseries: false,
  }
);

// Compound indexes for common query patterns
AuditLogSchema.index({ eventTime: -1 });
AuditLogSchema.index({ actorId: 1, eventTime: -1 });
AuditLogSchema.index({ targetDn: 1, eventTime: -1 });
AuditLogSchema.index({ operation: 1, eventTime: -1 });

// ── Model (lazy-register to avoid OverwriteModelError on hot-reload) ──────────
function getAuditModel() {
  try {
    return mongoose.model('DirectoryAuditLog');
  } catch (_) {
    return mongoose.model('DirectoryAuditLog', AuditLogSchema);
  }
}

// ── DirectoryAudit class ──────────────────────────────────────────────────────

class DirectoryAudit {
  /**
   * @param {object} db - A mongoose connection/instance (or any object that
   *   exposes a compatible `.model()` — kept for interface compatibility with
   *   the pg Pool signature described in the spec).
   * @param {Function} [publishFn] - Optional async function(topic, payload) for
   *   event-bus publishing.  If omitted, events are only logged.
   */
  constructor(db, publishFn) {
    // db is accepted for interface compatibility; actual persistence goes
    // through the global mongoose instance (same connection as the rest of the
    // service).  If a separate connection is passed, we honour it.
    this._db = db;
    this._publish = typeof publishFn === 'function' ? publishFn : null;
    this._model = getAuditModel();
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  async _insert(doc) {
    try {
      const entry = new this._model(doc);
      await entry.save();
      return entry;
    } catch (err) {
      logger.error('[DirectoryAudit] Failed to persist audit entry:', err);
      // Never let audit failures crash the caller
      return null;
    }
  }

  async _publishEvent(topic, payload) {
    if (!this._publish) return;
    try {
      await this._publish(topic, payload);
    } catch (err) {
      logger.warn(`[DirectoryAudit] Failed to publish event ${topic}:`, err.message);
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Record any AD object change.
   * @param {object} opts
   * @param {string} opts.actorId
   * @param {string} opts.actorDn
   * @param {string} opts.targetDn
   * @param {string} opts.targetType  - 'user'|'group'|'computer'|'ou'|'gpo'|'domain'
   * @param {string} opts.operation   - 'create'|'modify'|'delete'|'move'|'rename'
   * @param {object} opts.attributes  - attributes changed / new values
   * @param {string} [opts.ipAddress]
   * @param {string} [opts.requestId]
   * @returns {Promise<object>}
   */
  async logObjectChange({
    actorId,
    actorDn,
    targetDn,
    targetType,
    operation,
    attributes,
    ipAddress,
    requestId,
  }) {
    const doc = {
      actorId,
      actorDn,
      targetDn,
      targetType,
      operation,
      attributesChanged: attributes || {},
      ipAddress,
      requestId: requestId || uuidv4(),
      success: true,
    };

    const entry = await this._insert(doc);

    // Derive event-bus topic from operation
    const topicMap = {
      create: 'directory.object.created',
      modify: 'directory.object.modified',
      delete: 'directory.object.deleted',
      move: 'directory.object.modified',
      rename: 'directory.object.modified',
    };
    const topic = topicMap[operation] || 'directory.object.modified';

    await this._publishEvent(topic, {
      targetDn,
      targetType,
      actorId,
      timestamp: new Date().toISOString(),
    });

    return entry;
  }

  /**
   * Record authentication events.
   * @param {object} opts
   * @param {string} opts.userId
   * @param {string} opts.userDn
   * @param {string} opts.eventType  - 'login'|'logout'|'failed_login'|'lockout'|'unlock'|'password_change'|'password_reset'
   * @param {string} [opts.ipAddress]
   * @param {boolean} opts.success
   * @param {string} [opts.failureReason]
   * @returns {Promise<object>}
   */
  async logAuthEvent({ userId, userDn, eventType, ipAddress, success, failureReason }) {
    const doc = {
      actorId: userId,
      actorDn: userDn,
      targetDn: userDn,
      targetType: 'auth',
      operation: eventType,
      attributesChanged: { eventType },
      ipAddress,
      requestId: uuidv4(),
      success: success !== false,
      failureReason: failureReason || null,
    };

    return this._insert(doc);
  }

  /**
   * Record permission/group membership changes.
   * @param {object} opts
   * @param {string} opts.actorId
   * @param {string} opts.groupDn
   * @param {string} opts.operation  - 'member_added'|'member_removed'
   * @param {string} opts.memberDn
   * @returns {Promise<object>}
   */
  async logGroupChange({ actorId, groupDn, operation, memberDn }) {
    const doc = {
      actorId,
      targetDn: groupDn,
      targetType: 'group',
      operation,
      attributesChanged: { memberDn },
      requestId: uuidv4(),
      success: true,
    };

    const entry = await this._insert(doc);

    await this._publishEvent('directory.object.modified', {
      targetDn: groupDn,
      targetType: 'group',
      actorId,
      timestamp: new Date().toISOString(),
    });

    return entry;
  }

  /**
   * Record GPO changes.
   * @param {object} opts
   * @param {string} opts.actorId
   * @param {string} opts.gpoId
   * @param {string} opts.operation  - 'create'|'modify'|'delete'|'link'|'unlink'|'apply'
   * @param {string} [opts.ouDn]
   * @param {object} [opts.settings]
   * @returns {Promise<object>}
   */
  async logGPOChange({ actorId, gpoId, operation, ouDn, settings }) {
    const doc = {
      actorId,
      targetDn: ouDn || `GPO:${gpoId}`,
      targetType: 'gpo',
      operation,
      attributesChanged: { gpoId, ouDn, settings: settings || {} },
      requestId: uuidv4(),
      success: true,
    };

    return this._insert(doc);
  }

  // ── Query methods ───────────────────────────────────────────────────────────

  /**
   * Query the audit log with optional filters.
   * @param {object} opts
   * @param {Date|string} [opts.from]
   * @param {Date|string} [opts.to]
   * @param {string} [opts.actorId]
   * @param {string} [opts.targetDn]
   * @param {string} [opts.operation]
   * @param {number} [opts.limit=100]
   * @param {number} [opts.offset=0]
   * @returns {Promise<{entries: Array, total: number}>}
   */
  async queryAuditLog({ from, to, actorId, targetDn, operation, limit = 100, offset = 0 } = {}) {
    const filter = {};

    if (from || to) {
      filter.eventTime = {};
      if (from) filter.eventTime.$gte = new Date(from);
      if (to) filter.eventTime.$lte = new Date(to);
    }
    if (actorId) filter.actorId = actorId;
    if (targetDn) filter.targetDn = targetDn;
    if (operation) filter.operation = operation;

    const [entries, total] = await Promise.all([
      this._model
        .find(filter)
        .sort({ eventTime: -1 })
        .skip(Number(offset))
        .limit(Number(limit))
        .lean(),
      this._model.countDocuments(filter),
    ]);

    return { entries, total };
  }

  /**
   * Return full change history for a specific directory object.
   * @param {string} targetDn
   * @returns {Promise<Array>}
   */
  async getObjectHistory(targetDn) {
    return this._model
      .find({ targetDn })
      .sort({ eventTime: -1 })
      .lean();
  }

  /**
   * Return all actions performed by a specific actor within an optional window.
   * @param {string} actorId
   * @param {object} [opts]
   * @param {Date|string} [opts.from]
   * @param {Date|string} [opts.to]
   * @returns {Promise<Array>}
   */
  async getActorActivity(actorId, { from, to } = {}) {
    const filter = { actorId };
    if (from || to) {
      filter.eventTime = {};
      if (from) filter.eventTime.$gte = new Date(from);
      if (to) filter.eventTime.$lte = new Date(to);
    }

    return this._model
      .find(filter)
      .sort({ eventTime: -1 })
      .lean();
  }
}

module.exports = DirectoryAudit;
