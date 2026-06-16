'use strict';

const { randomUUID } = require('crypto');
const EnrollmentAggregate = require('../domain/aggregates/EnrollmentAggregate');

/**
 * EnrollmentService — orchestrates device enrollment workflows.
 *
 * Accepts `{ db, enrollmentRepository, eventBus }` (DI-style).
 * Falls back gracefully when enrollmentRepository is not provided (e.g. DB unavailable)
 * by using an in-memory map so existing callers are not broken.
 */
class EnrollmentService {
  /**
   * @param {object} db          — legacy db module (kept for fallback / health checks)
   * @param {object} eventBus    — EventBus instance
   * @param {object} [enrollmentRepository] — IEnrollmentRepository implementation
   */
  constructor(db, eventBus, enrollmentRepository = null) {
    this._db = db;
    this._eventBus = eventBus;
    this._repo = enrollmentRepository;

    // In-memory fallback for when the repo / DB is unavailable
    this._memStore = new Map();
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * Begin a new enrollment flow.
   * @param {object} data
   * @param {string} data.hostname
   * @param {string} data.platform
   * @param {string} [data.requestedBy]
   * @param {object} [data.metadata]
   * @returns {Promise<object>} enrollment plain object (toJSON)
   */
  async initiateEnrollment(data) {
    const id = data.id || randomUUID();
    const enrollment = EnrollmentAggregate.create({ ...data, id });

    await this._save(enrollment);
    this._dispatchEvents(enrollment);

    return enrollment.toJSON();
  }

  /**
   * Mark an enrollment as completed and link it to a device.
   * @param {string} enrollmentId
   * @param {object} deviceData
   * @param {string} deviceData.deviceId
   * @returns {Promise<object>} updated enrollment plain object
   */
  async completeEnrollment(enrollmentId, deviceData) {
    const enrollment = await this._findById(enrollmentId);
    if (!enrollment) throw new Error(`Enrollment not found: ${enrollmentId}`);

    const deviceId = deviceData.deviceId || randomUUID();
    enrollment.complete(deviceId);

    await this._save(enrollment);
    this._dispatchEvents(enrollment);

    // Notify higher-level event subscribers (legacy EventBus contract)
    if (this._eventBus) {
      this._eventBus.emit('device:enrolled', {
        device: { id: deviceId, platform: enrollment.platform, enrolledAt: enrollment.completedAt }
      });
    }

    return enrollment.toJSON();
  }

  /**
   * Approve a pending enrollment.
   * @param {string} enrollmentId
   * @returns {Promise<object>}
   */
  async approveEnrollment(enrollmentId) {
    const enrollment = await this._findById(enrollmentId);
    if (!enrollment) throw new Error(`Enrollment not found: ${enrollmentId}`);

    enrollment.approve();
    await this._save(enrollment);
    this._dispatchEvents(enrollment);

    return enrollment.toJSON();
  }

  /**
   * Reject a pending enrollment.
   * @param {string} enrollmentId
   * @param {string} [reason]
   * @returns {Promise<object>}
   */
  async rejectEnrollment(enrollmentId, reason = '') {
    const enrollment = await this._findById(enrollmentId);
    if (!enrollment) throw new Error(`Enrollment not found: ${enrollmentId}`);

    enrollment.reject(reason);
    await this._save(enrollment);
    this._dispatchEvents(enrollment);

    return enrollment.toJSON();
  }

  /**
   * Fetch a single enrollment by id.
   * @param {string} id
   * @returns {Promise<object|null>}
   */
  async getEnrollment(id) {
    const enrollment = await this._findById(id);
    return enrollment ? enrollment.toJSON() : null;
  }

  /**
   * Return all enrollments, optionally filtered.
   * @param {object} [filters]
   * @returns {Promise<object[]>}
   */
  async listEnrollments(filters = {}) {
    if (this._repo) {
      try {
        const enrollments = await this._repo.findAll(filters);
        return enrollments.map(e => e.toJSON());
      } catch (err) {
        // fall through to memory store
      }
    }
    let items = [...this._memStore.values()];
    if (filters.status) items = items.filter(e => e._status === filters.status);
    if (filters.deviceId) items = items.filter(e => e._deviceId === filters.deviceId);
    return items.map(e => e.toJSON());
  }

  /**
   * Basic verification step (can be extended with token/signature validation).
   * @param {string|object} tokenOrData — a raw token string or { enrollmentId } object
   * @returns {Promise<object|null>}
   */
  async verifyEnrollment(tokenOrData) {
    // Support both legacy string token and object form
    if (typeof tokenOrData === 'string') {
      // Token-based lookup: find enrollment whose metadata.token matches
      const all = [...this._memStore.values()];
      const match = all.find(e => e._metadata && e._metadata.token === tokenOrData);
      return match ? match.toJSON() : null;
    }
    const { enrollmentId } = tokenOrData;
    const enrollment = await this._findById(enrollmentId);
    if (!enrollment) return null;
    return enrollment.toJSON();
  }

  /**
   * Alias for getEnrollment — used by route handlers in index.js.
   * @param {string} id
   * @returns {Promise<object|null>}
   */
  async getEnrollmentStatus(id) {
    return this.getEnrollment(id);
  }

  /**
   * Count enrollments in pending state (used by health-check endpoint).
   * @returns {Promise<number>}
   */
  async getPendingCount() {
    try {
      const items = await this.listEnrollments({ status: 'pending' });
      return items.length;
    } catch {
      return 0;
    }
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  async _findById(id) {
    if (this._repo) {
      try {
        return await this._repo.findById(id);
      } catch {
        // fall through to memory store
      }
    }
    return this._memStore.get(id) || null;
  }

  async _save(enrollment) {
    this._memStore.set(enrollment.id, enrollment);
    if (this._repo) {
      try {
        await this._repo.save(enrollment);
      } catch (err) {
        // Memory store already updated — log and continue
        console.warn('[EnrollmentService] repo.save failed, using memory fallback:', err.message);
      }
    }
  }

  _dispatchEvents(enrollment) {
    const events = enrollment.getAndClearDomainEvents();
    if (this._eventBus && events.length) {
      for (const event of events) {
        this._eventBus.emit(event.type, event.payload);
      }
    }
  }
}

module.exports = EnrollmentService;
