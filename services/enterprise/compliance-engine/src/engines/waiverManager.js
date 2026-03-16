'use strict';

/**
 * WaiverManager – manages compliance exception waivers with audit trails,
 * auto-expiry and device/group scoping.
 */
class WaiverManager {
  constructor({ pgPool, redis, logger }) {
    this.pgPool = pgPool;
    this.redis = redis;
    this.logger = logger;
  }

  // ---------------------------------------------------------------------------
  // Core operations
  // ---------------------------------------------------------------------------

  /**
   * Create a new waiver.
   * @param {object} waiver
   * @param {string} waiver.deviceId - target device (or null for group)
   * @param {string} [waiver.groupId] - target group (alternative to deviceId)
   * @param {string} waiver.checkId - the compliance check to waive
   * @param {string} waiver.reason - justification
   * @param {string} waiver.approvedBy - who approved the waiver
   * @param {string} waiver.expiresAt - ISO date when waiver expires
   * @param {string} [waiver.baselineId] - optional baseline scope
   */
  async createWaiver(waiver) {
    if (!waiver.checkId) throw new Error('checkId is required');
    if (!waiver.reason) throw new Error('reason is required');
    if (!waiver.approvedBy) throw new Error('approvedBy is required');
    if (!waiver.expiresAt) throw new Error('expiresAt is required');
    if (!waiver.deviceId && !waiver.groupId) {
      throw new Error('Either deviceId or groupId is required');
    }

    const expiresAt = new Date(waiver.expiresAt);
    if (expiresAt <= new Date()) throw new Error('expiresAt must be in the future');

    const { rows } = await this.pgPool.query(
      `INSERT INTO compliance_waivers
       (device_id, device_group, baseline_id, check_id, reason, approved_by, expires_at, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
       RETURNING *`,
      [
        waiver.deviceId || null,
        waiver.groupId || null,
        waiver.baselineId || null,
        waiver.checkId,
        waiver.reason,
        waiver.approvedBy,
        expiresAt.toISOString(),
      ]
    );

    const created = rows[0];

    // Cache in Redis for fast lookup
    await this._cacheWaiver(created);

    this.logger.info('Waiver created', {
      id: created.id,
      deviceId: created.device_id,
      checkId: created.check_id,
      expiresAt: created.expires_at,
    });

    return created;
  }

  /**
   * Revoke a waiver by ID.
   */
  async revokeWaiver(waiverId) {
    const { rows } = await this.pgPool.query(
      `UPDATE compliance_waivers SET status = 'revoked' WHERE id = $1 AND status = 'active' RETURNING *`,
      [waiverId]
    );
    if (rows.length === 0) return null;

    const waiver = rows[0];
    await this._invalidateWaiverCache(waiver);

    this.logger.info('Waiver revoked', { id: waiverId });
    return waiver;
  }

  /**
   * Check if a specific check is waived for a device.
   */
  async isWaived(deviceId, checkId) {
    // Fast path: Redis cache
    const cacheKey = `waiver:${deviceId}:${checkId}`;
    try {
      const cached = await this.redis.get(cacheKey);
      if (cached !== null) return cached === '1';
    } catch {
      // Redis unavailable, fall through to DB
    }

    // Query database
    try {
      const { rows } = await this.pgPool.query(
        `SELECT id FROM compliance_waivers
         WHERE (device_id = $1 OR device_group IN (
           SELECT device_group FROM compliance_waivers WHERE device_id = $1
         ))
         AND check_id = $2
         AND status = 'active'
         AND expires_at > NOW()
         LIMIT 1`,
        [deviceId, checkId]
      );
      const waived = rows.length > 0;

      // Cache result (short TTL)
      try {
        await this.redis.setex(cacheKey, 300, waived ? '1' : '0');
      } catch {
        // best effort
      }

      return waived;
    } catch {
      return false;
    }
  }

  /**
   * Get all active waivers.
   */
  async getActiveWaivers() {
    // First, expire any past-due waivers
    await this._expireWaivers();

    const { rows } = await this.pgPool.query(
      `SELECT * FROM compliance_waivers WHERE status = 'active' ORDER BY expires_at ASC`
    );
    return rows;
  }

  /**
   * Get active waivers for a specific device.
   */
  async getActiveWaiversForDevice(deviceId) {
    const { rows } = await this.pgPool.query(
      `SELECT * FROM compliance_waivers
       WHERE (device_id = $1 OR device_group IS NOT NULL)
       AND status = 'active' AND expires_at > NOW()
       ORDER BY expires_at ASC`,
      [deviceId]
    );
    return rows;
  }

  /**
   * Count active waivers.
   */
  async countActive() {
    try {
      const { rows } = await this.pgPool.query(
        `SELECT COUNT(*) AS count FROM compliance_waivers WHERE status = 'active' AND expires_at > NOW()`
      );
      return parseInt(rows[0].count, 10);
    } catch {
      return 0;
    }
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Auto-expire waivers that are past their expiration date.
   */
  async _expireWaivers() {
    try {
      const { rowCount } = await this.pgPool.query(
        `UPDATE compliance_waivers SET status = 'expired'
         WHERE status = 'active' AND expires_at <= NOW()`
      );
      if (rowCount > 0) {
        this.logger.info('Auto-expired waivers', { count: rowCount });
      }
    } catch (err) {
      this.logger.error('Failed to expire waivers', { error: err.message });
    }
  }

  /**
   * Cache a waiver in Redis.
   */
  async _cacheWaiver(waiver) {
    if (!waiver.device_id) return;
    const key = `waiver:${waiver.device_id}:${waiver.check_id}`;
    const ttl = Math.max(1, Math.floor((new Date(waiver.expires_at) - Date.now()) / 1000));
    try {
      await this.redis.setex(key, Math.min(ttl, 86400), '1');
    } catch {
      // best effort
    }
  }

  /**
   * Invalidate waiver cache entry.
   */
  async _invalidateWaiverCache(waiver) {
    if (!waiver.device_id) return;
    const key = `waiver:${waiver.device_id}:${waiver.check_id}`;
    try {
      await this.redis.del(key);
    } catch {
      // best effort
    }
  }
}

module.exports = WaiverManager;
