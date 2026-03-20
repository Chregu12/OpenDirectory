'use strict';

const logger = require('../utils/logger');

class WaiverManager {
  constructor(db) {
    this.db = db;
  }

  /**
   * Create a compliance waiver with expiration and approval tracking.
   */
  async createWaiver(data) {
    const { deviceId, deviceGroup, baselineId, checkId, reason, approvedBy, expiresAt } = data;

    // Validation
    if (!checkId) {
      throw new Error('check_id is required');
    }
    if (!reason || reason.trim().length < 10) {
      throw new Error('A meaningful reason is required (minimum 10 characters)');
    }
    if (!approvedBy) {
      throw new Error('approved_by is required');
    }
    if (!expiresAt) {
      throw new Error('expires_at is required');
    }

    const expirationDate = new Date(expiresAt);
    if (isNaN(expirationDate.getTime())) {
      throw new Error('Invalid expires_at date format');
    }
    if (expirationDate <= new Date()) {
      throw new Error('expires_at must be in the future');
    }

    // Maximum waiver duration: 1 year
    const maxExpiration = new Date();
    maxExpiration.setFullYear(maxExpiration.getFullYear() + 1);
    if (expirationDate > maxExpiration) {
      throw new Error('Waiver duration cannot exceed 1 year');
    }

    if (!deviceId && !deviceGroup) {
      throw new Error('Either device_id or device_group is required');
    }

    // Check for duplicate active waivers
    const duplicateCheck = await this.db.query(
      `SELECT id FROM compliance_waivers
       WHERE check_id = $1 AND status = 'active' AND expires_at > NOW()
         AND (device_id = $2 OR device_group = $3)`,
      [checkId, deviceId || null, deviceGroup || null]
    );

    if (duplicateCheck.rows.length > 0) {
      throw new Error(`An active waiver already exists for check ${checkId} on this device/group`);
    }

    const { rows } = await this.db.query(
      `INSERT INTO compliance_waivers
        (device_id, device_group, baseline_id, check_id, reason, approved_by, expires_at, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
       RETURNING *`,
      [
        deviceId || null,
        deviceGroup || null,
        baselineId || null,
        checkId,
        reason.trim(),
        approvedBy,
        expirationDate.toISOString(),
      ]
    );

    logger.info(`Created waiver ${rows[0].id} for check ${checkId}`, {
      waiverId: rows[0].id,
      deviceId,
      deviceGroup,
      checkId,
      approvedBy,
      expiresAt: expirationDate.toISOString(),
    });

    return rows[0];
  }

  /**
   * Revoke an active waiver.
   */
  async revokeWaiver(id) {
    const { rows } = await this.db.query(
      `UPDATE compliance_waivers SET status = 'revoked' WHERE id = $1 AND status = 'active' RETURNING *`,
      [id]
    );

    if (rows.length === 0) {
      throw new Error(`Waiver not found or already revoked/expired: ${id}`);
    }

    logger.info(`Revoked waiver ${id}`, { waiverId: id, checkId: rows[0].check_id });
    return rows[0];
  }

  /**
   * Get all active waivers for a device.
   */
  async getActiveWaivers(deviceId) {
    const { rows } = await this.db.query(
      `SELECT cw.*, cb.name AS baseline_name, cb.framework
       FROM compliance_waivers cw
       LEFT JOIN compliance_baselines cb ON cw.baseline_id = cb.id
       WHERE (cw.device_id = $1 OR cw.device_id IS NULL)
         AND cw.status = 'active'
         AND cw.expires_at > NOW()
       ORDER BY cw.created_at DESC`,
      [deviceId]
    );
    return rows;
  }

  /**
   * List all waivers with optional filters.
   */
  async listWaivers(filters = {}) {
    let query = `
      SELECT cw.*, cb.name AS baseline_name, cb.framework
      FROM compliance_waivers cw
      LEFT JOIN compliance_baselines cb ON cw.baseline_id = cb.id
      WHERE 1=1
    `;
    const params = [];

    if (filters.status) {
      params.push(filters.status);
      query += ` AND cw.status = $${params.length}`;
    }

    if (filters.deviceId) {
      params.push(filters.deviceId);
      query += ` AND cw.device_id = $${params.length}`;
    }

    if (filters.deviceGroup) {
      params.push(filters.deviceGroup);
      query += ` AND cw.device_group = $${params.length}`;
    }

    if (filters.baselineId) {
      params.push(filters.baselineId);
      query += ` AND cw.baseline_id = $${params.length}`;
    }

    if (filters.checkId) {
      params.push(filters.checkId);
      query += ` AND cw.check_id = $${params.length}`;
    }

    query += ' ORDER BY cw.created_at DESC';

    if (filters.limit) {
      params.push(filters.limit);
      query += ` LIMIT $${params.length}`;
    }

    if (filters.offset) {
      params.push(filters.offset);
      query += ` OFFSET $${params.length}`;
    }

    const { rows } = await this.db.query(query, params);
    return rows;
  }

  /**
   * Mark expired waivers. Run on schedule (e.g., hourly).
   */
  async cleanupExpired() {
    const { rows } = await this.db.query(
      `UPDATE compliance_waivers
       SET status = 'expired'
       WHERE status = 'active' AND expires_at <= NOW()
       RETURNING id, check_id, device_id, device_group`,
    );

    if (rows.length > 0) {
      logger.info(`Expired ${rows.length} waivers`, {
        expiredIds: rows.map(r => r.id),
      });
    }

    return rows;
  }

  /**
   * Get waiver statistics.
   */
  async getStats() {
    const { rows } = await this.db.query(
      `SELECT
         status,
         COUNT(*) AS count
       FROM compliance_waivers
       GROUP BY status`
    );

    const stats = { active: 0, expired: 0, revoked: 0, total: 0 };
    for (const row of rows) {
      stats[row.status] = parseInt(row.count, 10);
      stats.total += parseInt(row.count, 10);
    }

    // Waivers expiring within 7 days
    const { rows: expiringSoon } = await this.db.query(
      `SELECT COUNT(*) AS count FROM compliance_waivers
       WHERE status = 'active' AND expires_at <= NOW() + INTERVAL '7 days'`
    );
    stats.expiringSoon = parseInt(expiringSoon[0].count, 10);

    return stats;
  }
}

module.exports = WaiverManager;
