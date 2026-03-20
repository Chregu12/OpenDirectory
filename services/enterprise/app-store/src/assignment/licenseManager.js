'use strict';

const LICENSE_TYPES = ['unlimited', 'per-device', 'per-user', 'concurrent'];
const LICENSE_ALERT_THRESHOLD = 0.8; // 80%

class LicenseManager {
  constructor(pool, redis, logger) {
    this.pool = pool;
    this.redis = redis;
    this.logger = logger;
  }

  /**
   * Set or update license configuration for an app.
   */
  async setLicense(appId, { licenseType = 'unlimited', totalCount = 0 }) {
    if (!LICENSE_TYPES.includes(licenseType)) {
      throw new Error(`Invalid license type. Must be one of: ${LICENSE_TYPES.join(', ')}`);
    }

    const result = await this.pool.query(
      `INSERT INTO licenses (app_id, license_type, total_count, used_count)
       VALUES ($1, $2, $3, 0)
       ON CONFLICT (app_id) DO UPDATE
       SET license_type = $2, total_count = $3
       RETURNING *`,
      [appId, licenseType, totalCount]
    );

    this.logger.info('License configured', { appId, licenseType, totalCount });
    return result.rows[0];
  }

  /**
   * Allocate a license for an app on a device.
   */
  async allocateLicense(appId, deviceId, userId = null) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Check license record
      const licenseResult = await client.query(
        'SELECT * FROM licenses WHERE app_id = $1 FOR UPDATE',
        [appId]
      );

      // If no license record, treat as unlimited
      if (licenseResult.rows.length === 0) {
        await client.query(
          `INSERT INTO license_allocations (app_id, device_id, user_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (app_id, device_id) DO NOTHING`,
          [appId, deviceId, userId]
        );
        await client.query('COMMIT');
        return { allocated: true, unlimited: true };
      }

      const license = licenseResult.rows[0];

      // Unlimited licenses
      if (license.license_type === 'unlimited') {
        await client.query(
          `INSERT INTO license_allocations (app_id, device_id, user_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (app_id, device_id) DO NOTHING`,
          [appId, deviceId, userId]
        );
        await client.query(
          `UPDATE licenses SET used_count = (
            SELECT COUNT(*) FROM license_allocations WHERE app_id = $1
          ) WHERE app_id = $1`,
          [appId]
        );
        await client.query('COMMIT');
        return { allocated: true, unlimited: true };
      }

      // Check per-user: same user can install on multiple devices
      if (license.license_type === 'per-user' && userId) {
        const existingUser = await client.query(
          `SELECT COUNT(DISTINCT user_id) as user_count FROM license_allocations WHERE app_id = $1`,
          [appId]
        );
        const existingForUser = await client.query(
          `SELECT id FROM license_allocations WHERE app_id = $1 AND user_id = $2`,
          [appId, userId]
        );
        // If user already has a license, allow on additional device
        if (existingForUser.rows.length > 0) {
          await client.query(
            `INSERT INTO license_allocations (app_id, device_id, user_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (app_id, device_id) DO NOTHING`,
            [appId, deviceId, userId]
          );
          await client.query('COMMIT');
          return { allocated: true };
        }
        // New user: check limit
        if (parseInt(existingUser.rows[0].user_count, 10) >= license.total_count) {
          await client.query('ROLLBACK');
          throw new Error('No available licenses');
        }
      }

      // Check per-device / concurrent count
      if (license.license_type === 'per-device' || license.license_type === 'concurrent') {
        if (license.used_count >= license.total_count) {
          await client.query('ROLLBACK');
          throw new Error('No available licenses');
        }
      }

      // Allocate
      await client.query(
        `INSERT INTO license_allocations (app_id, device_id, user_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (app_id, device_id) DO NOTHING`,
        [appId, deviceId, userId]
      );

      await client.query(
        `UPDATE licenses SET used_count = (
          SELECT COUNT(*) FROM license_allocations WHERE app_id = $1
        ) WHERE app_id = $1`,
        [appId]
      );

      await client.query('COMMIT');

      // Check for alert threshold
      const updated = await this.pool.query('SELECT * FROM licenses WHERE app_id = $1', [appId]);
      if (updated.rows.length > 0) {
        const lic = updated.rows[0];
        if (lic.total_count > 0 && lic.used_count / lic.total_count >= LICENSE_ALERT_THRESHOLD) {
          this.logger.warn('License usage approaching limit', {
            appId,
            used: lic.used_count,
            total: lic.total_count,
            percentage: Math.round((lic.used_count / lic.total_count) * 100),
          });
        }
      }

      this.logger.info('License allocated', { appId, deviceId });
      return { allocated: true };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Release a license when an app is uninstalled.
   */
  async releaseLicense(appId, deviceId) {
    const result = await this.pool.query(
      'DELETE FROM license_allocations WHERE app_id = $1 AND device_id = $2 RETURNING *',
      [appId, deviceId]
    );

    if (result.rows.length > 0) {
      await this.pool.query(
        `UPDATE licenses SET used_count = GREATEST(0, (
          SELECT COUNT(*) FROM license_allocations WHERE app_id = $1
        )) WHERE app_id = $1`,
        [appId]
      );
      this.logger.info('License released', { appId, deviceId });
    }

    return { released: result.rows.length > 0 };
  }

  /**
   * Get license usage for an app.
   */
  async getLicenseUsage(appId) {
    const licenseResult = await this.pool.query(
      'SELECT * FROM licenses WHERE app_id = $1',
      [appId]
    );

    if (licenseResult.rows.length === 0) {
      return { appId, licenseType: 'unlimited', totalCount: 0, usedCount: 0, available: true };
    }

    const license = licenseResult.rows[0];
    const allocations = await this.pool.query(
      'SELECT device_id, user_id, allocated_at FROM license_allocations WHERE app_id = $1 ORDER BY allocated_at',
      [appId]
    );

    return {
      appId,
      licenseType: license.license_type,
      totalCount: license.total_count,
      usedCount: license.used_count,
      available: license.license_type === 'unlimited' || license.used_count < license.total_count,
      utilizationPercent: license.total_count > 0
        ? Math.round((license.used_count / license.total_count) * 100)
        : 0,
      allocations: allocations.rows,
      alertThresholdReached: license.total_count > 0 && license.used_count / license.total_count >= LICENSE_ALERT_THRESHOLD,
    };
  }

  /**
   * Check if a license is available for an app.
   */
  async checkAvailability(appId) {
    const licenseResult = await this.pool.query(
      'SELECT * FROM licenses WHERE app_id = $1',
      [appId]
    );

    if (licenseResult.rows.length === 0) return { available: true, unlimited: true };

    const license = licenseResult.rows[0];
    if (license.license_type === 'unlimited') return { available: true, unlimited: true };

    return {
      available: license.used_count < license.total_count,
      remaining: license.total_count - license.used_count,
      total: license.total_count,
      used: license.used_count,
    };
  }

  /**
   * Get license overview for all apps.
   */
  async getLicenseOverview() {
    const result = await this.pool.query(
      `SELECT l.*, a.name AS app_name
       FROM licenses l
       JOIN apps a ON a.id = l.app_id
       ORDER BY a.name`
    );

    return result.rows.map((row) => ({
      appId: row.app_id,
      appName: row.app_name,
      licenseType: row.license_type,
      totalCount: row.total_count,
      usedCount: row.used_count,
      available: row.license_type === 'unlimited' || row.used_count < row.total_count,
      utilizationPercent: row.total_count > 0
        ? Math.round((row.used_count / row.total_count) * 100)
        : 0,
      alertThresholdReached: row.total_count > 0 && row.used_count / row.total_count >= LICENSE_ALERT_THRESHOLD,
    }));
  }
}

module.exports = { LicenseManager, LICENSE_TYPES };
