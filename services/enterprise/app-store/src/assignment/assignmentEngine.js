'use strict';

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'app-store-assignment' },
  transports: [new winston.transports.Console()],
});

class AssignmentEngine {
  /**
   * @param {import('pg').Pool} pool - PostgreSQL connection pool
   * @param {import('../distribution/distributionEngine')} distributionEngine - Distribution engine for triggering required pushes
   */
  constructor(pool, distributionEngine) {
    this.pool = pool;
    this.distributionEngine = distributionEngine;
  }

  /**
   * Assign an app to one or more targets
   * @param {string} appId - The app to assign
   * @param {Array<{target_type: string, target_id: string, target_name?: string}>} targets - Assignment targets
   * @param {string} installType - 'required', 'available', or 'uninstall'
   * @param {string} createdBy - User creating the assignment
   * @returns {Array} Created assignments
   */
  async assignApp(appId, targets, installType = 'available', createdBy = null) {
    // Verify app exists
    const appResult = await this.pool.query('SELECT id, display_name FROM store_apps WHERE id = $1', [appId]);
    if (appResult.rows.length === 0) {
      throw new Error('App not found');
    }

    const validTargetTypes = ['ou', 'group', 'domain', 'device', 'user'];
    const validInstallTypes = ['required', 'available', 'uninstall'];

    if (!validInstallTypes.includes(installType)) {
      throw new Error(`Invalid install type: ${installType}. Must be one of: ${validInstallTypes.join(', ')}`);
    }

    const client = await this.pool.connect();
    const assignments = [];

    try {
      await client.query('BEGIN');

      for (const target of targets) {
        if (!validTargetTypes.includes(target.target_type)) {
          throw new Error(`Invalid target type: ${target.target_type}. Must be one of: ${validTargetTypes.join(', ')}`);
        }

        // Check for existing assignment for same app + target
        const existing = await client.query(
          `SELECT id FROM store_assignments WHERE app_id = $1 AND target_type = $2 AND target_id = $3`,
          [appId, target.target_type, target.target_id]
        );

        if (existing.rows.length > 0) {
          // Update existing assignment
          const updateResult = await client.query(
            `UPDATE store_assignments SET install_type = $1, target_name = $2, created_by = $3
             WHERE app_id = $4 AND target_type = $5 AND target_id = $6 RETURNING *`,
            [installType, target.target_name || null, createdBy, appId, target.target_type, target.target_id]
          );
          assignments.push(updateResult.rows[0]);
        } else {
          // Create new assignment
          const insertResult = await client.query(
            `INSERT INTO store_assignments (app_id, target_type, target_id, target_name, install_type, created_by)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [appId, target.target_type, target.target_id, target.target_name || null, installType, createdBy]
          );
          assignments.push(insertResult.rows[0]);
        }
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    logger.info('App assigned to targets', {
      appId,
      appName: appResult.rows[0].display_name,
      targetCount: targets.length,
      installType,
    });

    // If the assignment is 'required', trigger push for affected devices
    if (installType === 'required') {
      this._triggerRequiredPush(targets).catch((err) => {
        logger.error('Failed to trigger required app push after assignment', { error: err.message });
      });
    }

    return assignments;
  }

  /**
   * Remove an assignment
   */
  async removeAssignment(assignId) {
    const result = await this.pool.query(
      'DELETE FROM store_assignments WHERE id = $1 RETURNING *',
      [assignId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    logger.info('Assignment removed', { assignId, appId: result.rows[0].app_id });
    return result.rows[0];
  }

  /**
   * Get all assignments for an app
   */
  async getAppAssignments(appId) {
    const result = await this.pool.query(
      `SELECT * FROM store_assignments WHERE app_id = $1 ORDER BY target_type, target_name ASC`,
      [appId]
    );
    return result.rows;
  }

  /**
   * Get all assignments for a specific target
   */
  async getTargetAssignments(targetType, targetId) {
    const result = await this.pool.query(
      `SELECT sa.*, sapp.display_name as app_name, sapp.category, sapp.icon_url
       FROM store_assignments sa
       JOIN store_apps sapp ON sa.app_id = sapp.id
       WHERE sa.target_type = $1 AND sa.target_id = $2
       ORDER BY sapp.display_name ASC`,
      [targetType, targetId]
    );
    return result.rows;
  }

  /**
   * Trigger push of required apps to devices affected by the assignment targets
   */
  async _triggerRequiredPush(targets) {
    if (!this.distributionEngine) return;

    for (const target of targets) {
      if (target.target_type === 'device') {
        // Direct device assignment - push immediately
        try {
          await this.distributionEngine.pushRequiredApps(target.target_id);
        } catch (error) {
          logger.warn('Failed to push required apps to device', {
            deviceId: target.target_id,
            error: error.message,
          });
        }
      }
      // For OU, group, domain, user targets we would need to resolve
      // the list of devices and push to each. This is handled asynchronously
      // by the device enrollment flow and periodic sync.
      logger.info('Required app push triggered for target', {
        targetType: target.target_type,
        targetId: target.target_id,
      });
    }
  }
}

module.exports = AssignmentEngine;
