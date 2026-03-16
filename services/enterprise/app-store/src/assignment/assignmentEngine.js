'use strict';

const VALID_TARGET_TYPES = ['device', 'user', 'group', 'ou', 'domain'];
const VALID_ASSIGNMENT_TYPES = ['required', 'available'];

class AssignmentEngine {
  constructor(pool, redis, logger) {
    this.pool = pool;
    this.redis = redis;
    this.logger = logger;
  }

  /**
   * Assign an app to a target (group, OU, device, user, domain).
   */
  async assignApp(appId, targetType, targetId, assignmentType = 'available') {
    if (!VALID_TARGET_TYPES.includes(targetType)) {
      throw new Error(`Invalid target type. Must be one of: ${VALID_TARGET_TYPES.join(', ')}`);
    }
    if (!VALID_ASSIGNMENT_TYPES.includes(assignmentType)) {
      throw new Error(`Invalid assignment type. Must be one of: ${VALID_ASSIGNMENT_TYPES.join(', ')}`);
    }

    // Verify app exists
    const appCheck = await this.pool.query('SELECT id FROM apps WHERE id = $1', [appId]);
    if (appCheck.rows.length === 0) throw new Error('App not found');

    const result = await this.pool.query(
      `INSERT INTO assignments (app_id, target_type, target_id, assignment_type)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (app_id, target_type, target_id) DO UPDATE
       SET assignment_type = $4
       RETURNING *`,
      [appId, targetType, targetId, assignmentType]
    );

    this.logger.info('App assigned', { appId, targetType, targetId, assignmentType });
    return result.rows[0];
  }

  /**
   * Remove an assignment.
   */
  async unassignApp(assignmentId) {
    const result = await this.pool.query(
      'DELETE FROM assignments WHERE id = $1 RETURNING *',
      [assignmentId]
    );
    if (result.rows.length === 0) throw new Error('Assignment not found');

    this.logger.info('App unassigned', { assignmentId });
    return { deleted: true, id: assignmentId };
  }

  /**
   * Unassign by app/target combination.
   */
  async unassignAppByTarget(appId, targetType, targetId) {
    const result = await this.pool.query(
      'DELETE FROM assignments WHERE app_id = $1 AND target_type = $2 AND target_id = $3 RETURNING *',
      [appId, targetType, targetId]
    );
    if (result.rows.length === 0) throw new Error('Assignment not found');
    return { deleted: true };
  }

  /**
   * Get all assignments for a device, resolving group/OU/domain memberships.
   * Takes a device context with deviceId, groups, ou, domain, userId.
   */
  async getAssignmentsForDevice(deviceId, deviceContext = {}) {
    const { groups = [], ou = null, domain = null, userId = null } = deviceContext;

    // Build all possible target conditions
    const conditions = [];
    const values = [];
    let idx = 1;

    // Direct device assignment
    conditions.push(`(target_type = 'device' AND target_id = $${idx++})`);
    values.push(deviceId);

    // User assignment
    if (userId) {
      conditions.push(`(target_type = 'user' AND target_id = $${idx++})`);
      values.push(userId);
    }

    // Group assignments
    for (const groupId of groups) {
      conditions.push(`(target_type = 'group' AND target_id = $${idx++})`);
      values.push(groupId);
    }

    // OU assignment
    if (ou) {
      conditions.push(`(target_type = 'ou' AND target_id = $${idx++})`);
      values.push(ou);
    }

    // Domain assignment
    if (domain) {
      conditions.push(`(target_type = 'domain' AND target_id = $${idx++})`);
      values.push(domain);
    }

    const where = conditions.join(' OR ');

    const result = await this.pool.query(
      `SELECT a.*, apps.name AS app_name, apps.platforms, apps.mandatory AS app_mandatory
       FROM assignments a
       JOIN apps ON apps.id = a.app_id
       WHERE ${where}
       ORDER BY a.assignment_type ASC, apps.name ASC`,
      values
    );

    // Deduplicate: if the same app is assigned multiple times, "required" wins over "available"
    const appMap = new Map();
    for (const row of result.rows) {
      const existing = appMap.get(row.app_id);
      if (!existing || row.assignment_type === 'required') {
        appMap.set(row.app_id, row);
      }
    }

    return Array.from(appMap.values());
  }

  /**
   * Get mandatory apps for a device context.
   */
  async getMandatoryAppsForDevice(deviceId, deviceContext = {}) {
    const assignments = await this.getAssignmentsForDevice(deviceId, deviceContext);
    return assignments.filter((a) => a.assignment_type === 'required' || a.app_mandatory);
  }

  /**
   * List all assignments with optional filters.
   */
  async listAssignments({ appId, targetType, targetId, assignmentType, limit = 100, offset = 0 } = {}) {
    const conditions = [];
    const values = [];
    let idx = 1;

    if (appId) {
      conditions.push(`a.app_id = $${idx++}`);
      values.push(appId);
    }
    if (targetType) {
      conditions.push(`a.target_type = $${idx++}`);
      values.push(targetType);
    }
    if (targetId) {
      conditions.push(`a.target_id = $${idx++}`);
      values.push(targetId);
    }
    if (assignmentType) {
      conditions.push(`a.assignment_type = $${idx++}`);
      values.push(assignmentType);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countResult = await this.pool.query(
      `SELECT COUNT(*) FROM assignments a ${where}`,
      values
    );

    values.push(limit, offset);
    const result = await this.pool.query(
      `SELECT a.*, apps.name AS app_name
       FROM assignments a
       JOIN apps ON apps.id = a.app_id
       ${where}
       ORDER BY a.created_at DESC
       LIMIT $${idx++} OFFSET $${idx}`,
      values
    );

    return {
      assignments: result.rows,
      total: parseInt(countResult.rows[0].count, 10),
      limit,
      offset,
    };
  }

  /**
   * Get assignments for a specific app.
   */
  async getAssignmentsForApp(appId) {
    const result = await this.pool.query(
      `SELECT * FROM assignments WHERE app_id = $1 ORDER BY target_type, target_id`,
      [appId]
    );
    return result.rows;
  }

  /**
   * Get all app IDs assigned to a given target.
   */
  async getAppIdsForTarget(targetType, targetId) {
    const result = await this.pool.query(
      `SELECT app_id, assignment_type FROM assignments WHERE target_type = $1 AND target_id = $2`,
      [targetType, targetId]
    );
    return result.rows;
  }
}

module.exports = { AssignmentEngine, VALID_TARGET_TYPES, VALID_ASSIGNMENT_TYPES };
