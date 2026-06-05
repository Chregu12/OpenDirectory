'use strict';

const PolicyAggregate = require('../domain/PolicyAggregate');

/**
 * PolicyRepository — database access layer for policies.
 *
 * Returns PolicyAggregate instances so that callers always work with
 * domain objects rather than raw DB rows.
 */
class PolicyRepository {
  /**
   * @param {object} db - the postgres db module (exposes db.query)
   */
  constructor(db) {
    this.db = db;
  }

  /**
   * Find a policy by its primary key.
   * @param {string} id
   * @returns {Promise<PolicyAggregate|null>}
   */
  async findById(id) {
    const result = await this.db.query(
      'SELECT * FROM policies WHERE id = $1',
      [id]
    );
    if (!result.rows.length) return null;
    return PolicyAggregate.fromRow(result.rows[0]);
  }

  /**
   * Find all policies, optionally filtered.
   * @param {object} filters - optional: { type, platform, enabled }
   * @param {object} pagination - optional: { limit, offset }
   * @returns {Promise<{policies: PolicyAggregate[], total: number}>}
   */
  async findAll(filters = {}, pagination = {}) {
    const conditions = [];
    const params = [];
    let idx = 1;

    if (filters.type !== undefined) {
      conditions.push(`type = $${idx++}`);
      params.push(filters.type);
    }
    if (filters.platform !== undefined) {
      conditions.push(`(platform = $${idx++} OR platform = 'all')`);
      params.push(filters.platform);
    }
    if (filters.enabled !== undefined) {
      conditions.push(`enabled = $${idx++}`);
      params.push(filters.enabled);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit  = pagination.limit  || 50;
    const offset = pagination.offset || 0;

    const countResult = await this.db.query(
      `SELECT COUNT(*) AS total FROM policies ${where}`,
      params
    );
    const total = parseInt(countResult.rows[0].total, 10);

    const dataResult = await this.db.query(
      `SELECT * FROM policies ${where} ORDER BY priority DESC, created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
      [...params, limit, offset]
    );

    const policies = dataResult.rows.map(row => PolicyAggregate.fromRow(row));
    return { policies, total };
  }

  /**
   * Persist a PolicyAggregate (insert or update).
   * Sets the aggregate's id on first insert.
   * @param {PolicyAggregate} policy
   * @returns {Promise<PolicyAggregate>}
   */
  async save(policy) {
    if (!policy.id) {
      // Insert
      const result = await this.db.query(
        `INSERT INTO policies
           (name, type, platform, rules, settings, enabled, priority, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          policy.name,
          policy.type,
          policy.platform,
          JSON.stringify(policy.rules),
          JSON.stringify(policy.settings),
          policy.enabled,
          policy.priority,
          policy.createdAt,
          policy.updatedAt
        ]
      );
      policy.id = result.rows[0].id;
      return PolicyAggregate.fromRow(result.rows[0]);
    }

    // Update
    const result = await this.db.query(
      `UPDATE policies
       SET name = $1, type = $2, platform = $3, rules = $4, settings = $5,
           enabled = $6, priority = $7, updated_at = $8
       WHERE id = $9
       RETURNING *`,
      [
        policy.name,
        policy.type,
        policy.platform,
        JSON.stringify(policy.rules),
        JSON.stringify(policy.settings),
        policy.enabled,
        policy.priority,
        policy.updatedAt,
        policy.id
      ]
    );
    if (!result.rows.length) throw new Error(`Policy ${policy.id} not found for update`);
    return PolicyAggregate.fromRow(result.rows[0]);
  }

  /**
   * Delete a policy by id.
   * @param {string} id
   * @returns {Promise<boolean>} true if deleted, false if not found
   */
  async delete(id) {
    const result = await this.db.query(
      'DELETE FROM policies WHERE id = $1 RETURNING id',
      [id]
    );
    return result.rows.length > 0;
  }
}

module.exports = PolicyRepository;
