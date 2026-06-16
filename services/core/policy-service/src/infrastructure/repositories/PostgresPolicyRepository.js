'use strict';

const PolicyAggregate = require('../../domain/PolicyAggregate');
const IPolicyRepository = require('../../domain/repositories/IPolicyRepository');

/**
 * PostgresPolicyRepository — infrastructure implementation of the policy
 * repository backed by PostgreSQL.
 *
 * Returns PolicyAggregate instances so callers always work with domain objects
 * rather than raw DB rows.
 */
class PostgresPolicyRepository extends IPolicyRepository {
  /**
   * @param {object} db - the postgres db module (exposes db.query)
   */
  constructor(db) {
    super();
    this._db = db;
  }

  /**
   * Find a policy by its primary key.
   * @param {string} id
   * @returns {Promise<PolicyAggregate|null>}
   */
  async findById(id) {
    const result = await this._db.query(
      'SELECT * FROM policies WHERE id = $1',
      [id]
    );
    if (!result.rows.length) return null;
    return PolicyAggregate.fromRow(result.rows[0]);
  }

  /**
   * Find all policies, with optional filters and pagination.
   * @param {object} filters   - optional: { type, platform, status }
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
    if (filters.status !== undefined) {
      conditions.push(`status = $${idx++}`);
      params.push(filters.status);
    }
    if (filters.platform !== undefined) {
      conditions.push(`(platform = $${idx++} OR platform = 'all')`);
      params.push(filters.platform);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit  = pagination.limit  ?? 50;
    const offset = pagination.offset ?? 0;

    const [countRes, dataRes] = await Promise.all([
      this._db.query(`SELECT COUNT(*) AS total FROM policies ${where}`, params),
      this._db.query(
        `SELECT * FROM policies ${where} ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
        [...params, limit, offset]
      ),
    ]);

    return {
      policies: dataRes.rows.map(row => PolicyAggregate.fromRow(row)),
      total: parseInt(countRes.rows[0].total, 10),
    };
  }

  /**
   * Find all active policies ordered by priority.
   * @returns {Promise<PolicyAggregate[]>}
   */
  async findActive() {
    const result = await this._db.query(
      `SELECT * FROM policies WHERE status = 'active' ORDER BY priority ASC`
    );
    return result.rows.map(row => PolicyAggregate.fromRow(row));
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
      const result = await this._db.query(
        `INSERT INTO policies
           (name, description, type, platform, rules, settings, priority,
            enforce, block_inheritance, wmi_filter, security_filter, created_by, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING *`,
        [
          policy.name,
          policy.description || null,
          policy.type,
          policy.platform || 'all',
          JSON.stringify(policy.rules || []),
          JSON.stringify(policy.settings || {}),
          policy.priority || 100,
          policy.enforce || false,
          policy.block_inheritance || false,
          policy.wmi_filter ? JSON.stringify(policy.wmi_filter) : null,
          policy.security_filter ? JSON.stringify(policy.security_filter) : null,
          policy.created_by || null,
          policy.status || 'draft'
        ]
      );
      policy.id = result.rows[0].id;
      return PolicyAggregate.fromRow(result.rows[0]);
    }

    // Update
    const result = await this._db.query(
      `UPDATE policies
       SET name = COALESCE($1, name),
           description = COALESCE($2, description),
           type = COALESCE($3, type),
           platform = COALESCE($4, platform),
           rules = COALESCE($5, rules),
           settings = COALESCE($6, settings),
           priority = COALESCE($7, priority),
           enforce = COALESCE($8, enforce),
           block_inheritance = COALESCE($9, block_inheritance),
           wmi_filter = COALESCE($10, wmi_filter),
           security_filter = COALESCE($11, security_filter),
           version = version + 1,
           updated_at = NOW()
       WHERE id = $12
       RETURNING *`,
      [
        policy.name || null,
        policy.description !== undefined ? policy.description : null,
        policy.type || null,
        policy.platform || null,
        policy.rules ? JSON.stringify(policy.rules) : null,
        policy.settings ? JSON.stringify(policy.settings) : null,
        policy.priority || null,
        policy.enforce !== undefined ? policy.enforce : null,
        policy.block_inheritance !== undefined ? policy.block_inheritance : null,
        policy.wmi_filter ? JSON.stringify(policy.wmi_filter) : null,
        policy.security_filter ? JSON.stringify(policy.security_filter) : null,
        policy.id
      ]
    );
    if (!result.rows.length) throw new Error(`Policy ${policy.id} not found for update`);
    return PolicyAggregate.fromRow(result.rows[0]);
  }

  /**
   * Activate a policy (set status = 'active').
   * @param {string} id
   * @returns {Promise<PolicyAggregate|null>}
   */
  async activate(id) {
    const result = await this._db.query(
      `UPDATE policies SET status = 'active', activated_at = NOW(), updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [id]
    );
    if (!result.rows.length) return null;
    return PolicyAggregate.fromRow(result.rows[0]);
  }

  /**
   * Deactivate a policy (set status = 'inactive').
   * @param {string} id
   * @returns {Promise<PolicyAggregate|null>}
   */
  async deactivate(id) {
    const result = await this._db.query(
      `UPDATE policies SET status = 'inactive', updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [id]
    );
    if (!result.rows.length) return null;
    return PolicyAggregate.fromRow(result.rows[0]);
  }

  /**
   * Delete a policy by id.
   * @param {string} id
   * @returns {Promise<boolean>} true if deleted, false if not found
   */
  async delete(id) {
    const result = await this._db.query(
      'DELETE FROM policies WHERE id = $1 RETURNING id',
      [id]
    );
    return result.rows.length > 0;
  }
}

module.exports = PostgresPolicyRepository;
