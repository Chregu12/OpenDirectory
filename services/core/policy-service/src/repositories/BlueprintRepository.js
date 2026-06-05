'use strict';

const BlueprintAggregate = require('../domain/BlueprintAggregate');

/**
 * BlueprintRepository — database access layer for blueprints.
 *
 * Returns BlueprintAggregate instances so that callers always work with
 * domain objects rather than raw DB rows.
 */
class BlueprintRepository {
  /**
   * @param {object} db - the postgres db module (exposes db.query)
   */
  constructor(db) {
    this.db = db;
  }

  /**
   * Find a blueprint by its primary key.
   * @param {string} id
   * @returns {Promise<BlueprintAggregate|null>}
   */
  async findById(id) {
    const result = await this.db.query(
      'SELECT * FROM blueprints WHERE id = $1',
      [id]
    );
    if (!result.rows.length) return null;
    return BlueprintAggregate.fromRow(result.rows[0]);
  }

  /**
   * Find all blueprints, optionally filtered by platform.
   * @param {object} filters - optional: { platform }
   * @param {object} pagination - optional: { limit, offset }
   * @returns {Promise<{blueprints: BlueprintAggregate[], total: number}>}
   */
  async findAll(filters = {}, pagination = {}) {
    const conditions = [];
    const params = [];
    let idx = 1;

    if (filters.platform !== undefined) {
      conditions.push(`(platform = $${idx++} OR platform = 'all')`);
      params.push(filters.platform);
    }

    const where  = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit  = pagination.limit  || 50;
    const offset = pagination.offset || 0;

    const countResult = await this.db.query(
      `SELECT COUNT(*) AS total FROM blueprints ${where}`,
      params
    );
    const total = parseInt(countResult.rows[0].total, 10);

    const dataResult = await this.db.query(
      `SELECT * FROM blueprints ${where} ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
      [...params, limit, offset]
    );

    const blueprints = dataResult.rows.map(row => BlueprintAggregate.fromRow(row));
    return { blueprints, total };
  }

  /**
   * Persist a BlueprintAggregate (insert or update).
   * Sets the aggregate's id on first insert.
   * @param {BlueprintAggregate} blueprint
   * @returns {Promise<BlueprintAggregate>}
   */
  async save(blueprint) {
    if (!blueprint.id) {
      // Insert
      const result = await this.db.query(
        `INSERT INTO blueprints
           (name, description, platform, policies, settings, version, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          blueprint.name,
          blueprint.description,
          blueprint.platform,
          JSON.stringify(blueprint.policies),
          JSON.stringify(blueprint.settings),
          blueprint.version,
          blueprint.createdAt,
          blueprint.updatedAt
        ]
      );
      blueprint.id = result.rows[0].id;
      return BlueprintAggregate.fromRow(result.rows[0]);
    }

    // Update
    const result = await this.db.query(
      `UPDATE blueprints
       SET name = $1, description = $2, platform = $3, policies = $4,
           settings = $5, version = $6, updated_at = $7
       WHERE id = $8
       RETURNING *`,
      [
        blueprint.name,
        blueprint.description,
        blueprint.platform,
        JSON.stringify(blueprint.policies),
        JSON.stringify(blueprint.settings),
        blueprint.version,
        blueprint.updatedAt,
        blueprint.id
      ]
    );
    if (!result.rows.length) throw new Error(`Blueprint ${blueprint.id} not found for update`);
    return BlueprintAggregate.fromRow(result.rows[0]);
  }

  /**
   * Delete a blueprint by id.
   * @param {string} id
   * @returns {Promise<boolean>} true if deleted, false if not found
   */
  async delete(id) {
    const result = await this.db.query(
      'DELETE FROM blueprints WHERE id = $1 RETURNING id',
      [id]
    );
    return result.rows.length > 0;
  }
}

module.exports = BlueprintRepository;
