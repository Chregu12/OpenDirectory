'use strict';

const BlueprintAggregate = require('../../domain/BlueprintAggregate');

class PostgresBlueprintRepository {
  constructor(db) {
    this._db = db;
  }

  async findById(id) {
    const r = await this._db.query('SELECT * FROM blueprints WHERE id = $1', [id]);
    return r.rows.length ? BlueprintAggregate.fromRow(r.rows[0]) : null;
  }

  async findAll(filters = {}, pagination = {}) {
    const conditions = [];
    const params = [];
    let idx = 1;

    if (filters.platform !== undefined) { conditions.push(`(platform = $${idx++} OR platform = 'all')`); params.push(filters.platform); }

    const where  = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit  = pagination.limit  || 50;
    const offset = pagination.offset || 0;

    const [countRes, dataRes] = await Promise.all([
      this._db.query(`SELECT COUNT(*) AS total FROM blueprints ${where}`, params),
      this._db.query(
        `SELECT * FROM blueprints ${where} ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
        [...params, limit, offset]
      ),
    ]);

    return {
      blueprints: dataRes.rows.map(r => BlueprintAggregate.fromRow(r)),
      total:      parseInt(countRes.rows[0].total, 10),
    };
  }

  async save(blueprint) {
    if (!blueprint.id) {
      const r = await this._db.query(
        `INSERT INTO blueprints (name, description, platform, policies, settings, version, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [blueprint.name, blueprint.description, blueprint.platform,
         JSON.stringify(blueprint.policies), JSON.stringify(blueprint.settings),
         blueprint.version, blueprint.createdAt, blueprint.updatedAt]
      );
      blueprint.id = r.rows[0].id;
      return BlueprintAggregate.fromRow(r.rows[0]);
    }

    const r = await this._db.query(
      `UPDATE blueprints
       SET name=$1, description=$2, platform=$3, policies=$4, settings=$5, version=$6, updated_at=$7
       WHERE id=$8 RETURNING *`,
      [blueprint.name, blueprint.description, blueprint.platform,
       JSON.stringify(blueprint.policies), JSON.stringify(blueprint.settings),
       blueprint.version, blueprint.updatedAt, blueprint.id]
    );
    if (!r.rows.length) throw new Error(`Blueprint ${blueprint.id} not found`);
    return BlueprintAggregate.fromRow(r.rows[0]);
  }

  async delete(id) {
    const r = await this._db.query('DELETE FROM blueprints WHERE id=$1 RETURNING id', [id]);
    return r.rows.length > 0;
  }
}

module.exports = PostgresBlueprintRepository;
