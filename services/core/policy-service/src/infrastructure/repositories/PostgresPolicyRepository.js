'use strict';

const PolicyAggregate = require('../../domain/PolicyAggregate');

class PostgresPolicyRepository {
  constructor(db) {
    this._db = db;
  }

  async findById(id) {
    const r = await this._db.query('SELECT * FROM policies WHERE id = $1', [id]);
    return r.rows.length ? PolicyAggregate.fromRow(r.rows[0]) : null;
  }

  async findAll(filters = {}, pagination = {}) {
    const conditions = [];
    const params = [];
    let idx = 1;

    if (filters.type     !== undefined) { conditions.push(`type = $${idx++}`);                              params.push(filters.type); }
    if (filters.platform !== undefined) { conditions.push(`(platform = $${idx++} OR platform = 'all')`);    params.push(filters.platform); }
    if (filters.enabled  !== undefined) { conditions.push(`enabled = $${idx++}`);                           params.push(filters.enabled); }

    const where  = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit  = pagination.limit  || 50;
    const offset = pagination.offset || 0;

    const [countRes, dataRes] = await Promise.all([
      this._db.query(`SELECT COUNT(*) AS total FROM policies ${where}`, params),
      this._db.query(
        `SELECT * FROM policies ${where} ORDER BY priority DESC, created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
        [...params, limit, offset]
      ),
    ]);

    return {
      policies: dataRes.rows.map(r => PolicyAggregate.fromRow(r)),
      total:    parseInt(countRes.rows[0].total, 10),
    };
  }

  async findActive(platform) {
    const r = await this._db.query(
      `SELECT * FROM policies WHERE enabled = true AND (platform = $1 OR platform = 'all') ORDER BY priority DESC`,
      [platform]
    );
    return r.rows.map(row => PolicyAggregate.fromRow(row));
  }

  async save(policy) {
    if (!policy.id) {
      const r = await this._db.query(
        `INSERT INTO policies (name, type, platform, rules, settings, enabled, priority, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [policy.name, policy.type, policy.platform,
         JSON.stringify(policy.rules), JSON.stringify(policy.settings),
         policy.enabled, policy.priority, policy.createdAt, policy.updatedAt]
      );
      policy.id = r.rows[0].id;
      return PolicyAggregate.fromRow(r.rows[0]);
    }

    const r = await this._db.query(
      `UPDATE policies
       SET name=$1, type=$2, platform=$3, rules=$4, settings=$5, enabled=$6, priority=$7, updated_at=$8
       WHERE id=$9 RETURNING *`,
      [policy.name, policy.type, policy.platform,
       JSON.stringify(policy.rules), JSON.stringify(policy.settings),
       policy.enabled, policy.priority, policy.updatedAt, policy.id]
    );
    if (!r.rows.length) throw new Error(`Policy ${policy.id} not found`);
    return PolicyAggregate.fromRow(r.rows[0]);
  }

  async delete(id) {
    const r = await this._db.query('DELETE FROM policies WHERE id=$1 RETURNING id', [id]);
    return r.rows.length > 0;
  }
}

module.exports = PostgresPolicyRepository;
