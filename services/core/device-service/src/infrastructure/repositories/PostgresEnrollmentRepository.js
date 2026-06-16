'use strict';

const IEnrollmentRepository = require('../../domain/repositories/IEnrollmentRepository');
const EnrollmentAggregate = require('../../domain/aggregates/EnrollmentAggregate');

class PostgresEnrollmentRepository extends IEnrollmentRepository {
  /**
   * @param {object} db — the db module from src/db.js (exposes query, isAvailable, etc.)
   */
  constructor(db) {
    super();
    this._db = db;
  }

  async save(enrollment) {
    const row = enrollment.toJSON();
    await this._db.query(
      `INSERT INTO enrollments(id, device_id, hostname, platform, status, requested_by,
        initiated_at, completed_at, metadata)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT(id) DO UPDATE SET
         device_id = EXCLUDED.device_id,
         hostname = EXCLUDED.hostname,
         platform = EXCLUDED.platform,
         status = EXCLUDED.status,
         requested_by = EXCLUDED.requested_by,
         initiated_at = EXCLUDED.initiated_at,
         completed_at = EXCLUDED.completed_at,
         metadata = EXCLUDED.metadata`,
      [
        row.id,
        row.deviceId,
        row.hostname,
        row.platform,
        row.status,
        row.requestedBy,
        row.initiatedAt,
        row.completedAt,
        JSON.stringify(row.metadata || {}),
      ]
    );
  }

  async findById(id) {
    const result = await this._db.query(
      'SELECT * FROM enrollments WHERE id = $1',
      [id]
    );
    if (!result.rows.length) return null;
    return this._toAggregate(result.rows[0]);
  }

  async findAll(filters = {}) {
    const conditions = [];
    const params = [];

    if (filters.status) {
      params.push(filters.status);
      conditions.push(`status = $${params.length}`);
    }
    if (filters.deviceId) {
      params.push(filters.deviceId);
      conditions.push(`device_id = $${params.length}`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const result = await this._db.query(
      `SELECT * FROM enrollments ${where} ORDER BY initiated_at DESC`,
      params
    );
    return result.rows.map(row => this._toAggregate(row));
  }

  async delete(id) {
    await this._db.query('DELETE FROM enrollments WHERE id = $1', [id]);
  }

  _toAggregate(row) {
    return new EnrollmentAggregate({
      id: row.id,
      deviceId: row.device_id,
      hostname: row.hostname,
      platform: row.platform,
      status: row.status,
      requestedBy: row.requested_by,
      initiatedAt: row.initiated_at,
      completedAt: row.completed_at,
      metadata: row.metadata || {},
    });
  }
}

module.exports = PostgresEnrollmentRepository;
