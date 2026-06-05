'use strict';
const IDeviceRepository = require('../../domain/repositories/IDeviceRepository');
const DeviceAggregate = require('../../domain/aggregates/DeviceAggregate');

class PostgresDeviceRepository extends IDeviceRepository {
  constructor(db) {
    super();
    this._db = db;
  }

  async findById(deviceId) {
    const result = await this._db.query('SELECT * FROM devices WHERE id = $1', [deviceId]);
    if (!result.rows[0]) return null;
    return this._toAggregate(result.rows[0]);
  }

  async findAll(filters = {}) {
    let q = 'SELECT * FROM devices WHERE 1=1';
    const params = [];
    if (filters.platform) { params.push(filters.platform); q += ` AND platform = $${params.length}`; }
    if (filters.status)   { params.push(filters.status);   q += ` AND status = $${params.length}`; }
    if (filters.limit)    { params.push(filters.limit);    q += ` LIMIT $${params.length}`; }
    if (filters.offset)   { params.push(filters.offset);   q += ` OFFSET $${params.length}`; }
    const result = await this._db.query(q, params);
    return result.rows.map(r => this._toAggregate(r));
  }

  async save(device) {
    const d = device.toJSON();
    await this._db.query(
      `INSERT INTO devices (id, hostname, platform, status, is_compliant, compliance_violations, last_seen, enrolled_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (id) DO UPDATE SET
         hostname=$2, platform=$3, status=$4, is_compliant=$5,
         compliance_violations=$6, last_seen=$7`,
      [d.id, d.hostname, d.platform, d.status, d.isCompliant,
       JSON.stringify(d.complianceViolations), d.lastSeen, d.enrolledAt]
    );
    return device;
  }

  async delete(deviceId) {
    await this._db.query('DELETE FROM devices WHERE id = $1', [deviceId]);
  }

  async exists(deviceId) {
    const r = await this._db.query('SELECT 1 FROM devices WHERE id = $1', [deviceId]);
    return r.rows.length > 0;
  }

  _toAggregate(row) {
    return new DeviceAggregate({
      id: row.id, hostname: row.hostname, platform: row.platform,
      status: row.status, isCompliant: row.is_compliant,
      complianceViolations: row.compliance_violations || [],
      lastSeen: row.last_seen, enrolledAt: row.enrolled_at,
    });
  }
}

module.exports = PostgresDeviceRepository;
