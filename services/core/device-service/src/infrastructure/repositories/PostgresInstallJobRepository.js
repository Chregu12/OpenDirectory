'use strict';
const IInstallJobRepository = require('../../domain/repositories/IInstallJobRepository');
const InstallJobAggregate = require('../../domain/aggregates/InstallJobAggregate');

class PostgresInstallJobRepository extends IInstallJobRepository {
  constructor(db) { super(); this._db = db; }

  async findById(jobId) {
    const r = await this._db.query('SELECT * FROM install_jobs WHERE job_id = $1', [jobId]);
    return r.rows[0] ? this._toAggregate(r.rows[0]) : null;
  }

  async findByDevice(deviceId) {
    const r = await this._db.query('SELECT * FROM install_jobs WHERE device_id = $1 ORDER BY queued_at DESC LIMIT 50', [deviceId]);
    return r.rows.map(row => this._toAggregate(row));
  }

  async findPendingForDevice(deviceId) {
    const r = await this._db.query("SELECT * FROM install_jobs WHERE device_id = $1 AND status IN ('queued','delivered')", [deviceId]);
    return r.rows.map(row => this._toAggregate(row));
  }

  async save(job) {
    const j = job.toJSON();
    await this._db.query(
      `INSERT INTO install_jobs (job_id, device_id, app_id, app_name, package_id, format, version, status, queued_at, completed_at, error)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (job_id) DO UPDATE SET status=$8, completed_at=$10, error=$11, version=$7`,
      [j.jobId, j.deviceId, j.appId, j.appName, j.packageId, j.format, j.version, j.status, j.queuedAt, j.completedAt, j.error]
    );
    return job;
  }

  _toAggregate(row) {
    return new InstallJobAggregate({
      jobId: row.job_id, deviceId: row.device_id, appId: row.app_id,
      appName: row.app_name, packageId: row.package_id, format: row.format,
      version: row.version, status: row.status, queuedAt: row.queued_at,
      completedAt: row.completed_at, error: row.error,
    });
  }
}

module.exports = PostgresInstallJobRepository;
