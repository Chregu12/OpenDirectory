'use strict';

const IDeviceRepository = require('../../domain/repositories/IDeviceRepository');
const DeviceAggregate = require('../../domain/aggregates/DeviceAggregate');

/**
 * PostgresDeviceRepository
 *
 * All device-related SQL lives here. Extends IDeviceRepository with the
 * DDD aggregate interface (findById/findAll/save/delete/exists) and also
 * exposes practical helper methods used by index.js route handlers:
 * upsertDevice, getDevice, getAllDevices, deleteDevice, updateDeviceStatus,
 * saveComplianceResult, getStammdaten, updateStammdaten, uploadPhoto, getPhoto.
 */
class PostgresDeviceRepository extends IDeviceRepository {
  /**
   * @param {object} db  - the db module (provides isAvailable(), query(), pool)
   */
  constructor(db) {
    super();
    this._db = db;
    // In-memory fallback (mirrors the one removed from db.js)
    this._memory = new Map();
  }

  // ── DDD aggregate interface (IDeviceRepository) ───────────────────────────

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

  // ── internal helpers ──────────────────────────────────────────────────────

  _rowToDevice(row) {
    return {
      id: row.id,
      name: row.name,
      platform: row.platform,
      osVersion: row.os_version,
      status: row.status,
      enrolledAt: row.enrolled_at,
      lastSeen: row.last_seen,
      assignedUser: row.assigned_user,
      serialNumber: row.serial_number,
      model: row.model,
      agentVersion: row.agent_version,
      complianceStatus: row.compliance_status,
      metadata: row.metadata || {},
    };
  }

  // ── device CRUD (moved from db.js) ───────────────────────────────────────

  async upsertDevice(device) {
    if (this._db.isAvailable()) {
      try {
        await this._db.query(`
          INSERT INTO devices(id, name, platform, os_version, status, enrolled_at, last_seen, assigned_user, serial_number, model, agent_version, compliance_status, metadata)
          VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
          ON CONFLICT(id) DO UPDATE SET
            name = EXCLUDED.name,
            platform = EXCLUDED.platform,
            os_version = EXCLUDED.os_version,
            status = EXCLUDED.status,
            last_seen = EXCLUDED.last_seen,
            assigned_user = EXCLUDED.assigned_user,
            serial_number = EXCLUDED.serial_number,
            model = EXCLUDED.model,
            agent_version = EXCLUDED.agent_version,
            compliance_status = EXCLUDED.compliance_status,
            metadata = EXCLUDED.metadata
        `, [
          device.id,
          device.name || null,
          device.platform || null,
          device.osVersion || device.os_version || null,
          device.status || 'active',
          device.enrolledAt || device.enrolled_at || new Date().toISOString(),
          device.lastSeen || device.last_seen || null,
          device.assignedUser || device.assigned_user || null,
          device.serialNumber || device.serial_number || null,
          device.model || null,
          device.agentVersion || device.agent_version || null,
          device.complianceStatus || device.compliance_status || 'unknown',
          JSON.stringify(device.metadata || {}),
        ]);
        return;
      } catch (err) {
        console.error('[PostgresDeviceRepository] upsertDevice error:', err.message);
        this._memory.set(device.id, device);
      }
    } else {
      this._memory.set(device.id, device);
    }
  }

  async getDevice(id) {
    if (this._db.isAvailable()) {
      try {
        const r = await this._db.query('SELECT * FROM devices WHERE id=$1', [id]);
        return r.rows.length ? this._rowToDevice(r.rows[0]) : null;
      } catch (err) {
        console.error('[PostgresDeviceRepository] getDevice error:', err.message);
      }
    }
    return this._memory.get(id) || null;
  }

  async getAllDevices() {
    if (this._db.isAvailable()) {
      try {
        const r = await this._db.query('SELECT * FROM devices ORDER BY enrolled_at DESC');
        return r.rows.map(row => this._rowToDevice(row));
      } catch (err) {
        console.error('[PostgresDeviceRepository] getAllDevices error:', err.message);
      }
    }
    return [...this._memory.values()];
  }

  async deleteDevice(id) {
    this._memory.delete(id);
    if (this._db.isAvailable()) {
      try {
        await this._db.query('DELETE FROM devices WHERE id=$1', [id]);
      } catch (err) {
        console.error('[PostgresDeviceRepository] deleteDevice error:', err.message);
      }
    }
  }

  async updateDeviceStatus(id, status, lastSeen) {
    const ts = lastSeen || new Date().toISOString();
    if (this._db.isAvailable()) {
      try {
        await this._db.query(
          'UPDATE devices SET status=$2, last_seen=$3 WHERE id=$1',
          [id, status, ts]
        );
        return;
      } catch (err) {
        console.error('[PostgresDeviceRepository] updateDeviceStatus error:', err.message);
      }
    }
    const dev = this._memory.get(id);
    if (dev) {
      dev.status = status;
      dev.lastSeen = ts;
    }
  }

  async saveComplianceResult(deviceId, results) {
    if (this._db.isAvailable()) {
      try {
        await this._db.query(`
          INSERT INTO device_compliance(device_id, platform, settings, compliant, failed_checks)
          VALUES($1, $2, $3, $4, $5)
        `, [
          deviceId,
          results.platform || null,
          JSON.stringify(results.settings || results),
          results.compliant !== undefined ? results.compliant : false,
          results.failedChecks || results.failed_checks || [],
        ]);
      } catch (err) {
        console.error('[PostgresDeviceRepository] saveComplianceResult error:', err.message);
      }
    }
  }

  // ── Stammdaten (master data) ──────────────────────────────────────────────

  /**
   * Returns the stammdaten sub-object from a device's metadata.
   * Falls back to the in-memory store if DB is unavailable.
   *
   * @param {string} deviceId
   * @returns {Promise<object>}
   */
  async getStammdaten(deviceId) {
    if (this._db.isAvailable()) {
      const r = await this._db.query(
        `SELECT metadata FROM devices WHERE id = $1`,
        [deviceId]
      );
      if (r.rows.length) return r.rows[0].metadata?.stammdaten || {};
      return {};
    }
    const d = this._memory.get(deviceId);
    return d?.metadata?.stammdaten || {};
  }

  /**
   * Merges `fields` into the stammdaten sub-object (photo is excluded here;
   * use uploadPhoto instead).
   *
   * @param {string} deviceId
   * @param {object} fields
   */
  async updateStammdaten(deviceId, fields) {
    if (this._db.isAvailable()) {
      await this._db.query(
        `UPDATE devices
         SET metadata = jsonb_set(
           COALESCE(metadata, '{}'),
           '{stammdaten}',
           COALESCE(metadata->'stammdaten', '{}') || $1::jsonb
         )
         WHERE id = $2`,
        [JSON.stringify(fields), deviceId]
      );
    }
  }

  /**
   * Stores a photo (base64 data URL) inside metadata.stammdaten.photo.
   *
   * @param {string} deviceId
   * @param {string} photo  base64 data URL, e.g. "data:image/jpeg;base64,..."
   */
  async uploadPhoto(deviceId, photo) {
    if (this._db.isAvailable()) {
      await this._db.query(
        `UPDATE devices
         SET metadata = jsonb_set(
           COALESCE(metadata, '{}'),
           '{stammdaten,photo}',
           $1::jsonb
         )
         WHERE id = $2`,
        [JSON.stringify(photo), deviceId]
      );
    }
  }

  /**
   * Retrieves the raw photo value (base64 data URL) from metadata.stammdaten.photo.
   *
   * @param {string} deviceId
   * @returns {Promise<string|null>}
   */
  async getPhoto(deviceId) {
    if (!this._db.isAvailable()) return null;
    const r = await this._db.query(
      `SELECT metadata->'stammdaten'->>'photo' AS photo FROM devices WHERE id = $1`,
      [deviceId]
    );
    return r.rows[0]?.photo || null;
  }
}

module.exports = PostgresDeviceRepository;
