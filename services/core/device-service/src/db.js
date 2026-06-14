'use strict';

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'devices',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

let dbAvailable = false;

async function runMigrations() {
  const migrationsDir = path.join(__dirname, '..', 'migrations');
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  for (const file of files) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    try {
      await pool.query(sql);
    } catch (err) {
      console.error(`[device-db] Migration ${file} error:`, err.message);
    }
  }
  console.log(`[device-db] ${files.length} migration(s) applied`);
}

async function initDb() {
  try {
    await pool.query('SELECT 1');
    dbAvailable = true;
    await runMigrations();
    console.log('[device-db] PostgreSQL connected');
  } catch (err) {
    console.warn('[device-db] PostgreSQL not available, using in-memory fallback:', err.message);
    dbAvailable = false;
  }
}

function isAvailable() {
  return dbAvailable;
}

async function query(sql, params) {
  if (!dbAvailable) throw new Error('DB not available');
  return pool.query(sql, params);
}

// In-memory fallback store
const memoryDevices = new Map();

async function upsertDevice(device) {
  if (dbAvailable) {
    try {
      await pool.query(`
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
    } catch (err) {
      console.error('[device-db] upsertDevice error:', err.message);
      memoryDevices.set(device.id, device);
    }
  } else {
    memoryDevices.set(device.id, device);
  }
}

function rowToDevice(row) {
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

async function getDevice(id) {
  if (dbAvailable) {
    try {
      const r = await pool.query('SELECT * FROM devices WHERE id=$1', [id]);
      return r.rows.length ? rowToDevice(r.rows[0]) : null;
    } catch (err) {
      console.error('[device-db] getDevice error:', err.message);
    }
  }
  return memoryDevices.get(id) || null;
}

async function getAllDevices() {
  if (dbAvailable) {
    try {
      const r = await pool.query('SELECT * FROM devices ORDER BY enrolled_at DESC');
      return r.rows.map(rowToDevice);
    } catch (err) {
      console.error('[device-db] getAllDevices error:', err.message);
    }
  }
  return [...memoryDevices.values()];
}

async function deleteDevice(id) {
  memoryDevices.delete(id);
  if (dbAvailable) {
    try {
      await pool.query('DELETE FROM devices WHERE id=$1', [id]);
    } catch (err) {
      console.error('[device-db] deleteDevice error:', err.message);
    }
  }
}

async function updateDeviceStatus(id, status, lastSeen) {
  const ts = lastSeen || new Date().toISOString();
  if (dbAvailable) {
    try {
      await pool.query(
        'UPDATE devices SET status=$2, last_seen=$3 WHERE id=$1',
        [id, status, ts]
      );
      return;
    } catch (err) {
      console.error('[device-db] updateDeviceStatus error:', err.message);
    }
  }
  const dev = memoryDevices.get(id);
  if (dev) {
    dev.status = status;
    dev.lastSeen = ts;
  }
}

async function saveComplianceResult(deviceId, results) {
  if (dbAvailable) {
    try {
      await pool.query(`
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
      console.error('[device-db] saveComplianceResult error:', err.message);
    }
  }
}

module.exports = {
  initDb,
  isAvailable,
  query,
  upsertDevice,
  getDevice,
  getAllDevices,
  deleteDevice,
  updateDeviceStatus,
  saveComplianceResult,
};
