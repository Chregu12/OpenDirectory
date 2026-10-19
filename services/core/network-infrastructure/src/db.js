'use strict';

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME || 'network',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

let _available = false;

/**
 * Run the SQL migration file and mark DB as available.
 * On any error the module degrades gracefully (in-memory fallback remains active).
 */
async function initDb() {
  try {
    const migrationPath = path.join(__dirname, '..', 'migrations', '001_network.sql');
    const sql = fs.readFileSync(migrationPath, 'utf8');
    await pool.query(sql);
    _available = true;
    console.info('[db] PostgreSQL connected and migrations applied');
  } catch (err) {
    console.warn('[db] PostgreSQL unavailable, falling back to in-memory store:', err.message);
    _available = false;
  }
}

/** @returns {boolean} */
function isAvailable() {
  return _available;
}

// ── DNS Records ────────────────────────────────────────────────────────────────

/**
 * Get all DNS records, optionally filtered by zone.
 * @param {string} [zone]
 * @returns {Promise<object[]>}
 */
async function getDnsRecords(zone) {
  if (zone) {
    const { rows } = await pool.query(
      'SELECT * FROM dns_records WHERE zone = $1 ORDER BY name, type',
      [zone]
    );
    return rows;
  }
  const { rows } = await pool.query('SELECT * FROM dns_records ORDER BY zone, name, type');
  return rows;
}

/**
 * Insert or update a DNS record (upsert on name+type+zone).
 * @param {{ name: string, type: string, value: string, zone?: string, ttl?: number }} record
 * @returns {Promise<object>}
 */
async function upsertDnsRecord(record) {
  const { name, type, value, zone = 'opendirectory.local', ttl = 300 } = record;
  const { rows } = await pool.query(
    `INSERT INTO dns_records (name, type, value, zone, ttl, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (name, type, zone) DO UPDATE
       SET value = EXCLUDED.value,
           ttl   = EXCLUDED.ttl,
           updated_at = NOW()
     RETURNING *`,
    [name, type, value, zone, ttl]
  );
  return rows[0];
}

/**
 * Delete a DNS record by id.
 * @param {string} id
 * @returns {Promise<boolean>}
 */
async function deleteDnsRecord(id) {
  const { rowCount } = await pool.query('DELETE FROM dns_records WHERE id = $1', [id]);
  return rowCount > 0;
}

// ── DHCP Leases ────────────────────────────────────────────────────────────────

/**
 * Get all DHCP leases.
 * @returns {Promise<object[]>}
 */
async function getDhcpLeases() {
  const { rows } = await pool.query('SELECT * FROM dhcp_leases ORDER BY lease_start DESC');
  return rows;
}

/**
 * Insert or update a DHCP lease (upsert on mac_address).
 * @param {{ mac_address: string, ip_address?: string, hostname?: string, lease_end?: string, status?: string, vlan_id?: number }} lease
 * @returns {Promise<object>}
 */
async function upsertDhcpLease(lease) {
  const {
    mac_address,
    ip_address = null,
    hostname = null,
    lease_end = null,
    status = 'active',
    vlan_id = null,
  } = lease;
  const { rows } = await pool.query(
    `INSERT INTO dhcp_leases (mac_address, ip_address, hostname, lease_start, lease_end, status, vlan_id)
     VALUES ($1, $2, $3, NOW(), $4, $5, $6)
     ON CONFLICT (mac_address) DO UPDATE
       SET ip_address  = EXCLUDED.ip_address,
           hostname    = EXCLUDED.hostname,
           lease_end   = EXCLUDED.lease_end,
           status      = EXCLUDED.status,
           vlan_id     = EXCLUDED.vlan_id
     RETURNING *`,
    [mac_address, ip_address, hostname, lease_end, status, vlan_id]
  );
  return rows[0];
}

// ── VLANs ──────────────────────────────────────────────────────────────────────

/**
 * Get all VLANs.
 * @returns {Promise<object[]>}
 */
async function getVlans() {
  const { rows } = await pool.query('SELECT * FROM vlans ORDER BY id');
  return rows;
}

/**
 * Insert or update a VLAN (upsert on id).
 * @param {{ id: number, name: string, subnet?: string, gateway?: string, description?: string }} vlan
 * @returns {Promise<object>}
 */
async function upsertVlan(vlan) {
  const { id, name, subnet = null, gateway = null, description = null } = vlan;
  const { rows } = await pool.query(
    `INSERT INTO vlans (id, name, subnet, gateway, description)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (id) DO UPDATE
       SET name        = EXCLUDED.name,
           subnet      = EXCLUDED.subnet,
           gateway     = EXCLUDED.gateway,
           description = EXCLUDED.description
     RETURNING *`,
    [id, name, subnet, gateway, description]
  );
  return rows[0];
}

module.exports = {
  initDb,
  isAvailable,
  getDnsRecords,
  upsertDnsRecord,
  deleteDnsRecord,
  getDhcpLeases,
  upsertDhcpLease,
  getVlans,
  upsertVlan,
};
