const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || process.env.POSTGRES_DB || 'auth',
  user: process.env.DB_USER || process.env.POSTGRES_USER || 'postgres',
  password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || '',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

async function runMigrations() {
  const migrationPath = path.join(__dirname, '..', 'migrations', '001_initial_schema.sql');
  if (!fs.existsSync(migrationPath)) return;
  const sql = fs.readFileSync(migrationPath, 'utf8');
  try {
    await pool.query(sql);
    console.log('[DB] Migrations applied');
  } catch (err) {
    console.error('[DB] Migration error (will use in-memory fallback):', err.message);
  }
}

let dbAvailable = false;

async function initDb() {
  try {
    await pool.query('SELECT 1');
    dbAvailable = true;
    await runMigrations();
    console.log('[DB] PostgreSQL connected');
  } catch (err) {
    console.warn('[DB] PostgreSQL not available, using in-memory fallback:', err.message);
    dbAvailable = false;
  }
}

function isAvailable() { return dbAvailable; }

async function query(sql, params) {
  if (!dbAvailable) throw new Error('DB not available');
  return pool.query(sql, params);
}

async function getPermissionMatrix() {
  const result = await query(`
    SELECT user_id, resource, level, override, source, last_used, days_idle
    FROM permission_assignments
    ORDER BY user_id, resource
  `);
  return result.rows;
}

async function upsertPermission(userId, resource, level, source = 'manual') {
  await query(`
    INSERT INTO permission_assignments(user_id, resource, level, override, source)
    VALUES($1, $2, $3, $3, $4)
    ON CONFLICT(user_id, resource)
    DO UPDATE SET level=$3, override=$3, source=$4, assigned_at=NOW()
  `, [userId, resource, level, source]);
}

async function getPimRequests(status) {
  if (status) {
    const result = await query('SELECT * FROM pim_requests WHERE status=$1 ORDER BY requested_at DESC', [status]);
    return result.rows;
  }
  const result = await query('SELECT * FROM pim_requests ORDER BY requested_at DESC LIMIT 100');
  return result.rows;
}

async function createPimRequest(id, userId, userName, resource, level, justification, durationHours) {
  const result = await query(`
    INSERT INTO pim_requests(id, user_id, resource, level, justification, duration_hours, status)
    VALUES($1, $2, $3, $4, $5, $6, 'pending')
    RETURNING *
  `, [id, userId, resource, level, justification, durationHours]);
  return result.rows[0];
}

async function approvePimRequest(id, approvedBy) {
  const reqResult = await query('SELECT * FROM pim_requests WHERE id=$1', [id]);
  if (!reqResult.rows.length) return null;
  const req = reqResult.rows[0];
  const expiresAt = new Date(Date.now() + req.duration_hours * 3600_000);
  await query(`
    UPDATE pim_requests SET status='approved', resolved_at=NOW(), approved_by=$2, expires_at=$3
    WHERE id=$1
  `, [id, approvedBy, expiresAt]);
  // Create active elevation
  const { v4: uuidv4 } = require('uuid');
  const elevId = uuidv4();
  await query(`
    INSERT INTO pim_active(id, request_id, user_id, resource, level, expires_at)
    VALUES($1, $2, $3, $4, $5, $6)
  `, [elevId, id, req.user_id, req.resource, req.level, expiresAt]);
  return { ...req, status: 'approved', expiresAt };
}

async function denyPimRequest(id) {
  const result = await query(
    `UPDATE pim_requests SET status='denied', resolved_at=NOW() WHERE id=$1 RETURNING *`,
    [id]
  );
  return result.rows[0];
}

async function getActiveElevations() {
  const result = await query(
    `SELECT * FROM pim_active WHERE expires_at > NOW() ORDER BY activated_at DESC`
  );
  return result.rows;
}

async function insertEscalationAlert(userId, adminCount, resources) {
  await query(`
    INSERT INTO escalation_alerts(user_id, admin_count, resources)
    VALUES($1, $2, $3)
  `, [userId, adminCount, JSON.stringify(resources)]);
}

async function getEscalationAlerts() {
  const result = await query(
    `SELECT * FROM escalation_alerts WHERE resolved=false ORDER BY detected_at DESC LIMIT 50`
  );
  return result.rows;
}

module.exports = { initDb, query, isAvailable, pool, getPermissionMatrix, upsertPermission, getPimRequests, createPimRequest, approvePimRequest, denyPimRequest, getActiveElevations, insertEscalationAlert, getEscalationAlerts };
