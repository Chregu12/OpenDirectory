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

let dbAvailable = false;

async function initDb() {
  try {
    await pool.query('SELECT 1');
    dbAvailable = true;
    const migrationPath = path.join(__dirname, '..', 'migrations', '001_audit_log.sql');
    if (fs.existsSync(migrationPath)) {
      const sql = fs.readFileSync(migrationPath, 'utf8');
      await pool.query(sql);
    }
    console.log('[auth-db] PostgreSQL connected');
  } catch (err) {
    console.warn('[auth-db] PostgreSQL not available:', err.message);
    dbAvailable = false;
  }
}

async function logAuditEvent({ eventType, actor, target, message, severity = 'info', ipAddress, metadata = {} }) {
  if (!dbAvailable) {
    // In-memory fallback — keep last 200 events
    inMemoryAuditLog.push({ id: inMemoryAuditLog.length + 1, event_type: eventType, actor, target, message, severity, ip_address: ipAddress, metadata, created_at: new Date().toISOString() });
    if (inMemoryAuditLog.length > 200) inMemoryAuditLog.shift();
    return;
  }
  try {
    await pool.query(
      `INSERT INTO audit_events(event_type, actor, target, message, severity, ip_address, metadata)
       VALUES($1, $2, $3, $4, $5, $6, $7)`,
      [eventType, actor || null, target || null, message, severity, ipAddress || null, JSON.stringify(metadata)]
    );
  } catch (err) {
    console.error('[audit-db] insert error:', err.message);
  }
}

async function getRecentEvents(limit = 20) {
  if (dbAvailable) {
    try {
      const result = await pool.query(
        'SELECT * FROM audit_events ORDER BY created_at DESC LIMIT $1',
        [limit]
      );
      return result.rows;
    } catch (err) {
      console.error('[audit-db] query error:', err.message);
    }
  }
  return [...inMemoryAuditLog].reverse().slice(0, limit);
}

const inMemoryAuditLog = [];

function isAvailable() { return dbAvailable; }

module.exports = { initDb, logAuditEvent, getRecentEvents, isAvailable };
