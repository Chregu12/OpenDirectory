'use strict';

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
      throw new Error(`Device migration ${file} failed`, { cause: err });
    }
  }
  console.log(`[device-db] ${files.length} migration(s) applied`);
}

async function initDb() {
  try {
    await pool.query('SELECT 1');
    await runMigrations();
    dbAvailable = true;
    console.log('[device-db] PostgreSQL connected');
  } catch (err) {
    dbAvailable = false;
    throw new Error('Device inventory requires migrated PostgreSQL', { cause: err });
  }
}

function isAvailable() {
  return dbAvailable;
}

async function query(sql, params) {
  if (!dbAvailable) throw new Error('DB not available');
  return pool.query(sql, params);
}

async function healthCheck() {
  if (!dbAvailable) return { status: 'unavailable' };
  try {
    await pool.query('SELECT 1');
    return { status: 'healthy' };
  } catch (err) {
    return { status: 'error', error: err.message };
  }
}

module.exports = {
  initDb,
  isAvailable,
  query,
  healthCheck,
  pool,
  async transaction(operation, { readOnly = false, beforeCommit } = {}) {
    if (!dbAvailable) throw Object.assign(new Error('Device storage unavailable'), { status: 503 });
    const client = await pool.connect();
    try {
      await client.query(readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
      await client.query("SET LOCAL lock_timeout='5s'"); await client.query("SET LOCAL statement_timeout='15s'");
      const result = await operation(client); if (beforeCommit) await beforeCommit(client); await client.query('COMMIT'); return result;
    } catch (error) { try { await client.query('ROLLBACK'); } catch {} throw error; }
    finally { client.release(); }
  },
};
