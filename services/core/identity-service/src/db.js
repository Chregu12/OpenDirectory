'use strict';

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// docker-compose wires identity-service with DATABASE_URL (postgres://.../identity)
// — see docker-compose.yml. Fall back to discrete DB_* vars (same convention
// as device-service/authentication-service/least-privilege) for parity with
// deployments or local dev setups that don't set DATABASE_URL, and default
// the database name to 'identity' to match the docker-compose database.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    })
  : new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      database: process.env.DB_NAME || process.env.POSTGRES_DB || 'identity',
      user: process.env.DB_USER || process.env.POSTGRES_USER || 'postgres',
      password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || '',
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

pool.on('error', (err) => console.error('[identity-db] Unexpected PG pool error:', err.message));

let dbAvailable = false;

async function runMigrations() {
  const migrationsDir = path.join(__dirname, '..', 'migrations');
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  for (const file of files) {
    try {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await pool.query(sql);
    } catch (err) {
      console.error(`[identity-db] Migration ${file} error:`, err.message);
      throw err;
    }
  }
  console.log(`[identity-db] ${files.length} migration(s) applied`);
}

async function initDb() {
  try {
    await pool.query('SELECT 1');
    await runMigrations();
    dbAvailable = true;
    console.log('[identity-db] PostgreSQL connected');
    return true;
  } catch (err) {
    console.warn('[identity-db] PostgreSQL not available, using in-memory fallback:', err.message);
    dbAvailable = false;
    return false;
  }
}

function isAvailable() {
  return dbAvailable;
}

async function query(sql, params) {
  if (!dbAvailable) throw new Error('DB not available');
  return pool.query(sql, params);
}

async function transaction(operation, { actor, readOnly = false, beforeCommit } = {}) {
  if (!dbAvailable) throw Object.assign(new Error('Identity storage unavailable'), { status: 503 });
  const client = await pool.connect();
  try {
    await client.query(readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
    await client.query("SET LOCAL lock_timeout = '5s'");
    await client.query("SET LOCAL statement_timeout = '15s'");
    if (actor) await client.query("SELECT set_config('opendirectory.actor', $1, true)", [actor]);
    const result = await operation(client);
    if (beforeCommit) await beforeCommit(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    throw error;
  } finally { client.release(); }
}

function write(sql, params, actor) { return transaction(client => client.query(sql, params), { actor }); }

module.exports = { initDb, isAvailable, query, write, transaction, pool };
