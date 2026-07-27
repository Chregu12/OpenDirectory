'use strict';

// Postgres persistence for api-backend, following the identity-service
// pattern (services/core/identity-service/src/db.js): a lazily-connected
// Pool, a plain file-scan migration runner, and an isAvailable() flag that
// callers use to decide DB-first vs. in-memory-fallback per operation. See
// server.js for the DB-first / in-memory-mirror call sites.
//
// docker-compose wires api-backend with DATABASE_URL (postgres://.../api).
// Fall back to discrete DB_* vars (same convention as identity-service /
// device-service / authentication-service) for parity with deployments or
// local dev setups that don't set DATABASE_URL, defaulting the database
// name to 'api' to match the docker-compose database.

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

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
      database: process.env.DB_NAME || process.env.POSTGRES_DB || 'api',
      user: process.env.DB_USER || process.env.POSTGRES_USER || 'postgres',
      password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || '',
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

pool.on('error', (err) => console.error('[api-backend-db] Unexpected PG pool error:', err.message));

let dbAvailable = false;

async function runMigrations() {
  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  for (const file of files) {
    try {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await pool.query(sql);
    } catch (err) {
      console.error(`[api-backend-db] Migration ${file} error:`, err.message);
    }
  }
  console.log(`[api-backend-db] ${files.length} migration(s) applied`);
}

async function initDb() {
  try {
    await pool.query('SELECT 1');
    dbAvailable = true;
    await runMigrations();
    console.log('[api-backend-db] PostgreSQL connected');
  } catch (err) {
    console.warn('[api-backend-db] PostgreSQL not available, using in-memory fallback:', err.message);
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

module.exports = { initDb, isAvailable, query, pool };
