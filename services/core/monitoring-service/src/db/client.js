'use strict';

// Postgres persistence client for monitoring-service, following the
// identity-service / api-backend pattern (services/core/identity-service/src/db.js,
// services/platform/api-backend/db.js): a lazily-connected Pool, a plain
// file-scan migration runner (scanning the sibling migrations/ directory —
// the pre-existing dead_letter_log migration lives there too), and an
// isAvailable() flag callers use to decide DB-first vs. in-memory-fallback
// per operation. See src/database/alertStore.js for the DB-first /
// in-memory-mirror call sites.
//
// Unlike identity-service/api-backend, monitoring-service's production
// wiring (deploy/docker-compose.prod.yml) does not currently set
// DATABASE_URL — it passes discrete POSTGRES_HOST/POSTGRES_PASSWORD env
// vars instead, and this service's own src/config/index.js already defines
// a `database` block (DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD/DB_SSL —
// note the POSTGRES_* vs DB_* naming mismatch against the prod compose
// file is pre-existing and out of scope here) that was defined but never
// consumed until now. This client reads that config as its primary source
// and additionally supports DATABASE_URL as an override, for parity with
// the DATABASE_URL convention the rest of the repo's services use.

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const config = require('../config');

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      max: config.database.poolMax,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    })
  : new Pool({
      host: config.database.host,
      port: config.database.port,
      database: config.database.name,
      user: config.database.user,
      password: config.database.password,
      ssl: config.database.ssl,
      max: config.database.poolMax,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

pool.on('error', (err) => console.error('[monitoring-db] Unexpected PG pool error:', err.message));

let dbAvailable = false;
let initPromise = null;

async function runMigrations() {
  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs.readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort();
  for (const file of files) {
    try {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await pool.query(sql);
    } catch (err) {
      console.error(`[monitoring-db] Migration ${file} error:`, err.message);
    }
  }
  console.log(`[monitoring-db] ${files.length} migration(s) applied`);
}

// Idempotent: AlertStore (and any future DB-backed store in this service)
// calls initDb() from its own constructor; only the first call actually
// connects/migrates, the rest await the same in-flight/settled promise.
async function initDb() {
  if (!initPromise) {
    initPromise = (async () => {
      try {
        await pool.query('SELECT 1');
        dbAvailable = true;
        await runMigrations();
        console.log('[monitoring-db] PostgreSQL connected');
      } catch (err) {
        console.warn('[monitoring-db] PostgreSQL not available, using in-memory fallback:', err.message);
        dbAvailable = false;
      }
    })();
  }
  return initPromise;
}

function isAvailable() {
  return dbAvailable;
}

async function query(sql, params) {
  if (!dbAvailable) throw new Error('DB not available');
  return pool.query(sql, params);
}

module.exports = { initDb, isAvailable, query, pool };
