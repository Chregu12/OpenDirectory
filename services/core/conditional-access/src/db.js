/**
 * Database pool for the Conditional Access service.
 * Uses pg.Pool backed by environment variables.
 *
 * Also provides a minimal init/migration-runner surface — consistent with
 * the pattern used by authentication-service and least-privilege — so that
 * security-critical data (encryption recovery keys, break-glass audit
 * trail, PIM session recordings) can persist to Postgres instead of
 * disappearing whenever the process restarts.
 *
 * The module exports the Pool instance itself (unchanged from before) with
 * initDb()/isAvailable()/runMigrations() attached as extra properties, so
 * every existing `require('./db')` call site that treats the export as a
 * plain pg.Pool (e.g. `db.query(...)`, `new SessionRecorder(db)`) keeps
 * working exactly as before.
 */

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME     || 'opendirectory',
    user:     process.env.DB_USER     || 'postgres',
    password: process.env.DB_PASSWORD || '',
    max:      parseInt(process.env.DB_POOL_MAX || '10', 10),
    idleTimeoutMillis:    30000,
    connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle DB client:', err);
});

let dbAvailable = false;

/**
 * Run every *.sql file in src/db/migrations, in filename order.
 * Migrations are idempotent (CREATE TABLE IF NOT EXISTS / CREATE INDEX IF
 * NOT EXISTS) so re-running them on every boot is safe.
 */
async function runMigrations() {
    const migrationsDir = path.join(__dirname, 'db', 'migrations');
    if (!fs.existsSync(migrationsDir)) return;

    const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
    for (const file of files) {
        try {
            const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
            await pool.query(sql);
        } catch (err) {
            console.error(`[ca-db] Migration ${file} failed:`, err.message);
        }
    }
    console.log(`[ca-db] ${files.length} migration(s) applied`);
}

/**
 * Initialize the DB pool: verify connectivity and run migrations.
 * Fully self-contained — never throws. On failure it logs a warning and
 * leaves isAvailable() === false so callers fall back to in-memory storage.
 * Safe to call unconditionally at service startup.
 */
async function initDb() {
    try {
        await pool.query('SELECT 1');
        dbAvailable = true;
        await runMigrations();
        console.log('[ca-db] PostgreSQL connected');
    } catch (err) {
        console.warn('[ca-db] PostgreSQL not available, using in-memory fallback:', err.message);
        dbAvailable = false;
    }
}

function isAvailable() {
    return dbAvailable;
}

pool.initDb = initDb;
pool.runMigrations = runMigrations;
pool.isAvailable = isAvailable;

module.exports = pool;
