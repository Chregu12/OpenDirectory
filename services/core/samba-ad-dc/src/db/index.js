'use strict';

const fs = require('fs');
const path = require('path');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

// ---------------------------------------------------------------------------
// PostgreSQL pool + migration runner
//
// Mirrors the initDb()/runMigrations()/isAvailable() pattern used across the
// rest of the platform (see services/core/authentication-service/src/db.js,
// services/core/identity-service/src/db.js and
// services/core/least-privilege/src/db.js): a single pg Pool, a
// self-contained migration runner that applies migrations/*.sql in filename
// order, and an isAvailable() gate so callers can tell "no DB configured /
// DB unreachable / schema not fully applied" apart from "DB fully up and
// migrated".
//
// samba-ad-dc previously created a bare `pg.Pool` in index.js and handed it
// straight to TrustManager/ComputerManager/ReplicationManager, but nothing
// ever ran migrations/*.sql against it — the tables those managers query
// (domain_trusts, laps_passwords, laps_access_log, bitlocker_keys,
// bitlocker_key_access_log, replication_log, replication_state) were never
// created, so every write against a "configured" DB threw at query time.
// Most critically, computerManager.escrowBitLockerKey's DB write threw on a
// missing table, and outside of that, code paths that treated `this.db` as
// "just a truthy Pool" had no way to distinguish "connected and migrated"
// from "Pool object exists but nothing has actually been proven to work".
//
// This module is that missing migration runner. It stays optional/
// non-throwing at module load and during initDb() (matching this service's
// existing "DB is optional infra, LDAP/Samba is the source of truth"
// posture — see the original index.js comment this replaces), but unlike
// the sibling services' pattern it deliberately does NOT mark the DB
// "available" if any individual migration file failed to apply. Sibling
// services flip dbAvailable=true as soon as the initial `SELECT 1` succeeds
// and log-but-ignore any later per-file migration error; here that would
// mean a partially-migrated DB gets reported as "available", and callers
// like escrowBitLockerKey (see computerManager.js) — which now treats
// isAvailable()===true as a promise that the write will actually land
// somewhere durable — would go on to attempt an INSERT against a table
// that never got created. For a feature whose entire purpose is disaster
// recovery, "the pool responded to SELECT 1" is not sufficient evidence
// that the write will actually persist. See the Abbruch-Mandat note in the
// task this module was built for: no fake-green schema state.
// ---------------------------------------------------------------------------

let pool = null;
let dbAvailable = false;

if (process.env.DATABASE_URL) {
  try {
    // eslint-disable-next-line global-require
    const { Pool } = require('pg');
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
    pool.on('error', (err) => logger.warn('PG pool error', { error: err.message }));
    logger.info('PostgreSQL pool initialised');
  } catch (err) {
    logger.warn('pg module not available — DB features disabled', { error: err.message });
    pool = null;
  }
}

/**
 * Apply every migrations/*.sql file (sorted by filename) against the pool,
 * in order. Each file is tried independently — one broken/conflicting file
 * does not stop the loop from attempting the rest — but every failure is
 * collected and returned so the caller (initDb) can decide whether the
 * overall schema state is trustworthy.
 *
 * Never throws: connection-level failures surface as a single `failed`
 * entry, not an unhandled rejection, so callers can always safely await
 * this.
 *
 * @returns {Promise<{applied: string[], failed: {file: string, error: string}[]}>}
 */
async function runMigrations() {
  if (!pool) return { applied: [], failed: [] };

  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) return { applied: [], failed: [] };

  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  const applied = [];
  const failed = [];

  for (const file of files) {
    try {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await pool.query(sql);
      applied.push(file);
    } catch (err) {
      logger.error(`Migration ${file} failed`, { error: err.message });
      failed.push({ file, error: err.message });
    }
  }

  logger.info(`${applied.length}/${files.length} migration(s) applied`, {
    applied,
    failed: failed.map(f => f.file)
  });

  return { applied, failed };
}

/**
 * Initialise the DB: probe connectivity, then apply migrations. Never
 * throws — always resolves, and isAvailable() reflects the outcome
 * afterwards. Safe to call fire-and-forget at service startup.
 *
 * dbAvailable is only set true when:
 *   1. DATABASE_URL was set and the pg module + Pool constructed OK, AND
 *   2. a `SELECT 1` round-trip succeeded (DB is reachable), AND
 *   3. every migrations/*.sql file applied without error (schema is
 *      actually the shape callers expect).
 *
 * If any of those fail, dbAvailable stays/becomes false and callers must
 * treat the DB as absent — see isAvailable().
 *
 * @returns {Promise<boolean>} the resulting isAvailable() value
 */
async function initDb() {
  if (!pool) {
    dbAvailable = false;
    return false;
  }

  try {
    await pool.query('SELECT 1');
  } catch (err) {
    logger.warn('PostgreSQL not reachable — DB-backed features disabled', { error: err.message });
    dbAvailable = false;
    return false;
  }

  const { failed } = await runMigrations();
  if (failed.length > 0) {
    dbAvailable = false;
    logger.error(
      'One or more migrations failed — treating DB as unavailable so callers do not ' +
      'silently write to (or report success for) tables that were never created',
      { failedMigrations: failed.map(f => f.file) }
    );
    return false;
  }

  dbAvailable = true;
  logger.info('PostgreSQL connected and migrations applied — DB-backed features enabled');
  return true;
}

/**
 * @returns {boolean} whether the DB is connected AND fully migrated.
 */
function isAvailable() {
  return dbAvailable;
}

/**
 * Query wrapper. Throws a clear, catchable error when the DB isn't
 * available instead of forwarding to a Pool that may not even exist yet —
 * callers (TrustManager/ComputerManager/ReplicationManager) already wrap
 * `this.db.query(...)` calls in try/catch, so this integrates with their
 * existing error handling without any call-site changes.
 *
 * @param {string} sql
 * @param {Array} [params]
 */
async function query(sql, params) {
  if (!dbAvailable) throw new Error('DB not available');
  return pool.query(sql, params);
}

module.exports = {
  initDb,
  isAvailable,
  runMigrations,
  query,
  get pool() { return pool; }
};
