'use strict';

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

let pool = null;

/**
 * Initialize the PostgreSQL connection pool.
 * Reads connection config from DATABASE_URL env var.
 */
function getPool() {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:5432/opendirectory';
    pool = new Pool({
      connectionString,
      max: parseInt(process.env.PG_POOL_MAX || '20', 10),
      idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT || '30000', 10),
      connectionTimeoutMillis: parseInt(process.env.PG_CONNECT_TIMEOUT || '5000', 10),
    });

    pool.on('error', (err) => {
      logger.error('Unexpected PostgreSQL pool error', { error: err.message });
    });

    pool.on('connect', () => {
      logger.debug('New PostgreSQL client connected');
    });
  }
  return pool;
}

/**
 * Execute a single query against the pool.
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const result = await getPool().query(text, params);
    const duration = Date.now() - start;
    logger.debug('Query executed', { text: text.substring(0, 80), duration, rows: result.rowCount });
    return result;
  } catch (err) {
    logger.error('Query failed', { text: text.substring(0, 80), error: err.message });
    throw err;
  }
}

/**
 * Get a client from the pool for transaction support.
 */
async function getClient() {
  const client = await getPool().connect();
  return client;
}

/**
 * Run all SQL migration files in order.
 */
async function runMigrations() {
  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) {
    logger.warn('Migrations directory not found, skipping');
    return;
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const filePath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(filePath, 'utf-8');
    try {
      await query(sql);
      logger.info(`Migration applied: ${file}`);
    } catch (err) {
      // Ignore "already exists" errors for idempotent migrations
      if (err.code === '42P07' || err.code === '42710') {
        logger.debug(`Migration already applied: ${file}`);
      } else {
        throw err;
      }
    }
  }
}

/**
 * Test the database connection.
 */
async function testConnection() {
  try {
    const result = await query('SELECT NOW() AS now');
    logger.info('PostgreSQL connection verified', { serverTime: result.rows[0].now });
    return true;
  } catch (err) {
    logger.error('PostgreSQL connection failed', { error: err.message });
    return false;
  }
}

/**
 * Gracefully shut down the pool.
 */
async function shutdown() {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('PostgreSQL pool shut down');
  }
}

module.exports = {
  getPool,
  query,
  getClient,
  runMigrations,
  testConnection,
  shutdown,
};
