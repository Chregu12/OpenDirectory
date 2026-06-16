/**
 * Database pool for the Conditional Access service.
 * Uses pg.Pool backed by environment variables.
 */

const { Pool } = require('pg');

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

module.exports = pool;
