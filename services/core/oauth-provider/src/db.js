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
  const migrationsDir = path.join(__dirname, '..', 'migrations');
  if (!fs.existsSync(migrationsDir)) return;
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  for (const file of files) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    try {
      await pool.query(sql);
    } catch (err) {
      console.error(`[DB] Migration ${file} error:`, err.message);
    }
  }
  console.log(`[DB] ${files.length} migration(s) applied`);
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

// OAuth Clients
async function getClient(id) {
  const r = await query('SELECT * FROM oauth_clients WHERE id=$1', [id]);
  if (!r.rows.length) return null;
  const row = r.rows[0];
  return { id: row.id, name: row.name, clientSecret: row.secret, redirectUris: row.redirect_uris, grants: row.grants, scopes: row.scopes };
}

async function upsertClient(client) {
  await query(`
    INSERT INTO oauth_clients(id, name, secret, redirect_uris, grants, scopes)
    VALUES($1, $2, $3, $4, $5, $6)
    ON CONFLICT(id) DO UPDATE SET name=$2, secret=$3, redirect_uris=$4, grants=$5, scopes=$6, updated_at=NOW()
  `, [client.id, client.name, client.clientSecret || null, JSON.stringify(client.redirectUris || []), JSON.stringify(client.grants || []), JSON.stringify(client.scopes || [])]);
}

async function getAllClients() {
  const r = await query('SELECT * FROM oauth_clients ORDER BY created_at');
  return r.rows.map(row => ({ id: row.id, name: row.name, clientSecret: row.secret, redirectUris: row.redirect_uris, grants: row.grants, scopes: row.scopes }));
}

async function deleteClient(id) {
  await query('DELETE FROM oauth_clients WHERE id=$1', [id]);
}

// Auth Codes
async function saveAuthCode(code, record) {
  await query(`
    INSERT INTO oauth_auth_codes(code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
    VALUES($1, $2, $3, $4, $5, $6, $7, to_timestamp($8/1000.0))
    ON CONFLICT(code) DO NOTHING
  `, [code, record.clientId, record.userId, record.redirectUri || null, record.scope || null, record.codeChallenge || null, record.codeChallengeMethod || null, record.expiresAt]);
}

async function getAndDeleteAuthCode(code) {
  const r = await query('DELETE FROM oauth_auth_codes WHERE code=$1 AND expires_at > NOW() RETURNING *', [code]);
  if (!r.rows.length) return null;
  const row = r.rows[0];
  return { clientId: row.client_id, userId: row.user_id, redirectUri: row.redirect_uri, scope: row.scope, codeChallenge: row.code_challenge, codeChallengeMethod: row.code_challenge_method, expiresAt: new Date(row.expires_at).getTime() };
}

// Access Tokens
async function saveToken(hash, payload) {
  const expiresAt = new Date((payload.iat + (payload.exp - payload.iat)) * 1000);
  await query(`
    INSERT INTO oauth_tokens(token, client_id, user_id, scope, expires_at)
    VALUES($1, $2, $3, $4, $5)
    ON CONFLICT(token) DO NOTHING
  `, [hash, payload.aud || null, payload.sub || null, payload.scope || null, expiresAt]);
}

async function getToken(hash) {
  const r = await query('SELECT * FROM oauth_tokens WHERE token=$1 AND expires_at > NOW()', [hash]);
  return r.rows[0] || null;
}

async function revokeToken(hash) {
  await query('DELETE FROM oauth_tokens WHERE token=$1', [hash]);
  await query('DELETE FROM oauth_refresh_tokens WHERE token=$1', [hash]);
}

// Enrolled Devices
async function upsertDevice(device) {
  await query(`
    INSERT INTO enrolled_devices(id, token, hostname, platform, os_version, ip_address, status, data)
    VALUES($1, $2, $3, $4, $5, $6, $7, $8)
    ON CONFLICT(id) DO UPDATE SET last_seen=NOW(), status=$7, data=$8
  `, [device.id, device.enrollmentToken || null, device.hostname || null, device.platform || null, device.os || null, device.ip || null, device.status || 'active', JSON.stringify(device)]);
}

async function getDevice(id) {
  const r = await query('SELECT * FROM enrolled_devices WHERE id=$1', [id]);
  return r.rows[0] || null;
}

async function getAllDevices() {
  const r = await query('SELECT * FROM enrolled_devices ORDER BY registered_at DESC');
  return r.rows;
}

async function updateDeviceStatus(id, status) {
  await query('UPDATE enrolled_devices SET status=$2, last_seen=NOW() WHERE id=$1', [id, status]);
}

module.exports = { initDb, query, isAvailable, pool, getClient, upsertClient, getAllClients, deleteClient, saveAuthCode, getAndDeleteAuthCode, saveToken, getToken, revokeToken, upsertDevice, getDevice, getAllDevices, updateDeviceStatus };
