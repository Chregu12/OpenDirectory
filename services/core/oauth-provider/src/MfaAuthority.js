'use strict';

const crypto = require('crypto');
const { readKeyFile } = require('./SigningKeys');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const { boundMfa } = require('../../../../packages/mfa-authorization-contract');
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

class MfaError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
function fail(status, code) { throw new MfaError(status, code); }
function base32(bytes) {
  let bits = 0; let value = 0; let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; output += BASE32[(value >>> bits) & 31]; }
  }
  if (bits) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}
function decodeSecret(secret) {
  if (typeof secret !== 'string' || !/^[A-Z2-7]{32}$/.test(secret)) fail(503, 'invalid_mfa_secret');
  let bits = 0; let value = 0; const bytes = [];
  for (const character of secret) {
    value = (value << 5) | BASE32.indexOf(character); bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >>> bits) & 255); }
  }
  return Buffer.from(bytes);
}
function totp(secret, counter) {
  if (!Number.isSafeInteger(counter) || counter < 0) fail(503, 'invalid_mfa_counter');
  const message = Buffer.alloc(8); message.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', decodeSecret(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}
function matchedCounter(secret, code, now, lastCounter) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const current = Math.floor(now / 30000); let match = null;
  for (const counter of [current - 1, current, current + 1]) {
    if (counter >= 0 && counter > lastCounter && crypto.timingSafeEqual(Buffer.from(totp(secret, counter)), Buffer.from(code))) match = counter;
  }
  return match;
}

class MfaCipher {
  #key;
  constructor({ keyFile = process.env.OAUTH_MFA_KEY_FILE, demo = false, production = process.env.NODE_ENV === 'production' } = {}) {
    if (demo && production) throw new Error('Demo MFA is forbidden in production');
    if (keyFile) {
      let material;
      try { material = readKeyFile(keyFile, true).trim(); } catch { throw new Error('Cannot load protected MFA encryption key'); }
      if (!/^[a-f0-9]{64}$/.test(material)) throw new Error('MFA key must contain 32 random bytes as lowercase hex');
      this.#key = Buffer.from(material, 'hex');
    } else {
      if (!demo) throw new Error('A protected persistent OAuth MFA key file is required');
      this.#key = crypto.randomBytes(32);
    }
    this.kid = crypto.createHash('sha256').update(this.#key).digest('hex');
  }
  encrypt(userId, slot, secret) {
    decodeSecret(secret);
    const nonce = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', this.#key, nonce);
    cipher.setAAD(Buffer.from(`opendirectory-mfa-v1:${userId}:${slot}`));
    const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return ['v1', this.kid, nonce.toString('base64url'), cipher.getAuthTag().toString('base64url'), encrypted.toString('base64url')].join('.');
  }
  decrypt(userId, slot, record) {
    try {
      if (typeof record !== 'string' || record.length > 512) throw new Error();
      const parts = record.split('.');
      if (parts.length !== 5 || parts[0] !== 'v1' || parts[1] !== this.kid || !/^[A-Za-z0-9_-]{16}$/.test(parts[2])
        || !/^[A-Za-z0-9_-]{22}$/.test(parts[3]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[4])) throw new Error();
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.#key, Buffer.from(parts[2], 'base64url'));
      decipher.setAAD(Buffer.from(`opendirectory-mfa-v1:${userId}:${slot}`)); decipher.setAuthTag(Buffer.from(parts[3], 'base64url'));
      const secret = Buffer.concat([decipher.update(Buffer.from(parts[4], 'base64url')), decipher.final()]).toString('utf8');
      decodeSecret(secret); return secret;
    } catch { fail(503, 'mfa_key_or_record_unavailable'); }
  }
}

function initial(userId) {
  return { user_id: userId, revision: '0', enabled: false, encrypted_seed: null, pending_seed: null, pending_session: null,
    pending_expires_at: null, last_counter: '-1', failed_attempts: 0, locked_until: null };
}

class MfaAuthority {
  constructor(database, { demo = false, production = process.env.NODE_ENV === 'production', keyFile } = {}) {
    this.database = database; this.demo = demo; this.cipher = new MfaCipher({ demo, production, keyFile });
    this.memory = new Map(); this.audit = []; this.queue = Promise.resolve();
  }
  async ready() {
    if (this.demo) return;
    await this.read(async connection => {
      await connection.query('SELECT user_id FROM oauth_mfa_factors LIMIT 0'); await connection.query('SELECT id FROM oauth_mfa_audit LIMIT 0');
    });
  }
  async read(operation) {
    let connection;
    try {
      connection = await this.database.pool.connect(); await connection.query('BEGIN READ ONLY');
      await connection.query("SET LOCAL statement_timeout='1500ms'; SET LOCAL lock_timeout='1000ms'");
      const result = await operation(connection); await connection.query('COMMIT'); return result;
    } catch (error) {
      if (connection) await connection.query('ROLLBACK').catch(() => {});
      if (error instanceof MfaError) throw error;
      fail(503, 'mfa_authority_unavailable');
    } finally { connection?.release(); }
  }
  async transaction(userId, operation) {
    if (!validUuid(userId)) fail(403, 'canonical_user_required');
    if (this.demo) {
      const run = async () => {
        const row = structuredClone(this.memory.get(userId) || initial(userId)); const audit = [];
        const result = await operation(row, Date.now(), async (action, sessionId) => audit.push({ userId, action, sessionId, revision: row.revision }));
        this.memory.set(userId, row); this.audit.push(...audit); return result;
      };
      const next = this.queue.then(run, run); this.queue = next.catch(() => {}); return next;
    }
    let connection;
    try {
      connection = await this.database.pool.connect(); await connection.query('BEGIN');
      await connection.query("SET LOCAL statement_timeout='1500ms'; SET LOCAL lock_timeout='1000ms'");
      await connection.query('INSERT INTO oauth_mfa_factors(user_id) VALUES($1) ON CONFLICT DO NOTHING', [userId]);
      const row = (await connection.query('SELECT * FROM oauth_mfa_factors WHERE user_id=$1 FOR UPDATE', [userId])).rows[0];
      const now = Number((await connection.query('SELECT EXTRACT(EPOCH FROM clock_timestamp())*1000 AS now')).rows[0].now);
      if (!row || !Number.isFinite(now)) fail(503, 'mfa_authority_unavailable');
      const result = await operation(row, now, (action, sessionId = null) => connection.query(
        'INSERT INTO oauth_mfa_audit(user_id,revision,session_id,action) VALUES($1,$2,$3,$4)', [userId, row.revision, sessionId, action]), connection);
      await connection.query(`UPDATE oauth_mfa_factors SET revision=$2,enabled=$3,encrypted_seed=$4,pending_seed=$5,pending_session=$6,
        pending_expires_at=$7,last_counter=$8,failed_attempts=$9,locked_until=$10 WHERE user_id=$1`,
      [userId, row.revision, row.enabled, row.encrypted_seed, row.pending_seed, row.pending_session, row.pending_expires_at,
        row.last_counter, row.failed_attempts, row.locked_until]);
      await connection.query('COMMIT'); return result;
    } catch (error) {
      if (connection) await connection.query('ROLLBACK').catch(() => {});
      if (error instanceof MfaError) throw error;
      fail(503, 'mfa_authority_unavailable');
    } finally { connection?.release(); }
  }
  actor(payload) {
    if (payload?.actor_type !== 'user' || !validUuid(payload.identity_authorization?.userId) || !validUuid(payload.sid)) fail(403, 'canonical_user_required');
    return payload.identity_authorization.userId;
  }
  async state(userId) {
    if (!validUuid(userId)) fail(403, 'canonical_user_required');
    if (this.demo) return structuredClone(this.memory.get(userId) || initial(userId));
    return this.read(async connection => {
      const row = (await connection.query('SELECT * FROM oauth_mfa_factors WHERE user_id=$1', [userId])).rows[0];
      if (!row) fail(503, 'mfa_authority_unavailable');
      return row;
    });
  }
  async status(payload) {
    const row = await this.state(this.actor(payload)); const now = Date.now();
    return { enabled: row.enabled, pending: !!row.pending_seed && new Date(row.pending_expires_at).getTime() > now,
      pendingOwned: !!row.pending_seed && row.pending_session === payload.sid && new Date(row.pending_expires_at).getTime() > now,
      method: 'totp', reauthenticationRequiredAfterChange: true };
  }
  async enroll(payload) {
    const userId = this.actor(payload);
    return this.transaction(userId, async (row, now, audit) => {
      if (row.enabled) fail(409, 'mfa_already_enabled');
      if (row.locked_until && new Date(row.locked_until).getTime() > now) fail(429, 'mfa_temporarily_locked');
      const secret = base32(crypto.randomBytes(20));
      row.pending_seed = this.cipher.encrypt(userId, 'pending', secret); row.pending_session = payload.sid;
      row.pending_expires_at = new Date(now + 600000); row.failed_attempts = 0; row.locked_until = null;
      await audit('setup_started', payload.sid);
      return { secret, otpauthUri: `otpauth://totp/OpenDirectory:${encodeURIComponent(userId)}?secret=${secret}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30`, expiresAt: row.pending_expires_at.toISOString() };
    });
  }
  async verify(row, code, now, slot, audit, sessionId) {
    if (row.locked_until && new Date(row.locked_until).getTime() > now) return { status: 429, error: 'mfa_temporarily_locked' };
    const secret = this.cipher.decrypt(row.user_id, slot, slot === 'pending' ? row.pending_seed : row.encrypted_seed);
    const counter = matchedCounter(secret, code, now, Number(row.last_counter));
    if (counter === null) {
      row.failed_attempts = row.locked_until ? 1 : Math.min(5, row.failed_attempts + 1);
      row.locked_until = row.failed_attempts >= 5 ? new Date(now + 300000) : null;
      await audit('verification_failed', sessionId); return { status: 401, error: 'invalid_otp' };
    }
    row.last_counter = String(counter); row.failed_attempts = 0; row.locked_until = null;
    return { secret };
  }
  async confirm(payload, code) {
    const userId = this.actor(payload);
    const result = await this.transaction(userId, async (row, now, audit) => {
      if (row.enabled || !row.pending_seed || row.pending_session !== payload.sid || new Date(row.pending_expires_at).getTime() <= now) fail(409, 'mfa_setup_not_pending');
      const proof = await this.verify(row, code, now, 'pending', audit, payload.sid); if (proof.error) return proof;
      row.encrypted_seed = this.cipher.encrypt(userId, 'active', proof.secret); row.enabled = true; row.revision = String(BigInt(row.revision) + 1n);
      row.pending_seed = null; row.pending_session = null; row.pending_expires_at = null;
      await audit('enabled', payload.sid); return { enabled: true, reauthenticationRequired: true };
    });
    if (result.error) fail(result.status, result.error); return result;
  }
  async disable(payload, code) {
    const result = await this.transaction(this.actor(payload), async (row, now, audit) => {
      if (!row.enabled) fail(409, 'mfa_not_enabled');
      const proof = await this.verify(row, code, now, 'active', audit, payload.sid); if (proof.error) return proof;
      row.enabled = false; row.encrypted_seed = null; row.last_counter = '-1'; row.revision = String(BigInt(row.revision) + 1n);
      await audit('disabled', payload.sid); return { enabled: false, reauthenticationRequired: true };
    });
    if (result.error) fail(result.status, result.error); return result;
  }
  async login(userId, code) {
    if (this.demo && !validUuid(userId)) return { authTime: Math.floor(Date.now() / 1000), methods: ['pwd'] };
    const result = await this.transaction(userId, async (row, now, audit) => {
      if (row.enabled && !code) return { status: 401, error: 'otp_required' };
      if (row.enabled) {
        const proof = await this.verify(row, code, now, 'active', audit); if (proof.error) return proof;
        await audit('verified');
      }
      return { schemaVersion: 1, userId, revision: String(row.revision), methods: row.enabled ? ['pwd', 'otp'] : ['pwd'], authTime: Math.floor(now / 1000) };
    });
    if (result.error) fail(result.status, result.error); return result;
  }
  async matches(payload) {
    if (this.demo && !validUuid(payload?.identity_authorization?.userId) && !payload?.mfa_authorization) return true;
    if (!boundMfa(payload)) return false;
    const row = await this.state(payload.identity_authorization.userId);
    if (row.enabled) this.cipher.decrypt(row.user_id, 'active', row.encrypted_seed);
    return String(row.revision) === payload.mfa_authorization.revision && row.enabled === (payload.amr.length === 2);
  }
}

module.exports = { MfaAuthority, MfaCipher, MfaError, base32, totp, matchedCounter };
