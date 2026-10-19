'use strict';

const crypto = require('crypto');
const { MfaError, base32, matchedCounter } = require('./MfaAuthority');
const { validContext, validUuid, sameContext } = require('../../../../packages/identity-authorization-contract');
const CODE = /^[a-f0-9]{8}(?:-[a-f0-9]{8}){3}$/;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function fail(status, code) { throw new MfaError(status, code); }
function recoveryHash(userId, code) {
  if (typeof code !== 'string' || !CODE.test(code)) fail(400, 'invalid_recovery_code_format');
  return hash('opendirectory-mfa-recovery-v1|' + userId + '|' + code);
}
function parseChallenge(value) {
  if (typeof value !== 'string' || value.length !== 80) fail(401, 'invalid_recovery_challenge');
  const [id, secret] = value.split('.');
  if (!validUuid(id) || !/^[A-Za-z0-9_-]{43}$/.test(secret || '') || Buffer.from(secret, 'base64url').toString('base64url') !== secret) fail(401, 'invalid_recovery_challenge');
  return { id, tokenHash: hash(value) };
}
function active(challenge, row, now) {
  return challenge && row.enabled && String(challenge.factor_revision) === String(row.revision)
    && !challenge.consumed_at && !challenge.superseded_at && new Date(challenge.expires_at).getTime() > now;
}
function setup(userId, secret, expiresAt) {
  return { secret, otpauthUri: `otpauth://totp/OpenDirectory:${userId}?secret=${secret}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30`, expiresAt: new Date(expiresAt).toISOString() };
}

class MfaRecovery {
  constructor({ mfa, identity, issuer }) { this.mfa = mfa; this.identity = identity; this.issuer = issuer; }
  persistent() { if (this.mfa.demo) fail(503, 'persistent_mfa_recovery_required'); }
  async ready() {
    this.persistent();
    await this.mfa.read(async connection => {
      for (const table of ['oauth_mfa_recovery_codes', 'oauth_mfa_recovery_challenges', 'oauth_mfa_recovery_audit']) await connection.query(`SELECT * FROM ${table} LIMIT 0`);
    });
  }
  async current(subject, context) {
    try {
      const state = await this.identity.state(subject);
      if (!sameContext(state.context, context)) fail(401, 'recovery_identity_changed');
    } catch (error) { throw new MfaError(error.status || 503, error.code || 'identity_authority_unavailable'); }
  }
  async audit(connection, row, action, sessionId = null, challengeId = null) {
    await connection.query('INSERT INTO oauth_mfa_recovery_audit(user_id,factor_revision,session_id,challenge_id,action) VALUES($1,$2,$3,$4,$5)',
      [row.user_id, row.revision, sessionId, challengeId, action]);
  }
  async status(payload) {
    this.persistent(); const userId = this.mfa.actor(payload);
    return this.mfa.read(async connection => {
      const row = (await connection.query(`SELECT factors.revision,COUNT(codes.code_hash)::int AS remaining
        FROM oauth_mfa_factors factors LEFT JOIN oauth_mfa_recovery_codes codes ON codes.user_id=factors.user_id
          AND codes.factor_revision=factors.revision AND codes.consumed_at IS NULL AND codes.revoked_at IS NULL
        WHERE factors.user_id=$1 AND factors.enabled GROUP BY factors.revision`, [userId])).rows[0];
      if (!row || row.revision !== payload.mfa_authorization?.revision || row.remaining > 8) fail(401, 'authorization_changed');
      return { remaining: row.remaining };
    });
  }
  async rotate(payload, code) {
    this.persistent(); const userId = this.mfa.actor(payload);
    const result = await this.mfa.transaction(userId, async (row, now, audit, connection) => {
      if (!row.enabled) fail(409, 'mfa_not_enabled');
      if (String(row.revision) !== payload.mfa_authorization?.revision) fail(401, 'authorization_changed');
      const proof = await this.mfa.verify(row, code, now, 'active', audit, payload.sid); if (proof.error) return proof;
      await connection.query('UPDATE oauth_mfa_recovery_codes SET revoked_at=clock_timestamp() WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL', [userId]);
      await connection.query('UPDATE oauth_mfa_recovery_challenges SET superseded_at=clock_timestamp() WHERE user_id=$1 AND consumed_at IS NULL AND superseded_at IS NULL', [userId]);
      const recoveryCodes = Array.from({ length: 8 }, () => crypto.randomBytes(16).toString('hex').match(/.{8}/g).join('-'));
      for (const recoveryCode of recoveryCodes) await connection.query('INSERT INTO oauth_mfa_recovery_codes(code_hash,user_id,factor_revision) VALUES($1,$2,$3)', [recoveryHash(userId, recoveryCode), userId, row.revision]);
      await audit('verified', payload.sid); await this.audit(connection, row, 'codes_rotated', payload.sid);
      return { recoveryCodes, remaining: 8 };
    });
    if (result.error) fail(result.status, result.error); return result;
  }
  async start(subject, context, recoveryCode) {
    this.persistent();
    if (typeof subject !== 'string' || !subject || subject.length > 255 || !validContext(context)) fail(403, 'canonical_user_required');
    const userId = context.userId; const codeHash = recoveryHash(userId, recoveryCode);
    const result = await this.mfa.transaction(userId, async (row, now, audit, connection) => {
      await this.current(subject, context);
      if (!row.enabled) fail(401, 'invalid_recovery_code');
      if (row.locked_until && new Date(row.locked_until).getTime() > now) fail(429, 'mfa_temporarily_locked');
      const used = await connection.query(`UPDATE oauth_mfa_recovery_codes SET consumed_at=clock_timestamp()
        WHERE code_hash=$1 AND user_id=$2 AND factor_revision=$3 AND consumed_at IS NULL AND revoked_at IS NULL RETURNING code_hash`, [codeHash, userId, row.revision]);
      if (used.rowCount !== 1) {
        row.failed_attempts = row.locked_until ? 1 : Math.min(5, row.failed_attempts + 1); row.locked_until = row.failed_attempts >= 5 ? new Date(now + 300000) : null;
        await this.audit(connection, row, 'verification_failed'); return { status: 401, error: 'invalid_recovery_code' };
      }
      row.failed_attempts = 0; row.locked_until = null;
      await connection.query('UPDATE oauth_mfa_recovery_challenges SET superseded_at=clock_timestamp() WHERE user_id=$1 AND consumed_at IS NULL AND superseded_at IS NULL', [userId]);
      const id = crypto.randomUUID(); const challenge = id + '.' + crypto.randomBytes(32).toString('base64url'); const secret = base32(crypto.randomBytes(20));
      const record = (await connection.query(`INSERT INTO oauth_mfa_recovery_challenges(id,token_hash,user_id,factor_revision,issuer,subject,identity_context,encrypted_seed,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()) RETURNING expires_at`,
      [id, hash(challenge), userId, row.revision, this.issuer, subject, JSON.stringify(context), this.mfa.cipher.encrypt(userId, 'recovery:' + id, secret)])).rows[0];
      await this.audit(connection, row, 'started', null, id);
      return { challenge, ...setup(userId, secret, record.expires_at) };
    });
    if (result.error) fail(result.status, result.error);
    await this.current(subject, context); return result;
  }
  async confirm(challenge, code) {
    this.persistent(); const { id, tokenHash } = parseChallenge(challenge);
    const snapshot = await this.mfa.read(async connection => (await connection.query('SELECT * FROM oauth_mfa_recovery_challenges WHERE id=$1 AND token_hash=$2', [id, tokenHash])).rows[0]);
    if (!snapshot || snapshot.issuer !== this.issuer || !validContext(snapshot.identity_context)
      || snapshot.identity_context.userId !== snapshot.user_id) fail(401, 'invalid_recovery_challenge');
    const result = await this.mfa.transaction(snapshot.user_id, async (row, now, audit, connection) => {
      const current = (await connection.query('SELECT * FROM oauth_mfa_recovery_challenges WHERE id=$1 AND token_hash=$2 FOR UPDATE', [id, tokenHash])).rows[0];
      if (!active(current, row, now)) fail(401, 'invalid_recovery_challenge');
      await this.current(current.subject, current.identity_context);
      if (current.locked_until && new Date(current.locked_until).getTime() > now) fail(429, 'mfa_temporarily_locked');
      const secret = this.mfa.cipher.decrypt(row.user_id, 'recovery:' + id, current.encrypted_seed);
      const counter = matchedCounter(secret, code, now, -1);
      if (counter === null) {
        const attempts = current.locked_until ? 1 : Math.min(5, current.failed_attempts + 1);
        await connection.query('UPDATE oauth_mfa_recovery_challenges SET failed_attempts=$2,locked_until=$3 WHERE id=$1', [id, attempts, attempts >= 5 ? new Date(now + 300000) : null]);
        await this.audit(connection, row, 'verification_failed', null, id); return { status: 401, error: 'invalid_otp' };
      }
      await connection.query('UPDATE oauth_mfa_recovery_challenges SET consumed_at=clock_timestamp() WHERE id=$1', [id]);
      await connection.query("SELECT set_config('opendirectory.mfa_recovery',$1,true)", [id]);
      row.revision = String(BigInt(row.revision) + 1n); row.encrypted_seed = this.mfa.cipher.encrypt(row.user_id, 'active', secret);
      row.last_counter = String(counter); row.failed_attempts = 0; row.locked_until = null;
      await audit('recovered'); await this.audit(connection, row, 'completed', null, id);
      return { enabled: true, reauthenticationRequired: true };
    });
    if (result.error) fail(result.status, result.error); return result;
  }
}

module.exports = { MfaRecovery, recoveryHash, parseChallenge };
