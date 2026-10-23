'use strict';

const crypto = require('crypto');
const { MfaError, base32, matchedCounter } = require('./MfaAuthority');
const { validContext, validUuid, sameContext } = require('../../../../packages/identity-authorization-contract');
const credentialContract = require('../../../../packages/credential-authorization-contract');
const hash = value => crypto.createHash('sha256').update('opendirectory-mfa-enrollment-v1|' + value).digest('hex');
function fail(status, code) { throw new MfaError(status, code); }
function parseEnrollment(value) {
  if (typeof value !== 'string' || value.length !== 80) fail(401, 'invalid_enrollment_challenge');
  const [id, secret] = value.split('.');
  if (!validUuid(id) || !/^[A-Za-z0-9_-]{43}$/.test(secret || '') || Buffer.from(secret, 'base64url').toString('base64url') !== secret) fail(401, 'invalid_enrollment_challenge');
  return { id, tokenHash: hash(value) };
}
class MfaEnrollment {
  constructor({ mfa, clients, identity, applications, issuer }) { Object.assign(this, { mfa, clients, identity, applications, issuer }); }
  persistent() { if (this.mfa.demo) fail(503, 'persistent_mfa_enrollment_required'); }
  async ready() {
    this.persistent(); await this.mfa.read(async connection => {
      await connection.query('SELECT id,credential_authorization FROM oauth_mfa_enrollments LIMIT 0'); await connection.query('SELECT id FROM oauth_mfa_enrollment_audit LIMIT 0');
    });
  }
  client(client) {
    if (!client?.enabled || !client.grantTypes.some(grant => ['authorization_code','urn:ietf:params:oauth:grant-type:device_code'].includes(grant))) fail(403, 'mfa_enrollment_not_allowed');
  }
  async eligible(record) {
    try {
      const client = await this.clients.get(record.client_id); this.client(client);
      if (client.version !== String(record.client_revision)) fail(401, 'enrollment_authorization_changed');
      const state = await this.identity.state(record.subject);
      if (!client.mfaRequired && !state.authentication?.required) fail(403, 'mfa_enrollment_not_allowed');
      if (!sameContext(state.context, record.identity_context) || !credentialContract.sameBinding(state.credentialAuthorization, record.credential_authorization)
        || !await this.applications.matches(client.clientId, state, record.application_context)) fail(401, 'enrollment_authorization_changed');
    } catch (error) { throw new MfaError(error.status || 503, error.code || 'identity_authority_unavailable'); }
  }
  async audit(connection, userId, id, action) { await connection.query('INSERT INTO oauth_mfa_enrollment_audit(user_id,enrollment_id,action) VALUES($1,$2,$3)', [userId, id, action]); }
  async start(clientId, subject, credentialAuthentication) {
    this.persistent(); const client = await this.clients.get(clientId); this.client(client);
    const state = await this.identity.state(subject);
    if (!credentialContract.matchesPasswordAuthentication(state, credentialAuthentication, subject)) fail(401, 'credential_authorization_changed');
    if (!validContext(state.context)) fail(403, 'canonical_user_required');
    if (!client.mfaRequired && !state.authentication?.required) fail(403, 'mfa_enrollment_not_allowed');
    const application = await this.applications.context(clientId, state); const userId = state.context.userId;
    const record = { client_id: clientId, client_revision: client.version, subject, identity_context: state.context, application_context: application,
      credential_authorization: state.credentialAuthorization || null };
    const result = await this.mfa.transaction(userId, async (row, now, audit, connection) => {
      await this.eligible(record);
      if (row.enabled) fail(409, 'mfa_already_enabled');
      if (row.locked_until && new Date(row.locked_until).getTime() > now) fail(429, 'mfa_temporarily_locked');
      await connection.query('UPDATE oauth_mfa_enrollments SET superseded_at=clock_timestamp() WHERE user_id=$1 AND consumed_at IS NULL AND superseded_at IS NULL', [userId]);
      const id = crypto.randomUUID(); const challenge = id + '.' + crypto.randomBytes(32).toString('base64url'); const secret = base32(crypto.randomBytes(20));
      const stored = (await connection.query(`INSERT INTO oauth_mfa_enrollments(id,token_hash,user_id,factor_revision,issuer,subject,identity_context,client_id,client_revision,application_context,expires_at,credential_authorization)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp(),$11) RETURNING expires_at`,
      [id, hash(challenge), userId, row.revision, this.issuer, subject, JSON.stringify(state.context), clientId, client.version, JSON.stringify(application),
        state.credentialAuthorization ? JSON.stringify(state.credentialAuthorization) : null])).rows[0];
      row.pending_seed = this.mfa.cipher.encrypt(userId, 'enrollment:' + id, secret); row.pending_session = id; row.pending_expires_at = stored.expires_at;
      row.failed_attempts = 0; row.locked_until = null;
      await audit('setup_started'); await this.audit(connection, userId, id, 'started');
      return { challenge, secret, otpauthUri: `otpauth://totp/OpenDirectory:${userId}?secret=${secret}&issuer=OpenDirectory&algorithm=SHA1&digits=6&period=30`, expiresAt: new Date(stored.expires_at).toISOString() };
    });
    await this.eligible(record); return result;
  }
  async confirm(challenge, code) {
    this.persistent(); const { id, tokenHash } = parseEnrollment(challenge);
    const snapshot = await this.mfa.read(async connection => (await connection.query('SELECT * FROM oauth_mfa_enrollments WHERE id=$1 AND token_hash=$2', [id, tokenHash])).rows[0]);
    if (!snapshot || snapshot.issuer !== this.issuer || !validContext(snapshot.identity_context) || snapshot.user_id !== snapshot.identity_context.userId) fail(401, 'invalid_enrollment_challenge');
    const result = await this.mfa.transaction(snapshot.user_id, async (row, now, audit, connection) => {
      const current = (await connection.query('SELECT * FROM oauth_mfa_enrollments WHERE id=$1 AND token_hash=$2 FOR UPDATE', [id, tokenHash])).rows[0];
      if (!current || current.consumed_at || current.superseded_at || new Date(current.expires_at).getTime() <= now || row.enabled
        || String(current.factor_revision) !== String(row.revision) || row.pending_session !== id || !row.pending_seed) fail(401, 'invalid_enrollment_challenge');
      await this.eligible(current);
      if (row.locked_until && new Date(row.locked_until).getTime() > now) fail(429, 'mfa_temporarily_locked');
      const secret = this.mfa.cipher.decrypt(row.user_id, 'enrollment:' + id, row.pending_seed); const counter = matchedCounter(secret, code, now, -1);
      if (counter === null) {
        row.failed_attempts = row.locked_until ? 1 : Math.min(5, row.failed_attempts + 1); row.locked_until = row.failed_attempts >= 5 ? new Date(now + 300000) : null;
        await this.audit(connection, row.user_id, id, 'verification_failed'); return { status: 401, error: 'invalid_otp' };
      }
      await connection.query('UPDATE oauth_mfa_enrollments SET consumed_at=clock_timestamp() WHERE id=$1', [id]);
      row.enabled = true; row.revision = String(BigInt(row.revision) + 1n); row.encrypted_seed = this.mfa.cipher.encrypt(row.user_id, 'active', secret);
      row.last_counter = String(counter); row.pending_seed = null; row.pending_session = null; row.pending_expires_at = null; row.failed_attempts = 0; row.locked_until = null;
      await audit('enabled'); await this.audit(connection, row.user_id, id, 'completed'); await this.eligible(current);
      return { enabled: true, reauthenticationRequired: true };
    });
    if (result.error) fail(result.status, result.error); return result;
  }
}
module.exports = { MfaEnrollment, parseEnrollment };
