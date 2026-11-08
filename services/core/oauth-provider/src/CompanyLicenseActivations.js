'use strict';

const { randomUUID } = require('crypto');
const contract = require('../../../../packages/company-license-activation');
const { validContext, validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { provenMfa } = require('../../../../packages/mfa-authorization-contract');
function fail(status, code, cause) { throw Object.assign(new Error(code, { cause }), { status, code }); }
class CompanyLicenseActivations {
  constructor(database, { maximum = Number(process.env.COMPANY_LICENSE_ACTIVATION_MAX_SECONDS || 36000), eligibility,
    fetchImpl = (...args) => global.fetch(...args) } = {}) {
    if (!contract.DURATIONS.includes(maximum)) throw new Error('Invalid company license activation maximum');
    this.database = database; this.maximum = maximum;
    this.eligibility = eligibility || ((user, authorization) => contract.request(new URL(contract.ELIGIBILITY_PATH, process.env.OAUTH_IDENTITY_AUTHORITY_URL || process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001').href, contract.ELIGIBILITY_PATH, authorization, user, fetchImpl));
  }
  human(user) {
    if (user?.actor_type !== 'user' || !validUuid(user.sid) || !validContext(user.identity_authorization) || !validRevision(user.client_revision)) fail(403, 'company_license_session_required');
  }
  async state(user, connection = this.database) {
    this.human(user);
    const rows = (await connection.query('SELECT *,floor(extract(epoch FROM expires_at))::bigint AS deadline,expires_at>clock_timestamp() AS unexpired FROM oauth_company_license_activations WHERE session_id=$1 ORDER BY (revoked_at IS NULL) DESC,created_at DESC,id DESC LIMIT 1', [user.sid])).rows;
    const row = rows[0]; const active = row && !row.revoked_at && row.unexpired && provenMfa(user) && contract.matches(row.binding, contract.binding(user));
    return { known: !!row, activation: active ? { schemaVersion: 1, scope: 'company-licenses', id: row.id, tenant: row.tenant, expiresAt: Number(row.deadline) } : null };
  }
  async claim(user) { return (await this.state(user)).activation; }
  async status(user, authorization) {
    this.human(user); const source = await this.eligibility(user, authorization); const state = await this.state(user);
    if (state.activation && !contract.sameTenantContext(source.tenant, state.activation.tenant)) state.activation = null;
    return { schemaVersion: 1, scope: 'company-licenses', tenant: source.tenant, durations: contract.DURATIONS.filter(value => value <= this.maximum),
      requiresFreshMfa: !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user), activation: state.activation };
  }
  async change(user, authorization, input) {
    this.human(user);
    const activate = contract.exact(input, ['durationSeconds', 'reason', 'confirm']);
    const revoke = contract.exact(input, ['activationId', 'confirm']) && validUuid(input.activationId);
    if ((!activate && !revoke) || input.confirm !== true) fail(400, 'exact_company_license_activation_required');
    if (activate && (!contract.DURATIONS.includes(input.durationSeconds) || input.durationSeconds > this.maximum || typeof input.reason !== 'string'
      || input.reason.trim().length < 5 || input.reason.trim().length > 500 || /[\x00-\x1f\x7f]/.test(input.reason))) fail(400, 'invalid_company_license_activation');
    if (activate && !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'fresh_company_license_mfa_required');
    const source = await this.eligibility(user, authorization);
    const client = await this.database.pool.connect();
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL lock_timeout='2500ms'"); await client.query("SET LOCAL statement_timeout='5000ms'");
      const session = (await client.query('SELECT * FROM oauth_sessions WHERE id=$1 FOR UPDATE', [user.sid])).rows[0];
      if (!session || session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) fail(401, 'company_license_session_changed');
      const current = await this.state(user, client);
      if (activate) {
        if (current.activation) fail(409, 'company_license_activation_already_active');
        await client.query('UPDATE oauth_company_license_activations SET revoked_at=clock_timestamp() WHERE session_id=$1 AND revoked_at IS NULL', [user.sid]);
        await client.query(`INSERT INTO oauth_company_license_activations(id,session_id,binding,tenant,reason,duration_seconds,created_at,expires_at)
          SELECT $1,$2,$3,$4,$5,$6::integer,instant,LEAST(instant+$6::integer*interval '1 second',$7::timestamptz) FROM (SELECT date_trunc('second',clock_timestamp()) AS instant) clock`,
        [randomUUID(), user.sid, contract.binding(user), source.tenant, input.reason.trim(), input.durationSeconds, session.expires_at]);
      } else {
        const changed = await client.query('UPDATE oauth_company_license_activations SET revoked_at=clock_timestamp() WHERE session_id=$1 AND id=$2 AND revoked_at IS NULL RETURNING id', [user.sid, input.activationId]);
        if (!changed.rows.length) fail(409, 'company_license_activation_changed');
      }
      const after = await this.eligibility(user, authorization);
      if (!contract.sameTenantContext(source.tenant, after.tenant) || JSON.stringify(source.context) !== JSON.stringify(after.context)
        || (activate && !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user))) fail(401, 'company_license_activation_authority_changed');
      const result = await this.state(user, client);
      await client.query('COMMIT'); return { schemaVersion: 1, activation: result.activation };
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); if (error.status) throw error; fail(503, 'company_license_activation_unavailable', error); }
    finally { client.release(); }
  }
}
module.exports = { CompanyLicenseActivations };
